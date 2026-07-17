"""Kubernetes manifest ingestion.

Reads pod-bearing YAML manifests (Pod, Deployment, StatefulSet, DaemonSet,
Job, CronJob, ReplicaSet, ReplicationController) and flattens each workload
and its containers into the system model. The flattening is deliberate: every
security-relevant field (privileged, hostNetwork, capabilities, image tag,
resource limits) is surfaced as a plain scalar/list attribute so the same
structured matcher vocabulary that scores Terraform can score Kubernetes -
no eval, no bespoke per-field code in the rule engine.

Beyond pod-bearing kinds, RBAC (Role/ClusterRole, RoleBinding/
ClusterRoleBinding) and NetworkPolicy objects are flattened into their own
component types (k8s_rbac_role, k8s_rbac_binding, k8s_network_policy) so the
rule layer can reason about excessive-permission RBAC and missing network
segmentation with the same matcher vocabulary.

Uses pyyaml, which is already a core dependency; no extra install needed.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from attestral.model import Component, SystemModel

# Kinds that carry a pod template we care about, and where the pod spec lives.
_POD_KINDS = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "ReplicationController": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}

_RBAC_ROLE_KINDS = {"Role", "ClusterRole"}
_RBAC_BINDING_KINDS = {"RoleBinding", "ClusterRoleBinding"}

_DANGEROUS_MANIFEST_HINTS = ("apiVersion", "kind")

# The AppArmor annotation is keyed by container name; this is its stable prefix.
_APPARMOR_ANNOTATION_PREFIX = "container.apparmor.security.beta.kubernetes.io/"

# Env var name fragments (case-insensitive) that mark a value as secret-bearing.
# Feeds the "secret hardcoded in env" risk chain (_env_plaintext_secret).
_SECRET_NAME_HINTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "credential",
)


def _dig(doc: dict, path: tuple[str, ...]) -> dict | None:
    node: Any = doc
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node if isinstance(node, dict) else None


def _seccomp_type(node: dict) -> str | None:
    """The seccompProfile.type on a securityContext, tolerating malformed nodes."""
    profile = node.get("seccompProfile")
    return profile.get("type") if isinstance(profile, dict) else None


def _apparmor_type(node: dict) -> str | None:
    """The appArmorProfile.type on a securityContext (GA in 1.30), if present."""
    profile = node.get("appArmorProfile")
    return profile.get("type") if isinstance(profile, dict) else None


def _image_attrs(image: str) -> dict[str, Any]:
    """Split a container image reference into tag-mutability signals."""
    ref = str(image or "")
    # Strip a registry host (contains a dot or port) before reading the tag,
    # so `registry:5000/app` is not mistaken for a tagged image.
    last = ref.rsplit("/", 1)[-1]
    tag = last.split(":", 1)[1] if ":" in last else ""
    return {
        "image": ref,
        "_image_untagged": ref != "" and tag == "",
    }


def _env_signals(container: dict) -> dict[str, bool]:
    """Scan container env for the two secret-handling signals.

    Feeds two risk chains:
      _env_plaintext_secret -> a literal `value:` on a secret-named var
                               (hardcoded credential in the manifest).
      _env_uses_secret_ref  -> the good pattern (valueFrom.secretKeyRef);
                               informational so a rule can reward it.
    """
    env = container.get("env") or []
    plaintext = False
    secret_ref = False
    for entry in env:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", "")).lower()
        value_from = entry.get("valueFrom")
        if isinstance(value_from, dict) and value_from.get("secretKeyRef"):
            secret_ref = True
        # A literal `value` (not sourced from valueFrom) on a secret-named var.
        if "value" in entry and any(h in name for h in _SECRET_NAME_HINTS):
            plaintext = True
    return {
        "_env_plaintext_secret": plaintext,
        "_env_uses_secret_ref": secret_ref,
    }


def _container_component(
    workload_id: str, source: str, container: dict, index: int,
    pod_seccomp: str | None = None,
    pod_run_as_user: Any = None,
    pod_has_selinux: bool = False,
    pod_annotations: dict | None = None,
) -> Component:
    name = str(container.get("name", f"container-{index}"))
    sec = container.get("securityContext") or {}
    caps_cfg = sec.get("capabilities") or {}
    caps = caps_cfg.get("add") or []
    caps_drop = caps_cfg.get("drop") or []
    resources = container.get("resources") or {}
    limits = resources.get("limits") or {}
    requests = resources.get("requests") or {}
    ports = container.get("ports") or []

    attrs: dict[str, Any] = {
        "workload": workload_id,
        "_has_limits": bool(limits),
        "_has_requests": bool(requests),
        "_has_probes": bool(
            container.get("livenessProbe") or container.get("readinessProbe")
        ),
        "_capabilities_add": [str(c) for c in caps],
        "_capabilities_drop": [str(c) for c in caps_drop],
        # PodSecurity 'restricted' requires an explicit drop of ALL capabilities.
        "_drops_all_caps": any(str(c).upper() == "ALL" for c in caps_drop),
        # A hostPort binds the container to a node port, bypassing Service/NetworkPolicy.
        "_has_host_port": any(
            isinstance(p, dict) and p.get("hostPort") for p in ports
        ),
    }
    if "imagePullPolicy" in container:
        attrs["image_pull_policy"] = container["imagePullPolicy"]
    # Seccomp resolves container-first, then falls back to the pod-level default;
    # only surface it when actually configured so `attr_missing` means unconfined-by-default.
    seccomp = _seccomp_type(sec)
    seccomp = seccomp if seccomp is not None else pod_seccomp
    if seccomp is not None:
        attrs["seccomp_profile"] = seccomp
    attrs.update(_image_attrs(container.get("image", "")))
    attrs.update(_env_signals(container))
    # Only surface securityContext booleans that are actually declared, so
    # `attr_missing` matchers can distinguish "set to safe" from "unset".
    for src_key, dst_key in (
        ("privileged", "privileged"),
        ("allowPrivilegeEscalation", "allow_privilege_escalation"),
        ("readOnlyRootFilesystem", "read_only_root_filesystem"),
        ("runAsNonRoot", "run_as_non_root"),
    ):
        if src_key in sec:
            attrs[dst_key] = sec[src_key]

    # runAsUser resolves container-first, then the pod-level default; feeds the
    # "runs as root (uid 0)" risk chain. 0 is a valid value, so guard on None.
    run_as_user = sec.get("runAsUser", pod_run_as_user)
    if run_as_user is not None:
        attrs["run_as_user"] = run_as_user

    # AppArmor: the GA securityContext.appArmorProfile.type wins over the legacy
    # per-container annotation. Lowercased so a rule can match "unconfined"
    # regardless of the source's casing; unset -> attribute absent (attr_missing).
    apparmor = _apparmor_type(sec)
    if apparmor is None and pod_annotations:
        apparmor = pod_annotations.get(_APPARMOR_ANNOTATION_PREFIX + name)
    if apparmor is not None:
        attrs["_apparmor_profile"] = str(apparmor).lower()

    # SELinux options present at the container OR pod level (custom label -> risk).
    attrs["_has_selinux_options"] = ("seLinuxOptions" in sec) or bool(pod_has_selinux)

    return Component(
        id=f"k8s_container.{workload_id.split('.', 1)[-1]}.{name}",
        type="k8s_container",
        name=name,
        source=source,
        attributes=attrs,
        trust_boundary="cluster",
    )


def _workload_component(
    kind: str, wl_name: str, source: str, pod: dict, namespace: str = "default"
) -> Component:
    volumes = pod.get("volumes") or []
    vol_types = [t for v in volumes if isinstance(v, dict) for t in v if t != "name"]
    # serviceAccountName resolves to "default" when unset (both are the risky case);
    # `serviceAccount` is the deprecated spelling. Feeds the default-SA risk chain.
    sa_name = pod.get("serviceAccountName") or pod.get("serviceAccount") or "default"
    attrs: dict[str, Any] = {
        "kind": kind,
        "namespace": namespace,
        "host_network": bool(pod.get("hostNetwork", False)),
        "host_pid": bool(pod.get("hostPID", False)),
        "host_ipc": bool(pod.get("hostIPC", False)),
        "service_account_name": str(sa_name),
        "_volume_types": vol_types,
    }
    if "automountServiceAccountToken" in pod:
        attrs["automount_service_account_token"] = pod["automountServiceAccountToken"]
    return Component(
        id=f"k8s_workload.{wl_name}",
        type="k8s_workload",
        name=wl_name,
        source=source,
        attributes=attrs,
        trust_boundary="cluster",
    )


def _rbac_role_component(doc: dict, source: str) -> Component:
    """Flatten a Role/ClusterRole into wildcard/secrets-grant signals.

    Feeds the excessive-RBAC risk chain: wildcard verbs/resources and a grant
    over `secrets` are the CIS 5.1.x least-privilege violations.
    """
    kind = str(doc.get("kind", "Role"))
    meta = doc.get("metadata") or {}
    name = str(meta.get("name", kind.lower()))
    rules = doc.get("rules") or []
    verbs: list[str] = []
    resources: list[str] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        verbs.extend(str(v) for v in (rule.get("verbs") or []))
        resources.extend(str(r) for r in (rule.get("resources") or []))
    is_cluster = kind == "ClusterRole"
    attrs: dict[str, Any] = {
        "kind": kind,
        "_is_cluster_role": is_cluster,
        "_wildcard_verbs": "*" in verbs,
        "_wildcard_resources": "*" in resources,
        "_grants_secrets": "secrets" in resources,
    }
    # A ClusterRole is cluster-scoped; only a namespaced Role carries a namespace.
    if not is_cluster:
        attrs["namespace"] = str(meta.get("namespace") or "default")
    return Component(
        id=f"k8s_rbac_role.{name}",
        type="k8s_rbac_role",
        name=name,
        source=source,
        attributes=attrs,
        trust_boundary="cluster",
    )


def _rbac_binding_component(doc: dict, source: str) -> Component:
    """Flatten a RoleBinding/ClusterRoleBinding into escalation signals.

    Feeds the privilege-escalation risk chain: a binding to `cluster-admin`
    (CIS 5.1.1) or any cluster-scoped binding is the high-blast-radius grant.
    """
    kind = str(doc.get("kind", "RoleBinding"))
    meta = doc.get("metadata") or {}
    name = str(meta.get("name", kind.lower()))
    role_ref = doc.get("roleRef")
    ref_name = str(role_ref.get("name", "")) if isinstance(role_ref, dict) else ""
    ref_kind = str(role_ref.get("kind", "")) if isinstance(role_ref, dict) else ""
    attrs: dict[str, Any] = {
        "kind": kind,
        "role_ref_name": ref_name,
        "role_ref_kind": ref_kind,
        "_binds_cluster_admin": ref_name == "cluster-admin",
        "_is_cluster_scope": kind == "ClusterRoleBinding",
    }
    return Component(
        id=f"k8s_rbac_binding.{name}",
        type="k8s_rbac_binding",
        name=name,
        source=source,
        attributes=attrs,
        trust_boundary="cluster",
    )


def _network_policy_component(doc: dict, source: str) -> Component:
    """Flatten a NetworkPolicy, flagging a namespace-wide default-deny ingress.

    Feeds the missing-segmentation risk chain (CIS 5.3.2): a model-level rule
    can later flag namespaces that run workloads but declare no default-deny.
    """
    meta = doc.get("metadata") or {}
    name = str(meta.get("name", "networkpolicy"))
    namespace = str(meta.get("namespace") or "default")
    spec = doc.get("spec")
    spec = spec if isinstance(spec, dict) else {}
    # An empty podSelector ({} or unset) selects every pod in the namespace.
    empty_selector = not (spec.get("podSelector") or {})
    policy_types = spec.get("policyTypes") or []
    covers_ingress = any(str(t) == "Ingress" for t in policy_types)
    attrs: dict[str, Any] = {
        "_namespace": namespace,
        "_is_default_deny": empty_selector and covers_ingress,
    }
    return Component(
        id=f"k8s_network_policy.{namespace}.{name}",
        type="k8s_network_policy",
        name=name,
        source=source,
        attributes=attrs,
        trust_boundary="cluster",
    )


def _ingest_pod_doc(doc: dict, kind: str, source: str, model: SystemModel) -> None:
    pod = _dig(doc, _POD_KINDS[kind])
    if pod is None:
        return
    meta = doc.get("metadata") or {}
    wl_name = str(meta.get("name", kind.lower()))
    namespace = str(meta.get("namespace") or "default")
    workload = _workload_component(kind, wl_name, source, pod, namespace)
    model.add(workload)
    # Pod-level context inherited by every container that omits its own.
    pod_sec = pod.get("securityContext") or {}
    pod_seccomp = _seccomp_type(pod_sec)
    pod_run_as_user = pod_sec.get("runAsUser")
    pod_has_selinux = "seLinuxOptions" in pod_sec
    # The AppArmor annotation lives on the pod template's metadata, not its spec.
    pod_meta = _dig(doc, _POD_KINDS[kind][:-1] + ("metadata",)) or {}
    pod_annotations = pod_meta.get("annotations")
    pod_annotations = pod_annotations if isinstance(pod_annotations, dict) else {}
    containers = (pod.get("containers") or []) + (pod.get("initContainers") or [])
    for i, c in enumerate(containers):
        if isinstance(c, dict):
            model.add(_container_component(
                workload.id, source, c, i,
                pod_seccomp=pod_seccomp,
                pod_run_as_user=pod_run_as_user,
                pod_has_selinux=pod_has_selinux,
                pod_annotations=pod_annotations,
            ))


def _ingest_doc(doc: dict, source: str, model: SystemModel) -> None:
    if not isinstance(doc, dict):
        return
    kind = doc.get("kind")
    if kind in _POD_KINDS:
        _ingest_pod_doc(doc, kind, source, model)
    elif kind in _RBAC_ROLE_KINDS:
        model.add(_rbac_role_component(doc, source))
    elif kind in _RBAC_BINDING_KINDS:
        model.add(_rbac_binding_component(doc, source))
    elif kind == "NetworkPolicy":
        model.add(_network_policy_component(doc, source))


def ingest_kubernetes(path: str | Path, model: SystemModel) -> SystemModel:
    p = Path(path)
    files = [p] if p.is_file() else sorted(
        list(p.rglob("*.yaml")) + list(p.rglob("*.yml"))
    )
    for f in files:
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        # Cheap pre-filter: skip YAML that is clearly not a k8s manifest.
        if not all(h in text for h in _DANGEROUS_MANIFEST_HINTS):
            continue
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError:
            continue
        for doc in docs:
            _ingest_doc(doc, str(f), model)
    return model
