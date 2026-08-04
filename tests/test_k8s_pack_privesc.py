"""Coverage for the Kubernetes privilege-escalation wave (ATL-536..537).

The two signals earlier waves recorded as ingester gaps, now ingested and
ruled: the concrete node path behind a hostPath volume (`_hostpath_paths`, so
a runtime-socket mount is distinguishable from a benign /var/log mount) and
the full verb list on a Role/ClusterRole (`_verbs`, so the CIS 5.1.8
escalate/bind/impersonate verbs are matchable by exact token). Fixtures live
in examples/k8s-privesc/.
"""
from attestral.ingest.kubernetes import ingest_kubernetes
from attestral.model import SystemModel
from attestral.rules import RuleEngine

FIXTURE = "examples/k8s-privesc"

NEW_IDS = {"ATL-536", "ATL-537"}


def _fire(path: str) -> set[str]:
    model = ingest_kubernetes(path, SystemModel())
    return {f.rule_id for f in RuleEngine().evaluate(model)}


def test_all_wave_rules_fire():
    fired = _fire(FIXTURE)
    missing = NEW_IDS - fired
    assert not missing, f"wave rules never fired: {sorted(missing)}"


def test_wave_ids_registered():
    ids = {r["id"] for r in RuleEngine().rules}
    assert NEW_IDS <= ids


def test_no_duplicate_rule_ids():
    ids = [r["id"] for r in RuleEngine().rules]
    assert len(ids) == len(set(ids))


def test_runtime_socket_mount_fires():
    fired = _fire(f"{FIXTURE}/runtime-socket.yaml")
    # Both findings are real: the socket-specific critical AND the generic
    # hostPath high - the severity story is "hostPath is bad, the runtime
    # socket is node takeover".
    assert "ATL-536" in fired
    assert "ATL-510" in fired


def test_generic_hostpath_does_not_fire_socket_rule():
    fired = _fire(f"{FIXTURE}/control.yaml")
    assert "ATL-510" in fired  # /var/log is still a hostPath volume
    assert "ATL-536" not in fired  # ...but never guessed into a socket finding


def test_escalation_verbs_fire():
    fired = _fire(f"{FIXTURE}/escalation-role.yaml")
    assert "ATL-537" in fired
    # No wildcards / secrets in the fixture roles: the escalation-verb rule is
    # the only RBAC finding.
    assert "ATL-532" not in fired
    assert "ATL-533" not in fired
    assert "ATL-534" not in fired


def test_read_only_role_stays_silent():
    fired = _fire(f"{FIXTURE}/control.yaml")
    assert "ATL-537" not in fired


def test_wildcard_verbs_do_not_fire_escalation_rule(tmp_path):
    # "*" implies every verb, but that is ATL-533's finding (wildcard verbs);
    # ATL-537 matches only the literal escalation tokens - no double report.
    (tmp_path / "role.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: wildcard\n"
        "rules:\n"
        "  - apiGroups: ['*']\n    resources: ['*']\n    verbs: ['*']\n"
    )
    fired = _fire(str(tmp_path))
    assert "ATL-533" in fired
    assert "ATL-537" not in fired


def test_ingester_emits_hostpath_paths():
    model = ingest_kubernetes(f"{FIXTURE}/runtime-socket.yaml", SystemModel())
    wl = model.by_type("k8s_workload")[0]
    assert wl.attr("_hostpath_paths") == ["/var/run/docker.sock"]

    control = ingest_kubernetes(f"{FIXTURE}/control.yaml", SystemModel())
    assert control.by_type("k8s_workload")[0].attr("_hostpath_paths") == ["/var/log"]


def test_ingester_emits_rbac_verbs():
    model = ingest_kubernetes(f"{FIXTURE}/escalation-role.yaml", SystemModel())
    roles = {r.name: r for r in model.by_type("k8s_rbac_role")}
    assert roles["release-operator"].attr("_verbs") == [
        "get", "list", "bind", "escalate",
    ]
    assert roles["support-impersonator"].attr("_verbs") == ["impersonate"]


def test_hostpath_paths_fail_closed(tmp_path):
    # A malformed hostPath (scalar instead of a dict, or no path key) must
    # contribute nothing - the attribute stays an empty list and the socket
    # rule cannot fire. A trailing slash is normalised, never a bypass.
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
        "spec:\n"
        "  volumes:\n"
        "    - name: bad\n      hostPath: oops\n"
        "    - name: empty\n      hostPath: {}\n"
        "  containers:\n    - name: c\n      image: app@sha256:abc\n"
    )
    model = ingest_kubernetes(tmp_path, SystemModel())
    wl = model.by_type("k8s_workload")[0]
    assert wl.attr("_hostpath_paths") == []
    fired = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-536" not in fired


def test_hostpath_trailing_slash_normalised(tmp_path):
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
        "spec:\n"
        "  volumes:\n"
        "    - name: sock\n"
        "      hostPath:\n        path: /var/run/docker.sock/\n"
        "  containers:\n    - name: c\n      image: app@sha256:abc\n"
    )
    model = ingest_kubernetes(tmp_path, SystemModel())
    assert model.by_type("k8s_workload")[0].attr("_hostpath_paths") == [
        "/var/run/docker.sock"
    ]
    fired = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-536" in fired
