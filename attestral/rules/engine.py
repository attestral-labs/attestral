"""Deterministic rule engine: structured matchers over the system model.

No eval(), no string execution - every matcher is a named, typed check.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from attestral.model import Component, Finding, Severity, SystemModel

_RULES_DIR = Path(__file__).parent
_CORE = _RULES_DIR / "core_rules.yaml"


def _builtin_packs() -> list[Path]:
    """All shipped rule files: core_rules.yaml plus any `*_pack.yaml` provider
    packs in the rules directory. Splitting cloud packs into their own files
    keeps the pack modular and lets provider expansions land without touching
    the shared core file. Deterministic (sorted) load order."""
    return [_CORE] + sorted(_RULES_DIR.glob("*_pack.yaml"))

# Cross-server reference matching only considers tool names that are
# structurally identifiers (send_message, list-issues, createIssue), never
# plain English words: a server legitimately named "search" would otherwise
# flag every description containing that word.
_MIN_TOOL_REF_LEN = 4


def _identifier_like(name: str) -> bool:
    if len(name) < _MIN_TOOL_REF_LEN:
        return False
    if "_" in name or "-" in name:
        return True
    return any(a.islower() and b.isupper() for a, b in zip(name, name[1:]))


def _references(surface: str, name: str) -> bool:
    """Case-insensitive, word-boundary occurrence of `name` in `surface`."""
    pattern = r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])"
    return re.search(pattern, surface, re.IGNORECASE) is not None


def _capability_components(model: SystemModel) -> list[tuple[Component, set[str]]]:
    """Every component that hands the agent runtime capabilities: MCP servers
    and subagent delegates. The fleet-level rules reason over this union so
    capability combos compose across the delegation hop."""
    out: list[tuple[Component, set[str]]] = []
    for c in list(model.by_type("mcp_server")) + list(model.by_type("subagent")):
        out.append((c, set(c.attr("_capabilities") or [])))
    return out


def _distinct_servers(model: SystemModel) -> list[Component]:
    """mcp_server components de-duplicated by (id, source), so a config file
    that happens to match two discovery globs never counts as two servers."""
    seen: set[tuple[str, str]] = set()
    out: list[Component] = []
    for c in model.by_type("mcp_server"):
        key = (c.id, c.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def _matches(component: Component, match: dict[str, Any]) -> bool:
    for kind, spec in match.items():
        if kind == "attr_equals":
            if not all(component.attr(k) == v for k, v in spec.items()):
                return False
        elif kind == "attr_in":
            if not all(component.attr(k) in v for k, v in spec.items()):
                return False
        elif kind == "attr_missing":
            keys = spec if isinstance(spec, list) else [spec]
            if not all(component.attr(k) is None for k in keys):
                return False
        elif kind == "attr_starts_with":
            if not all(str(component.attr(k, "")).startswith(v) for k, v in spec.items()):
                return False
        elif kind == "attr_contains":
            if not all(v in str(component.attr(k, "")) for k, v in spec.items()):
                return False
        elif kind == "attr_list_contains":
            if not all(v in (component.attr(k) or []) for k, v in spec.items()):
                return False
        elif kind == "attr_list_any_of":
            # Match when a value equals a list item (exact token, e.g. a capability
            # name) or an item is a path *under* a value root (v + "/"). We do NOT
            # do bare substring matching: a root of "/" must not match every arg that
            # merely contains a slash (docker refs, URLs, a Windows "/c" flag).
            ok = False
            for k, values in spec.items():
                items = [str(x) for x in (component.attr(k) or [])]
                if any(any(v == i or i.startswith(v + "/") for i in items) for v in values):
                    ok = True
            if not ok:
                return False
        elif kind == "attr_any_contains":
            ok = False
            for k, values in spec.items():
                hay = component.attr(k)
                hay = " ".join(str(x) for x in hay) if isinstance(hay, list) else str(hay or "")
                if any(v in hay for v in values):
                    ok = True
            if not ok:
                return False
        else:
            return False  # unknown matcher: fail closed
    return True


class RuleEngine:
    def __init__(self, rule_paths: list[str | Path] | None = None):
        paths = _builtin_packs() + [Path(p) for p in (rule_paths or [])]
        self.rules: list[dict] = []
        for p in paths:
            data = yaml.safe_load(Path(p).read_text()) or {}
            self.rules.extend(data.get("rules", []))

    def evaluate(self, model: SystemModel) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            target = rule.get("target", "")
            match = rule.get("match", {})
            if target == "model":
                findings.extend(self._evaluate_model_rule(rule, match, model))
                continue
            for c in model.by_type(target):
                if _matches(c, match):
                    findings.append(self._finding(rule, c.id, c.source))
        findings.sort(key=lambda f: f.severity.rank, reverse=True)
        return findings

    def _evaluate_model_rule(self, rule: dict, match: dict, model: SystemModel) -> list[Finding]:
        if "model_has_both" in match:
            a, b = match["model_has_both"]
            if model.by_type(a) and model.by_type(b):
                return [self._finding(rule, "model", "system model")]
        elif "model_capability_combo" in match:
            # Fires when every capability group is covered by SOME component
            # of the runtime - an MCP server or a subagent the main agent can
            # delegate to. Capabilities compose transitively: a fleet with no
            # shell still reaches shell through a delegate whose tool grants
            # include Bash. The combination is the risk, and the finding names
            # who contributes each side of it.
            groups = match["model_capability_combo"]
            if not (isinstance(groups, list) and groups
                    and all(isinstance(g, list) and g for g in groups)):
                return []  # malformed spec: fail closed
            reachable = _capability_components(model)
            fleet: set[str] = set()
            for _c, caps in reachable:
                fleet.update(caps)
            if all(fleet & set(g) for g in groups):
                parts = []
                for g in groups:
                    hit = sorted(fleet & set(g))
                    names = sorted({
                        c.name for c, caps in reachable if caps & set(g)
                    })[:4]
                    parts.append(f"{'/'.join(hit)} via {', '.join(names)}")
                return [self._finding(
                    rule, "model", "system model",
                    detail="Capability chain: " + "; ".join(parts) + ".",
                )]
        elif "model_taint_flow" in match:
            # A declared unsafe data-flow path: some server ingests untrusted
            # input (a `sources` capability) and some server performs a
            # sensitive action (a `sinks` capability). Distinct from the
            # capability_combo trifecta in that it names the actual source and
            # sink servers - the path is what the structural model can see.
            spec = match["model_taint_flow"]
            if not (isinstance(spec, dict)
                    and isinstance(spec.get("sources"), list) and spec["sources"]
                    and isinstance(spec.get("sinks"), list) and spec["sinks"]):
                return []  # malformed spec: fail closed
            src_caps, sink_caps = set(spec["sources"]), set(spec["sinks"])
            src_servers, sink_servers = [], []
            for c, caps in _capability_components(model):
                if caps & src_caps:
                    src_servers.append(c.name)
                if caps & sink_caps:
                    sink_servers.append(c.name)
            if src_servers and sink_servers:
                detail = (
                    f"Untrusted-input server(s) [{', '.join(sorted(set(src_servers)))}] "
                    f"and sensitive-action server(s) [{', '.join(sorted(set(sink_servers)))}] "
                    "share one agent, so injected content can reach the action."
                )
                return [self._finding(rule, "model:taint_flow", "system model", detail=detail)]
        elif "model_external_agent_reach" in match:
            # ASI07 inter-agent reachability: an A2A endpoint that any external
            # agent can invoke (no auth, or schemes defined but not required)
            # fronts a runtime whose tools carry a sensitive capability. So an
            # unauthenticated caller can drive tools that read private data or
            # run commands - a crossing only the system model can see, because
            # neither the card nor any one server is the finding.
            sensitive = match["model_external_agent_reach"]
            if not (isinstance(sensitive, list) and sensitive
                    and all(isinstance(s, str) for s in sensitive)):
                return []  # malformed spec: fail closed
            public = [c for c in model.by_type("a2a_agent")
                      if c.attr("_effectively_public")]
            if not public:
                return []
            sset = set(sensitive)
            reachable: list[str] = []
            for c, caps in _capability_components(model):
                hit = caps & sset
                if hit:
                    reachable.append(f"{c.name} ({'/'.join(sorted(hit))})")
            if not reachable:
                return []
            endpoints = ", ".join(sorted(c.name for c in public))
            detail = (
                f"Public A2A endpoint(s) [{endpoints}] front a runtime whose "
                f"tools carry sensitive capabilities: {', '.join(sorted(reachable))}. "
                "An external agent that reaches the card URL can drive them."
            )
            return [self._finding(rule, "model:external_reach", "system model", detail=detail)]
        elif "model_external_cloud_reach" in match:
            # The full external->cloud path: an effectively-public A2A endpoint
            # fronts a runtime that also holds cloud credentials. So an external
            # agent can delegate a task that drives a cloud-credentialed tool and
            # reach your cloud account - three hops (caller -> endpoint -> tool ->
            # cloud) that only the whole-system model connects.
            if match["model_external_cloud_reach"] is not True:
                return []  # malformed spec: fail closed
            public = [c for c in model.by_type("a2a_agent")
                      if c.attr("_effectively_public")]
            cloud = [c for c in model.by_type("mcp_server")
                     if c.attr("_has_cloud_credentials")]
            if not (public and cloud):
                return []
            endpoints = ", ".join(sorted(c.name for c in public))
            servers = ", ".join(
                f"{c.name} ({', '.join(c.attr('_cloud_credential_keys') or [])})"
                for c in sorted(cloud, key=lambda c: c.name)
            )
            detail = (
                f"Public A2A endpoint(s) [{endpoints}] share a runtime with "
                f"cloud-credentialed tool server(s) [{servers}], so an external "
                "agent that reaches the card can pivot into the cloud account."
            )
            return [self._finding(rule, "model:external_cloud_reach", "system model", detail=detail)]
        elif "model_shared_identity_reach" in match:
            # The identity-propagation gap at the data layer: an effectively-
            # public A2A endpoint means many distinct external callers, and a
            # data-access server that reaches its store through one static env
            # credential means every one of those callers reads with the same
            # downstream identity - so the store can never enforce per-caller
            # entitlements. Neither side is the finding alone; only the
            # assembled model shows the crossing. One finding per flagged
            # server, so remediation lands on the component that owns the
            # credential (mirrors ATL-205's per-server attribution).
            if match["model_shared_identity_reach"] is not True:
                return []  # malformed spec: fail closed
            public = [c for c in model.by_type("a2a_agent")
                      if c.attr("_effectively_public")]
            if not public:
                return []
            endpoints = ", ".join(sorted(c.name for c in public))
            findings = []
            for c in _distinct_servers(model) + list(model.by_type("subagent")):
                if not c.attr("_shared_static_credential"):
                    continue
                findings.append(self._finding(
                    rule, c.id, c.source,
                    detail=(
                        f"Public A2A endpoint(s) [{endpoints}] front data "
                        f"server '{c.name}', which reaches its store through "
                        "one static service credential - every external "
                        "caller reads with the same downstream identity."
                    ),
                ))
            return findings
        elif "model_attack_path" in match:
            # The assembled kill chain: entry (external A2A) -> pivot (code
            # execution) -> impact (exfiltration/cloud), all in one runtime.
            # The per-component rules see the rungs; this traces the ladder.
            if match["model_attack_path"] is not True:
                return []  # malformed spec: fail closed
            from attestral.paths import external_attack_paths
            paths = external_attack_paths(model)
            if not paths:
                return []
            detail = "Complete external attack path - " + "; ".join(
                p.describe() for p in paths
            ) + "."
            return [self._finding(rule, "model:attack_path", "system model", detail=detail)]
        elif "model_railed_dialog_unrailed_execution" in match:
            # A guardrails config rails the dialog channel while an
            # auto-approved shell-capable tool acts entirely outside it. The
            # rails are real - but they govern conversation, not tool side
            # effects, so the safety they imply never reaches the agent's most
            # dangerous capability. Only the system model sees both surfaces:
            # the rails config knows nothing of the tool fleet, and the fleet
            # config knows nothing of the rails. One finding per offending
            # execution component, naming both sides.
            if match["model_railed_dialog_unrailed_execution"] is not True:
                return []  # malformed spec: fail closed
            rails = sorted(model.by_type("guardrails_config"), key=lambda c: c.name)
            if not rails:
                return []
            rail_names = ", ".join(dict.fromkeys(c.name for c in rails))
            findings = []
            seen: set[tuple[str, str]] = set()
            for c, caps in _capability_components(model):
                if "shell" not in caps or not c.attr("_auto_approve"):
                    continue
                key = (c.id, c.source)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._finding(
                    rule, c.id, c.source,
                    detail=(
                        f"Guardrails config(s) [{rail_names}] rail the dialog "
                        f"channel, but auto-approved execution tool '{c.name}' "
                        "runs shell commands outside them with no human "
                        "checkpoint."
                    ),
                ))
            return findings
        elif "model_tool_name_collision" in match:
            # Two servers claiming one tool name: the client's routing decides
            # which implementation answers, so a lower-trust server can shadow
            # the trusted one. One finding per colliding name.
            if match["model_tool_name_collision"] is not True:
                return []  # malformed spec: fail closed
            owners: dict[str, list[Component]] = {}
            for c in _distinct_servers(model):
                for t in dict.fromkeys(str(x) for x in (c.attr("_tool_names") or [])):
                    owners.setdefault(t, []).append(c)
            findings = []
            for tool, servers in sorted(owners.items()):
                if len(servers) < 2:
                    continue
                names = ", ".join(sorted({s.name for s in servers}))
                sources = "; ".join(sorted({s.source for s in servers}))
                findings.append(self._finding(
                    rule, f"model:tool:{tool}", sources,
                    detail=f"Tool '{tool}' is exposed by {len(servers)} servers: {names}.",
                ))
            return findings
        elif "model_cross_server_tool_reference" in match:
            # The shadowing pattern itself: one server's tool metadata talks
            # about a tool that belongs to a different server. Matching is
            # purely structural (identifier cross-reference against the fleet
            # inventory) - the injection *language* is the ML layer's job.
            if match["model_cross_server_tool_reference"] is not True:
                return []  # malformed spec: fail closed
            servers = _distinct_servers(model)
            findings = []
            for a in servers:
                descs = a.attr("_tool_descriptions") or []
                surface = " ".join(
                    [str(a.attr("description") or "")]
                    + [str(d.get("description", "")) for d in descs]
                ).strip()
                if not surface:
                    continue
                own = {str(t) for t in (a.attr("_tool_names") or [])}
                for b in servers:
                    if a is b or a.name == b.name:
                        continue  # same server (or same identity twice: ATL-206's job)
                    for t in dict.fromkeys(str(x) for x in (b.attr("_tool_names") or [])):
                        if t in own or not _identifier_like(t):
                            continue
                        if _references(surface, t):
                            findings.append(self._finding(
                                rule, a.id, a.source,
                                detail=f"'{a.name}' describes behavior for tool "
                                       f"'{t}', which belongs to server '{b.name}'.",
                            ))
            return findings
        elif "model_server_name_conflict" in match:
            # One server name, several launch targets: which code answers to
            # that identity depends on config precedence. Identical mirrored
            # definitions are fine; only differing definitions fire.
            if match["model_server_name_conflict"] is not True:
                return []  # malformed spec: fail closed
            by_name: dict[str, list[Component]] = {}
            for c in _distinct_servers(model):
                by_name.setdefault(c.name, []).append(c)
            findings = []
            for name, comps in sorted(by_name.items()):
                signatures = {
                    (str(c.attr("command") or ""),
                     tuple(str(x) for x in (c.attr("args") or [])),
                     str(c.attr("url") or ""))
                    for c in comps
                }
                if len(comps) >= 2 and len(signatures) >= 2:
                    sources = sorted({c.source for c in comps})
                    findings.append(self._finding(
                        rule, f"model:server:{name}", "; ".join(sources),
                        detail=(
                            f"Server name '{name}' resolves to {len(signatures)} "
                            f"different launch targets across: {', '.join(sources)}."
                        ),
                    ))
            return findings
        return []

    @staticmethod
    def _finding(rule: dict, component_id: str, source: str, detail: str = "") -> Finding:
        description = rule.get("description", "")
        if detail:
            description = f"{description} {detail}" if description else detail
        return Finding(
            rule_id=rule["id"],
            title=rule["title"],
            severity=Severity(rule["severity"]),
            component_id=component_id,
            description=description,
            recommendation=rule.get("recommendation", ""),
            source=source,
            framework_refs=rule.get("frameworks", []),
            origin="deterministic",
        )
