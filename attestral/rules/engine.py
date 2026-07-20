"""Deterministic rule engine: structured matchers over the system model.

No eval(), no string execution - every matcher is a named, typed check.
"""
from __future__ import annotations

import re
import unicodedata
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


# A bounded homoglyph fold: the non-Latin code points that render as common
# Latin identifier characters. Deliberately NOT the full Unicode confusables
# table - just the letters an attacker reaches for to clone an ASCII tool name,
# so the fold stays high-precision. NFKC already folds full-width and
# compatibility variants; this adds the cross-script look-alikes NFKC keeps.
_CONFUSABLES = {
    # Cyrillic small letters -> their Latin look-alike
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "ѕ": "s", "і": "i", "ј": "j",
    "н": "h", "к": "k", "м": "m", "т": "t", "в": "b",
    # Greek small letters -> their Latin look-alike
    "ο": "o", "α": "a", "ι": "i", "ρ": "p", "υ": "u",
    "κ": "k", "ν": "v", "χ": "x", "ε": "e",
}


def _normalize_tool_name(name: str) -> str:
    """Fold a tool name to the identity a human reads in the tool list: NFKC
    (full-width / compatibility variants), casefold, homoglyph letters mapped to
    their Latin look-alike, zero-width and other format/control characters
    removed, whitespace stripped. Two names with the same fold but different raw
    text are confusable - one can impersonate the other."""
    folded = unicodedata.normalize("NFKC", name).casefold()
    folded = "".join(_CONFUSABLES.get(ch, ch) for ch in folded)
    visible = "".join(ch for ch in folded if unicodedata.category(ch) not in ("Cf", "Cc"))
    return "".join(visible.split())


def _references(surface: str, name: str) -> bool:
    """Case-insensitive, word-boundary occurrence of `name` in `surface`."""
    pattern = r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])"
    return re.search(pattern, surface, re.IGNORECASE) is not None


def _capability_components(model: SystemModel) -> list[tuple[Component, set[str]]]:
    """Every component that hands the agent runtime capabilities: MCP servers,
    subagent delegates, and code-defined agents. The fleet-level rules reason
    over this union so capability combos compose across the delegation hop and
    across config-vs-code surfaces alike."""
    return [(c, set(c.attr("_capabilities") or [])) for c in model.tool_surfaces()]


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
        # Collapse exact duplicates - the same rule on the same component, e.g. a
        # server discovered in several configs - so the count reflects distinct
        # issues, not repeated rows.
        seen: set[tuple[str, str]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.rule_id, f.component_id)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        unique.sort(key=lambda f: f.severity.rank, reverse=True)
        return unique

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
        elif "model_ifc_violation" in match:
            # Roadmap M6: the trifecta/taint flow stated as a formal information-
            # flow lattice property. Fires when a labelled flow (a high-
            # confidentiality source reaching a low-confidentiality egress sink,
            # or a low-integrity source reaching a trust-critical sink) has no
            # declassifier/endorser on the path. Precise and citable, not a
            # heuristic; complements ATL-202/207, and clears once a mitigation is
            # modeled while those coarse rules still fire.
            if match["model_ifc_violation"] is not True:
                return []  # only `true` is defined: fail closed
            from attestral.ifc import violations
            vios = violations(model)
            if not vios:
                return []
            dims = "/".join(v.kind for v in vios)
            detail = (f"Information-flow lattice violation ({dims}). "
                      + " ".join(v.justification for v in vios))
            return [self._finding(rule, "model:ifc", "system model", detail=detail)]
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
        elif "model_tool_name_confusable_collision" in match:
            # Names that are DISTINCT as raw text but collide once folded to the
            # identity a human reads (case, full-width, zero-width, homoglyph).
            # ATL-204 owns the raw-equal case; this fires ONLY when >=2 different
            # raw spellings from >=2 servers share a fold, so the two never
            # double-count. One finding per confusable fold.
            if match["model_tool_name_confusable_collision"] is not True:
                return []  # malformed spec: fail closed
            folds: dict[str, dict[str, list[Component]]] = {}
            for c in _distinct_servers(model):
                for t in dict.fromkeys(str(x) for x in (c.attr("_tool_names") or [])):
                    folds.setdefault(_normalize_tool_name(t), {}).setdefault(t, []).append(c)
            findings = []
            for fold, raws in sorted(folds.items()):
                if len(raws) < 2:
                    continue  # a single raw spelling: unique, or ATL-204's exact clash
                servers = {s.name for owners in raws.values() for s in owners}
                if len(servers) < 2:
                    continue  # all variants on one server: not cross-server shadowing
                variants = ", ".join(repr(r) for r in sorted(raws))
                names = ", ".join(sorted(servers))
                sources = "; ".join(sorted(
                    {s.source for owners in raws.values() for s in owners}))
                findings.append(self._finding(
                    rule, f"model:tool-confusable:{fold}", sources,
                    detail=f"Tool names {variants} fold to the same identifier but are "
                           f"declared by different servers: {names}.",
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
        elif "model_cross_repo_toxic_flow" in match:
            # Fires only on a fleet model (components tagged with `_repo`, as
            # `attestral fleet` produces): the union of the repos' capabilities
            # forms a complete attack chain that NO single repo forms alone. This
            # is the flow a per-repo scan structurally cannot see - each repo is
            # clean on its own. Inert on an ordinary single-repo scan, where no
            # component carries a `_repo` tag so there are fewer than two repos.
            if match["model_cross_repo_toxic_flow"] is not True:
                return []  # malformed spec: fail closed
            repo_caps: dict[str, set[str]] = {}
            for c, caps in _capability_components(model):
                repo = c.attr("_repo")
                if repo:
                    repo_caps.setdefault(repo, set()).update(caps)
            if len(repo_caps) < 2:
                return []
            entry = {r for r, cs in repo_caps.items() if cs & {"network", "saas_data", "memory"}}
            pivot = {r for r, cs in repo_caps.items() if cs & {"shell"}}
            impact = {r for r, cs in repo_caps.items() if cs & {"network", "messaging"}}
            if not (entry and pivot and impact) or (entry & pivot & impact):
                return []  # incomplete, or some single repo completes it alone
            detail = (
                f"Untrusted-input repo(s) [{', '.join(sorted(entry))}] can reach "
                f"code execution in [{', '.join(sorted(pivot))}] and exfiltrate "
                f"through [{', '.join(sorted(impact))}]; no single repo completes "
                "this chain."
            )
            return [self._finding(rule, "fleet", "fleet model", detail=detail)]
        elif "model_sampling_covert_invocation" in match:
            # A server that DECLARES the sampling capability can issue
            # server-initiated model completions (Unit 42, MCP sampling, 2025):
            # covert tool invocation, conversation hijacking, resource theft. The
            # escalation is architectural - a sampling-capable server sharing the
            # runtime with an autonomy surface (a tool that runs with no human
            # checkpoint, or a shell) means a server-driven completion can reach
            # tools the user never approved. Neither config sees the other: the
            # sampling declaration and the autonomy grant live on different
            # servers. One finding per sampling-capable server (attribution to
            # the component that carries the capability).
            if match["model_sampling_covert_invocation"] is not True:
                return []  # malformed spec: fail closed
            sampling = [
                c for c in _distinct_servers(model)
                if "sampling" in (c.attr("_declared_capabilities") or [])
            ]
            if not sampling:
                return []
            autonomy = sorted({
                c.name for c, caps in _capability_components(model)
                if c.attr("_auto_approve") or "shell" in caps
            })
            if not autonomy:
                return []
            surface = ", ".join(autonomy)
            return [
                self._finding(
                    rule, s.id, s.source,
                    detail=(
                        f"Sampling-capable server '{s.name}' shares the runtime "
                        f"with autonomous execution surface(s) [{surface}], so a "
                        "server-initiated completion can drive tools with no "
                        "human checkpoint."
                    ),
                )
                for s in sampling
            ]
        elif "model_injection_reaches_cloud" in match:
            # The internal analogue of ATL-209 (external->cloud): an
            # untrusted-input tool (web/fetch, SaaS, or memory the agent reads
            # back) and a cloud-credentialed tool server share one agent, so an
            # indirect prompt injection in the content the agent ingests can
            # drive cloud APIs with those credentials - agent->cloud reachability
            # that only the assembled model sees, because neither the fetch tool
            # nor the cloud tool is the finding alone. No public endpoint is
            # required, so this covers the common case ATL-209 does not.
            if match["model_injection_reaches_cloud"] is not True:
                return []  # malformed spec: fail closed
            src_caps = {"network", "saas_data", "memory"}
            sources = sorted({
                c.name for c, caps in _capability_components(model) if caps & src_caps
            })
            cloud = [c for c in model.by_type("mcp_server") if c.attr("_has_cloud_credentials")]
            if not (sources and cloud):
                return []
            cloud_desc = ", ".join(
                f"{c.name} ({', '.join(c.attr('_cloud_credential_keys') or [])})"
                for c in sorted(cloud, key=lambda c: c.name)
            )
            detail = (
                f"Untrusted-input tool(s) [{', '.join(sources)}] and "
                f"cloud-credentialed tool server(s) [{cloud_desc}] share one "
                "agent, so indirect prompt injection can drive cloud APIs with "
                "those credentials."
            )
            return [self._finding(rule, "model:injection_to_cloud", "system model", detail=detail)]
        elif "model_agent_reaches_admin_iam" in match:
            # The true agent->cloud identity join no linter can copy: a
            # Kubernetes agent/tool workload binds, through its ServiceAccount's
            # IRSA role-arn annotation (cluster boundary), to an AWS IAM role
            # that grants AdministratorAccess or a wildcard policy (cloud
            # boundary). Any prompt injection or tool compromise inside that
            # runtime inherits full control of the account, so one agentic
            # incident's blast radius becomes the entire cloud account. Neither
            # side is the finding alone; only the assembled model performs the
            # ARN-name join. One finding per (agent runtime, admin role) pair,
            # attributed to the workload. An admin role no SA resolves to (a
            # CI/CD or break-glass role) never fires - the join is required.
            if match["model_agent_reaches_admin_iam"] is not True:
                return []  # only `true` is defined: fail closed
            admin_roles: dict[str, Component] = {}
            for c in model.by_type("aws_iam_role"):
                # by_type prefix-matches aws_iam_role_policy(_attachment) too;
                # only the role itself carries the derived admin signal.
                if c.type != "aws_iam_role" or not c.attr("_admin_wildcard"):
                    continue
                for key in (c.name, c.attr("_role_name"), c.attr("_role_arn")):
                    if isinstance(key, str) and key:
                        admin_roles[key] = c
            if not admin_roles:
                return []
            findings = []
            for wl in model.by_type("k8s_workload"):
                if wl.type != "k8s_workload":
                    continue
                arn = wl.attr("_irsa_role_arn")
                if not (isinstance(arn, str) and arn):
                    continue
                role_name = arn.split(":role/", 1)[1] if ":role/" in arn else ""
                role = admin_roles.get(arn) or (
                    admin_roles.get(role_name) if role_name else None
                )
                if role is None:
                    continue  # unresolved join: fail closed
                sa = wl.attr("service_account_name") or "default"
                findings.append(self._finding(
                    rule, wl.id, wl.source,
                    detail=(
                        f"Agent runtime workload '{wl.name}' (ServiceAccount "
                        f"'{sa}') assumes IAM role '{role.name}', which grants "
                        "AdministratorAccess or a wildcard (Action '*' on "
                        "Resource '*') policy, so any injection or tool "
                        "compromise in the runtime inherits full control of "
                        "the cloud account."
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
            confidence=rule.get("confidence", "high"),
        )
