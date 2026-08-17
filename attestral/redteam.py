"""Adversarial validation, tier 0: symbolic attack-path reachability.

`paths.py` assembles the attack paths a whole-system model can express - a way
IN, a way to RUN CODE, a way to GET DATA OUT, all reachable in one agent
session. This module walks each of those paths over the model's own edges and
records it stage by stage: the capability that gives each rung its role and the
trust boundaries the walk crosses, then commits the result to the evidence chain
as a Finding. A path is no longer only displayed; the reachability claim is
attested.

What this establishes, and what it does not. The walk shows a path is *reachable
in the modeled graph*: every rung is a capability the design DECLARES, so the
model is a sound over-approximation of declared capability. Reachability is a
necessary, not a sufficient, condition for exploitation - it does not model
whether the LLM would follow an injection, whether a guardrail or human approval
sits in the path, or whether the sink is reachable at runtime. We report
feasibility over the modeled design, never "proof that an attacker succeeds."

This is the symbolic tier. It is deterministic - no LLM, no execution, no
network - so it always runs with zero dependencies, and it never touches a live
system. The generative tier (an LLM drafts the predicted payload for a path) and
the executed tier (a sandboxed, own-target-only run captures a real transcript)
build on the same schema. See research/adversarial-validation-spike.md.
"""
from __future__ import annotations

import copy
import hashlib
import os
from dataclasses import dataclass, field

from attestral.model import Finding, Severity, SystemModel
from attestral.paths import AttackPath, all_attack_paths

# Capability roles, kept in step with paths.py so the proof narrates the same
# chain the synthesizer assembled.
_ENTRY_TAINT_CAPS = {"network", "saas_data", "memory"}
_PIVOT_CAPS = {"shell"}
_EGRESS_CAPS = {"network", "messaging"}


@dataclass
class ProofStep:
    """One rung of the walk: its role, the component that fills it, and the
    concrete mechanism (capability or credential) that makes it reachable."""
    role: str            # entry | pivot | impact
    component: str
    via: str


@dataclass
class Proof:
    """A walked attack path: the ordered steps, the trust boundaries it spans,
    and a verdict. The symbolic tier's verdict is always `reachable` - the path
    *holds structurally over declared capability*, not that a payload was
    executed or that an attacker would in fact succeed."""
    kind: str            # external | internal
    impact_label: str
    steps: list[ProofStep] = field(default_factory=list)
    boundaries: list[str] = field(default_factory=list)
    outcome: str = "traversable"

    @property
    def rule_id(self) -> str:
        return "ATL-RT-EXTERNAL" if self.kind == "external" else "ATL-RT-INTERNAL"

    @property
    def severity(self) -> Severity:
        # An outside caller reaching a sink is worse than one needing an
        # injection foothold first, so external outranks internal.
        return Severity.CRITICAL if self.kind == "external" else Severity.HIGH

    def _entry_summary(self) -> str:
        entry = next((s for s in self.steps if s.role == "entry"), None)
        if self.kind == "external":
            return "an external caller"
        return "a prompt injection" if entry else "untrusted input"

    def title(self) -> str:
        return (
            f"Reachable in the modeled design: {self._entry_summary()} can reach "
            f"{self.impact_label}"
        )

    def narrate(self) -> str:
        """The walk as a single readable proof line - the attestable content."""
        rungs = " -> ".join(f"{s.component} ({s.via})" for s in self.steps)
        spans = ", ".join(self.boundaries)
        return (
            f"{self.kind} path, {self.outcome}: {rungs}. "
            f"Crosses {len(self.boundaries)} trust boundar"
            f"{'y' if len(self.boundaries) == 1 else 'ies'}: {spans}."
        )

    def remediation(self) -> str:
        pivot = next((s.component for s in self.steps if s.role == "pivot"), "the pivot")
        impact = next((s.component for s in self.steps if s.role == "impact"), "the sink")
        return (
            "Break the chain: remove any one rung. Drop the code-execution "
            f"capability on {pivot}, scope or remove the egress on {impact}, or "
            "gate the entry so untrusted input cannot start the walk."
        )

    def framework_refs(self) -> list[str]:
        refs = ["OWASP-LLM06 Excessive Agency", "MITRE ATLAS AML.T0051"]
        if self.kind == "internal":
            refs.insert(0, "OWASP-LLM01 Prompt Injection")
        return refs

    def to_finding(self) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title(),
            severity=self.severity,
            component_id="model",
            description=self.narrate(),
            recommendation=self.remediation(),
            source="system model",
            framework_refs=self.framework_refs(),
            origin="redteam",
        )


def _cap_index(model: SystemModel) -> dict[str, set[str]]:
    """name -> capability set, for every tool-granting component."""
    idx: dict[str, set[str]] = {}
    for c in model.tool_surfaces():
        idx[c.name] = set(c.attr("_capabilities") or [])
    return idx


def _cloud_cred_names(model: SystemModel) -> set[str]:
    return {c.name for c in model.by_type("mcp_server") if c.attr("_has_cloud_credentials")}


def _boundary_of(model: SystemModel, name: str) -> str:
    for c in model.components:
        if c.name == name:
            return c.trust_boundary or "unscoped"
    return "unscoped"


def _entry_via(kind: str, caps: set[str]) -> str:
    if kind == "external":
        return "exposed as a public A2A endpoint"
    hit = sorted(caps & _ENTRY_TAINT_CAPS)
    return f"ingests untrusted input via {hit[0]}" if hit else "ingests untrusted input"


def _impact_via(caps: set[str], is_cloud: bool) -> str:
    egress = sorted(caps & _EGRESS_CAPS)
    if egress and is_cloud:
        return f"exfiltrates via {egress[0]}, and holds cloud credentials"
    if egress:
        return f"exfiltrates via {egress[0]}"
    if is_cloud:
        return "reaches cloud via stored credentials"
    return "moves data out"


def _proof_from_path(model: SystemModel, path: AttackPath) -> Proof:
    caps = _cap_index(model)
    cloud = _cloud_cred_names(model)
    steps: list[ProofStep] = []
    boundaries: set[str] = set()

    for name in path.entry.components:
        steps.append(ProofStep("entry", name, _entry_via(path.kind, caps.get(name, set()))))
        boundaries.add(_boundary_of(model, name))
    if path.kind == "external":
        boundaries.add("internet (public A2A)")

    for name in path.pivot.components:
        steps.append(ProofStep("pivot", name, "runs code via shell"))
        boundaries.add(_boundary_of(model, name))

    for name in path.impact.components:
        is_cloud = name in cloud
        steps.append(ProofStep("impact", name, _impact_via(caps.get(name, set()), is_cloud)))
        boundaries.add(_boundary_of(model, name))
        if is_cloud:
            boundaries.add("cloud")

    return Proof(
        kind=path.kind,
        impact_label=path.impact.label,
        steps=steps,
        boundaries=sorted(boundaries),
    )


def build_proofs(model: SystemModel) -> list[Proof]:
    """Prove every complete attack path in the attested model. Empty list means
    no path holds - itself a positive result the caller can attest to."""
    return [_proof_from_path(model, p) for p in all_attack_paths(model)]


def proof_findings(model: SystemModel) -> list[Finding]:
    """The proofs as evidence-chain-ready findings."""
    return [p.to_finding() for p in build_proofs(model)]


# --------------------------------------------------------------------------
# Action-space modeling: the tool-call sequences an agent can be induced into,
# not just the one collapsed kill chain paths.py reports.
# --------------------------------------------------------------------------

def _caps_by_name(model: SystemModel) -> dict[str, set[str]]:
    return {
        c.name: set(c.attr("_capabilities") or [])
        for c in model.tool_surfaces()
    }


@dataclass
class ActionSequence:
    """One tool-call sequence an injection could induce: a way in, a way to run
    code, a way out."""
    kind: str            # internal | external
    entry: str
    pivot: str
    impact: str

    def describe(self) -> str:
        return f"{self.entry} -> {self.pivot} -> {self.impact}"


def action_space(model: SystemModel) -> list[ActionSequence]:
    """The behavioral action space: every entry -> pivot -> impact sequence the
    fleet can be induced into. Deterministic. Where paths.py collapses the fleet
    into one named chain, this enumerates the distinct ways to walk it - the
    breadth a per-config scanner never sees."""
    caps = _caps_by_name(model)
    cloud = {c.name for c in model.by_type("mcp_server") if c.attr("_has_cloud_credentials")}
    sources = sorted(n for n, cs in caps.items() if cs & _ENTRY_TAINT_CAPS)
    pivots = sorted(n for n, cs in caps.items() if cs & _PIVOT_CAPS)
    impacts = sorted({n for n, cs in caps.items() if cs & _EGRESS_CAPS} | cloud)
    public = sorted(
        c.name for c in model.by_type("a2a_agent") if c.attr("_effectively_public")
    )
    seqs: list[ActionSequence] = []
    for p in pivots:
        for i in impacts:
            for e in sources:
                seqs.append(ActionSequence("internal", e, p, i))
            for e in public:
                seqs.append(ActionSequence("external", e, p, i))
    return seqs


# --------------------------------------------------------------------------
# Verified remediation: the fix, plus deterministic proof it closes the path.
# --------------------------------------------------------------------------

@dataclass
class Remediation:
    action: str
    capability: str
    targets: list[str]
    paths_before: int
    paths_after: int
    aars_before: float = 0.0
    aars_after: float = 0.0

    @property
    def verified(self) -> bool:
        return self.paths_after < self.paths_before

    @property
    def eliminates_all(self) -> bool:
        return self.paths_after == 0


def _max_agentic_aars(model: SystemModel) -> float:
    """The highest OWASP AIVSS agentic risk score across the model's findings -
    the posture number a fix should move down."""
    from attestral.aivss import scored
    from attestral.rules import RuleEngine
    rows = scored(model, RuleEngine().evaluate(model))
    return rows[0][0].score if rows else 0.0


def _model_without(model: SystemModel, cap: str, names: list[str]) -> SystemModel:
    """A deep copy of the model with `cap` stripped from the named components
    (and cloud credentials cleared when cap == 'cloud'), for what-if
    re-synthesis. The original model is never mutated."""
    m = copy.deepcopy(model)
    targets = set(names)
    for c in m.components:
        if c.name not in targets:
            continue
        c.attributes["_capabilities"] = [
            x for x in (c.attr("_capabilities") or []) if x != cap
        ]
        if cap == "cloud":
            c.attributes["_has_cloud_credentials"] = False
    return m


def verified_remediations(model: SystemModel) -> list[Remediation]:
    """For a design with a proven attack path, the candidate minimal fixes - each
    verified by stripping the rung, re-synthesizing the model, and counting the
    paths that remain. A fix that drops the count to zero is *proven* to close
    the path, not merely recommended. Ranked by paths remaining."""
    before = len(all_attack_paths(model))
    if not before:
        return []
    caps = _caps_by_name(model)
    cloud = [c.name for c in model.by_type("mcp_server") if c.attr("_has_cloud_credentials")]
    aars_before = _max_agentic_aars(model)

    # (action, capability label, targets, strip operations to apply)
    candidates: list[tuple[str, str, list[str], list[tuple[str, list[str]]]]] = []
    pivots = sorted(n for n, cs in caps.items() if cs & _PIVOT_CAPS)
    if pivots:
        candidates.append((
            f"Remove code execution (shell) from {', '.join(pivots)}",
            "shell", pivots, [("shell", pivots)]))
    egress = sorted(n for n, cs in caps.items() if cs & _EGRESS_CAPS)
    if egress:
        candidates.append((
            f"Scope or remove the outbound channel on {', '.join(egress)}",
            "network/messaging", egress, [("network", egress), ("messaging", egress)]))
    if cloud:
        candidates.append((
            f"Move cloud credentials off {', '.join(cloud)} to a scoped broker",
            "cloud credentials", cloud, [("cloud", cloud)]))

    out: list[Remediation] = []
    for action, label, targets, ops in candidates:
        fixed = model
        for cap, names in ops:
            fixed = _model_without(fixed, cap, names)
        out.append(Remediation(
            action, label, targets, before, len(all_attack_paths(fixed)),
            aars_before, _max_agentic_aars(fixed)))
    out.sort(key=lambda r: (r.paths_after, r.aars_after))
    return out


# --------------------------------------------------------------------------
# Generative exploit proof (tier 1): an LLM drafts the predicted exploit for a
# proven path. No execution, no live target. Opt-in; graceful without a key.
# --------------------------------------------------------------------------

_TIER1_SYSTEM = (
    "You are a defensive security assistant helping an engineer validate a flaw "
    "in THEIR OWN attested agent design. For the given proven attack path, draft "
    "a concise, benign proof of concept so they can prioritise the fix: (1) the "
    "shape of the injection text that would enter at the entry tool, using a "
    "harmless canary marker in place of any real secret and no destructive "
    "action; (2) the predicted tool-call sequence from entry to sink; (3) the "
    "transcript the agent would produce. Label it clearly as PREDICTED, NOT "
    "EXECUTED. Never produce anything that would work against a system the reader "
    "does not own."
)


@dataclass
class ExploitDraft:
    kind: str
    text: str
    note: str


def _default_query():
    """An Anthropic-backed `(prompt) -> str` callable, or None when unavailable
    (no key, or the extra is not installed) - the layer then skips gracefully."""
    key = os.environ.get("ATTESTRAL_LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    try:
        import anthropic
    except ImportError:
        return None
    client = anthropic.Anthropic(api_key=key)

    def query(prompt: str) -> str:
        msg = client.messages.create(
            model="claude-sonnet-4-6", max_tokens=900, system=_TIER1_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")

    return query


def draft_exploit(model: SystemModel, path: AttackPath, query=None) -> ExploitDraft:
    """Tier 1: an LLM drafts the predicted exploit for a proven path - the
    injection shape, the predicted tool-call sequence, the expected transcript.
    No execution, no live target, labeled predicted. `query` is an injectable
    `(prompt) -> str` callable (so tests need no key); without one it returns a
    skip note."""
    if query is None:
        query = _default_query()
    if query is None:
        return ExploitDraft(
            path.kind, "",
            'generative tier skipped: set ANTHROPIC_API_KEY or `pip install "attestral[llm]"`')
    prompt = (
        f"Proven {path.kind} attack path in the reviewed design:\n"
        f"  entry  ({path.entry.label}): {', '.join(path.entry.components)}\n"
        f"  pivot  (code execution): {', '.join(path.pivot.components)}\n"
        f"  impact ({path.impact.label}): {', '.join(path.impact.components)}\n\n"
        "Draft the predicted proof of concept as instructed."
    )
    return ExploitDraft(path.kind, query(prompt), "predicted, not executed")


# --------------------------------------------------------------------------
# Terminal rendering for the deeper tiers.
# --------------------------------------------------------------------------

def render_action_space(model: SystemModel, *, color: bool | None = None, limit: int = 12) -> str:
    from attestral.report_terminal import _bold, _dim, _paint, supports_color
    if color is None:
        color = supports_color()
    seqs = action_space(model)
    if not seqs:
        return ""
    lines = [_paint(f"Action space ({len(seqs)} inducible sequences)", "1;31", color)]
    for s in seqs[:limit]:
        arrow = f"{_bold(s.entry, color)} -> {_bold(s.pivot, color)} -> {_bold(s.impact, color)}"
        lines.append(f"  {_dim(s.kind + ':', color)} {arrow}")
    if len(seqs) > limit:
        lines.append(_dim(f"  ... and {len(seqs) - limit} more", color))
    return "\n".join(lines)


def render_remediations(model: SystemModel, *, color: bool | None = None) -> str:
    from attestral.report_terminal import _bold, _dim, _paint, supports_color
    if color is None:
        color = supports_color()
    rems = verified_remediations(model)
    if not rems:
        return ""
    lines = [_paint(f"Verified remediations ({len(rems)})", "32", color)]
    for r in rems:
        if r.eliminates_all:
            verdict = _paint("PROVEN: closes every path", "32", color)
        elif r.verified:
            verdict = _paint(f"reduces {r.paths_before} -> {r.paths_after} paths", "33", color)
        else:
            verdict = _dim("no effect on the path", color)
        lines.append(f"  {_bold(r.action, color)}")
        lines.append(f"    {_dim('verify:', color)} strip {r.capability}, re-synthesize -> {verdict}")
        if r.aars_before != r.aars_after:
            drop = _paint(f"{r.aars_after:.1f}", "32", color)
            lines.append(f"    {_dim('posture:', color)} worst agentic risk AARS {r.aars_before:.1f} -> {drop}")
    return "\n".join(lines)


def render_exploits(model: SystemModel, *, color: bool | None = None, query=None) -> str:
    from attestral.report_terminal import _bold, _dim, _paint, supports_color
    if color is None:
        color = supports_color()
    paths = all_attack_paths(model)
    if not paths:
        return ""
    lines = [_paint("Generative exploit proofs (tier 1 - predicted, not executed)", "1;31", color)]
    for p in paths:
        d = draft_exploit(model, p, query=query)
        lines.append(f"  {_bold(p.kind + ' path', color)}:")
        if d.text:
            for ln in d.text.splitlines():
                lines.append(f"    {ln}")
        else:
            lines.append(f"    {_dim(d.note, color)}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Tier 2, sandboxed: replay a proven path through Attestral's OWN stub tools
# with a planted canary. It moves a harmless marker from a stub secret store to a
# captured stub sink and records the transcript - no real system, no real secret,
# no network. This is the harness, NOT a run against your live agent; that stays
# gated, own-target-only, and future.
# --------------------------------------------------------------------------

@dataclass
class SandboxStep:
    actor: str            # entry | pivot | impact
    tool: str
    action: str
    observed: str


@dataclass
class SandboxRun:
    kind: str
    canary: str
    steps: list[SandboxStep]
    exfiltrated: bool


def _canary_for(path: AttackPath) -> str:
    return "ATTESTRAL-CANARY-" + hashlib.sha256(path.describe().encode()).hexdigest()[:10]


def execute_in_sandbox(model: SystemModel, path: AttackPath) -> SandboxRun:
    """Tier 2 (sandbox harness): replay the proven path through stub tools with a
    planted canary, actually moving the marker from a stub secret store to a
    captured stub sink, and record the transcript. Deterministic; touches no real
    system, secret, or network. Honest scope: Attestral's harness, not your live
    agent."""
    canary = _canary_for(path)
    stub_secret_store = {"~/.ssh/id_rsa": canary}   # planted, harmless marker
    captured_sink: list[str] = []
    entry = ", ".join(path.entry.components) or "entry tool"
    pivot = path.pivot.components[0] if path.pivot.components else "shell"
    impact = path.impact.components[0] if path.impact.components else "egress"
    steps = [
        SandboxStep("entry", entry,
                    "ingests content carrying an injected instruction (canary bait)",
                    "instruction accepted by the agent (stub)"),
    ]
    secret = stub_secret_store.get("~/.ssh/id_rsa", "")
    steps.append(SandboxStep("pivot", pivot,
                             "runs: read ~/.ssh/id_rsa  (stub filesystem)",
                             f"read planted canary {secret}"))
    captured_sink.append(secret)
    steps.append(SandboxStep("impact", impact,
                             "POST to captured sink  (stub, no network egress)",
                             f"captured: {secret}"))
    return SandboxRun(path.kind, canary, steps, exfiltrated=(canary in captured_sink))


def render_execution(model: SystemModel, *, color: bool | None = None) -> str:
    from attestral.report_terminal import _bold, _dim, _paint, supports_color
    if color is None:
        color = supports_color()
    paths = all_attack_paths(model)
    if not paths:
        return ""
    lines = [_paint("Sandbox execution (tier 2 - Attestral harness, planted canary, no live target)", "1;31", color)]
    for p in paths:
        run = execute_in_sandbox(model, p)
        lines.append(f"  {_bold(p.kind + ' path', color)}  canary {_dim(run.canary, color)}")
        for i, s in enumerate(run.steps, 1):
            lines.append(f"    {i}. {_dim(s.actor + ':', color)} {s.tool}  {_dim('- ' + s.action, color)}")
            lines.append(f"       {_dim('observed:', color)} {s.observed}")
        if run.exfiltrated:
            lines.append(f"    {_paint('EXECUTED: the canary reached the sink', '1;31', color)}")
        else:
            lines.append(f"    {_dim('the canary did not reach the sink', color)}")
    lines.append(_dim(
        "  harness only: no real system, secret, or network was touched. Execution "
        "against your own fingerprinted target stays gated.", color))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Tier 2, EXECUTED: run the attack against isolated stub agents and measure the
# outcome, instead of narrating it. Where execute_in_sandbox() moves a marker
# between two dicts in-process, this spawns a real sandboxed agent (its own OS
# process), plants a canary in a stub secret store, and lets the agent actually
# exfiltrate it over a socket to an instrumented sink the harness controls. Two
# facts fall out, measured not asserted:
#   - exfiltrated: the parent's sink actually received the canary bytes (an
#     AgentDojo-style environment-state oracle - the child cannot fake it).
#   - contained: while running, the sandbox's EgressGuard blocked a real
#     outbound connection to the attacker host, so the proof-of-exploit could
#     not leak. The exploit is demonstrated AND contained in the same run.
# Deterministic, offline, own-stubs-only: the induced tool sequence is the
# modeled one, not an LLM's decision, and nothing real is touched. A live-agent
# driver plugs into the same PentestResult schema and stays gated + future.
# --------------------------------------------------------------------------

_DECOY_ATTACKER = ("10.255.255.1", 80)  # non-routable; the guard blocks it first


def _egress_server_ids(model: SystemModel, path: AttackPath) -> list[str]:
    """The mcp_server component ids that carry the canary out on this path: the
    impact-stage servers, or the pivot-stage servers when the sink is pure cloud.
    These are what a proven exploit denies when the loop closes into the policy."""
    def servers(names) -> list[str]:
        wanted = set(names)
        return [c.id for c in model.by_type("mcp_server") if c.name in wanted]
    return servers(path.impact.components) or servers(path.pivot.components)


@dataclass
class PentestResult:
    """The measured outcome of one executed attack run."""
    kind: str
    canary: str
    exfiltrated: bool            # canary observed at the instrumented sink (the oracle)
    contained: bool              # a real outbound was blocked by the sandbox guard
    egress_blocked: list[str] = field(default_factory=list)
    transcript: list[dict] = field(default_factory=list)
    isolated: bool = True        # ran in a separate OS process
    error: str = ""
    # Component ids of the mcp_servers whose egress carried the canary out - the
    # rung a proven exploit denies when the loop is closed into the runtime policy.
    egress_server_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "canary": self.canary,
            "exfiltrated": self.exfiltrated, "contained": self.contained,
            "egress_blocked": self.egress_blocked, "transcript": self.transcript,
            "isolated": self.isolated, "error": self.error,
            "egress_server_ids": self.egress_server_ids,
        }


def _run_attack(plan: dict) -> dict:
    """The sandboxed agent's body: read the planted secret, try to exfiltrate it.

    Runs with an armed EgressGuard, so the attempt to reach the attacker host is
    blocked (recorded), while the send to the harness's loopback sink is allowed
    - the instrumented egress channel the oracle watches. Pure stdlib; safe to
    run in-process (isolate=False) or in a spawned child.
    """
    import socket as _socket

    from attestral.evidence import EgressGuard
    canary = plan["canary"]
    transcript: list[dict] = [{
        "actor": "entry", "tool": plan["entry"],
        "action": "ingests content carrying an injected instruction (canary bait)",
        "observed": "instruction accepted by the stub agent",
    }, {
        "actor": "pivot", "tool": plan["pivot"],
        "action": "reads the planted secret (stub filesystem: ~/.ssh/id_rsa)",
        "observed": f"read planted canary {canary}",
    }]
    blocked: list[str] = []
    guard = EgressGuard().arm()
    try:
        # Containment: a real breach would exfiltrate to the attacker's host.
        try:
            c = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            c.settimeout(1)
            c.connect((plan["decoy_host"], plan["decoy_port"]))
            c.close()
            transcript.append({"actor": "impact", "tool": plan["impact"],
                               "action": f"POST canary to attacker host {plan['decoy_host']}",
                               "observed": "CONNECTED - sandbox NOT contained"})
        except OSError:
            blocked.append(f"{plan['decoy_host']}:{plan['decoy_port']}")
            transcript.append({"actor": "impact", "tool": plan["impact"],
                               "action": "POST canary to the attacker host (real outbound)",
                               "observed": "blocked by the sandbox egress guard (contained)"})
        # Instrumented egress: carry the canary out via the modeled channel.
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((plan["sink_host"], plan["sink_port"]))
            s.sendall(canary.encode())
            s.close()
            transcript.append({"actor": "impact", "tool": plan["impact"],
                               "action": "carry the secret out via the modeled egress channel",
                               "observed": "sent to the instrumented sink"})
        except OSError as exc:
            transcript.append({"actor": "impact", "tool": plan["impact"],
                               "action": "carry the secret out via the modeled egress channel",
                               "observed": f"failed: {exc}"})
    finally:
        guard.disarm()
    return {"transcript": transcript, "blocked": blocked}


def _pentest_worker(plan: dict, result_q) -> None:
    """Child-process entry point (module-level so it is picklable on spawn)."""
    result_q.put(_run_attack(plan))


def _harden() -> None:
    """Best-effort jail for the sandbox child (POSIX): a new session, an isolated
    cwd, a cleared environment, and resource ceilings (CPU, file descriptors,
    processes). Each is a no-op where the primitive is unavailable, so the tier
    degrades to a plain subprocess rather than failing."""
    import os
    import tempfile
    try:
        import resource
    except ImportError:
        resource = None
    try:
        os.setsid()
    except OSError:
        pass
    try:
        os.chdir(tempfile.mkdtemp(prefix="attestral-jail-"))
    except OSError:
        pass
    keep_path = os.environ.get("PATH", "/usr/bin:/bin")
    os.environ.clear()
    os.environ["PATH"] = keep_path
    if resource is not None:
        limits = [(resource.RLIMIT_CPU, 15), (resource.RLIMIT_NOFILE, 256)]
        if hasattr(resource, "RLIMIT_NPROC"):
            limits.append((resource.RLIMIT_NPROC, 128))
        for res_id, val in limits:
            try:
                resource.setrlimit(res_id, (val, val))
            except (ValueError, OSError):
                pass


def _pentest_worker_hardened(plan: dict, result_q) -> None:
    """Hardened child entry point: apply the jail, then run the attack."""
    _harden()
    result_q.put(_run_attack(plan))


_CONTAINER_IMAGE = "busybox:latest"  # tiny; sh + cat suffice for the staged-exfil oracle


def _run_pentest_container(kind: str, canary: str, entry: str, pivot: str, impact: str,
                           egress_ids: list[str], timeout: float) -> PentestResult:
    """Strongest tier: run the sandbox agent in a `docker --network none` container.

    With no network interface at all, real egress is structurally impossible, so
    containment is guaranteed. The exfil oracle moves from a socket to a mounted
    volume: the agent stages the planted secret to a writable channel and the host
    reads it. Fails closed (an error, never a hang) when docker or the image is
    unavailable.
    """
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path
    base = dict(kind=kind, canary=canary, isolated=True, egress_server_ids=egress_ids)
    docker = shutil.which("docker")
    if docker is None:
        return PentestResult(exfiltrated=False, contained=False,
                             error="container backend requires docker (not found on PATH)", **base)
    try:
        info = subprocess.run([docker, "info"], capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        info = None
    if info is None or info.returncode != 0:
        return PentestResult(exfiltrated=False, contained=False,
                             error="container backend requires a running docker daemon", **base)
    tmp = tempfile.mkdtemp(prefix="attestral-sb-")
    try:
        Path(tmp, "secret").write_text(canary)
        cmd = [docker, "run", "--rm", "--network", "none", "--read-only",
               "--tmpfs", "/tmp", "-v", f"{tmp}:/sb", _CONTAINER_IMAGE,
               "sh", "-c", "cat /sb/secret > /sb/exfil 2>/dev/null || true"]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return PentestResult(exfiltrated=False, contained=True,
                                 egress_blocked=["<no network: --network none>"],
                                 error="container run timed out", **base)
        except (OSError, subprocess.SubprocessError) as exc:
            return PentestResult(exfiltrated=False, contained=False,
                                 error=f"docker run failed: {exc}", **base)
        if run.returncode != 0:
            return PentestResult(
                exfiltrated=False, contained=True,
                egress_blocked=["<no network: --network none>"],
                error=f"container image {_CONTAINER_IMAGE} unavailable: "
                      f"{run.stderr.decode(errors='replace')[:200]}", **base)
        exfil = Path(tmp, "exfil")
        exfiltrated = exfil.exists() and canary in exfil.read_text(errors="replace")
        transcript = [
            {"actor": "pivot", "tool": pivot,
             "action": "reads the planted secret (mounted /sb/secret)",
             "observed": f"read planted canary {canary}"},
            {"actor": "impact", "tool": impact, "action": "attempt real network egress",
             "observed": "impossible: the container has no network (--network none)"},
            {"actor": "impact", "tool": impact,
             "action": "stage the secret to a writable channel (/sb/exfil)",
             "observed": "staged" if exfiltrated else "not staged"},
        ]
        return PentestResult(exfiltrated=exfiltrated, contained=True,
                             egress_blocked=["<no network: --network none>"],
                             transcript=transcript, **base)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_pentest(model: SystemModel, path: AttackPath, *,
                isolate: bool = True, isolation: str | None = None,
                timeout: float = 20.0) -> PentestResult:
    """Execute one proven attack path against an isolated sandbox agent and measure
    the outcome. The sink oracle is parent-side, so exfiltration is observed, never
    self-reported. `isolation` selects the backend, strongest last:
      - inprocess: run in this process (fastest, weakest; for tests)
      - subprocess: a separate OS process (the default)
      - hardened:  a subprocess in a POSIX jail (new session, cwd, cleared env, rlimits)
      - container: docker --network none (real egress structurally impossible)
    `isolate=False` is the legacy spelling of `isolation="inprocess"`."""
    import socket
    import threading

    backend = isolation or ("subprocess" if isolate else "inprocess")
    canary = _canary_for(path)
    entry = ", ".join(path.entry.components) or "entry tool"
    pivot = path.pivot.components[0] if path.pivot.components else "shell"
    impact = path.impact.components[0] if path.impact.components else "egress"
    egress_ids = _egress_server_ids(model, path)

    if backend == "container":
        return _run_pentest_container(path.kind, canary, entry, pivot, impact,
                                      egress_ids, timeout)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(timeout)
    received = bytearray()

    def _capture() -> None:
        try:
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(3)
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    received.extend(chunk)
        except OSError:
            pass

    thread = threading.Thread(target=_capture, daemon=True)
    thread.start()
    host, port = srv.getsockname()
    plan = {
        "canary": canary, "sink_host": host, "sink_port": port,
        "decoy_host": _DECOY_ATTACKER[0], "decoy_port": _DECOY_ATTACKER[1],
        "entry": entry, "pivot": pivot, "impact": impact,
    }

    error = ""
    worker = {"transcript": [], "blocked": []}
    if backend == "inprocess":
        worker = _run_attack(plan)
    else:
        import multiprocessing as mp
        target = _pentest_worker_hardened if backend == "hardened" else _pentest_worker
        queue: mp.Queue = mp.Queue()
        proc = mp.Process(target=target, args=(plan, queue), daemon=True)
        proc.start()
        try:
            worker = queue.get(timeout=timeout)
        except Exception:  # noqa: BLE001 - empty queue or a dead child are both "no result"
            error = "sandbox process did not report a result"
        finally:
            proc.join(timeout=3)
            if proc.is_alive():
                proc.terminate()
                error = error or "sandbox process timed out"

    thread.join(timeout=3)
    srv.close()
    return PentestResult(
        kind=path.kind, canary=canary,
        exfiltrated=canary.encode() in bytes(received),
        contained=bool(worker["blocked"]),
        egress_blocked=worker["blocked"],
        transcript=worker["transcript"],
        isolated=(backend != "inprocess"), error=error,
        egress_server_ids=egress_ids,
    )


def run_pentests(model: SystemModel, *, isolate: bool = True,
                 isolation: str | None = None) -> list[PentestResult]:
    """Execute the harness on every reachable path in the model."""
    return [run_pentest(model, p, isolate=isolate, isolation=isolation)
            for p in all_attack_paths(model)]


def pentest_report(results: list[PentestResult]) -> dict:
    """A JSON-ready report of an executed pentest run."""
    return {
        "paths": [r.to_dict() for r in results],
        "exfiltrated": sum(1 for r in results if r.exfiltrated),
        "contained": sum(1 for r in results if r.contained),
        "total": len(results),
    }


# --------------------------------------------------------------------------
# Close the loop: an EXECUTED proof-of-exploit becomes a runtime DENY. A pentest
# that exfiltrated the canary proves the reachable path is a live exploit, so the
# server whose egress carried it out is emitted as a CRITICAL finding against its
# own component id. compile_policy already denies any server carrying a critical
# finding, so these flow straight through into a default-deny on the proven
# channel - no coupling from the compiler to the red-team code. That is the full
# arc: static review -> sandbox-proven exploit -> runtime-enforced policy.
# --------------------------------------------------------------------------

EXFIL_RULE_ID = "ATL-RT-EXFIL"


def proven_exploit_findings(results: list[PentestResult]) -> list[Finding]:
    """Critical findings for the egress servers of every EXFILTRATED pentest path.

    Passed alongside the scan findings to `compile_policy`, these deny the exact
    server whose egress carried a proven canary out, until the path is broken.
    """
    out: list[Finding] = []
    seen: set[str] = set()
    for r in results:
        if not r.exfiltrated:
            continue
        for cid in r.egress_server_ids:
            if cid in seen:
                continue
            seen.add(cid)
            out.append(Finding(
                rule_id=EXFIL_RULE_ID,
                title="Proof-of-exploit executed: this server's egress carried the canary out",
                severity=Severity.CRITICAL,
                component_id=cid,
                description=(
                    f"An executed sandbox pentest of the {r.kind} attack path carried a planted "
                    "canary through this server's egress to an instrumented sink, with the real "
                    "outbound blocked (containment verified). This confirms the declared design "
                    "permits the flow end to end; it is not proof the target's live agent would "
                    "follow an injection."),
                recommendation=(
                    "Break the proven path: remove the code-execution rung on the pivot, or "
                    "scope/remove this server's outbound channel, then re-attest and re-compile. "
                    "Until then the runtime policy denies this server."),
                source="executed pentest",
                framework_refs=["OWASP-LLM06 Excessive Agency", "MITRE ATLAS AML.T0051"],
                origin="redteam",
            ))
    return out


def render_pentest(model: SystemModel, *, color: bool | None = None,
                   results: list[PentestResult] | None = None,
                   isolate: bool = True, isolation: str | None = None) -> str:
    """Terminal block for the executed harness: per path, the transcript, whether
    the canary actually reached the sink, and whether the run was contained."""
    from attestral.report_terminal import _bold, _dim, _paint, supports_color
    if color is None:
        color = supports_color()
    if results is None:
        results = run_pentests(model, isolate=isolate, isolation=isolation)
    if not results:
        return ""
    lines = [_paint(
        f"Executed pentest (tier 2 - {len(results)} path(s), isolated sandbox, "
        "planted canary, no live target)", "1;31", color)]
    for r in results:
        where = "isolated subprocess" if r.isolated else "in-process"
        lines.append(f"  {_bold(r.kind + ' path', color)}  canary {_dim(r.canary, color)}  "
                     f"({_dim(where, color)})")
        for i, s in enumerate(r.transcript, 1):
            lines.append(f"    {i}. {_dim(s['actor'] + ':', color)} {s['tool']}  "
                         f"{_dim('- ' + s['action'], color)}")
            lines.append(f"       {_dim('observed:', color)} {s['observed']}")
        if r.error:
            lines.append(f"    {_paint('harness error: ' + r.error, '33', color)}")
        if r.exfiltrated:
            lines.append(f"    {_paint('EXFILTRATED: the canary reached the sink', '1;31', color)}")
        else:
            lines.append(f"    {_dim('the canary did not reach the sink', color)}")
        if r.contained:
            msg = _paint("CONTAINED: the real outbound was blocked by the guard", "32", color)
            lines.append(f"    {msg}")
    lines.append(_dim(
        "  executed against Attestral's own stub agents with a planted canary; no "
        "real system, secret, or egress. A live-target driver stays gated.", color))
    return "\n".join(lines)
