"""Adversarial validation, tier 0: symbolic proof-of-traversability.

`paths.py` assembles the attack paths a whole-system model can express - a way
IN, a way to RUN CODE, a way to GET DATA OUT, all reachable in one agent
session. This module walks each of those paths over the model's own edges and
turns it into a *proof*: stage by stage, it names the capability that gives each
rung its role and the trust boundaries the walk crosses, then commits the result
to the evidence chain as a Finding. A path is no longer only displayed; it is
attested.

This is the symbolic tier. It is deterministic - no LLM, no execution, no
network - so it always runs with zero dependencies, and it never touches a live
system. The generative tier (an LLM drafts the concrete payload for a path) and
the executed tier (a sandboxed, own-target-only run captures a real transcript)
build on the same proof schema. See research/adversarial-validation-spike.md.
"""
from __future__ import annotations

import copy
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
    and a verdict. The symbolic tier's verdict is always `traversable` - it
    proves the path *holds structurally*, not that a payload was executed."""
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
            f"Proven traversable: {self._entry_summary()} can reach "
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
    for c in list(model.by_type("mcp_server")) + list(model.by_type("subagent")):
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
        for c in list(model.by_type("mcp_server")) + list(model.by_type("subagent"))
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

    @property
    def verified(self) -> bool:
        return self.paths_after < self.paths_before

    @property
    def eliminates_all(self) -> bool:
        return self.paths_after == 0


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
    out: list[Remediation] = []
    pivots = sorted(n for n, cs in caps.items() if cs & _PIVOT_CAPS)
    if pivots:
        after = len(all_attack_paths(_model_without(model, "shell", pivots)))
        out.append(Remediation(
            f"Remove code execution (shell) from {', '.join(pivots)}",
            "shell", pivots, before, after))
    egress = sorted(n for n, cs in caps.items() if cs & _EGRESS_CAPS)
    if egress:
        m = _model_without(_model_without(model, "network", egress), "messaging", egress)
        out.append(Remediation(
            f"Scope or remove the outbound channel on {', '.join(egress)}",
            "network/messaging", egress, before, len(all_attack_paths(m))))
    if cloud:
        after = len(all_attack_paths(_model_without(model, "cloud", cloud)))
        out.append(Remediation(
            f"Move cloud credentials off {', '.join(cloud)} to a scoped broker",
            "cloud credentials", cloud, before, after))
    out.sort(key=lambda r: r.paths_after)
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
