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
