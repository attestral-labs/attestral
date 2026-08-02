"""Design-level capability-envelope diff between two revisions of a design.

The highest-leverage review question on an agent PR is not "what is wrong now"
but "did this change widen what the agent can reach". This module answers it
structurally: build the system model on the old and the new revision, compare
the capability envelope component by component, and classify the change with
the NARROWING / EXPANSION vocabulary of attestral/narrowing.py - deliberately
the same language, deliberately none of the same code, because narrowing.py
classifies compiled POLICY envelopes while this classifies the attested MODEL
itself, before any policy exists.

Widening signals - the precise set, each one is enough to fail --fail-on-widen:

  - a component ADDED whose envelope is non-empty: it declares at least one
    capability (`_capabilities`), holds secrets (`_env_has_secrets`), holds
    cloud credentials (`_has_cloud_credentials`), or runs auto-approved
    (`_auto_approve`). A pure docs/inventory component carrying none of those
    adds surface area on paper but no reach, so it is NOT a widening signal.
  - on a component present in BOTH revisions: a capability token added;
    secrets appearing in env (false -> true); cloud credentials appearing;
    auto-approve appearing.
  - a component-to-component edge ADDED whose endpoints sit in different
    trust boundaries (`references`, `routes_to`, `uses_service_account`,
    `credential_reach`, ...). Sentinel edges (`boundary:*`, `taint:*`) attest
    a crossing exists but name no second component, so they never count here.

Narrowing signals are the exact mirror: a non-empty-envelope component
removed; a capability removed; secrets / cloud credentials / auto-approve
cleared; a cross-boundary edge removed.

Verdict:
  WIDENED   - at least one widening signal and no narrowing signal
  NARROWED  - at least one narrowing signal and no widening signal
  MIXED     - both kinds of signal present
  UNCHANGED - neither

The findings delta (rule ids newly firing / no longer firing, model-level vs
per-component, with severities) is reported as supporting evidence but never
moves the verdict on its own: the envelope is the gate here, and a severity
gate over findings already exists (`attestral scan --fail-on`,
`attestral diff --fail-on`). The CI gate fails on WIDENED *or* MIXED - i.e.
on ANY widening signal - so a change cannot smuggle a widening through by
also narrowing something else.

Deterministic and offline by construction: components are keyed by id, every
list is sorted, and findings come from the deterministic rule engine only
(no ML, no LLM), so the same pair of designs always renders byte-identically.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json

from attestral.model import Component, Finding, SystemModel

WIDENED = "WIDENED"
NARROWED = "NARROWED"
UNCHANGED = "UNCHANGED"
MIXED = "MIXED"

# The verdicts --fail-on-widen fails on: everything containing a widening signal.
GATE_VERDICTS = (WIDENED, MIXED)


@dataclass
class ComponentChange:
    """A component present in only one revision, with the envelope it carries.

    `carries` lists the reach the component brings: its capability tokens plus
    the credential/autonomy flags. Non-empty `carries` on an ADDED component is
    a widening signal; on a REMOVED one, a narrowing signal. Empty `carries`
    (a pure docs component) is inventory, reported but never a signal.
    """
    id: str
    type: str
    boundary: str | None
    carries: list[str] = field(default_factory=list)


@dataclass
class EnvelopeChange:
    """How one surviving component's envelope moved between the revisions."""
    id: str
    type: str
    boundary: str | None
    widenings: list[str] = field(default_factory=list)
    narrowings: list[str] = field(default_factory=list)


@dataclass
class EdgeChange:
    """A component-to-component edge crossing trust boundaries, on one side only."""
    source_id: str
    target_id: str
    kind: str
    source_boundary: str | None
    target_boundary: str | None


@dataclass
class FindingDelta:
    """One rule that fires on exactly one side of the diff."""
    rule_id: str
    severity: str
    component_id: str
    title: str


@dataclass
class DesignDiff:
    """The capability-envelope difference between an old and a new design."""
    components_added: list[ComponentChange] = field(default_factory=list)
    components_removed: list[ComponentChange] = field(default_factory=list)
    envelope_changes: list[EnvelopeChange] = field(default_factory=list)
    crossing_edges_added: list[EdgeChange] = field(default_factory=list)
    crossing_edges_removed: list[EdgeChange] = field(default_factory=list)
    findings_new_model: list[FindingDelta] = field(default_factory=list)
    findings_new_component: list[FindingDelta] = field(default_factory=list)
    findings_resolved_model: list[FindingDelta] = field(default_factory=list)
    findings_resolved_component: list[FindingDelta] = field(default_factory=list)
    verdict: str = UNCHANGED

    @property
    def widenings(self) -> list[str]:
        """Every widening signal, rendered one per line (the gate's evidence)."""
        out: list[str] = []
        for c in self.components_added:
            if c.carries:
                out.append(f"component added: {c.id} ({c.type}, "
                           f"{c.boundary or 'no boundary'}) carrying "
                           + ", ".join(c.carries))
        for e in self.envelope_changes:
            out.extend(f"{e.id}: {w}" for w in e.widenings)
        for e in self.crossing_edges_added:
            out.append(f"cross-boundary edge added: {e.source_id} -> {e.target_id} "
                       f"({e.kind}) [{e.source_boundary} -> {e.target_boundary}]")
        return out

    @property
    def narrowings(self) -> list[str]:
        """Every narrowing signal, rendered one per line."""
        out: list[str] = []
        for c in self.components_removed:
            if c.carries:
                out.append(f"component removed: {c.id} ({c.type}, "
                           f"{c.boundary or 'no boundary'}) which carried "
                           + ", ".join(c.carries))
        for e in self.envelope_changes:
            out.extend(f"{e.id}: {n}" for n in e.narrowings)
        for e in self.crossing_edges_removed:
            out.append(f"cross-boundary edge removed: {e.source_id} -> {e.target_id} "
                       f"({e.kind}) [{e.source_boundary} -> {e.target_boundary}]")
        return out

    def to_dict(self) -> dict:
        d = asdict(self)
        # Derived, but the most useful fields for a CI consumer: the flattened
        # signal lists the verdict was computed from.
        d["widenings"] = self.widenings
        d["narrowings"] = self.narrowings
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def _envelope(c: Component) -> dict:
    """The component's capability envelope: the four reach signals the diff
    (and the widening definition in the module docstring) keys on."""
    return {
        "caps": sorted(str(t) for t in (c.attr("_capabilities") or [])),
        "secrets": bool(c.attr("_env_has_secrets")),
        "cloud_credentials": bool(c.attr("_has_cloud_credentials")),
        "auto_approve": bool(c.attr("_auto_approve")),
    }


def _carries(c: Component) -> list[str]:
    """The envelope as a human-readable list; empty = a pure docs component."""
    env = _envelope(c)
    out = list(env["caps"])
    if env["secrets"]:
        out.append("secrets in env")
    if env["cloud_credentials"]:
        out.append("cloud credentials")
    if env["auto_approve"]:
        out.append("auto-approve")
    return out


def _by_id(model: SystemModel) -> dict[str, Component]:
    out: dict[str, Component] = {}
    for c in model.components:
        out.setdefault(c.id, c)
    return out


def _envelope_change(old: Component, new: Component) -> EnvelopeChange | None:
    """The widenings/narrowings on one surviving component, or None if its
    envelope did not move."""
    o, n = _envelope(old), _envelope(new)
    wide: list[str] = []
    narrow: list[str] = []
    for cap in sorted(set(n["caps"]) - set(o["caps"])):
        wide.append(f"capability added: {cap}")
    for cap in sorted(set(o["caps"]) - set(n["caps"])):
        narrow.append(f"capability removed: {cap}")
    if n["secrets"] and not o["secrets"]:
        wide.append("secrets now in env")
    elif o["secrets"] and not n["secrets"]:
        narrow.append("secrets cleared from env")
    if n["cloud_credentials"] and not o["cloud_credentials"]:
        wide.append("cloud credentials now in env")
    elif o["cloud_credentials"] and not n["cloud_credentials"]:
        narrow.append("cloud credentials cleared")
    if n["auto_approve"] and not o["auto_approve"]:
        wide.append("auto-approve enabled")
    elif o["auto_approve"] and not n["auto_approve"]:
        narrow.append("auto-approve disabled")
    if not wide and not narrow:
        return None
    return EnvelopeChange(new.id, new.type, new.trust_boundary, wide, narrow)


def _crossing_edges(model: SystemModel) -> dict[tuple[str, str, str], EdgeChange]:
    """Component-to-component edges whose endpoints sit in different trust
    boundaries, keyed (source, target, kind). Sentinel endpoints
    (`boundary:*`, `taint:*`, anything that is not a modeled component) fail
    the component lookup and are excluded - fail closed, per the docstring."""
    by_id = _by_id(model)
    out: dict[tuple[str, str, str], EdgeChange] = {}
    for e in model.edges:
        s, t = by_id.get(e.source_id), by_id.get(e.target_id)
        if s is None or t is None:
            continue
        if s.trust_boundary == t.trust_boundary:
            continue
        key = (e.source_id, e.target_id, e.kind)
        out.setdefault(key, EdgeChange(
            e.source_id, e.target_id, e.kind, s.trust_boundary, t.trust_boundary))
    return out


def _finding_deltas(only: dict[tuple[str, str], Finding]) -> list[FindingDelta]:
    rows = [
        FindingDelta(f.rule_id, f.severity.value, f.component_id, f.title)
        for f in only.values()
    ]
    rows.sort(key=lambda r: (-_sev_rank(r.severity), r.rule_id, r.component_id))
    return rows


def _sev_rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity, 0)


def _is_model_level(r: FindingDelta) -> bool:
    """Model-level findings carry component_id "model" or "model:<facet>"
    (e.g. model:taint_flow, model:ifc) - see rules/engine.py."""
    return r.component_id == "model" or r.component_id.startswith("model:")


def diff_designs(old_model: SystemModel, new_model: SystemModel,
                 old_findings: list[Finding], new_findings: list[Finding]) -> DesignDiff:
    """Diff two assembled models (plus their deterministic findings) into a
    DesignDiff, computing the verdict per the module docstring. Pure and
    deterministic: no I/O, components keyed by id, every list sorted."""
    diff = DesignDiff()
    old_c, new_c = _by_id(old_model), _by_id(new_model)

    for cid in sorted(set(new_c) - set(old_c)):
        c = new_c[cid]
        diff.components_added.append(
            ComponentChange(c.id, c.type, c.trust_boundary, _carries(c)))
    for cid in sorted(set(old_c) - set(new_c)):
        c = old_c[cid]
        diff.components_removed.append(
            ComponentChange(c.id, c.type, c.trust_boundary, _carries(c)))
    for cid in sorted(set(old_c) & set(new_c)):
        change = _envelope_change(old_c[cid], new_c[cid])
        if change is not None:
            diff.envelope_changes.append(change)

    old_x, new_x = _crossing_edges(old_model), _crossing_edges(new_model)
    diff.crossing_edges_added = [new_x[k] for k in sorted(set(new_x) - set(old_x))]
    diff.crossing_edges_removed = [old_x[k] for k in sorted(set(old_x) - set(new_x))]

    old_f: dict[tuple[str, str], Finding] = {}
    for f in old_findings:
        old_f.setdefault((f.rule_id, f.component_id), f)
    new_f: dict[tuple[str, str], Finding] = {}
    for f in new_findings:
        new_f.setdefault((f.rule_id, f.component_id), f)
    newly = _finding_deltas({k: v for k, v in new_f.items() if k not in old_f})
    gone = _finding_deltas({k: v for k, v in old_f.items() if k not in new_f})
    diff.findings_new_model = [r for r in newly if _is_model_level(r)]
    diff.findings_new_component = [r for r in newly if not _is_model_level(r)]
    diff.findings_resolved_model = [r for r in gone if _is_model_level(r)]
    diff.findings_resolved_component = [r for r in gone if not _is_model_level(r)]

    wide, narrow = bool(diff.widenings), bool(diff.narrowings)
    if wide and narrow:
        diff.verdict = MIXED
    elif wide:
        diff.verdict = WIDENED
    elif narrow:
        diff.verdict = NARROWED
    else:
        diff.verdict = UNCHANGED
    return diff


_VERDICT_NOTE = {
    WIDENED: "this change widens what the agent can reach",
    NARROWED: "this change only narrows the agent's reach",
    MIXED: "this change both widens and narrows the agent's reach - review the widenings",
    UNCHANGED: "the capability envelope is unchanged",
}


def render_design_diff(diff: DesignDiff) -> str:
    """The diff as a terminal report: WIDENED, then NARROWED, then the findings
    delta, with the verdict line last. Deterministic plain text, no color."""
    lines: list[str] = []

    widenings, narrowings = diff.widenings, diff.narrowings
    if widenings:
        lines.append(f"WIDENED ({len(widenings)} signal{_s(widenings)})")
        lines.extend(f"  + {w}" for w in widenings)
    if narrowings:
        if lines:
            lines.append("")
        lines.append(f"NARROWED ({len(narrowings)} signal{_s(narrowings)})")
        lines.extend(f"  - {n}" for n in narrowings)

    # Inventory-only churn: components that came or went carrying nothing.
    # Shown so the report never hides a change, but explicitly not a signal.
    neutral = (
        [f"  + {c.id} ({c.type}) added" for c in diff.components_added if not c.carries]
        + [f"  - {c.id} ({c.type}) removed" for c in diff.components_removed
           if not c.carries]
    )
    if neutral:
        if lines:
            lines.append("")
        lines.append("Inventory (no reach change)")
        lines.extend(neutral)

    newly = diff.findings_new_model + diff.findings_new_component
    gone = diff.findings_resolved_model + diff.findings_resolved_component
    if newly or gone:
        if lines:
            lines.append("")
        lines.append("Findings delta")
        if newly:
            lines.append(f"  newly firing ({len(newly)}):")
            lines.extend(f"    [{r.severity}] {_where(r)} - {r.title}" for r in newly)
        if gone:
            lines.append(f"  no longer firing ({len(gone)}):")
            lines.extend(f"    [{r.severity}] {_where(r)} - {r.title}" for r in gone)

    if not lines:
        lines.append("No design change between the two revisions.")
    lines.append("")
    lines.append(f"verdict: {diff.verdict} - {_VERDICT_NOTE[diff.verdict]}")
    return "\n".join(lines)


def _s(items: list) -> str:
    return "" if len(items) == 1 else "s"


def _where(r: FindingDelta) -> str:
    scope = "model-level" if _is_model_level(r) else f"on {r.component_id}"
    return f"{r.rule_id} {scope}"
