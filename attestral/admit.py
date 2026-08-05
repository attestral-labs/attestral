"""Admission control for agent tools: should this agent be allowed to load this
tool, and prove why.

A scanner reviews what you already built. `attestral admit` answers the question
one step earlier, the one that actually gates a change: *before* you add an MCP
server to an agent's loadout, what does admitting it cost? It builds the current
attested design, builds the design WITH the proposed server added (re-deriving the
credential-reach and taint edges so the new tool's interactions with the existing
fleet appear), diffs the two, and returns a verdict with the evidence behind it.

This is the sharp end of the whole-system model: the risk of a new tool is almost
never in the tool itself. A read-only web fetcher is harmless alone; dropped into
a runtime that already holds a cloud credential, it becomes the injectable entry
of a confused-deputy path into named infrastructure (ATL-222). Only a model that
already knows the rest of the fleet, and the cloud it can reach, can price that.
So the verdict is not a rule on the tool; it is the security DELTA of admitting
it - the new findings, the new attack paths, the new cross-boundary reach it
grants, and the shift in worst-case blast radius. Deny reasons are named, so the
gate proves itself rather than asserting.

Deterministic, offline. It reuses the same model, rule engine, reachability, and
diff the scan uses, so the answer is the tool's own reasoning run against a
hypothetical, not a guess.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field

from attestral.delta import ModelDelta, diff_models
from attestral.model import Finding, Severity, SystemModel

# Findings whose APPEARANCE on admission is a categorical deny: a completed
# kill chain or a cross-boundary reach the design did not have before.
_CHAIN_RULES = {"ATL-202", "ATL-207", "ATL-210", "ATL-213", "ATL-217", "ATL-222"}


@dataclass
class AdmitVerdict:
    allowed: bool
    added: list[str] = field(default_factory=list)          # the server names admitted
    delta: ModelDelta | None = None                          # the security delta of admitting
    reach_granted: list[str] = field(default_factory=list)   # new named cloud/cluster sinks reachable
    reasons: list[str] = field(default_factory=list)         # why deny (or why allowed-with-notes)
    note: str = ""                                           # set when the change matched nothing


def _proposed_model(base: SystemModel, add_path: str) -> tuple["SystemModel | None", list[str]]:
    """A copy of `base` with the components from `add_path` merged in and every
    derived edge (taint / credential-reach / tool-access) recomputed over the
    combined fleet, so the new tool's reach into the EXISTING cloud model appears.
    Returns (proposed, added_names); proposed is None when nothing new was added."""
    from attestral.ingest import build_model
    from attestral.ingest.scan import (
        _add_credential_reach_edges,
        _add_reachability_edges,
        _add_taint_edges,
    )

    proposed = copy.deepcopy(base)
    add = build_model(add_path)
    existing = {c.id for c in proposed.components}
    added = [c for c in add.components if c.id not in existing]
    if not added:
        return None, []
    proposed.components.extend(added)
    derived = {"taint_source", "taint_sink", "credential_reach", "tool_access"}
    proposed.edges = [e for e in proposed.edges if e.kind not in derived]
    _add_reachability_edges(proposed)
    _add_taint_edges(proposed)
    _add_credential_reach_edges(proposed)
    return proposed, sorted({c.name for c in added})


def _named_reach(model: SystemModel) -> set[str]:
    """The set of 'entry->sink' cross-boundary reaches in a model, as stable
    strings, so admitting a tool can be diffed for NEW named-cloud reach."""
    from attestral.cloudreach import cross_boundary_reaches

    out: set[str] = set()
    for r in cross_boundary_reaches(model):
        for s in r.sinks:
            out.add(f"{r.entry} -> {s}")
    return out


def admit(base_path: str, add_path: str) -> AdmitVerdict:
    """Decide whether the server(s) in `add_path` may be admitted into the design
    at `base_path`, with the delta that justifies the verdict."""
    from attestral.ingest import build_model

    base = build_model(base_path)
    proposed, added = _proposed_model(base, add_path)
    if proposed is None:
        return AdmitVerdict(allowed=True, note=(
            "nothing to admit: the proposed config adds no server the design does "
            "not already have"))

    delta = diff_models(base, proposed)
    base_reach = _named_reach(base)
    new_reach = sorted(_named_reach(proposed) - base_reach)

    reasons: list[str] = []
    new_high = [f for f in delta.new_findings
                if f.severity.rank >= Severity.HIGH.rank]
    new_chains = [f for f in delta.new_findings if f.rule_id in _CHAIN_RULES]
    for f in new_chains:
        reasons.append(f"admitting completes {f.rule_id}: {f.title}")
    for f in new_high:
        if f.rule_id not in _CHAIN_RULES:
            reasons.append(f"admitting introduces {f.rule_id} ({f.severity.value}): {f.title}")
    if new_reach:
        shown = new_reach[:4]
        more = f" (+{len(new_reach) - len(shown)} more)" if len(new_reach) > len(shown) else ""
        reasons.append("admitting grants new cross-boundary reach into named "
                       f"infrastructure: {', '.join(shown)}{more}")
    for p in delta.new_paths:
        reasons.append(f"admitting opens a new attack path: {p}")

    allowed = not (new_high or new_chains or new_reach or delta.new_paths)
    if allowed and delta.new_findings:
        lows = sorted({f"{f.rule_id} ({f.severity.value})" for f in delta.new_findings})
        reasons.append("allowed with new lower-severity findings to review: "
                       + ", ".join(lows))
    return AdmitVerdict(allowed, added, delta, new_reach, reasons)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        k = (f.rule_id, f.component_id)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def render_admit(verdict: AdmitVerdict, *, color: bool | None = None) -> str:
    from attestral.report_terminal import _bold, _dim, _paint, supports_color
    if color is None:
        color = supports_color()
    if verdict.note:
        return _paint(f"ADMIT: {verdict.note}.", "33", color)

    who = ", ".join(verdict.added)
    if verdict.allowed:
        head = _paint(f"ADMIT: ALLOW  {who}", "1;32", color)
    else:
        head = _paint(f"ADMIT: DENY  {who}", "1;31", color)
    lines = [head, ""]
    for r in verdict.reasons:
        mark = "allow" if verdict.allowed else "deny"
        lines.append(f"  {_paint(mark + ':', '32' if verdict.allowed else '1;31', color)} {r}")
    d = verdict.delta
    if d is not None:
        lines.append("")
        if d.new_findings:
            lines.append(f"  {_dim('new findings:', color)} "
                         + ", ".join(sorted({f.rule_id for f in _dedupe(d.new_findings)})))
        if d.blast_after != d.blast_before:
            lines.append(f"  {_dim('worst-case blast radius:', color)} "
                         f"{d.blast_before:.1f} -> {_bold(f'{d.blast_after:.1f}', color)}/10"
                         + (f"  ({d.blast_top})" if d.blast_top else ""))
    lines.append("")
    lines.append(_dim("The verdict is the security delta of admitting the tool - the tool's "
                      "own reasoning run against your design, not a rule on the tool. Reach is "
                      "over the modeled edges: a prioritisation signal, not proof.", color))
    return "\n".join(lines)


def admit_report(verdict: AdmitVerdict) -> dict:
    d = verdict.delta
    return {
        "verdict": "allow" if verdict.allowed else "deny",
        "admitted": verdict.added,
        "reasons": verdict.reasons,
        "reach_granted": verdict.reach_granted,
        "new_findings": sorted({f.rule_id for f in _dedupe(d.new_findings)}) if d else [],
        "blast_before": d.blast_before if d else 0.0,
        "blast_after": d.blast_after if d else 0.0,
    }
