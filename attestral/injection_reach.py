"""Injection-reachability fusion: an injectable surface is only as dangerous as
what it can reach.

Two layers already exist and answer half the question each. The ML layer
(`ml.py`) scores *language* surfaces - MCP tool/server descriptions, system
prompts - for prompt injection. The blast-radius layer (`blast_radius.py`)
scores each surface's *if-compromised reach* over the modeled design. Neither
alone answers the question a reviewer actually has about an injectable tool
description: can an instruction injected HERE do anything - reach a secret, an
outbound channel, a shell? Text that reads as injection on a dead-end surface is
noise; the same text on a surface that reaches an egress channel is a live
exfiltration primitive.

This pass fuses the two. For every prompt-injection finding (`origin="ml"`), it
looks up the surface's blast-radius reach and, when that reach includes an
actionable sink, annotates the finding with the reachable chain and raises its
severity one band - exactly as `reachability.py` does for a walked attack chain,
capped by how dangerous the reach is:

  - reaches an outbound channel (network/messaging), a cloud crossing, or code
    execution (shell) -> exfiltration / command-and-control primitive, ceiling CRITICAL
  - reaches only private data (database/saas_data/filesystem) -> data-access
    primitive, ceiling HIGH
  - reaches only memory, or nothing sensitive -> contained, left at its ML severity

A finding on a non-surface language component (a poisoned system prompt or
agent-instruction file) does not appear in the blast-radius rows, but it *steers*
the agent runtime it configures, so its reach is the union of that runtime's tool
surfaces' reach, one hop further out (prompt -> tool -> sink).

Setting `reachability` also feeds AIVSS, which already treats any finding with a
reachable chain as fully weighted (`aivss.score`), so an injectable-and-reachable
surface outranks an injectable dead-end in the agentic ranking for free.

Idempotent and order-independent with `reachability.py`: a finding already on a
walked attack chain keeps that (stronger) annotation and is skipped here. Honest
scope, inherited from blast_radius: reach is over DECLARED capability in the
modeled design - a necessary, not sufficient, condition for exploitation, and a
prioritisation signal, never a proof the injection would succeed.

Deterministic, zero-dependency.
"""
from __future__ import annotations

from attestral.blast_radius import blast_radius
from attestral.model import Finding, Severity, SystemModel

# The ML layer's origin tag. Only its findings are language surfaces an injection
# can land in; deterministic/redteam findings are handled by their own passes.
_ML_ORIGIN = "ml"

# Sink classes that make an injection actionable. Reaching any EXFIL sink turns
# "text that reads like injection" into an exfiltration or command-and-control
# primitive; reaching a DATA sink makes it a private-data-access primitive.
# Memory alone is neither, so a memory-only reach stays contained.
_EXFIL_SINKS = {"network", "messaging", "cloud", "shell"}
_DATA_SINKS = {"database", "saas_data", "filesystem"}

# Severity bands indexed by rank, for the one-band escalation step (mirrors
# reachability.py so the two passes read the same).
_BANDS = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _ceiling(reached: dict[str, int]) -> Severity | None:
    """The severity ceiling justified by what an injection here can reach, or
    None when the reach is contained (memory-only / nothing sensitive)."""
    classes = set(reached)
    if classes & _EXFIL_SINKS:
        return Severity.CRITICAL
    if classes & _DATA_SINKS:
        return Severity.HIGH
    return None


def _reach_line(name: str, reached: dict[str, int]) -> str:
    """The reachable-sink chain as one compact line: `injection reach: summarize
    -> database (1h), network egress (1h)`. `reached` is already ordered nearest
    first, most sensitive first."""
    egress = {"network": "network egress", "messaging": "messaging egress"}
    parts = []
    for cls, hop in reached.items():
        label = egress.get(cls, cls)
        loc = "self" if hop == 0 else f"{hop}h"
        parts.append(f"{label} ({loc})")
    return f"injection reach: {name} -> " + ", ".join(parts)


def _reach_for(
    model: SystemModel, f: Finding, rows: dict[str, "object"]
) -> tuple[str, dict[str, int]] | None:
    """The (surface name, reachable-sink map) for a finding's component.

    A tool-granting surface has its own blast-radius row. A language surface that
    is not a tool grant (a system prompt / agent-instruction file) steers the
    agent runtime it sits in, so its reach is the union of that runtime's tool
    surfaces' reach, one hop further out."""
    row = rows.get(f.component_id)
    if row is not None:
        return row.name, row.reached
    comp = model.get(f.component_id)
    if comp is None:
        return None
    union: dict[str, int] = {}
    for s in model.tool_surfaces():
        if s.trust_boundary != comp.trust_boundary:
            continue
        srow = rows.get(s.id)
        if srow is None:
            continue
        for cls, hop in srow.reached.items():
            steered = hop + 1  # prompt -> tool -> sink
            if cls not in union or steered < union[cls]:
                union[cls] = steered
    ordered = dict(sorted(union.items(), key=lambda kv: kv[1]))
    return comp.name, ordered


def annotate_injection_reach(model: SystemModel, findings: list[Finding]) -> list[str]:
    """Escalate every prompt-injection finding whose surface can reach an
    actionable sink, attaching the reachable chain and raising its severity one
    band (capped by how dangerous the reach is).

    Mutates the findings in place and returns human-readable notes for the caller
    to echo. Idempotent: a finding already carrying a reachability chain (from
    this pass or reachability.py) is skipped, so a second pass never
    double-escalates and the two passes compose in either order.
    """
    rows = {b.component_id: b for b in blast_radius(model)}
    annotated = raised = 0
    for f in findings:
        if f.origin != _ML_ORIGIN or f.reachability:
            continue
        reach = _reach_for(model, f, rows)
        if reach is None:
            continue
        name, reached = reach
        ceiling = _ceiling(reached)
        if ceiling is None:  # dead-end / memory-only: the injection stays contained
            continue
        f.reachability = _reach_line(name, reached)
        f.reachability_role = "injection-source"
        annotated += 1
        new_rank = min(f.severity.rank + 1, ceiling.rank)
        if new_rank > f.severity.rank:
            f.escalated_from = f.severity.value
            f.severity = _BANDS[new_rank]
            raised += 1

    if not annotated:
        return []
    note = f"injection-reach: {annotated} injectable surface(s) reach an actionable sink"
    if raised:
        note += f"; {raised} raised one severity band"
    return [note]
