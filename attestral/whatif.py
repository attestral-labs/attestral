"""Counterfactual design review: the security delta of a change BEFORE you make it.

A scanner tells you what is wrong now. `attestral whatif` answers the next
question a designer actually has - "if I remove this server, or scope this
capability away, what does it fix?" - by applying a hypothetical change to the
attested model and diffing. It reuses the same system model, rule engine,
reachability, and blast-radius the scan uses, so the answer is the tool's own
reasoning run against a hypothetical, not a guess.

Two changes are supported, both non-destructive (they mutate a copy):
  - remove a component (a server / agent surface) entirely;
  - deny a capability on a named component (scope it down).

The result is a ModelDelta whose `resolved_findings`, `closed_paths`, and
blast-radius drop are the *benefit* of the change - the design-assistant move no
per-file linter offers.
"""
from __future__ import annotations

import copy

from attestral.delta import ModelDelta, diff_models
from attestral.model import SystemModel


def _rederive_edges(model: SystemModel) -> None:
    """Recompute the derived taint / reachability edges after a mutation, so a
    dropped capability actually closes the flows it fed. Uses the same edge
    derivation the ingest pipeline runs, so the counterfactual model is assembled
    exactly like a real one."""
    from attestral.ingest.scan import _add_reachability_edges, _add_taint_edges

    # Drop the derived edges (taint_source/taint_sink/tool_access) and re-add them
    # from the mutated components; declared edges (if any) are left untouched.
    derived = {"taint_source", "taint_sink", "tool_access"}
    model.edges = [e for e in model.edges if e.kind not in derived]
    _add_taint_edges(model)
    _add_reachability_edges(model)


def remove_component(model: SystemModel, name: str) -> SystemModel | None:
    """A copy of the model with every component named `name` removed, along with
    any edge referencing it. Returns None if nothing matched (so the caller can
    tell the user the name was not found rather than show an empty, misleading
    'no change' delta)."""
    ids = {c.id for c in model.components if c.name == name}
    if not ids:
        return None
    head = copy.deepcopy(model)
    head.components = [c for c in head.components if c.id not in ids]
    head.edges = [e for e in head.edges
                  if e.source_id not in ids and e.target_id not in ids]
    return head


def deny_capability(model: SystemModel, name: str, capability: str) -> SystemModel | None:
    """A copy of the model with `capability` removed from the named component's
    `_capabilities`, then the derived flows recomputed. Returns None if no such
    component holds that capability (nothing to scope away)."""
    head = copy.deepcopy(model)
    touched = False
    for c in head.components:
        if c.name != name:
            continue
        caps = list(c.attr("_capabilities") or [])
        if capability in caps:
            caps.remove(capability)
            c.attributes["_capabilities"] = caps
            touched = True
    if not touched:
        return None
    _rederive_edges(head)
    return head


def whatif(model: SystemModel, *, remove: str | None = None,
           deny: tuple[str, str] | None = None) -> tuple[ModelDelta | None, str]:
    """Apply one hypothetical change and diff. Returns (delta, note); delta is
    None when the change matched nothing, with `note` explaining why."""
    if remove:
        head = remove_component(model, remove)
        if head is None:
            return None, f"no component named '{remove}' - nothing to remove"
    elif deny:
        name, cap = deny
        head = deny_capability(model, name, cap)
        if head is None:
            return None, f"no component '{name}' holds capability '{cap}' - nothing to scope"
    else:
        return None, "specify a change: --remove NAME or --deny NAME:CAPABILITY"
    # base vs the counterfactual head; resolved_findings / closed_paths are the win.
    return diff_models(model, head), ""
