"""Structured remediation: the concrete source edit that clears each finding.

Every rule already ships a prose recommendation. This goes one step more
concrete: for a finding, it reads the rule's own matcher and the offending
component's actual value, and produces the exact edit to make in the source, a
before and an after, tied to the file the component came from. A finding a
developer can act on in one line gets fixed; a finding that only says what is
wrong gets ignored.

This is the source-side twin of `attestral fix`: `remediate` tells you the
change to make in your config so the finding never fires, `fix` compiles the
runtime control that enforces it at the proxy. Together they close the
"so what do I do about this" gap from both ends.

Derivation is deterministic and honest: a boolean security flag flips, a missing
control is added, a bad-prefix or bad-token value is transformed, and anything
model-level or not mechanically derivable falls back to the rule's
recommendation rather than inventing an edit.
"""
from __future__ import annotations

from dataclasses import dataclass

from attestral.model import Finding, SystemModel

# Known safe replacements for non-boolean flags, where the fix is a specific
# value rather than a negation. Keyed by (attribute, offending-value-lowered).
_SAFE_VALUE: dict[tuple[str, str], str] = {
    ("protocol", "http"): "HTTPS",
    ("image_tag_mutability", "mutable"): "IMMUTABLE",
    ("http_tokens", "optional"): "required",
    ("minimum_password_length", ""): "14 or more",
}

# Prefix transforms for attr_starts_with rules.
_PREFIX_FIX: dict[str, tuple[str, str]] = {
    "http://": ("http://", "https://"),
}


@dataclass
class Suggestion:
    rule_id: str
    component: str
    source: str          # the file the component came from
    attribute: str       # the attribute to edit ("" for a design-level change)
    before: str          # the offending current value (best-effort)
    after: str           # the suggested value
    edit: str            # a one-line human-readable edit instruction
    derived: bool        # True: a concrete edit; False: fell back to the recommendation


def _rule_index(rules: list[dict]) -> dict[str, dict]:
    return {str(r.get("id", "")): r for r in rules}


def _fmt(v: object) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def suggest(model: SystemModel, finding: Finding, rule: dict | None) -> Suggestion:
    """The concrete edit for one finding. Falls back to the recommendation when
    no single-attribute edit is derivable (model-level rules, compositional
    risk)."""
    comp = model.get(finding.component_id)
    source = comp.source if comp else finding.source
    fallback = Suggestion(finding.rule_id, finding.component_id, source, "", "", "",
                          finding.recommendation, False)
    if not rule:
        return fallback
    match = rule.get("match") or {}

    # Standing-credential findings have a mechanically derivable edit even though
    # they match ingester-derived attributes: the exact env keys to delete, with
    # the generated broker route as the replacement. This is the source-side half
    # of the broker-backed fix (`attestral fix --broker-output`).
    from attestral.broker import BROKER_FIX_RULES, plan_for
    if finding.rule_id in BROKER_FIX_RULES:
        plan = plan_for(model, finding.component_id)
        if plan is not None:
            keys = ", ".join(plan.stripped)
            return Suggestion(
                finding.rule_id, finding.component_id, source, "env",
                keys, "(brokered per-call token)",
                f"delete env key(s) {keys} from server '{plan.name}' in {source}; "
                f"replace them with the generated CB4A broker route "
                f"(`attestral fix --broker-output broker.yaml`)",
                True,
            )

    # Ingester-derived attributes (prefixed `_`, e.g. `_cidr_blocks`,
    # `_confused_deputy`) are not literal source fields, so a single-field edit
    # would be misleading. Fall back to the rule's recommendation for those.
    for spec in match.values():
        if isinstance(spec, dict):
            key = next(iter(spec), "")
            if isinstance(key, str) and key.startswith("_"):
                return fallback

    # attr_equals: a boolean flag flips; a known string flag maps to its safe value.
    if "attr_equals" in match:
        key, bad = next(iter(match["attr_equals"].items()))
        cur = comp.attr(key) if comp else bad
        if isinstance(bad, bool):
            after = _fmt(not bad)
        else:
            after = _SAFE_VALUE.get((key, str(bad).lower()), f"a value other than {_fmt(bad)}")
        return Suggestion(finding.rule_id, finding.component_id, source, key,
                          _fmt(cur), after, f"set `{key} = {after}`", True)

    # attr_missing: add the absent control.
    if "attr_missing" in match:
        key = match["attr_missing"]
        return Suggestion(finding.rule_id, finding.component_id, source, key,
                          "(absent)", "(set)", f"add `{key}` (it is currently unset)", True)

    # attr_starts_with: transform the offending prefix (e.g. http:// -> https://).
    if "attr_starts_with" in match:
        key, prefix = next(iter(match["attr_starts_with"].items()))
        cur = str(comp.attr(key) or "") if comp else prefix + "..."
        if prefix in _PREFIX_FIX:
            old, new = _PREFIX_FIX[prefix]
            after = cur.replace(old, new, 1) if cur.startswith(old) else new + "..."
        else:
            after = f"a value that does not start with {prefix!r}"
        return Suggestion(finding.rule_id, finding.component_id, source, key,
                          cur, after, f"change `{key}`: {cur} -> {after}", True)

    # attr_in / attr_any_contains / attr_list_contains: drop the offending token.
    for kind in ("attr_in", "attr_any_contains", "attr_list_contains", "attr_list_any_of"):
        if kind in match:
            key, bad = next(iter(match[kind].items()))
            bad_disp = ", ".join(str(b) for b in bad) if isinstance(bad, list) else str(bad)
            cur = comp.attr(key) if comp else ""
            return Suggestion(finding.rule_id, finding.component_id, source, key,
                              _fmt(cur), f"remove {bad_disp}",
                              f"change `{key}` so it no longer includes: {bad_disp}", True)

    # attr_contains: a substring in a text blob (e.g. a wildcard IAM policy).
    if "attr_contains" in match:
        key, bad = next(iter(match["attr_contains"].items()))
        return Suggestion(finding.rule_id, finding.component_id, source, key,
                          f"contains {bad!r}", "(scoped)",
                          f"remove {bad!r} from `{key}`; scope it explicitly", True)

    return fallback   # model-level and anything else: use the recommendation


def suggestions_for(model: SystemModel, findings: list[Finding],
                    rules: list[dict]) -> list[Suggestion]:
    idx = _rule_index(rules)
    out: list[Suggestion] = []
    for f in findings:
        if f.waived:
            continue
        out.append(suggest(model, f, idx.get(f.rule_id)))
    return out


def render_remediations(model: SystemModel, findings: list[Finding], rules: list[dict], *,
                        color: bool | None = None) -> str:
    from attestral.report_terminal import _bold, _dim, _paint, supports_color
    if color is None:
        color = supports_color()
    sugg = suggestions_for(model, findings, rules)
    if not sugg:
        return _paint("Nothing to remediate: clean scan.", "32", color)
    derived = sum(1 for s in sugg if s.derived)
    lines = [_paint(f"Remediation ({len(sugg)} findings, {derived} with a concrete edit)",
                    "1;31", color)]
    for s in sugg:
        lines.append("")
        lines.append(f"  {_paint(s.rule_id, '1;31', color)}  {_bold(s.component, color)}"
                     f"  {_dim(s.source, color)}")
        if s.derived:
            lines.append(f"    {_dim('edit:', color)} {s.edit}")
            if s.before and s.before != "(absent)":
                lines.append(f"    {_dim('now: ', color)} {s.attribute} = {s.before}")
        else:
            lines.append(f"    {_dim('fix: ', color)} {s.edit}")
    return "\n".join(lines)
