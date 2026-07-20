"""Human-facing terminal rendering for scan findings.

Zero third-party dependencies - hand-rolled ANSI only. Colour is emitted only
when the stream is an interactive TTY and NO_COLOR is not set; otherwise the
output degrades to clean plain text, so the same renderer serves an interactive
shell, a CI log, and a piped consumer.
"""
from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from attestral.model import Finding, SystemModel

# High -> low. INFO is included so nothing is silently dropped.
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

# ANSI SGR codes, keyed by severity.
_SEV_COLOR = {
    "critical": "1;31",  # bold red
    "high": "31",        # red
    "medium": "33",      # yellow
    "low": "36",         # cyan
    "info": "90",        # bright black / grey
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_HINT_WIDTH = 100  # remediation hint is trimmed to a single readable line


def supports_color(stream=None) -> bool:
    """True when colour should be emitted: a TTY stream and no NO_COLOR."""
    if os.environ.get("NO_COLOR"):
        return False
    stream = stream if stream is not None else sys.stdout
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def _paint(text: str, code: str, on: bool) -> str:
    return f"\033[{code}m{text}{_RESET}" if on else text


def _bold(text: str, on: bool) -> str:
    return f"{_BOLD}{text}{_RESET}" if on else text


def _dim(text: str, on: bool) -> str:
    return f"{_DIM}{text}{_RESET}" if on else text


def _one_line(text: str, width: int = _HINT_WIDTH) -> str:
    """Collapse whitespace and trim to a single terminal line."""
    flat = " ".join((text or "").split())
    if len(flat) <= width:
        return flat
    return flat[: width - 1].rstrip() + "..."


def _tag(f: "Finding") -> str:
    if f.waived:
        return "  (waived)"
    parts = []
    if f.confidence != "high":
        parts.append(f"confidence: {f.confidence}")
    if f.judge_verdict:
        parts.append(f"judge: {f.judge_verdict} {f.judge_confidence}")
    if f.escalated_from:
        parts.append(f"raised from {f.escalated_from}")
    return "".join(f"  ({p})" for p in parts)


def _plural(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _counts(findings: list["Finding"]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.severity.value] = out.get(f.severity.value, 0) + 1
    return out


def breakdown(findings: list["Finding"], color: bool) -> str:
    """`2 critical · 4 high · 3 medium` - only severities that are present."""
    counts = _counts(findings)
    parts = [
        _paint(f"{counts[s]} {s}", _SEV_COLOR[s], color)
        for s in _SEV_ORDER
        if counts.get(s)
    ]
    return " · ".join(parts)


# Component-type prefix -> the surface family it belongs to, in report order.
# A prefix match keeps this stable as new resource types are added.
_SURFACE_FAMILIES = [
    ("agent / MCP surface", ("mcp_server", "a2a_agent", "subagent", "code_agent",
                             "system_prompt", "skill", "agent_hook", "mcp_registry",
                             "agent_tool")),
    ("cloud resources", ("aws_", "azure_", "gcp_")),
    ("Kubernetes workloads", ("k8s_",)),
]

# What a design review deliberately does NOT read, stated up front so a clean
# scan is never mistaken for "nothing here" - it means "nothing in the surfaces
# Attestral reviews". Honesty about scope is what a skeptical evaluator checks.
_NOT_READ_NOTE = (
    "Design review, not SAST: reads declared config and agent wiring, not "
    "arbitrary application logic."
)


def _family_of(component_type: str) -> str | None:
    for label, prefixes in _SURFACE_FAMILIES:
        if any(component_type.startswith(p) for p in prefixes):
            return label
    return None


def render_discovery(model: "SystemModel", target: str, *, color: bool | None = None) -> str:
    """The zero-config preamble: what autodiscovery found, and from where, before
    any finding. `Reviewed N components across M files: <families>`, then the
    honest note on what a design review does not read. Empty string on an empty
    model (nothing was discovered - the caller says so its own way)."""
    if color is None:
        color = supports_color()
    if not model.components:
        return ""
    counts: dict[str, int] = {}
    for c in model.components:
        fam = _family_of(c.type)
        if fam:
            counts[fam] = counts.get(fam, 0) + 1
    sources = {c.source for c in model.components if c.source}
    n = len(model.components)
    head = (
        f"Reviewed {_plural(n, 'component')} across "
        f"{_plural(len(sources), 'source file')}"
    )
    fam_parts = [
        f"{counts[label]} {label}" for label, _ in _SURFACE_FAMILIES if counts.get(label)
    ]
    lines = [_bold(head, color) + (": " + " · ".join(fam_parts) if fam_parts else "")]
    lines.append(_dim(_NOT_READ_NOTE, color))
    return "\n".join(lines)


def render_attack_paths(model: "SystemModel", *, color: bool | None = None) -> str:
    """The assembled kill chains as a highlighted block: for each complete path,
    entry then pivot then impact, with the component at each rung. Empty string
    when no complete path exists. This is the connected story a scatter of
    individual findings does not convey."""
    if color is None:
        color = supports_color()
    from attestral.paths import all_attack_paths
    paths = all_attack_paths(model)
    if not paths:
        return ""
    lines = [_paint(f"Attack paths ({len(paths)})", _SEV_COLOR["critical"], color)]
    for p in paths:
        lines.append(f"  {_bold(f'{p.kind} chain', color)}:")
        for stage in (p.entry, p.pivot, p.impact):
            role = _dim(f"{stage.role}:", color)
            comps = _bold(", ".join(stage.components), color)
            lines.append(f"    {role} {stage.label}  [{comps}]")
    return "\n".join(lines)


# Stated on every non-empty adversarial-validation report so the reachability
# claim is never read as a claim of exploitability. Reachability over declared
# capability is a necessary, not sufficient, condition for a working attack.
_REACHABILITY_ASSUMPTION = (
    "Assumption: paths are computed over declared capability, treated as a sound "
    "over-approximation. A reachable path is necessary, not sufficient, for "
    "exploitation - it does not model whether the agent follows an injection, or "
    "whether a guardrail or human approval sits in the path."
)


def render_proofs(proofs: list, *, color: bool | None = None) -> str:
    """Render the tier-0 adversarial-validation report: for each attack path that
    is reachable in the modeled design, the numbered walk (component and the
    mechanism that reaches it), the trust boundaries it spans, and the verdict.
    When the list is empty, a positive line the caller can attest to: no path is
    reachable. Every non-empty report states the reachability assumption, so the
    claim is feasibility over the modeled graph, not proof of exploitability."""
    if color is None:
        color = supports_color()
    if not proofs:
        return _paint(
            "Adversarial validation: no attack path is reachable in the attested design.",
            "32", color,  # green
        )
    lines = [_paint(f"Adversarial validation ({len(proofs)} reachable)", _SEV_COLOR["critical"], color)]
    for p in proofs:
        sev = p.severity.value
        lines.append("")
        lines.append(f"  {_paint(p.rule_id, _SEV_COLOR[sev], color)}  {_bold(p.title(), color)}")
        for i, s in enumerate(p.steps, 1):
            role = _dim(f"{s.role}:", color)
            comp = _bold(s.component, color)
            lines.append(f"    {i}. {role} {comp}  {_dim('- ' + s.via, color)}")
        lines.append(f"    {_dim('boundaries:', color)} {', '.join(p.boundaries)}")
        lines.append(f"    {_dim('verdict:', color)} {p.outcome} (in the modeled graph)")
        lines.append(f"    {_dim('fix:', color)} {_one_line(p.remediation())}")
    lines.append("")
    lines.append(_dim(_REACHABILITY_ASSUMPTION, color))
    return "\n".join(lines)


def _flow_signature(f: "Finding") -> tuple | None:
    """A coalescing key for findings that describe the same reachability flow: the
    set of sinks an injection-reachability escalation reaches, independent of the
    surface it sits on. Findings that share it are one exfiltration flow told
    across several surfaces. Returns None for findings that should render on their
    own. Display only - it never changes the finding set or the evidence chain."""
    if f.reachability_role != "injection-source" or "->" not in f.reachability:
        return None
    tail = f.reachability.split("->", 1)[1]
    sinks = tuple(sorted(
        seg.split("(")[0].strip() for seg in tail.split(",") if seg.strip()))
    return ("injection-reach", sinks) if sinks else None


def _finding_lines(f: "Finding", sev: str, color: bool) -> list[str]:
    """The individual render block for one finding."""
    out = [f"  {_paint(f.rule_id, _SEV_COLOR[sev], color)}  {_bold(f.title, color)}  "
           f"({_dim(f.component_id, color)}){_tag(f)}"]
    if f.reachability:
        note = f.reachability
        if f.reachability_role:
            note += f" · this component: {f.reachability_role}"
        out.append(f"    {_dim('path:', color)} {_one_line(note)}")
    hint = _one_line(f.recommendation)
    if hint:
        out.append(f"    {_dim('fix:', color)} {hint}")
    out.append(f"    {_dim('run:', color)} attestral explain {f.rule_id}")
    return out


def _cluster_lines(members: list["Finding"], sev: str, color: bool) -> list[str]:
    """One render block for a set of findings that share a reachability flow, so N
    restatements of one flow read as a single ranked issue. Each member still
    exists in the evidence chain; this collapses only the display."""
    rule_ids = sorted({f.rule_id for f in members})
    sinks = ", ".join(_flow_signature(members[0])[1])
    surfaces = list(dict.fromkeys(f.component_id for f in members))
    out = [f"  {_paint('+'.join(rule_ids), _SEV_COLOR[sev], color)}  "
           f"{_bold('Prompt-injection flow reaching ' + sinks, color)}  "
           f"({_dim(', '.join(surfaces), color)})"]
    out.append(f"    {_dim('flow:', color)} {len(members)} injection findings across "
               f"{_plural(len(surfaces), 'surface')} reach the same sinks - one exfiltration "
               f"flow, not {len(members)} separate problems")
    hint = _one_line(members[0].recommendation)
    if hint:
        out.append(f"    {_dim('fix:', color)} {hint}")
    out.append(f"    {_dim('run:', color)} attestral explain {rule_ids[0]}")
    return out


def render_scan(
    model: "SystemModel",
    findings: list["Finding"],
    target: str,
    *,
    quiet: bool = False,
    color: bool | None = None,
) -> str:
    """Render the findings for a human. Returns the text block (no trailing gate).

    active findings are grouped by severity under a header breakdown line; each
    finding carries a one-line remediation hint and an `attestral explain`
    pointer. Waived findings are listed dimmed at the end. In `quiet` mode only
    the one-line summary is returned (empty string when the scan is clean).
    """
    if color is None:
        color = supports_color()

    active = [f for f in findings if not f.waived]
    waived = [f for f in findings if f.waived]

    summary = f"{_plural(len(model.components), 'component')} · {_plural(len(active), 'finding')}"
    if active:
        summary += " · " + breakdown(active, color)
    if waived:
        summary += f" · {len(waived)} waived"

    if quiet:
        # Only the summary line, and nothing at all on a clean scan.
        return summary if active or waived else ""

    lines: list[str] = []
    lines.append(f"{_bold('attestral', color)} · {target}")
    discovery = render_discovery(model, target, color=color)
    if discovery:
        lines.append(discovery)
    lines.append(summary)

    paths_block = render_attack_paths(model, color=color)
    if paths_block:
        lines.append("")
        lines.append(paths_block)

    if not active and not waived:
        lines.append("")
        lines.append(_paint("No findings. Clean scan.", _SEV_COLOR["low"], color))
        return "\n".join(lines)

    by_sev: dict[str, list["Finding"]] = {s: [] for s in _SEV_ORDER}
    for f in active:
        by_sev.setdefault(f.severity.value, []).append(f)

    for sev in _SEV_ORDER:
        group = by_sev.get(sev) or []
        if not group:
            continue
        # Coalesce findings that describe one reachability flow into a single
        # block, so the top of the report reads as N distinct problems rather
        # than one flow restated once per surface. Every finding stays in the
        # list and the evidence chain; only the display is collapsed, and the
        # header shows both the distinct-issue and the raw-finding count.
        clusters: dict[tuple, list] = {}
        for f in group:
            k = _flow_signature(f)
            if k is not None:
                clusters.setdefault(k, []).append(f)
        coalesced = {k: v for k, v in clusters.items() if len(v) >= 2}
        merged = sum(len(v) for v in coalesced.values())
        distinct = (len(group) - merged) + len(coalesced)

        lines.append("")
        head = (f"{sev.upper()} ({distinct} issues · {len(group)} findings)"
                if distinct != len(group) else f"{sev.upper()} ({len(group)})")
        lines.append(_paint(head, _SEV_COLOR[sev], color))

        rendered_keys: set[tuple] = set()
        for f in group:
            k = _flow_signature(f)
            if k in coalesced:
                if k in rendered_keys:
                    continue
                rendered_keys.add(k)
                lines.extend(_cluster_lines(coalesced[k], sev, color))
            else:
                lines.extend(_finding_lines(f, sev, color))

    if waived:
        lines.append("")
        lines.append(_dim(f"waived ({len(waived)})", color))
        for f in waived:
            reason = _one_line(f.waiver_reason) if f.waiver_reason else ""
            row = f"  {f.rule_id}  {f.title}  ({f.component_id})"
            if f.waived_by:
                row += f" - accepted by {f.waived_by}" + (f" on {f.waived_at}" if f.waived_at else "")
            if reason:
                row += f" - {reason}"
            lines.append(_dim(row, color))

    return "\n".join(lines)


def render_fleet(model: "SystemModel", *, color: bool | None = None) -> str:
    """One line-pair per MCP server: what the agent can reach, shown before any
    finding. This is what makes a clean scan trustworthy - the reviewed surface
    is on screen, not implied. Empty string when the model has no servers."""
    if color is None:
        color = supports_color()
    servers = [c for c in model.components if c.type == "mcp_server"]
    if not servers:
        return ""
    lines = [_bold(f"Agent tool surface ({_plural(len(servers), 'server')})", color)]
    for c in servers:
        url = str(c.attr("url") or "")
        launch = url or " ".join(
            [str(c.attr("command") or "")] + [str(a) for a in c.attr("args") or []]
        ).strip()
        transport = "remote" if url else "stdio"
        reach = ", ".join(c.attr("_capabilities") or []) or "unclassified"
        lines.append(
            f"  {_bold(c.name, color)}  {_dim(transport, color)} · {_one_line(launch, 72)}"
        )
        lines.append(f"    {_dim('reach:', color)} {reach}   {_dim(c.source, color)}")
    return "\n".join(lines)


def gate_line(fail_on: str, failed: bool, *, color: bool | None = None) -> str:
    """The final gate line. `failed` when findings sit at/above the threshold."""
    if color is None:
        color = supports_color(sys.stderr if failed else sys.stdout)
    if failed:
        # Kept byte-identical (sans colour) to the historical CI message.
        return _paint(f"FAIL-CLOSED: findings at or above '{fail_on}'",
                      _SEV_COLOR["critical"], color)
    return _paint(f"gate ok: no findings at or above '{fail_on}'",
                  "32", color)  # green
