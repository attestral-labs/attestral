"""Evidence layer: tamper-evident audit chain + report export."""
from __future__ import annotations

import datetime as _dt
import hashlib
import json

from attestral.model import Finding, SystemModel

GENESIS = "0" * 64


def audit_chain(findings: list[Finding]) -> list[dict]:
    """SHA-256 hash chain over findings: entry N commits to entry N-1.

    Any modification, insertion, or deletion of a past entry changes every
    subsequent hash - the chain head is the integrity commitment for the run.
    """
    prev = GENESIS
    chain = []
    for f in findings:
        payload = json.dumps(f.to_dict(), sort_keys=True)
        digest = hashlib.sha256((prev + payload).encode()).hexdigest()
        chain.append({"hash": digest, "prev": prev, "finding": f.to_dict()})
        prev = digest
    return chain


def verify_chain(chain: list[dict]) -> bool:
    prev = GENESIS
    for entry in chain:
        payload = json.dumps(entry["finding"], sort_keys=True)
        if entry["prev"] != prev:
            return False
        if hashlib.sha256((prev + payload).encode()).hexdigest() != entry["hash"]:
            return False
        prev = entry["hash"]
    return True


_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def render_pr_summary(
    model: SystemModel, findings: list[Finding], target: str, *, net_new: bool = False
) -> str:
    """A compact GitHub-flavored markdown summary for a PR comment or the CI job
    summary (`$GITHUB_STEP_SUMMARY`). Leads with the reviewed surface, renders
    each reachable attack path (entry -> pivot -> impact), then the findings as
    a skimmable table that names the reachability of each. `net_new` phrases the
    header for a baseline-gated run, where `findings` are only what the change
    introduced. This is the light PR artifact; the full audit report and
    evidence chain come from `attestral scan -o`."""
    from attestral.paths import all_attack_paths
    from attestral.report_terminal import _NOT_READ_NOTE, _family_of

    active = [f for f in findings if not f.waived]
    waived = [f for f in findings if f.waived]
    counts: dict[str, int] = {}
    for f in active:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    breakdown = " · ".join(f"{counts[s]} {s}" for s in _SEV_ORDER if counts.get(s)) or "none"

    fam: dict[str, int] = {}
    for c in model.components:
        label = _family_of(c.type)
        if label:
            fam[label] = fam.get(label, 0) + 1
    fam_line = " · ".join(f"{v} {k}" for k, v in fam.items())

    lines = ["## Attestral design review", ""]
    noun = "finding" if len(active) == 1 else "findings"
    if not active:
        verdict = "No new findings." if net_new else "Clean scan."
    elif net_new:
        verdict = f"**{len(active)}** net-new {noun} introduced by this change: {breakdown}."
    else:
        verdict = f"**{len(active)}** {noun}: {breakdown}."
    lines.append(
        f"Reviewed **{len(model.components)}** components in `{target}`"
        + (f" ({fam_line})." if fam_line else ".")
    )
    lines.append("")
    lines.append(verdict)

    paths = all_attack_paths(model)
    if paths:
        lines += ["", f"### Reachable attack paths ({len(paths)})", ""]
        for p in paths:
            rungs = " → ".join(
                f"`{', '.join(s.components)}`" for s in (p.entry, p.pivot, p.impact)
            )
            lines.append(f"- **{p.kind} chain** - {rungs}")
            lines.append(
                f"  <br>entry: {p.entry.label} · pivot: {p.pivot.label} · "
                f"impact: {p.impact.label}"
            )

    if active:
        lines += ["", "### Findings", "",
                  "| Severity | Finding | Component | Reachability |", "|---|---|---|---|"]
        by_sev = {s: [f for f in active if f.severity.value == s] for s in _SEV_ORDER}
        for sev in _SEV_ORDER:
            for f in by_sev[sev]:
                reach = "-"
                if f.reachability:
                    role = f.reachability_role or "on path"
                    reach = f"on {f.reachability.split(':')[0]} ({role})"
                    if f.escalated_from:
                        reach += f", raised from {f.escalated_from}"
                title = f.title.replace("|", "\\|")
                lines.append(
                    f"| {sev} | `{f.rule_id}` {title} | `{f.component_id}` | {reach} |"
                )
        lines.append("")
        lines.append("<sub>" + _NOT_READ_NOTE + "</sub>")

    if waived:
        lines += ["", f"<sub>{len(waived)} accepted/waived, kept on the evidence "
                  "chain with justification.</sub>"]
    return "\n".join(lines) + "\n"


def render_markdown(model: SystemModel, findings: list[Finding], target: str) -> str:
    chain = audit_chain(findings)
    head = chain[-1]["hash"] if chain else GENESIS
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    active = [f for f in findings if not f.waived]
    waived = [f for f in findings if f.waived]
    counts: dict[str, int] = {}
    for f in active:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    lines = [
        "# Attestral - Security Design Review",
        "",
        f"- **Target:** `{target}`",
        f"- **Generated:** {now}",
        f"- **Components modeled:** {len(model.components)}",
        f"- **Findings:** {len(active)} "
        f"({', '.join(f'{v} {k}' for k, v in counts.items()) or 'none'})"
        + (f"  ·  **{len(waived)} waived**" if waived else ""),
        f"- **Evidence chain head:** `{head}`",
        "",
        "## Findings",
        "",
    ]
    if not active:
        lines.append("No active findings from the deterministic rule pack.")
    for i, f in enumerate(active, 1):
        lines += [
            f"### {i}. [{f.severity.value.upper()}] {f.title}  `{f.rule_id}`",
            "",
            f"- **Component:** `{f.component_id}`  ·  **Source:** `{f.source}`",
            f"- **Frameworks:** {', '.join(f.framework_refs) or '-'}",
        ]
        if f.reachability:
            row = f"- **Reachable chain:** {f.reachability}"
            if f.reachability_role:
                row += f" (this component: {f.reachability_role})"
            if f.escalated_from:
                row += f" · severity raised from {f.escalated_from}"
            lines.append(row)
        lines += [
            "",
            f.description,
            "",
            f"**Recommendation:** {f.recommendation}",
            "",
        ]
    if waived:
        lines += [
            "## Waived findings (accepted risk)",
            "",
            "_Suppressed from the gate by a documented waiver, but retained in the",
            "evidence chain below with their justification._",
            "",
        ]
        for f in waived:
            row = (
                f"- **[{f.severity.value.upper()}] {f.title}** `{f.rule_id}` "
                f"(`{f.component_id}`): {f.waiver_reason}"
            )
            if f.waived_by:
                row += f" _(accepted by {f.waived_by}"
                row += f", {f.waived_at})_" if f.waived_at else ")_"
            lines.append(row)
        lines.append("")
    lines += [
        "## Evidence chain",
        "",
        "| # | Rule | Hash (first 16) | Prev (first 16) |",
        "|---|------|-----------------|-----------------|",
    ]
    for i, e in enumerate(chain, 1):
        lines.append(
            f"| {i} | {e['finding']['rule_id']} | `{e['hash'][:16]}` | `{e['prev'][:16]}` |"
        )
    lines += [
        "",
        "_Verify with `attestral verify report.json`. Any tampering with a past",
        "entry invalidates every later hash and the chain head above._",
        "",
    ]
    return "\n".join(lines)
