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
            lines += [
                f"- **[{f.severity.value.upper()}] {f.title}** `{f.rule_id}` "
                f"(`{f.component_id}`): {f.waiver_reason}",
            ]
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
