"""Evidence layer: tamper-evident audit chain, no-egress attestation, report export."""
from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import json
import socket

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


# --- Sovereign mode: enforce and attest that a scan ran fully local ----------
#
# Data sovereignty (GCC, defense, regulated finance) often makes "no client
# data leaves the environment" the only compliant posture, not a preference.
# Attestral is already terminal-first and local by default; sovereign mode adds
# teeth and a receipt: an egress guard that stops any outbound connection at the
# socket, and a self-verifying attestation that rides the same tamper-evidence
# idiom as the audit chain.

_LOOPBACK_HOSTS = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
)


class EgressBlocked(OSError):
    """Raised when the egress guard stops an outbound connection.

    Subclasses OSError so a networking library (the anthropic SDK, a model
    download, a stray telemetry call) surfaces it as an ordinary connection
    failure instead of an unexpected exception type.
    """


def _is_local_address(address: object) -> bool:
    """True if a connect() target stays on this host (loopback or a UNIX path)."""
    # AF_UNIX targets are a path (str/bytes) and never leave the machine.
    if isinstance(address, (str, bytes, bytearray)):
        return True
    try:
        host = address[0]  # AF_INET/AF_INET6: (host, port[, flowinfo, scopeid])
    except (TypeError, IndexError, KeyError):
        return False
    if not isinstance(host, str):
        return False
    if host in _LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False  # a real hostname needs the network - block it


class EgressGuard:
    """Process-wide block on outbound network connections, with a record.

    While armed, any attempt to connect a socket to a non-loopback address
    raises :class:`EgressBlocked` and is recorded in ``blocked``; loopback and
    UNIX-socket connections pass through (local IPC never leaves the host). This
    turns "no client data left the environment" into an enforced, observable
    property rather than a promise - whatever library tries to egress is stopped
    at the socket layer, before a single byte is sent. Idempotent: arming twice
    or disarming twice is safe, and the original methods are always restored.
    """

    def __init__(self) -> None:
        self.blocked: list[tuple[str, int | None]] = []
        self._armed = False
        self._orig_connect = None
        self._orig_connect_ex = None

    def _record(self, address: object) -> None:
        if isinstance(address, (list, tuple)) and address:
            host = str(address[0])
            port = address[1] if len(address) > 1 and isinstance(address[1], int) else None
        else:
            host, port = str(address), None
        self.blocked.append((host, port))

    def arm(self) -> EgressGuard:
        if self._armed:
            return self
        guard = self
        self._orig_connect = socket.socket.connect
        self._orig_connect_ex = socket.socket.connect_ex

        def connect(sock, address, *args, **kwargs):
            if _is_local_address(address):
                return guard._orig_connect(sock, address, *args, **kwargs)
            guard._record(address)
            raise EgressBlocked(f"sovereign mode blocked an outbound connection to {address}")

        def connect_ex(sock, address, *args, **kwargs):
            if _is_local_address(address):
                return guard._orig_connect_ex(sock, address, *args, **kwargs)
            guard._record(address)
            raise EgressBlocked(f"sovereign mode blocked an outbound connection to {address}")

        socket.socket.connect = connect
        socket.socket.connect_ex = connect_ex
        self._armed = True
        return self

    def disarm(self) -> None:
        if not self._armed:
            return
        socket.socket.connect = self._orig_connect
        socket.socket.connect_ex = self._orig_connect_ex
        self._armed = False

    def __enter__(self) -> EgressGuard:
        return self.arm()

    def __exit__(self, *exc: object) -> None:
        self.disarm()


def no_egress_attestation(
    *,
    target: str,
    components: int,
    findings: list[Finding],
    ml_tier: str,
    blocked: list[tuple[str, int | None]],
    chain_head: str,
    generated: str,
) -> dict:
    """A self-verifying record that a scan ran fully local.

    Reuses the audit chain's tamper-evidence idiom: the record carries a SHA-256
    over its own canonical form and binds itself to the run by including the
    evidence-chain head, so ``attestral verify`` can recompute both. A non-empty
    ``blocked`` list is the honest failure signal - something tried to egress and
    the guard stopped it - and is recorded, never hidden.
    """
    active = [f for f in findings if not f.waived]
    core = {
        "kind": "attestral.no-egress-attestation",
        "version": 1,
        "target": target,
        "generated": generated,
        "sovereign": True,
        "egress_guard": "armed",
        "clean": not blocked,
        "blocked_attempts": [
            f"{host}:{port}" if port is not None else host for host, port in blocked
        ],
        "layers": {"llm": False, "judge": False, "network_ml": False, "ml_tier": ml_tier},
        "components_reviewed": components,
        "findings": len(active),
        "chain_head": chain_head,
    }
    digest = hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()
    return {**core, "attestation_sha256": digest}


def verify_attestation(attestation: dict) -> bool:
    """Recompute a no-egress attestation's self-hash. True if untampered."""
    if not attestation or "attestation_sha256" not in attestation:
        return False
    core = {k: v for k, v in attestation.items() if k != "attestation_sha256"}
    digest = hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()
    return digest == attestation["attestation_sha256"]


def attestation_line(attestation: dict) -> str:
    """One terminal line summarizing a no-egress attestation."""
    n = len(attestation.get("blocked_attempts", []))
    status = "0 outbound connections" if attestation.get("clean") else f"{n} blocked"
    return (
        "no-egress attestation: guard armed, "
        f"{status} · ml tier {attestation['layers']['ml_tier']} · "
        f"chain {attestation.get('chain_head', '')[:16]} · "
        f"digest {attestation['attestation_sha256'][:16]}"
    )


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
    from attestral.report_terminal import (
        _CLEAN_VERDICTS,
        _NOT_READ_NOTE,
        _family_of,
        clean_scan_category,
    )

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
        # A baseline-gated run reports only what the change introduced, so the
        # full-surface scope caveat does not apply; a full scan states its scope
        # honestly, so a thin or empty review is never read as a clean bill.
        verdict = "No new findings." if net_new else _CLEAN_VERDICTS[clean_scan_category(model)]
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
