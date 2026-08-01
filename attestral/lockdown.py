"""Auto-lockdown: instant runtime containment when the deployment diverges.

`attestral drift --lockdown` turns a drift finding into an enforcement ACTION.
It quarantines every offending server (deny) via the same narrowing-verified
tightening `--remediate` uses, and emits a machine-consumable LOCKDOWN record
plus the enforcement policy to apply now, so a production responder (a webhook, a
sidecar, a CI job) can contain the divergence the moment it is seen.

What licenses AUTOMATIC application - and what a bare "kill the server" script
cannot claim - is a narrowing proof: the locked-down policy only ever REMOVES
capability from the reviewed design, never adds it, so applying it can only fail
safe (deny a server), never escalate. A compromised runtime that tries to
trigger a lockdown can, at worst, deny itself. That proof is why lockdown is the
one drift response safe to run without a human in the loop, where `--remediate`
(which changes the reviewed design) stays a proposal.

With `--enforce` the loop closes live: `push_lockdown` atomically publishes the
tightened policy to the file a running mcp-guard reads, and every push or
refusal is appended to a hash-chained, append-only journal (`journal_append` /
`verify_journal`) so the containment trail is tamper-evident, mirroring the
scan evidence chain. Detection never moves while enforcement acts: the
DriftMonitor keeps evaluating every event against the ORIGINAL attested policy,
so drift is always measured against the reviewed design and enforcement only
ever narrows the runtime.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from attestral.model import Finding


@dataclass
class Lockdown:
    """The containment action: which servers to deny, what tripped it, and the
    narrowing proof that makes applying it safe without review."""
    quarantined: list[str]
    triggers: list[dict]
    narrowing: str                 # narrowing.classify verdict over (design, locked)
    safe_to_apply: bool            # True unless the tightening somehow widened (never should)
    policy: dict = field(default_factory=dict)   # the locked-down enforcement policy

    @property
    def triggered(self) -> bool:
        return bool(self.quarantined)


def build_lockdown(policy: dict, findings: list[Finding]) -> Lockdown:
    """Quarantine every server that drifted, verified a narrowing of the design.

    Reuses `drift.remediate_drift` (same deny-only tightening as `--remediate`),
    then re-classifies the result so the record can carry an independent proof
    that the lockdown only removes capability."""
    from attestral.drift import remediate_drift
    from attestral.narrowing import classify

    triggers = [{
        "drf_id": f.rule_id,
        "server": f.component_id.removeprefix("mcp_server."),
        "detail": f.title,
    } for f in findings]
    if not findings:
        return Lockdown([], [], "unchanged", True, policy)
    locked, delta = remediate_drift(policy, findings)
    verdict = classify(policy, locked)
    quarantined = sorted({op["server"] for op in delta})
    return Lockdown(quarantined, triggers, verdict.overall,
                    not verdict.is_expansion, locked)


def lockdown_record(policy: dict, lock: Lockdown) -> dict:
    """The record a production responder applies: what tripped, what is denied,
    the narrowing proof that makes auto-apply safe, and the policy digests before
    and after so the responder verifies exactly what it is applying."""
    from attestral.compile import policy_digest, render_policy_yaml

    return {
        "action": "lockdown",
        "quarantined": lock.quarantined,
        "triggers": lock.triggers,
        "narrowing": lock.narrowing,
        "safe_to_apply": lock.safe_to_apply,
        "policy_before": policy_digest(policy, render_policy_yaml),
        "policy_after": policy_digest(lock.policy, render_policy_yaml),
    }


def render_lockdown(lock: Lockdown, *, color: bool | None = None) -> str:
    """Terminal banner: what was quarantined, what tripped it, and whether the
    narrowing proof holds (so the operator knows it is safe to auto-apply)."""
    from attestral.report_terminal import _bold, _dim, _paint, supports_color

    if color is None:
        color = supports_color()
    if not lock.triggered:
        return _paint("No lockdown needed: the runtime matches the attested design.",
                      "32", color)
    lines = [_paint("LOCKDOWN TRIGGERED - runtime diverged from the attested design",
                    "1;31", color)]
    lines.append(f"  quarantined {len(lock.quarantined)} server(s): "
                 f"{_bold(', '.join(lock.quarantined), color)}")
    for t in lock.triggers:
        lines.append(f"    {_dim('trigger:', color)} {t['drf_id']} {t['server']} - {t['detail']}")
    if lock.safe_to_apply:
        lines.append("  " + _paint("narrowing verified: safe to auto-apply "
                                   "(only removes capability, never grants)", "32", color))
        lines.append(_dim("  apply the emitted policy to the enforcement point to contain now.",
                          color))
    else:
        lines.append("  " + _paint("REFUSED: the tightening would widen the policy - "
                                   "not emitted", "1;31", color))
    return "\n".join(lines)


# --- live enforcement: push the lockdown to the point a running guard reads ------

def push_lockdown(lock: Lockdown, enforce_path: str | Path) -> Path:
    """Atomically publish the locked-down policy to the live enforcement point.

    ``enforce_path`` is the policy file a running mcp-guard reads. The write is a
    temp file in the same directory followed by ``os.replace``, so a concurrent
    reader sees either the old policy or the new one in full, never a torn write.
    Fail-closed: a lockdown whose narrowing proof did not hold is refused
    (raised) - the enforcement point must never receive a policy that could
    widen the attested design."""
    from attestral.compile import render_policy_yaml

    if not lock.safe_to_apply:
        raise RuntimeError("refusing to push: lockdown failed the narrowing proof")
    dest = Path(enforce_path)
    fd, tmp = tempfile.mkstemp(dir=str(dest.parent), prefix=f".{dest.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(render_policy_yaml(lock.policy))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return dest


# --- hash-chained containment journal: the tamper-evident audit trail ------------

def _entry_sha(entry: dict) -> str:
    """SHA-256 over the canonical JSON of an entry with ``entry_sha`` blanked.
    ``prev_sha`` stays in, so each hash commits to the whole chain behind it."""
    canon = dict(entry, entry_sha="")
    return hashlib.sha256(
        json.dumps(canon, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _journal_entries(path: Path) -> tuple[list[dict], bool]:
    """Parse the journal's JSONL lines. Returns ``(entries, clean)``; ``clean``
    is False when any non-empty line failed to parse as a JSON object."""
    entries: list[dict] = []
    clean = True
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            clean = False
            continue
        if isinstance(obj, dict):
            entries.append(obj)
        else:
            clean = False
    return entries, clean


def lockdown_journal_entry(policy: dict, lock: Lockdown, action: str) -> dict:
    """The journal payload for one containment decision.

    ``action`` is "push" (the lockdown went to the enforcement point) or
    "refused" (the narrowing proof failed, nothing was written). Reuses
    `lockdown_record`, so the entry carries the triggers, the quarantined
    servers, the narrowing verdict, and the before/after policy digests that
    bind exactly what was (or was not) applied. `journal_append` stamps the
    chain fields (seq, prev_sha, entry_sha)."""
    entry = lockdown_record(policy, lock)
    entry["action"] = action
    entry["ts"] = datetime.now(timezone.utc).isoformat()
    return entry


def journal_append(journal_path: str | Path, entry: dict) -> dict:
    """Append one entry to the hash-chained, append-only lockdown journal.

    Stamps ``seq`` (1-based), ``prev_sha`` (the previous entry's ``entry_sha``,
    empty for the first) and ``entry_sha`` (SHA-256 over the canonical JSON of
    the completed entry with ``entry_sha`` blanked), then appends one JSONL
    line. The chain is what makes the containment trail an audit artifact:
    altering, removing, inserting, or reordering any line breaks verification.
    Returns the completed entry as written."""
    path = Path(journal_path)
    prior, _ = _journal_entries(path) if path.exists() else ([], True)
    completed = dict(entry)
    completed["seq"] = len(prior) + 1
    completed["prev_sha"] = str(prior[-1].get("entry_sha", "")) if prior else ""
    completed["entry_sha"] = ""
    completed["entry_sha"] = _entry_sha(completed)
    with path.open("a") as fh:
        fh.write(json.dumps(completed, sort_keys=True, separators=(",", ":"), default=str) + "\n")
    return completed


@dataclass
class JournalVerification:
    """Result of re-verifying the lockdown journal's hash chain."""
    ok: bool
    entries: int
    reason: str = ""

    def __bool__(self) -> bool:
        return self.ok


def verify_journal(journal_path: str | Path) -> JournalVerification:
    """Recompute the journal's hash chain and report whether it is intact.

    Detects any altered, removed, inserted, or reordered line - the same
    tamper-evidence contract as the scan evidence chain. A missing journal
    verifies trivially (nothing was contained, nothing to attest); a malformed
    line fails closed."""
    path = Path(journal_path)
    if not path.exists():
        return JournalVerification(True, 0, "no journal")
    entries, clean = _journal_entries(path)
    if not clean:
        return JournalVerification(False, len(entries), "unparseable journal line")
    prev = ""
    for i, e in enumerate(entries, 1):
        if e.get("seq") != i:
            return JournalVerification(False, len(entries),
                                       f"entry {i}: sequence break (got {e.get('seq')!r})")
        if e.get("prev_sha") != prev:
            return JournalVerification(False, len(entries), f"entry {i}: prev_sha mismatch")
        if e.get("entry_sha") != _entry_sha(e):
            return JournalVerification(False, len(entries), f"entry {i}: entry_sha mismatch")
        prev = e["entry_sha"]
    return JournalVerification(True, len(entries), "chain intact")
