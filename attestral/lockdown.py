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
"""
from __future__ import annotations

from dataclasses import dataclass, field

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
