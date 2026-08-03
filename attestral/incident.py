"""Incident attestation: the replay forensics record, made audit-grade.

`attestral drift --replay` reconstructs an incident - when the runtime
diverged from the attested design, what contained it, whether the containment
journal holds. This module is the last step of that loop: it binds the
reconstruction into a DSSE-signable in-toto Statement, the same contract the
design-side attestation (`attest.py`) already speaks. The subject is the
recorded event stream (the evidence the incident is reconstructed from); the
predicate binds the policy digest the stream was judged against, the
containment journal's verdict and chain head, and a digest of the full replay
reconstruction. Any tamper - a doctored event line, a rewritten journal, an
edited verdict - makes verification FAIL, because every bound value is
recomputed from the supplied inputs, never trusted from the bundle.

The story completes: attested design -> runtime policy -> attested incident.
An operator hands an auditor one file that proves what happened, against
which reviewed design, with what containment - and the auditor re-derives it.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from attestral import __version__
from attestral.attest import STATEMENT_TYPE, VERIFIER_ID
from attestral.compile import policy_digest, render_policy_yaml
from attestral.drift import Replay, replay_drift

PREDICATE_TYPE = "https://attestral.dev/attestation/incident/v1"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _events_digest(events: list) -> str:
    return _sha256(json.dumps(events, sort_keys=True, default=str))


def _policy_digest(policy: dict) -> str:
    """The compiled policy's digest, in the SAME scheme the containment journal
    records (`policy_before`/`policy_after`), so an auditor can correlate the
    incident attestation with the journal it binds. Only a compiled policy has
    that digest; anything else is refused rather than hashed ambiguously."""
    if not isinstance(policy, dict) or not isinstance(policy.get("metadata"), dict):
        raise ValueError(
            "incident attestation needs the compiled, attested policy "
            "(attestral compile output with its metadata block) - refusing to "
            "digest an arbitrary mapping"
        )
    return policy_digest(policy, render_policy_yaml)


def _replay_digest(replay: Replay) -> str:
    """One digest over the entire reconstruction (timeline + summary), so an
    edit to any moment - not just the headline verdict - breaks the binding."""
    return f"sha256:{_sha256(json.dumps(replay.as_dict(), sort_keys=True))}"


def _journal_chain_head(journal_entries: list | None) -> str:
    """The last entry's hash - the containment trail's head, bound so a
    truncated or extended journal no longer matches the attested one."""
    if not journal_entries:
        return ""
    last = journal_entries[-1]
    return str(last.get("entry_sha", "")) if isinstance(last, dict) else ""


def build_incident_statement(
    policy: dict,
    events_name: str,
    events: list,
    journal_entries: list | None = None,
    *,
    malformed_events: int = 0,
    malformed_journal_lines: int = 0,
    signer: str = "",
    version: str = __version__,
    generated_at: str = "",
) -> dict:
    """Assemble the in-toto Statement for one reconstructed incident.

    The replay is always recomputed here - a caller can never bind a
    reconstruction that does not follow from the supplied policy, events, and
    journal. `signer` and `generated_at` are recorded, never recomputed by
    verify.
    """
    replay = replay_drift(
        policy, events, journal_entries,
        malformed_events=malformed_events,
        malformed_journal_lines=malformed_journal_lines,
    )
    s = replay.summary
    predicate: dict[str, Any] = {
        "policy": {"digest": {"sha256": _policy_digest(policy)}},
        "events": {
            "digest": {"sha256": _events_digest(events)},
            "count": s["events"],
            "malformed": s["malformed_event_lines"],
        },
        "journal": {
            "verdict": s["journal_verdict"],
            "entries": s["journal_entries"],
            "chainHead": _journal_chain_head(journal_entries),
        },
        "replay": {
            "digest": _replay_digest(replay),
            "finalState": s["final_state"],
            "firstDrift": s["first_drift"],
            "findings": s["findings"],
            "byRule": s["by_rule"],
            "pushes": s["pushes"],
            "refusals": s["refusals"],
            "driftToContainment": s["drift_to_containment"],
        },
        "verifier": {"id": VERIFIER_ID, "version": {"attestral": version}},
        "signer": signer,
        "generated_at": generated_at,
    }
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": events_name, "digest": {"sha256": _events_digest(events)}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def build_incident_bundle(
    policy: dict,
    events_name: str,
    events: list,
    journal_entries: list | None = None,
    *,
    malformed_events: int = 0,
    malformed_journal_lines: int = 0,
    private_pem: str | None = None,
    signer: str = "",
    version: str = __version__,
    generated_at: str = "",
) -> dict:
    """The on-disk bundle: `{statement, envelope}`. Unsigned when no key is
    given (envelope is null, every digest still bound - the zero-dep graceful
    degrade, same contract as the conformance bundle)."""
    statement = build_incident_statement(
        policy, events_name, events, journal_entries,
        malformed_events=malformed_events,
        malformed_journal_lines=malformed_journal_lines,
        signer=signer, version=version, generated_at=generated_at,
    )
    envelope = None
    if private_pem:
        from attestral.signing import sign_statement

        envelope = sign_statement(statement, private_pem, signer=signer)
    return {"statement": statement, "envelope": envelope}


def verify_incident_bundle(
    bundle: dict,
    policy: dict,
    events: list,
    journal_entries: list | None = None,
    *,
    malformed_events: int = 0,
    malformed_journal_lines: int = 0,
    public_pem: str | None = None,
) -> tuple[bool, list[str]]:
    """Recompute every bound value from the SUPPLIED policy, events, and
    journal, and compare. Returns (passed, failing_step_names).

    Fail-closed: any mismatch is a failure. `signer` and `generated_at` are
    read, never recomputed. Only the optional signature step touches the
    crypto extra; everything else runs with zero dependencies.
    """
    failures: list[str] = []
    statement = bundle.get("statement") or {}
    predicate = statement.get("predicate") or {}

    if statement.get("_type") != STATEMENT_TYPE:
        failures.append("statement.type")
    if statement.get("predicateType") != PREDICATE_TYPE:
        failures.append("statement.predicateType")

    subject = statement.get("subject") or [{}]
    bound_subject = (subject[0].get("digest") or {}).get("sha256") if subject else None
    if bound_subject != _events_digest(events):
        failures.append("subject")

    bound_policy = ((predicate.get("policy") or {}).get("digest") or {}).get("sha256")
    if bound_policy != _policy_digest(policy):
        failures.append("policy")

    recomputed = build_incident_statement(
        policy, "", events, journal_entries,
        malformed_events=malformed_events,
        malformed_journal_lines=malformed_journal_lines,
    )["predicate"]
    if (predicate.get("events") or {}) != recomputed["events"]:
        failures.append("events")
    if (predicate.get("journal") or {}) != recomputed["journal"]:
        failures.append("journal")
    if (predicate.get("replay") or {}) != recomputed["replay"]:
        failures.append("replay")

    if public_pem is not None:
        from attestral.signing import envelope_payload, verify_envelope

        envelope = bundle.get("envelope")
        if not envelope:
            failures.append("signature")
        else:
            sig_ok = verify_envelope(envelope, public_pem)
            bound_ok = envelope_payload(envelope) == statement
            if not (sig_ok and bound_ok):
                failures.append("signature")

    return (not failures, failures)


def render_incident(bundle: dict, *, color: bool | None = None) -> str:
    """Terminal summary of an incident bundle: the verdict, the containment
    story, and what the attestation binds - one glance for the responder."""
    from attestral.report_terminal import _bold, _dim, _paint, supports_color

    if color is None:
        color = supports_color()
    pred = (bundle.get("statement") or {}).get("predicate") or {}
    replay = pred.get("replay") or {}
    journal = pred.get("journal") or {}
    state = str(replay.get("finalState", "-"))
    code = {"CONFORM": "32", "CONTAINED": "33", "DRIFTED": "1;31"}.get(state, "0")
    lines = [_bold("Incident attestation", color) + "  " + _paint(state, code, color)]
    first = replay.get("firstDrift")
    if first:
        where = f"event #{first.get('ordinal')}"
        if first.get("ts"):
            where += f" at {first['ts']}"
        lines.append(f"  first drift: {first.get('rule_id')} at {where}")
    lines.append(
        f"  findings {replay.get('findings', 0)} · pushes {replay.get('pushes', 0)}"
        f" · refusals {replay.get('refusals', 0)}"
        f" · journal {journal.get('verdict', 'no journal')}"
    )
    signed = "signed" if bundle.get("envelope") else "unsigned"
    lines.append(_dim(
        f"  {signed} · binds policy digest, event stream, journal chain head, "
        "and the full reconstruction", color))
    return "\n".join(lines)
