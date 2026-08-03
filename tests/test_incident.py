"""Incident attestation: bind the replay reconstruction, then try to break it.

Every test follows the module's contract: the bundle is only as good as what
a verifier can RECOMPUTE from the supplied policy, events, and journal - so
each tamper case edits exactly one input or one bound field and asserts the
named step fails.
"""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from attestral.cli import main
from attestral.incident import (
    PREDICATE_TYPE,
    build_incident_bundle,
    build_incident_statement,
    render_incident,
    verify_incident_bundle,
)
from attestral.lockdown import journal_append

POLICY = {
    "version": 1,
    "metadata": {
        "generated_by": "attestral",
        "generated_at": "2026-08-01T09:00:00+00:00",
        "model_hash": "modelhash0000000000000000000000000000000000000000000000000000000",
        "review_chain_head": "chainhead00000000000000000000000000000000000000000000000000000000",
    },
    "default": "deny",
    "budgets": {"loop_repeat_threshold": 5, "max_calls_per_server": 100},
    "servers": {
        "web": {"allow": True},
        "shell": {"allow": False},
    },
}

BENIGN = [
    {"server": "web", "tool": "fetch", "args": ["a"], "ts": "2026-08-01T10:00:00Z"},
    {"server": "web", "tool": "fetch", "args": ["b"], "ts": "2026-08-01T10:00:05Z"},
]

DRIFTING = BENIGN + [
    {"server": "ghost", "tool": "exfil", "args": ["x"], "ts": "2026-08-01T10:00:10Z"},
]


def _journal(tmp_path, actions=("push",)):
    path = tmp_path / "containment.journal.jsonl"
    for action in actions:
        journal_append(path, {
            "action": action,
            "quarantined": ["ghost"],
            "narrowing": "narrowing-verified",
            "ts": "2026-08-01T10:00:12Z",
        })
    entries = [json.loads(line) for line in path.read_text().splitlines()]
    return path, entries


def test_statement_binds_subject_policy_and_verdict():
    st = build_incident_statement(POLICY, "events.jsonl", DRIFTING)
    assert st["predicateType"] == PREDICATE_TYPE
    assert st["subject"][0]["name"] == "events.jsonl"
    assert st["subject"][0]["digest"]["sha256"]
    pred = st["predicate"]
    assert pred["replay"]["finalState"] == "DRIFTED"
    assert pred["replay"]["firstDrift"]["rule_id"] == "DRF-001"
    assert pred["journal"]["verdict"] == "no journal"
    assert pred["policy"]["digest"]["sha256"]


def test_conform_stream_attests_conform():
    st = build_incident_statement(POLICY, "events.jsonl", BENIGN)
    assert st["predicate"]["replay"]["finalState"] == "CONFORM"
    assert st["predicate"]["replay"]["firstDrift"] is None


def test_roundtrip_verifies_unsigned():
    bundle = build_incident_bundle(POLICY, "events.jsonl", DRIFTING)
    ok, failures = verify_incident_bundle(bundle, POLICY, DRIFTING)
    assert ok and failures == []


def test_tampered_events_fail():
    bundle = build_incident_bundle(POLICY, "events.jsonl", DRIFTING)
    doctored = DRIFTING + [{"server": "web", "tool": "fetch", "args": ["c"]}]
    ok, failures = verify_incident_bundle(bundle, POLICY, doctored)
    assert not ok
    assert "subject" in failures and "events" in failures


def test_edited_verdict_fails_replay_step():
    bundle = build_incident_bundle(POLICY, "events.jsonl", DRIFTING)
    bundle["statement"]["predicate"]["replay"]["finalState"] = "CONFORM"
    ok, failures = verify_incident_bundle(bundle, POLICY, DRIFTING)
    assert not ok and "replay" in failures


def test_swapped_policy_fails():
    bundle = build_incident_bundle(POLICY, "events.jsonl", DRIFTING)
    widened = dict(POLICY, servers=dict(POLICY["servers"], ghost={"allow": True}))
    ok, failures = verify_incident_bundle(bundle, widened, DRIFTING)
    assert not ok and "policy" in failures


def test_journal_binds_chain_head_and_containment(tmp_path):
    _, entries = _journal(tmp_path)
    bundle = build_incident_bundle(POLICY, "events.jsonl", DRIFTING, entries)
    pred = bundle["statement"]["predicate"]
    assert pred["journal"]["verdict"] == "intact"
    assert pred["journal"]["chainHead"] == entries[-1]["entry_sha"]
    assert pred["replay"]["finalState"] == "CONTAINED"
    ok, failures = verify_incident_bundle(bundle, POLICY, DRIFTING, entries)
    assert ok and failures == []


def test_tampered_journal_fails_verification(tmp_path):
    _, entries = _journal(tmp_path)
    bundle = build_incident_bundle(POLICY, "events.jsonl", DRIFTING, entries)
    doctored = [dict(entries[0], quarantined=[])]
    ok, failures = verify_incident_bundle(bundle, POLICY, DRIFTING, doctored)
    assert not ok
    assert "journal" in failures and "replay" in failures


def test_tampered_journal_is_attested_as_tampered(tmp_path):
    _, entries = _journal(tmp_path)
    doctored = [dict(entries[0], quarantined=[])]
    st = build_incident_statement(POLICY, "events.jsonl", DRIFTING, doctored)
    assert st["predicate"]["journal"]["verdict"].startswith("TAMPERED")
    assert st["predicate"]["replay"]["finalState"] == "DRIFTED"  # no containment credit


def test_signed_roundtrip_and_wrong_key():
    pytest.importorskip("cryptography")
    from attestral.signing import generate_keypair

    priv, pub = generate_keypair()
    _, other_pub = generate_keypair()
    bundle = build_incident_bundle(POLICY, "events.jsonl", DRIFTING, private_pem=priv)
    assert bundle["envelope"] is not None
    ok, _ = verify_incident_bundle(bundle, POLICY, DRIFTING, public_pem=pub)
    assert ok
    ok, failures = verify_incident_bundle(bundle, POLICY, DRIFTING, public_pem=other_pub)
    assert not ok and failures == ["signature"]


def test_render_incident_summarizes():
    bundle = build_incident_bundle(POLICY, "events.jsonl", DRIFTING)
    text = render_incident(bundle, color=False)
    assert "DRIFTED" in text and "DRF-001" in text and "unsigned" in text


def _write_inputs(tmp_path, events):
    import yaml

    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(yaml.safe_dump(POLICY))
    events_file = tmp_path / "events.jsonl"
    events_file.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return policy_file, events_file


def test_cli_build_then_verify_roundtrip(tmp_path):
    policy_file, events_file = _write_inputs(tmp_path, DRIFTING)
    out = tmp_path / "incident.json"
    runner = CliRunner()
    r = runner.invoke(main, ["incident", str(policy_file), str(events_file),
                             "-o", str(out)])
    assert r.exit_code == 0, r.output
    assert "DRIFTED" in r.output and out.exists()
    r2 = runner.invoke(main, ["incident", str(policy_file), str(events_file),
                              "-o", str(out), "--verify"])
    assert r2.exit_code == 0, r2.output
    assert "VERIFIED" in r2.output


def test_cli_verify_catches_doctored_bundle(tmp_path):
    policy_file, events_file = _write_inputs(tmp_path, DRIFTING)
    out = tmp_path / "incident.json"
    runner = CliRunner()
    assert runner.invoke(main, ["incident", str(policy_file), str(events_file),
                                "-o", str(out)]).exit_code == 0
    bundle = json.loads(out.read_text())
    bundle["statement"]["predicate"]["replay"]["finalState"] = "CONFORM"
    out.write_text(json.dumps(bundle))
    r = runner.invoke(main, ["incident", str(policy_file), str(events_file),
                             "-o", str(out), "--verify"])
    assert r.exit_code == 1
    assert "replay" in r.output


def test_cli_journal_flag_binds_containment(tmp_path):
    policy_file, events_file = _write_inputs(tmp_path, DRIFTING)
    journal_path, _ = _journal(tmp_path)
    out = tmp_path / "incident.json"
    runner = CliRunner()
    r = runner.invoke(main, ["incident", str(policy_file), str(events_file),
                             "--journal", str(journal_path), "-o", str(out)])
    assert r.exit_code == 0, r.output
    assert "CONTAINED" in r.output
    r2 = runner.invoke(main, ["incident", str(policy_file), str(events_file),
                              "--journal", str(journal_path), "-o", str(out),
                              "--verify"])
    assert r2.exit_code == 0, r2.output
