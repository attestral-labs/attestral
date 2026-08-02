"""Incident forensics: `attestral drift --replay` reconstructs WHEN the runtime
diverged (each DRF pinned to the event ordinal and timestamp where it crossed)
and what contained it (the hash-chained lockdown journal merged into the same
timeline, chain verified first). Fail-closed reporting throughout: malformed
lines are counted, garbage timestamps degrade to ordinals, and a tampered
journal is a headline of the reconstruction - never an exception."""
import json

import yaml
from click.testing import CliRunner

from attestral.cli import main
from attestral.drift import replay_drift
from attestral.lockdown import journal_append

POLICY = {
    "servers": {
        "web": {"allow": True, "manifest_sha256": "attested0000"},
        "shell": {"allow": False, "reason": "denied by ATL-103"},
    },
    "budgets": {"loop_repeat_threshold": 3, "max_calls_per_server": 10},
}

FIXTURE = "examples/broker-bypass-runtime"


def _ev(second: int, **kw) -> dict:
    return {"ts": f"2026-07-12T09:00:{second:02d}Z", "server": "web", "tool": "t",
            "args": [f"a{second}"], **kw}


def _write_pair(tmp_path, events):
    pol = tmp_path / "pol.yaml"
    pol.write_text(yaml.safe_dump(POLICY))
    ev = tmp_path / "events.jsonl"
    ev.write_text("\n".join(e if isinstance(e, str) else json.dumps(e)
                            for e in events) + "\n")
    return pol, ev


# --- timeline reconstruction (API) ------------------------------------------------

def test_timeline_pins_the_rugpull_to_the_event_where_the_manifest_flipped():
    events = [_ev(0), _ev(1), _ev(2),
              _ev(3, manifest_sha256="rugpulled"),
              _ev(4, manifest_sha256="rugpulled")]  # repeat: fires once, at the flip
    r = replay_drift(POLICY, events)
    assert [(m["rule_id"], m["ordinal"]) for m in r.timeline] == [("DRF-005", 4)]
    assert r.timeline[0]["ts"] == "2026-07-12T09:00:03Z"
    assert r.summary["first_drift"] == {
        "ordinal": 4, "ts": "2026-07-12T09:00:03Z", "rule_id": "DRF-005"}
    assert r.summary["by_rule"] == {"DRF-005": 1}
    assert r.summary["final_state"] == "DRIFTED"  # no journal, nothing contained it


def test_budget_crossing_lands_at_the_crossing_call_not_the_last_one():
    events = [{"server": "web", "tool": "loop", "args": ["same"],
               "ts": f"2026-07-12T09:01:{i:02d}Z"} for i in range(5)]
    r = replay_drift(POLICY, events)  # loop_repeat_threshold=3 crosses at event 3
    moments = [(m["rule_id"], m["ordinal"]) for m in r.timeline]
    assert moments == [("DRF-006", 3)]


def test_ts_less_and_garbage_ts_degrade_to_ordinals():
    events = [{"server": "web", "tool": "t", "args": ["x"]},
              {"server": "ghost", "tool": "x", "ts": "not-a-time"}]
    r = replay_drift(POLICY, events)
    assert [(m["rule_id"], m["ordinal"], m["ts"]) for m in r.timeline] == \
        [("DRF-001", 2, None)]
    assert r.summary["first_drift"] == {"ordinal": 2, "ts": None, "rule_id": "DRF-001"}


def test_benign_stream_is_conform_with_an_empty_timeline():
    r = replay_drift(POLICY, [_ev(0), _ev(1)])
    assert r.timeline == []
    assert r.summary["final_state"] == "CONFORM"
    assert r.summary["first_drift"] is None
    assert r.summary["drift_to_containment"] is None
    assert r.summary["journal_verdict"] == "no journal"


# --- journal merge ----------------------------------------------------------------

def test_journal_push_orders_after_the_triggering_drift(tmp_path):
    j = tmp_path / "containment.journal.jsonl"
    entry = journal_append(j, {"action": "push", "quarantined": ["ghost"],
                               "narrowing": "narrowing",
                               "ts": "2026-07-12T09:00:02Z"})
    events = [_ev(0),
              {"ts": "2026-07-12T09:00:01Z", "server": "ghost", "tool": "x"},
              _ev(3)]
    r = replay_drift(POLICY, events, [entry])
    moments = [(m["kind"], m.get("rule_id") or m["action"], m["ordinal"])
               for m in r.timeline]
    # the push (ts 09:00:02) lands after the drift at event #2 (09:00:01), before #3
    assert moments == [("drift", "DRF-001", 2), ("containment", "push", 2)]
    assert r.summary["journal_verdict"] == "intact"
    assert r.summary["first_push"] == {"seq": 1, "ts": "2026-07-12T09:00:02Z",
                                       "after_event": 2}
    assert r.summary["drift_to_containment"] == {"seconds": 1.0}
    assert r.summary["final_state"] == "CONTAINED"


def test_journal_entry_without_comparable_ts_appends_after_the_last_event(tmp_path):
    j = tmp_path / "containment.journal.jsonl"
    entry = journal_append(j, {"action": "push", "quarantined": ["ghost"]})  # ts-less
    events = [{"server": "ghost", "tool": "x"}]  # ts-less events too
    r = replay_drift(POLICY, events, [entry])
    assert [(m["kind"], m["ordinal"]) for m in r.timeline] == \
        [("drift", 1), ("containment", 1)]  # appended after the last event
    assert r.summary["drift_to_containment"] == {"events": 0}  # honest fallback
    assert r.summary["final_state"] == "CONTAINED"


def test_tampered_journal_is_reported_in_the_summary_not_raised(tmp_path):
    j = tmp_path / "containment.journal.jsonl"
    entry = journal_append(j, {"action": "push", "quarantined": ["ghost"],
                               "ts": "2026-07-12T09:00:02Z"})
    forged = dict(entry, quarantined=["ghost", "everything-else"])  # sha now wrong
    events = [{"ts": "2026-07-12T09:00:01Z", "server": "ghost", "tool": "x"}]
    r = replay_drift(POLICY, events, [forged])
    assert r.summary["journal_verdict"].startswith("TAMPERED")
    # a tampered journal attests nothing: no containment credit, gap withheld
    assert r.summary["final_state"] == "DRIFTED"
    assert r.summary["first_push"] is None
    assert r.summary["drift_to_containment"] is None
    # but the CLAIMED entry still appears in the timeline for the responder to see
    assert any(m["kind"] == "containment" for m in r.timeline)


# --- CLI --------------------------------------------------------------------------

def test_cli_renders_the_timeline_and_flags_the_tampered_chain(tmp_path):
    pol, ev = _write_pair(tmp_path, [
        _ev(0), {"ts": "2026-07-12T09:00:01Z", "server": "ghost", "tool": "x"}])
    j = tmp_path / "enforce.yaml.journal.jsonl"
    entry = journal_append(j, {"action": "push", "quarantined": ["ghost"],
                               "ts": "2026-07-12T09:00:02Z"})
    sha = entry["entry_sha"]
    j.write_text(j.read_text().replace(
        sha, ("0" if sha[0] != "0" else "1") + sha[1:]))
    r = CliRunner().invoke(main, ["drift", str(pol), str(ev),
                                  "--replay", "--journal", str(j)])
    assert r.exit_code == 0, r.output  # reported, never raised
    assert "DRF-001" in r.output and "09:00:01" in r.output
    assert "TAMPERED" in r.output
    assert "DRIFTED" in r.output and "CONTAINED" not in r.output


def test_cli_output_writes_a_valid_json_incident_record(tmp_path):
    pol, ev = _write_pair(tmp_path, [
        _ev(0),
        {"ts": "2026-07-12T09:00:01Z", "server": "ghost", "tool": "x"},
        "{ this line is garbage",  # counted, never fatal
    ])
    out = tmp_path / "incident.json"
    r = CliRunner().invoke(main, ["drift", str(pol), str(ev),
                                  "--replay", "-o", str(out)])
    assert r.exit_code == 0, r.output
    rec = json.loads(out.read_text())
    s = rec["summary"]
    assert s["events"] == 2
    assert s["malformed_event_lines"] == 1
    assert s["findings"] == 1 and s["by_rule"] == {"DRF-001": 1}
    assert s["first_drift"]["ordinal"] == 2
    assert s["final_state"] == "DRIFTED"
    assert rec["timeline"][0]["rule_id"] == "DRF-001"


def test_cli_writes_nothing_without_dash_o(tmp_path):
    pol, ev = _write_pair(tmp_path, [
        _ev(0), {"ts": "2026-07-12T09:00:01Z", "server": "ghost", "tool": "x"}])
    r = CliRunner().invoke(main, ["drift", str(pol), str(ev), "--replay"])
    assert r.exit_code == 0, r.output
    assert {p.name for p in tmp_path.iterdir()} == {"pol.yaml", "events.jsonl"}


def test_replay_is_mutually_exclusive_with_streaming_and_actions(tmp_path):
    pol, ev = _write_pair(tmp_path, [_ev(0)])
    for combo in (["--watch"], ["--stdin"], ["--remediate"], ["--lockdown"]):
        r = CliRunner().invoke(main, ["drift", str(pol), str(ev), "--replay", *combo])
        assert r.exit_code == 2, (combo, r.output)
        assert "--replay" in r.output
    # --journal without --replay is a usage error too
    r = CliRunner().invoke(main, ["drift", str(pol), str(ev), "--journal", str(ev)])
    assert r.exit_code == 2
    assert "--journal" in r.output


def test_replay_fixture_stream_pins_the_broker_bypass(tmp_path):
    pol = tmp_path / "policy.yaml"
    r = CliRunner().invoke(main, ["compile", FIXTURE, "-o", str(pol)])
    assert r.exit_code == 0, r.output
    r = CliRunner().invoke(main, ["drift", str(pol),
                                  f"{FIXTURE}/runtime-events-malicious.jsonl",
                                  "--replay"])
    assert r.exit_code == 0, r.output
    assert "DRF-011" in r.output and "#1" in r.output
    assert "DRIFTED" in r.output


def test_replay_benign_fixture_stream_ends_conform(tmp_path):
    pol = tmp_path / "policy.yaml"
    r = CliRunner().invoke(main, ["compile", FIXTURE, "-o", str(pol)])
    assert r.exit_code == 0, r.output
    r = CliRunner().invoke(main, ["drift", str(pol),
                                  f"{FIXTURE}/runtime-events-benign.jsonl",
                                  "--replay"])
    assert r.exit_code == 0, r.output
    assert "CONFORM" in r.output
    assert "DRF-" not in r.output
