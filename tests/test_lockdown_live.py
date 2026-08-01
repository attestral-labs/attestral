"""Live containment: `attestral drift --stdin --lockdown --enforce`.

Closes the loop from streaming detection to a live enforcement point: the
DriftMonitor keeps measuring every event against the ORIGINAL attested policy,
and each time the quarantine set grows, the narrowing-verified lockdown is
pushed atomically to the policy file a running mcp-guard reads and appended to
a hash-chained journal. A lockdown that fails the narrowing proof is refused,
journaled, and never written - the monitor keeps running either way.
"""
import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from attestral.cli import main
from attestral.lockdown import journal_append, verify_journal

FIXTURE = "examples/broker-bypass-runtime"
MALICIOUS = f"{FIXTURE}/runtime-events-malicious.jsonl"
BENIGN = f"{FIXTURE}/runtime-events-benign.jsonl"


@pytest.fixture(scope="module")
def policy_file(tmp_path_factory):
    out = tmp_path_factory.mktemp("attested") / "policy.yaml"
    r = CliRunner().invoke(main, ["compile", FIXTURE, "-o", str(out)])
    assert r.exit_code == 0, r.output
    return out


def _stream(policy_file, tmp_path, stream, extra=()):
    enforce = tmp_path / "live-policy.yaml"
    r = CliRunner().invoke(
        main,
        ["drift", str(policy_file), "--stdin", "--lockdown",
         "--enforce", str(enforce), *extra],
        input=stream,
    )
    return r, enforce, Path(f"{enforce}.journal.jsonl")


def test_malicious_stream_pushes_lockdown_to_the_enforcement_point(policy_file, tmp_path):
    r, enforce, journal = _stream(policy_file, tmp_path, Path(MALICIOUS).read_text())
    # exit 2 is the responder signal, same as batch --lockdown
    assert r.exit_code == 2, r.output
    assert "LOCKDOWN pushed" in r.output and "github" in r.output
    live = yaml.safe_load(enforce.read_text())
    assert live["servers"]["github"]["allow"] is False
    entries = [json.loads(ln) for ln in journal.read_text().splitlines()]
    assert len(entries) == 1
    assert entries[0]["action"] == "push"
    assert entries[0]["quarantined"] == ["github"]
    assert entries[0]["policy_before"] != entries[0]["policy_after"]
    assert verify_journal(journal).ok
    # flip one byte of the recorded hash - the chain must detect it
    text = journal.read_text()
    sha = entries[0]["entry_sha"]
    journal.write_text(text.replace(sha, ("0" if sha[0] != "0" else "1") + sha[1:]))
    assert not verify_journal(journal).ok


def test_same_server_drifting_repeatedly_is_exactly_one_push(policy_file, tmp_path):
    stream = Path(MALICIOUS).read_text() * 3
    r, enforce, journal = _stream(policy_file, tmp_path, stream)
    assert r.exit_code == 2, r.output
    assert r.output.count("LOCKDOWN pushed") == 1
    entries = [json.loads(ln) for ln in journal.read_text().splitlines()]
    assert [e["action"] for e in entries] == ["push"]


def test_a_second_drifting_server_escalates_to_a_second_push(policy_file, tmp_path):
    stream = (Path(MALICIOUS).read_text()
              + json.dumps({"server": "rogue", "tool": "exfil"}) + "\n")
    r, enforce, journal = _stream(policy_file, tmp_path, stream)
    assert r.exit_code == 2, r.output
    entries = [json.loads(ln) for ln in journal.read_text().splitlines()]
    assert [e["action"] for e in entries] == ["push", "push"]
    assert entries[0]["quarantined"] == ["github"]
    assert entries[1]["quarantined"] == ["github", "rogue"]
    assert verify_journal(journal).ok
    live = yaml.safe_load(enforce.read_text())
    assert live["servers"]["github"]["allow"] is False
    assert live["servers"]["rogue"]["allow"] is False


def test_journal_chain_detects_edit_removal_and_reorder(tmp_path):
    j = tmp_path / "containment.journal.jsonl"
    e1 = journal_append(j, {"action": "push", "quarantined": ["a"]})
    e2 = journal_append(j, {"action": "push", "quarantined": ["a", "b"]})
    assert (e1["seq"], e2["seq"]) == (1, 2)
    assert e2["prev_sha"] == e1["entry_sha"]
    assert verify_journal(j).ok
    lines = j.read_text().splitlines()
    # altered value
    j.write_text(lines[0].replace('["a"]', '["x"]', 1) + "\n" + lines[1] + "\n")
    assert not verify_journal(j).ok
    # removed line
    j.write_text(lines[1] + "\n")
    assert not verify_journal(j).ok
    # reordered lines
    j.write_text(lines[1] + "\n" + lines[0] + "\n")
    assert not verify_journal(j).ok
    # intact again
    j.write_text("\n".join(lines) + "\n")
    assert verify_journal(j).ok


def test_reload_cmd_fires_after_a_push(policy_file, tmp_path):
    marker = tmp_path / "guard-reloaded"
    r, enforce, _ = _stream(policy_file, tmp_path, Path(MALICIOUS).read_text(),
                            extra=["--reload-cmd", f"touch {marker}"])
    assert r.exit_code == 2, r.output
    assert enforce.exists()
    assert marker.exists()


def test_failing_reload_cmd_is_a_warning_not_fatal(policy_file, tmp_path):
    r, enforce, journal = _stream(policy_file, tmp_path, Path(MALICIOUS).read_text(),
                                  extra=["--reload-cmd", "false"])
    assert r.exit_code == 2, r.output  # the push still counts
    assert "warning: --reload-cmd" in r.output
    assert enforce.exists() and verify_journal(journal).ok


def test_benign_stream_writes_nothing_and_exits_clean(policy_file, tmp_path):
    r, enforce, journal = _stream(policy_file, tmp_path, Path(BENIGN).read_text())
    assert r.exit_code == 0, r.output
    assert "LOCKDOWN" not in r.output
    assert not enforce.exists()
    assert not journal.exists()


def test_unsafe_lockdown_is_refused_journaled_and_never_written(policy_file, tmp_path, monkeypatch):
    import attestral.lockdown as lockdown_mod
    real = lockdown_mod.build_lockdown

    def unsafe(policy, findings):
        lock = real(policy, findings)
        if lock.triggered:  # force the narrowing proof to fail
            lock.safe_to_apply = False
            lock.narrowing = "expansion"
        return lock

    monkeypatch.setattr(lockdown_mod, "build_lockdown", unsafe)
    stream = Path(MALICIOUS).read_text() * 2 + Path(BENIGN).read_text()
    r, enforce, journal = _stream(policy_file, tmp_path, stream)
    assert r.exit_code == 0, r.output  # nothing pushed, stream ended cleanly
    assert "REFUSED lockdown" in r.output
    assert not enforce.exists()  # the enforcement point is never widened
    entries = [json.loads(ln) for ln in journal.read_text().splitlines()]
    assert [e["action"] for e in entries] == ["refused"]  # once, not per event
    assert verify_journal(journal).ok
    # the monitor kept running past the refusal: all three events were seen
    assert "3 events" in r.output


def test_batch_mode_honors_enforce_with_the_same_journal(policy_file, tmp_path):
    enforce = tmp_path / "live-policy.yaml"
    r = CliRunner().invoke(main, ["drift", str(policy_file), MALICIOUS,
                                  "--lockdown", "--enforce", str(enforce)])
    assert r.exit_code == 2, r.output
    assert "LOCKDOWN pushed" in r.output
    live = yaml.safe_load(enforce.read_text())
    assert live["servers"]["github"]["allow"] is False
    journal = Path(f"{enforce}.journal.jsonl")
    entries = [json.loads(ln) for ln in journal.read_text().splitlines()]
    assert [e["action"] for e in entries] == ["push"]
    assert verify_journal(journal).ok
