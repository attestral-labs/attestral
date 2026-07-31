"""Auto-lockdown: the instant containment half of the compile-to-drift loop.

`attestral drift --lockdown` turns a drift finding into an enforcement action -
the policy with the offending server quarantined - and carries a narrowing proof
that makes applying it safe without a human. The proof is the load-bearing part:
the lockdown only ever REMOVES capability, so a compromised runtime that trips it
can at worst deny itself.
"""
from click.testing import CliRunner

from attestral.cli import main
from attestral.compile import compile_policy
from attestral.drift import detect_drift, load_events
from attestral.ingest import build_model
from attestral.lockdown import build_lockdown, lockdown_record, render_lockdown
from attestral.narrowing import classify
from attestral.rules import RuleEngine

FIXTURE = "examples/broker-bypass-runtime"
MALICIOUS = f"{FIXTURE}/runtime-events-malicious.jsonl"
BENIGN = f"{FIXTURE}/runtime-events-benign.jsonl"


def _policy(path=FIXTURE):
    model = build_model(path)
    return compile_policy(model, RuleEngine().evaluate(model))


def test_lockdown_quarantines_the_drifted_server_and_is_a_narrowing():
    policy = _policy()
    findings = detect_drift(policy, load_events(MALICIOUS))
    assert [f.rule_id for f in findings] == ["DRF-011"]

    lock = build_lockdown(policy, findings)
    assert lock.triggered
    assert lock.quarantined == ["github"]
    assert lock.policy["servers"]["github"]["allow"] is False
    # the load-bearing safety property: the lockdown only removes capability
    assert lock.safe_to_apply and lock.narrowing in ("narrowing", "unchanged")
    assert not classify(policy, lock.policy).is_expansion


def test_no_drift_means_no_lockdown():
    policy = _policy()
    lock = build_lockdown(policy, detect_drift(policy, load_events(BENIGN)))
    assert not lock.triggered
    assert lock.quarantined == []
    assert "No lockdown needed" in render_lockdown(lock, color=False)


def test_lockdown_record_binds_the_before_and_after_policy_digests():
    policy = _policy()
    findings = detect_drift(policy, load_events(MALICIOUS))
    rec = lockdown_record(policy, build_lockdown(policy, findings))
    assert rec["action"] == "lockdown"
    assert rec["quarantined"] == ["github"]
    assert rec["triggers"][0]["drf_id"] == "DRF-011"
    assert rec["safe_to_apply"] is True
    # the digests bind exactly what is applied, and the lockdown changed the policy
    assert rec["policy_before"] and rec["policy_after"]
    assert rec["policy_before"] != rec["policy_after"]


def test_cli_lockdown_emits_artifacts_and_signals_with_exit_2(tmp_path):
    policy_out = tmp_path / "policy.yaml"
    r0 = CliRunner().invoke(main, ["compile", FIXTURE, "-o", str(policy_out)])
    assert r0.exit_code == 0, r0.output

    stem = tmp_path / "lock"
    r = CliRunner().invoke(main, ["drift", str(policy_out), MALICIOUS,
                                  "--lockdown", "-o", str(stem)])
    # exit 2 is the responder signal that a lockdown was emitted
    assert r.exit_code == 2, r.output
    assert "LOCKDOWN TRIGGERED" in r.output
    assert "narrowing verified" in r.output
    assert (tmp_path / "lock.lockdown.yaml").exists()
    assert (tmp_path / "lock.lockdown.json").exists()


def test_cli_lockdown_on_benign_stream_is_clean_exit_0(tmp_path):
    policy_out = tmp_path / "policy.yaml"
    CliRunner().invoke(main, ["compile", FIXTURE, "-o", str(policy_out)])
    r = CliRunner().invoke(main, ["drift", str(policy_out), BENIGN, "--lockdown"])
    assert r.exit_code == 0, r.output
    assert "No lockdown needed" in r.output
    # terminal-first: nothing written without a trigger
    assert not list(tmp_path.glob("*.lockdown.*"))
