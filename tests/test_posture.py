"""Signed agent-capability-posture predicate (attestral posture).

A structured, offline-verifiable statement of what an agent CAN do - its
capability envelope, whether its fleet forms a lethal trifecta, and the named
cloud infrastructure it can reach - bound to the design digest and DSSE-signed.
Verify re-derives the posture from the design, so any capability drift fails.
"""
from click.testing import CliRunner

from attestral.cli import main
from attestral.posture import (POSTURE_PREDICATE_TYPE, build_posture_bundle,
                               build_posture_statement, posture_delta,
                               verify_posture, verify_posture_runtime)
from attestral.signing import generate_keypair

TRIFECTA = "examples/agentic-risks"          # fleet forms a lethal trifecta
REACH = "examples/agent-cloud-confused-deputy"  # names a cross-boundary reach
CLEAN = "examples/guard-runtime"             # filesystem only, no trifecta/reach
GEN = "2026-01-01T00:00:00Z"


def _stmt(path):
    return build_posture_statement(path, generated_at=GEN)


# -- the predicate shape and verdicts --

def test_predicate_type_and_envelope():
    st = _stmt(TRIFECTA)
    assert st["predicateType"] == POSTURE_PREDICATE_TYPE
    p = st["predicate"]
    assert p["lethalTrifecta"] is True
    assert p["posture"] == "flagged"
    assert {"filesystem", "network", "shell"} <= set(p["capabilityEnvelope"])
    assert p["toolSurfaceCount"] == len(p["toolSurfaces"]) > 0


def test_cross_boundary_reach_is_named():
    p = _stmt(REACH)["predicate"]
    assert p["posture"] == "flagged"
    assert p["crossBoundaryReach"]  # non-empty, "entry -> sink" strings
    assert all(" -> " in r for r in p["crossBoundaryReach"])


def test_clean_design_is_clean_posture():
    p = _stmt(CLEAN)["predicate"]
    assert p["lethalTrifecta"] is False
    assert p["crossBoundaryReach"] == []
    assert p["posture"] == "clean"


# -- verify re-derives from the design --

def test_verify_same_design_passes():
    bundle = build_posture_bundle(TRIFECTA, generated_at=GEN)
    ok, failures = verify_posture(bundle, TRIFECTA)
    assert ok and failures == []


def test_verify_different_design_fails():
    bundle = build_posture_bundle(TRIFECTA, generated_at=GEN)
    ok, failures = verify_posture(bundle, CLEAN)
    assert not ok
    assert "subject.digest" in failures


def test_tampered_posture_field_fails():
    bundle = build_posture_bundle(TRIFECTA, generated_at=GEN)
    # forge a clean posture over a trifecta design
    bundle["statement"]["predicate"]["lethalTrifecta"] = False
    bundle["statement"]["predicate"]["posture"] = "clean"
    ok, failures = verify_posture(bundle, TRIFECTA)
    assert not ok
    assert "predicate.lethalTrifecta" in failures


# -- signature --

def test_signed_round_trip():
    priv, pub = generate_keypair()
    bundle = build_posture_bundle(TRIFECTA, private_pem=priv, signer="Ada L", generated_at=GEN)
    assert bundle["envelope"] is not None
    ok, failures = verify_posture(bundle, TRIFECTA, public_pem=pub)
    assert ok, failures


def test_wrong_key_fails_signature():
    priv, _ = generate_keypair()
    _, other_pub = generate_keypair()
    bundle = build_posture_bundle(TRIFECTA, private_pem=priv, generated_at=GEN)
    ok, failures = verify_posture(bundle, TRIFECTA, public_pem=other_pub)
    assert not ok and "signature" in failures


def test_unsigned_bundle_degrades_gracefully():
    bundle = build_posture_bundle(TRIFECTA, generated_at=GEN)  # no key
    assert bundle["envelope"] is None
    # integrity/re-derivation still verifies with no crypto
    ok, _ = verify_posture(bundle, TRIFECTA)
    assert ok


# -- the capability-posture narrowing gate (--against) --

def test_posture_delta_detects_widening():
    narrow = _stmt(CLEAN)["predicate"]
    wide = _stmt(TRIFECTA)["predicate"]
    d = posture_delta(narrow, wide)
    assert d["widened"] is True
    assert {"network", "shell"} <= set(d["addedCapabilities"])
    assert d["trifectaFormed"] is True


def test_posture_delta_narrowing_is_safe():
    wide = _stmt(TRIFECTA)["predicate"]
    narrow = _stmt(CLEAN)["predicate"]
    d = posture_delta(wide, narrow)
    assert d["widened"] is False
    assert d["addedCapabilities"] == [] and d["trifectaFormed"] is False


def test_cli_fail_on_widen_exits_3(tmp_path):
    prior = tmp_path / "prior.json"
    CliRunner().invoke(main, ["posture", CLEAN, "-o", str(prior)])
    r = CliRunner().invoke(main, ["posture", TRIFECTA, "--against", str(prior),
                                  "--fail-on-widen", "-o", str(tmp_path / "cur.json")])
    assert r.exit_code == 3
    assert "WIDENED" in r.output


def test_cli_narrowing_passes(tmp_path):
    prior = tmp_path / "prior.json"
    CliRunner().invoke(main, ["posture", TRIFECTA, "-o", str(prior)])
    r = CliRunner().invoke(main, ["posture", CLEAN, "--against", str(prior),
                                  "--fail-on-widen", "-o", str(tmp_path / "cur.json")])
    assert r.exit_code == 0
    assert "NARROWING" in r.output


def test_cli_fail_on_widen_requires_against(tmp_path):
    r = CliRunner().invoke(main, ["posture", TRIFECTA, "--fail-on-widen",
                                  "-o", str(tmp_path / "x.json")])
    assert r.exit_code != 0 and "against" in r.output.lower()


# -- runtime verification: did the agent stay within the attested envelope --

def test_runtime_within_envelope_conforms():
    st = _stmt(CLEAN)  # envelope = {filesystem}
    ok, violations = verify_posture_runtime(st, [{"server": "docs", "capabilities": ["filesystem"]}])
    assert ok and violations == []


def test_runtime_out_of_envelope_violates():
    st = _stmt(CLEAN)
    ok, violations = verify_posture_runtime(
        st, [{"server": "docs", "capabilities": ["shell"]},
             {"server": "docs", "capabilities": ["network"]}])
    assert not ok
    assert {v["capability"] for v in violations} == {"shell", "network"}


def test_runtime_fail_closed_on_unknown_or_absent():
    st = _stmt(CLEAN)
    # a non-modeled token, an absent field, a bare string, and a non-list scalar
    # (which used to crash) all fail closed - never a false violation, never a raise
    assert verify_posture_runtime(st, [{"capabilities": ["process"]}])[0]
    assert verify_posture_runtime(st, [{"tool": "x"}])[0]
    assert verify_posture_runtime(st, [{"capabilities": 5}])[0]           # non-list scalar
    assert verify_posture_runtime(st, [{"capabilities": {"a": 1}}])[0]    # object
    # a bare string token IS normalized to one token and checked
    ok, v = verify_posture_runtime(st, [{"server": "d", "capabilities": "shell"}])
    assert not ok and v[0]["capability"] == "shell"


def test_cli_malformed_runtime_line_is_unverifiable_not_conforming(tmp_path):
    bundle = tmp_path / "p.json"
    CliRunner().invoke(main, ["posture", CLEAN, "-o", str(bundle)])
    events = tmp_path / "e.jsonl"
    events.write_text('{"server":"d","capabilities":["filesystem"]} not json\n')
    r = CliRunner().invoke(main, ["posture", CLEAN, "--verify", "--runtime",
                                  str(events), "-o", str(bundle)])
    assert r.exit_code == 1
    assert "UNVERIFIABLE" in r.output and "CONFORMS" not in r.output


def test_cli_verify_and_against_are_mutually_exclusive(tmp_path):
    bundle = tmp_path / "p.json"
    CliRunner().invoke(main, ["posture", CLEAN, "-o", str(bundle)])
    r = CliRunner().invoke(main, ["posture", CLEAN, "--verify", "--against",
                                  str(bundle), "-o", str(bundle)])
    assert r.exit_code != 0 and "one mode" in r.output.lower()


def test_cli_rolling_baseline_detects_widen_without_clobbering(tmp_path):
    base = tmp_path / "base.json"
    CliRunner().invoke(main, ["posture", CLEAN, "-o", str(base)])       # narrow baseline
    before = base.read_text()
    r = CliRunner().invoke(main, ["posture", TRIFECTA, "--against", str(base),
                                  "--fail-on-widen", "-o", str(base)])  # -o == --against
    assert r.exit_code == 3 and "WIDENED" in r.output
    assert base.read_text() == before  # the failing gate did not overwrite the baseline


def test_cli_against_non_posture_bundle_is_usage_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"foo": "bar"}')
    r = CliRunner().invoke(main, ["posture", CLEAN, "--against", str(bad),
                                  "-o", str(tmp_path / "x.json")])
    assert r.exit_code != 0 and "not a posture bundle" in r.output.lower()


def test_cli_runtime_violation_exits_1(tmp_path):
    bundle = tmp_path / "p.json"
    CliRunner().invoke(main, ["posture", CLEAN, "-o", str(bundle)])
    events = tmp_path / "e.jsonl"
    events.write_text('{"server":"docs","tool":"x","capabilities":["shell"]}\n')
    r = CliRunner().invoke(main, ["posture", CLEAN, "--verify", "--runtime",
                                  str(events), "-o", str(bundle)])
    assert r.exit_code == 1
    assert "VIOLATION" in r.output and "shell" in r.output


def test_cli_runtime_conforming_passes(tmp_path):
    bundle = tmp_path / "p.json"
    CliRunner().invoke(main, ["posture", CLEAN, "-o", str(bundle)])
    events = tmp_path / "e.jsonl"
    events.write_text('{"server":"docs","tool":"r","capabilities":["filesystem"]}\n')
    r = CliRunner().invoke(main, ["posture", CLEAN, "--verify", "--runtime",
                                  str(events), "-o", str(bundle)])
    assert r.exit_code == 0
    assert "runtime CONFORMS" in r.output


def test_cli_runtime_requires_verify(tmp_path):
    events = tmp_path / "e.jsonl"
    events.write_text('{"server":"docs","capabilities":["shell"]}\n')
    r = CliRunner().invoke(main, ["posture", CLEAN, "--runtime", str(events),
                                  "-o", str(tmp_path / "p.json")])
    assert r.exit_code != 0 and "verify" in r.output.lower()
