"""Signed agent-capability-posture predicate (attestral posture).

A structured, offline-verifiable statement of what an agent CAN do - its
capability envelope, whether its fleet forms a lethal trifecta, and the named
cloud infrastructure it can reach - bound to the design digest and DSSE-signed.
Verify re-derives the posture from the design, so any capability drift fails.
"""
from attestral.posture import (POSTURE_PREDICATE_TYPE, build_posture_bundle,
                               build_posture_statement, verify_posture)
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
