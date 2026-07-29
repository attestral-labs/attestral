"""Optional Sigstore Rekor anchoring for a signed attestation.

The transport is injected, so the build -> submit -> parse -> verify path is
exercised with no network. Every honest boundary is pinned: a mismatched
attestation does not verify, an unsigned one is refused, and the receipt binds
the exact envelope it was produced for.
"""
import json

import pytest

from attestral.rekor import (
    DEFAULT_REKOR,
    anchor,
    dsse_proposed_entry,
    envelope_payload_sha256,
    receipt_line,
    verify_receipt,
)
from attestral.signing import generate_keypair, public_key_of, sign_statement

_STMT = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "review"}]}


def _signed_env(priv):
    return sign_statement(_STMT, priv, signer="reviewer")


def _fake_rekor(expect_kind="dsse"):
    """A poster that mimics Rekor's UUID-keyed response, and asserts the request."""
    seen = {}

    def poster(url, body):
        seen["url"] = url
        seen["body"] = body
        assert body["kind"] == expect_kind
        return {"a1b2c3": {
            "body": "ZmFrZS1ib2R5",
            "logIndex": 987654,
            "logID": "c0ffee",
            "integratedTime": 1785000000,
            "verification": {
                "inclusionProof": {"logIndex": 987654, "rootHash": "aa", "treeSize": 10 ** 6,
                                   "hashes": ["bb", "cc"]},
                "signedEntryTimestamp": "c2lnbmVk",
            },
        }}

    poster.seen = seen
    return poster


def test_proposed_entry_is_a_rekor_dsse_entry():
    priv, pub = generate_keypair()
    entry = dsse_proposed_entry(_signed_env(priv), pub)
    assert entry["kind"] == "dsse" and entry["apiVersion"] == "0.0.1"
    content = entry["spec"]["proposedContent"]
    assert "envelope" in content and content["verifiers"]        # envelope + verifier key
    assert json.loads(content["envelope"])["signatures"]         # the signed envelope


def test_anchor_returns_a_bound_receipt():
    priv, _ = generate_keypair()
    env = _signed_env(priv)
    poster = _fake_rekor()
    r = anchor(env, public_key_of(priv), poster=poster)
    assert r["uuid"] == "a1b2c3"
    assert r["log_index"] == 987654
    assert r["entry_url"].endswith("/api/v1/log/entries/a1b2c3")
    assert r["payload_sha256"] == envelope_payload_sha256(env)
    assert poster.seen["url"] == DEFAULT_REKOR + "/api/v1/log/entries"


def test_verify_receipt_accepts_its_own_attestation():
    priv, _ = generate_keypair()
    env = _signed_env(priv)
    r = anchor(env, public_key_of(priv), poster=_fake_rekor())
    ok, notes = verify_receipt(r, env)
    assert ok
    assert "rekor-cli verify" in notes[-1]   # points to full independent verification


def test_verify_receipt_rejects_a_different_attestation():
    priv, _ = generate_keypair()
    r = anchor(_signed_env(priv), public_key_of(priv), poster=_fake_rekor())
    other = sign_statement({"_type": "x", "subject": [{"name": "OTHER"}]}, priv)
    ok, notes = verify_receipt(r, other)
    assert not ok
    assert "does not bind this attestation" in notes[0]


def test_verify_receipt_rejects_an_incomplete_receipt():
    priv, _ = generate_keypair()
    env = _signed_env(priv)
    r = anchor(env, public_key_of(priv), poster=_fake_rekor())
    r.pop("inclusion_proof")
    ok, notes = verify_receipt(r, env)
    assert not ok


def test_anchor_refuses_an_unsigned_attestation():
    priv, pub = generate_keypair()
    unsigned = {"statement": _STMT, "envelope": None}["envelope"] or {}
    with pytest.raises(ValueError, match="signed attestation"):
        anchor(unsigned, pub, poster=_fake_rekor())


def test_a_signed_chain_head_envelope_is_anchorable():
    # `attestral sign` produces a DSSE envelope over the chain head, a different
    # payload than the attestation but the same envelope shape, so `sign --rekor`
    # anchors it through the same path.
    from attestral.signing import sign_head
    priv, _ = generate_keypair()
    env = sign_head("abc123head", 3, "demo-target", priv, signer="me")
    r = anchor(env, public_key_of(priv), poster=_fake_rekor())
    ok, _ = verify_receipt(r, env)
    assert ok


def test_receipt_line_is_a_one_line_summary():
    priv, _ = generate_keypair()
    r = anchor(_signed_env(priv), public_key_of(priv), poster=_fake_rekor())
    line = receipt_line(r)
    assert "Rekor" in line and "987654" in line and "\n" not in line


def test_cli_rekor_without_a_key_fails_gracefully(tmp_path):
    # No key -> no signature -> nothing to anchor. Must fail with a clear message
    # and never touch the network.
    from click.testing import CliRunner

    from attestral.cli import main
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"x": {"command": "uvx", "args": ["y"]}}}')
    out = tmp_path / "att.json"
    r = CliRunner().invoke(main, ["attest", str(tmp_path), "-o", str(out), "--rekor"])
    assert r.exit_code == 1
    assert "needs a signed attestation" in r.output
