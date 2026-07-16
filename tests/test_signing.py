"""Signed evidence chain: the hash chain is tamper-evident; the signature makes
it authentic, so a recomputed (integrity-valid) forgery is still caught."""
import hashlib
import json

import pytest
from click.testing import CliRunner

pytest.importorskip("cryptography")  # signing is the optional attestral[sign] extra

from attestral.cli import main  # noqa: E402
from attestral.signing import (  # noqa: E402
    envelope_head,
    generate_keypair,
    public_key_of,
    sign_head,
    verify_envelope,
)


def test_sign_and_verify_roundtrip():
    priv, pub = generate_keypair()
    env = sign_head("abc123", 5, "demo", priv, signer="Ada")
    assert verify_envelope(env, pub)
    assert envelope_head(env) == "abc123"


def test_wrong_key_does_not_verify():
    priv, _ = generate_keypair()
    _, other_pub = generate_keypair()
    env = sign_head("abc123", 5, "demo", priv)
    assert not verify_envelope(env, other_pub)


def test_tampered_payload_does_not_verify():
    priv, pub = generate_keypair()
    env = sign_head("abc123", 5, "demo", priv)
    env["payload"] = env["payload"][:-4] + "AAAA"   # flip the signed payload
    assert not verify_envelope(env, pub)


def test_public_key_of_matches_generated():
    priv, pub = generate_keypair()
    assert public_key_of(priv).strip() == pub.strip()


# --- end-to-end through the CLI --------------------------------------------

def _signed_report(tmp_path):
    runner = CliRunner()
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"ops": {"command": "bash", "args": ["-c", "x"]}}}')
    runner.invoke(main, ["sign", "--gen-key", str(tmp_path / "k")])
    runner.invoke(main, ["scan", str(tmp_path), "-o", str(tmp_path / "rev"), "--format", "json"])
    r = runner.invoke(main, ["sign", str(tmp_path / "rev.json"),
                             "--key", str(tmp_path / "k.key"), "--signer", "Ada"])
    assert r.exit_code == 0, r.output
    return runner, tmp_path / "rev.json", tmp_path / "k.pub"


def test_cli_sign_then_verify_authentic(tmp_path):
    runner, report, pub = _signed_report(tmp_path)
    r = runner.invoke(main, ["verify", str(report), "--public-key", str(pub)])
    assert r.exit_code == 0
    assert "signature VALID" in r.output


def test_cli_recomputed_chain_fails_authenticity(tmp_path):
    # The attack the plain hash chain could not catch: edit a finding AND
    # recompute the whole chain so integrity passes. The signature still fails.
    runner, report, pub = _signed_report(tmp_path)
    data = json.loads(report.read_text())
    data["chain"][0]["finding"]["severity"] = "low"
    prev = "0" * 64
    for e in data["chain"]:
        h = hashlib.sha256((prev + json.dumps(e["finding"], sort_keys=True)).encode()).hexdigest()
        e["hash"], e["prev"], prev = h, prev, h
    report.write_text(json.dumps(data))
    r = runner.invoke(main, ["verify", str(report), "--public-key", str(pub)])
    assert r.exit_code == 1
    assert "chain VALID" in r.output            # integrity passes (recomputed)
    assert "signature INVALID" in r.output      # authenticity catches it
    assert "different chain head" in r.output


def test_cli_sign_refuses_a_tampered_chain(tmp_path):
    runner, report, pub = _signed_report(tmp_path)
    data = json.loads(report.read_text())
    data["chain"][0]["finding"]["severity"] = "low"   # break integrity, don't recompute
    report.write_text(json.dumps(data))
    r = runner.invoke(main, ["sign", str(report), "--key", str(tmp_path / "k.key")])
    assert r.exit_code == 1 and "refusing to sign" in r.output
