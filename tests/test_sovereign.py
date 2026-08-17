"""Sovereign mode: the egress guard, the no-egress attestation, and the CLI wiring.

Sovereign mode is the compliance wedge for data-residency markets: the scan runs
fully local, an armed guard stops any outbound connection at the socket, and a
self-verifying attestation rides the evidence chain. These tests pin all three:
the guard actually blocks (and only external hosts), the attestation is
tamper-evident, and `scan --sovereign` refuses the online layers and emits a
receipt that `verify` can check.
"""
from __future__ import annotations

import json
import socket

import pytest
from click.testing import CliRunner

from attestral.cli import main
from attestral.evidence import (
    GENESIS,
    EgressBlocked,
    EgressGuard,
    no_egress_attestation,
    verify_attestation,
)

# A fetch server (egress/untrusted content) plus a shell server (code exec): a
# real design that produces findings, so the sealed chain head is non-trivial.
CHAIN_MCP = json.dumps({
    "mcpServers": {
        "web": {"command": "uvx", "args": ["mcp-server-fetch"]},
        "ops": {"command": "bash", "args": ["-c", "mcp-shell-server --serve"]},
    }
})


def _repo(tmp_path) -> str:
    (tmp_path / ".mcp.json").write_text(CHAIN_MCP)
    return str(tmp_path)


# --- the egress guard --------------------------------------------------------

def test_guard_blocks_external_and_records_it():
    with EgressGuard() as g:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with pytest.raises(EgressBlocked):
            s.connect(("93.184.216.34", 80))  # never actually dials - blocked first
        s.close()
    assert g.blocked and g.blocked[0] == ("93.184.216.34", 80)


def test_guard_allows_loopback():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()
    try:
        with EgressGuard() as g:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2)
            client.connect((host, port))  # loopback: allowed
            conn, _ = srv.accept()
            conn.close()
            client.close()
        assert g.blocked == []  # nothing local was recorded as blocked
    finally:
        srv.close()


def test_guard_restores_and_is_idempotent():
    orig = socket.socket.connect
    g = EgressGuard()
    g.arm()
    g.arm()  # idempotent
    assert socket.socket.connect is not orig
    g.disarm()
    g.disarm()  # idempotent
    assert socket.socket.connect is orig


# --- the attestation ---------------------------------------------------------

def test_attestation_self_verifies_and_detects_tamper():
    att = no_egress_attestation(
        target="repo", components=3, findings=[], ml_tier="heuristic",
        blocked=[], chain_head="ab" * 32, generated="2026-01-01 00:00 UTC",
    )
    assert att["clean"] is True
    assert verify_attestation(att)

    tampered = dict(att)
    tampered["clean"] = False  # flip a field without re-hashing
    assert not verify_attestation(tampered)


def test_attestation_records_blocked_attempts():
    att = no_egress_attestation(
        target="repo", components=1, findings=[], ml_tier="heuristic",
        blocked=[("8.8.8.8", 53)], chain_head=GENESIS, generated="g",
    )
    assert att["clean"] is False
    assert att["blocked_attempts"] == ["8.8.8.8:53"]
    assert verify_attestation(att)  # a blocked attempt is recorded, not hidden


# --- CLI wiring --------------------------------------------------------------

@pytest.mark.parametrize("flag", [["--llm"], ["--judge"], ["--ml"]])
def test_sovereign_refuses_online_layers(tmp_path, flag):
    r = CliRunner().invoke(main, ["scan", _repo(tmp_path), "--sovereign", *flag])
    assert r.exit_code != 0
    assert "sovereign mode" in r.output.lower()


def test_sovereign_emits_verifiable_attestation(tmp_path):
    runner = CliRunner()
    repo = _repo(tmp_path)
    r = runner.invoke(main, ["scan", repo, "--sovereign", "-o",
                             str(tmp_path / "rep"), "--format", "json"])
    assert r.exit_code == 0, r.output
    assert "no-egress attestation" in r.output

    data = json.loads((tmp_path / "rep.json").read_text())
    att = data["attestation"]
    assert att["clean"] is True and att["layers"]["ml_tier"] == "heuristic"
    assert verify_attestation(att)
    head = data["chain"][-1]["hash"] if data["chain"] else GENESIS
    assert att["chain_head"] == head

    v = runner.invoke(main, ["verify", str(tmp_path / "rep.json")])
    assert v.exit_code == 0, v.output
    assert "no-egress attestation VALID" in v.output


def test_verify_catches_tampered_attestation(tmp_path):
    runner = CliRunner()
    r = runner.invoke(main, ["scan", _repo(tmp_path), "--sovereign", "-o",
                             str(tmp_path / "rep"), "--format", "json"])
    assert r.exit_code == 0, r.output

    report = tmp_path / "rep.json"
    data = json.loads(report.read_text())
    data["attestation"]["clean"] = False  # tamper after sealing
    report.write_text(json.dumps(data))

    v = runner.invoke(main, ["verify", str(report)])
    assert v.exit_code == 1
    assert "attestation INVALID" in v.output
