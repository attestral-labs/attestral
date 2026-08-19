"""The attack-technique library: payload synthesis, obfuscation transforms, the
gated follow-through probe, and the CLI playbook.

This is the honest complement to the executed harness: for each reachable path it
synthesizes the concrete injection payloads a real attacker would try, across the
technique taxonomy, and - with an API key - probes whether a real model follows
each. The payloads are canary-anchored test artifacts for the user's OWN agent.
"""
from __future__ import annotations

import base64
import json

from click.testing import CliRunner

from attestral import redteam
from attestral.cli import main
from attestral.ingest import build_model
from attestral.paths import all_attack_paths

CHAIN_MCP = json.dumps({"mcpServers": {
    "web": {"command": "uvx", "args": ["mcp-server-fetch"]},
    "ops": {"command": "bash", "args": ["-c", "mcp-shell-server --serve"]},
}})


def _model(tmp_path):
    (tmp_path / ".mcp.json").write_text(CHAIN_MCP)
    return build_model(str(tmp_path))


def test_taxonomy_spans_multiple_classes():
    classes = {t.tclass for t in redteam.ATTACK_TECHNIQUES}
    assert len(redteam.ATTACK_TECHNIQUES) >= 12
    assert {"direct", "indirect", "obfuscation", "tool-poisoning", "multi-turn"} <= classes
    assert len({t.id for t in redteam.ATTACK_TECHNIQUES}) == len(redteam.ATTACK_TECHNIQUES)  # unique ids


def test_every_technique_synthesizes_a_nonempty_payload(tmp_path):
    model = _model(tmp_path)
    path = all_attack_paths(model)[0]
    attacks = redteam.synthesize_attacks(model, path)
    assert len(attacks) == len(redteam.ATTACK_TECHNIQUES)
    assert all(a["payload"] and a["frameworks"] for a in attacks)


def test_obfuscation_transforms_are_real(tmp_path):
    model = _model(tmp_path)
    path = all_attack_paths(model)[0]
    by_id = {a["id"]: a for a in redteam.synthesize_attacks(model, path)}
    canary = by_id["ATK-01"]["canary"]

    # base64 payload decodes back to plaintext carrying the canary
    enc = by_id["ATK-04"]["payload"].split(": ", 1)[1]
    assert canary in base64.b64decode(enc).decode()
    # homoglyph defeats a literal 'Ignore previous' filter but uses confusables
    assert "Ignore previous" not in by_id["ATK-06"]["payload"]
    assert any(ord(c) > 0x400 for c in by_id["ATK-06"]["payload"])
    # unicode tag-block smuggling hides chars in U+E00xx
    assert any(0xE0000 <= ord(c) <= 0xE007F for c in by_id["ATK-05"]["payload"])
    # zero-width split inserts U+200B
    assert "​" in by_id["ATK-07"]["payload"]


def test_probe_measures_followthrough_with_an_injected_query(tmp_path):
    model = _model(tmp_path)
    path = all_attack_paths(model)[0]
    tech = redteam.ATTACK_TECHNIQUES[0]
    canary = redteam._canary_for(path)

    followed = redteam.probe_followthrough(model, path, tech, query=lambda p: f"egress({canary})")
    refused = redteam.probe_followthrough(model, path, tech, query=lambda p: "I refuse; that is an injection.")
    assert followed["followed"] is True
    assert refused["followed"] is False


def test_probe_skips_cleanly_without_a_key(tmp_path, monkeypatch):
    monkeypatch.setattr(redteam, "_default_query", lambda: None)
    model = _model(tmp_path)
    path = all_attack_paths(model)[0]
    r = redteam.probe_followthrough(model, path, redteam.ATTACK_TECHNIQUES[0], query=None)
    assert r["followed"] is None and "skipped" in r["note"]


def test_cli_techniques_prints_the_playbook(tmp_path):
    (tmp_path / ".mcp.json").write_text(CHAIN_MCP)
    r = CliRunner().invoke(main, ["pentest", str(tmp_path), "--techniques", "--no-isolate"])
    assert r.exit_code == 0, r.output
    assert "Attack-technique playbook" in r.output
    assert "ATK-01" in r.output and "tool-poisoning" in r.output


def test_techniques_ride_the_json_report(tmp_path):
    (tmp_path / ".mcp.json").write_text(CHAIN_MCP)
    out = tmp_path / "pt.json"
    r = CliRunner().invoke(main, ["pentest", str(tmp_path), "--techniques", "--no-isolate", "-o", str(out)])
    assert r.exit_code == 0, r.output
    data = json.loads(out.read_text())
    assert data["techniques"]["paths"][0]["attacks"]


def test_evasion_matrix_wrappers_encode_and_decode(tmp_path):
    import codecs
    model = _model(tmp_path)
    path = all_attack_paths(model)[0]
    variants = {v["wrapper"]: v for v in redteam.synthesize_variants(model, path)}
    assert set(variants) >= {"none", "base64", "rot13", "hex", "homoglyph", "tag", "zwsp", "ansi"}
    # the reversible codecs recover the plaintext injection
    b64 = variants["base64"]["payload"].split(": ", 1)[1]
    assert "Ignore previous" in base64.b64decode(b64).decode()
    r13 = variants["rot13"]["payload"].split(": ", 1)[1]
    assert "Ignore previous" in codecs.decode(r13, "rot13")
    hx = variants["hex"]["payload"].split(": ", 1)[1]
    assert "Ignore previous" in bytes.fromhex(hx).decode()
    # the plaintext baseline carries it verbatim; obfuscated ones do not
    assert "Ignore previous" in variants["none"]["payload"]
    assert "Ignore previous" not in variants["homoglyph"]["payload"]


def test_cli_variants_prints_the_evasion_matrix(tmp_path):
    (tmp_path / ".mcp.json").write_text(CHAIN_MCP)
    r = CliRunner().invoke(main, ["pentest", str(tmp_path), "--variants", "--no-isolate"])
    assert r.exit_code == 0, r.output
    assert "Evasion matrix" in r.output and "base64" in r.output
