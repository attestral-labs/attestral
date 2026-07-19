"""Cedar compile target: golden output plus the round-trip decision invariant.

The load-bearing test is the round-trip: for every server in the neutral policy
dict, an allowed server compiles to exactly one ``permit`` and a denied server to
exactly one ``forbid``. That equality is what lets us claim the Cedar decision
matches the mcp-guard decision. The rest guard well-formedness and string safety.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from attestral.compile import (
    TARGETS,
    _cedar_str,
    compile_policy,
    render_cedar,
    render_policy_yaml,
)
from attestral.ingest import build_model
from attestral.rules import RuleEngine

FIXTURE = "examples/compile_cedar"
GOLDEN = Path(__file__).parent / "golden" / "attested-policy.cedar"
_GENERATED_AT = re.compile(r"// generated_at: .*")


def _policy():
    model = build_model(FIXTURE)
    findings = RuleEngine().evaluate(model)
    return compile_policy(model, findings, chain_head="abc123def456")


def _scrub(text: str) -> str:
    return _GENERATED_AT.sub("// generated_at: <SCRUBBED>", text)


def test_matches_golden():
    # generated_at is the only non-deterministic field; model_hash is stable for
    # a fixed fixture, so the rest of the output must be byte-for-byte the golden.
    got = _scrub(render_cedar(_policy()))
    assert got == GOLDEN.read_text()


def test_header_shape():
    out = render_cedar(_policy())
    assert out.startswith("// Cedar authorization policy")
    assert "// model_hash:" in out and "chain_head: abc123def456" in out
    assert "implicit deny" in out


def test_round_trip_decision_invariant():
    # The gate: Cedar decision == mcp-guard decision, per server.
    policy = _policy()
    out = render_cedar(policy)
    servers = policy["servers"]
    allowed = {n for n, e in servers.items() if e["allow"]}
    denied = {n for n, e in servers.items() if not e["allow"]}

    assert out.count("permit (") == len(allowed)
    assert out.count("forbid (") == len(denied)

    for name, entry in servers.items():
        principal = f'MCPServer::"{name}"'
        # Each server named exactly once, under the right effect.
        assert out.count(principal) == 1, f"{name} appears more than once"
        block = _block_for(out, principal)
        if entry["allow"]:
            assert block.startswith("permit ("), f"{name} allowed but not a permit"
        else:
            assert block.startswith("forbid ("), f"{name} denied but not a forbid"


def _block_for(out: str, principal: str) -> str:
    """Return the permit/forbid statement (from keyword to ';') naming principal."""
    idx = out.index(principal)
    start = max(out.rfind("permit (", 0, idx), out.rfind("forbid (", 0, idx))
    end = out.index(";", idx)
    return out[start:end + 1]


def test_denied_reason_is_a_comment_above_forbid():
    policy = _policy()
    out = render_cedar(policy)
    lines = out.splitlines()
    for name, entry in policy["servers"].items():
        if entry["allow"]:
            continue
        reason = entry["reason"]
        # The reason line must appear as a // comment, and a forbid naming this
        # server must follow it before the next blank-separated block.
        assert f"// {reason}" in lines
        cidx = lines.index(f"// {reason}")
        tail = "\n".join(lines[cidx:])
        assert f'forbid (\n  principal == MCPServer::"{name}"' in tail


def test_well_formed():
    out = render_cedar(_policy())
    # No block comments in Cedar; comments are // line-only.
    assert "/*" not in out and "*/" not in out
    # Balanced delimiters.
    assert out.count("(") == out.count(")")
    assert out.count("{") == out.count("}")
    assert out.count("[") == out.count("]")

    for block in _statements(out):
        assert block.rstrip().endswith(";"), f"statement missing ';':\n{block}"
        assert "principal" in block
        assert "action" in block
        assert "resource" in block

    # No unescaped quote inside a MCPServer entity id.
    for m in re.finditer(r'MCPServer::"((?:\\.|[^"\\])*)"', out):
        pass  # the regex only matches a properly-terminated, escaped literal
    # Every entity-id literal is well terminated: count of MCPServer::" equals
    # the count the escaped-literal regex can parse.
    assert out.count('MCPServer::"') == len(
        re.findall(r'MCPServer::"(?:\\.|[^"\\])*"', out)
    )

    # Annotation keys are snake_case identifiers.
    for key in re.findall(r"@(\w[\w]*)\(", out):
        assert re.fullmatch(r"[a-z][a-z0-9_]*", key), f"bad annotation key: {key}"


def _statements(out: str) -> list[str]:
    """The permit/forbid statements, ignoring the leading comment header."""
    body = out.split("\n\n", 1)[1] if "\n\n" in out else out
    blocks = [b for b in body.split("\n\n") if b.strip()]
    # Strip leading // comment lines from each block so the tail is the statement.
    stmts = []
    for b in blocks:
        stmt = "\n".join(
            ln for ln in b.splitlines() if not ln.lstrip().startswith("//")
        )
        stmts.append(stmt)
    return stmts


def test_string_safety_escapes_quotes_and_backslashes():
    assert _cedar_str('a"b') == 'a\\"b'
    assert _cedar_str("a\\b") == "a\\\\b"
    assert _cedar_str("a\nb\tc") == "a\\nb\\tc"

    # A synthetic policy with a hostile server name must still render a block
    # that survives the well-formedness lint (balanced, escaped, terminated).
    policy = {
        "metadata": {"model_hash": "0" * 64, "review_chain_head": "", "generated_at": "-"},
        "budgets": {"loop_repeat_threshold": 5, "max_calls_per_server": 100},
        "servers": {
            'ev"il\\one': {"allow": True, "constraints": {}, "attested_source": "src"},
        },
    }
    out = render_cedar(policy)
    assert 'MCPServer::"ev\\"il\\\\one"' in out
    assert out.count("(") == out.count(")")
    assert out.count('MCPServer::"') == len(
        re.findall(r'MCPServer::"(?:\\.|[^"\\])*"', out)
    )


def test_registry_wires_both_targets():
    assert TARGETS["mcp-guard"] == (render_policy_yaml, "mcp-guard-policy.yaml")
    assert TARGETS["cedar"] == (render_cedar, "attested-policy.cedar")


def test_cedar_cli_parse_if_available(tmp_path):
    # Optional: shell out to the real cedar CLI when present, skip otherwise -
    # a missing external tool is never an error (mirrors the ML-extra pattern).
    cedar = shutil.which("cedar")
    if not cedar:
        pytest.skip("cedar CLI not installed; skipping standalone parse check")
    policy_file = tmp_path / "policy.cedar"
    policy_file.write_text(render_cedar(_policy()))
    result = subprocess.run(
        [cedar, "check-parse", "--policies", str(policy_file)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
