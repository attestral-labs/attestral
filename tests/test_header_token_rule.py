"""ATL-157: a remote MCP server whose headers block embeds a LITERAL auth
token (CWE-798). Env indirection (`${VAR}`/`$VAR`) and placeholders must never
fire, and the derivation must not regress the ATL-109 OAuth-awareness (commit
e1a8362): an authed endpoint stays cleared, an OAuth https endpoint stays quiet.
"""
import json
from pathlib import Path

import pytest

from attestral.ingest import build_model
from attestral.ingest.mcp import _literal_auth_header_value
from attestral.rules import RuleEngine
from _helpers import ids_for

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def _ids(root: str) -> set[str]:
    return {f.rule_id for f in RuleEngine().evaluate(build_model(root))}


def _remote(tmp_path: Path, headers: dict, url: str = "https://mcp.example.com/mcp") -> str:
    (tmp_path / "mcp.json").write_text(
        json.dumps({"mcpServers": {"remote": {"url": url, "headers": headers}}})
    )
    return str(tmp_path)


def test_fixture_fires_atl157_on_the_literal_server_only():
    model = build_model(str(EXAMPLES / "mcp-header-token"))
    findings = RuleEngine().evaluate(model)
    hits = [f for f in findings if f.rule_id == "ATL-157"]
    assert len(hits) == 1
    assert "crm-bridge" in hits[0].component_id
    srv = model.get("mcp_server.crm-bridge")
    assert srv.attr("_has_static_auth_header") is True
    assert srv.attr("_static_auth_header_keys") == ["Authorization"]
    assert model.get("mcp_server.issue-tracker").attr("_has_static_auth_header") is None


@pytest.mark.parametrize("headers", [
    {"Authorization": "Bearer ${SERVICE_TOKEN}"},   # ${VAR} indirection
    {"X-API-Key": "$TRACKER_KEY"},                  # $VAR indirection
    {"Authorization": "Bearer <your-token-here>"},  # placeholder
    {"Authorization": "Bearer REDACTED"},           # sanitized example
    {"Content-Type": "application/json"},           # not an auth header
])
def test_indirection_placeholders_and_plain_headers_do_not_fire(tmp_path, headers):
    assert "ATL-157" not in _ids(_remote(tmp_path, headers))


def test_literal_api_key_header_fires(tmp_path):
    assert "ATL-157" in _ids(_remote(tmp_path, {"X-API-Key": "ak-3fb1d02c99e44f7"}))


def test_helper_fails_closed_on_non_strings():
    assert _literal_auth_header_value(None) is False
    assert _literal_auth_header_value(42) is False
    assert _literal_auth_header_value("") is False
    assert _literal_auth_header_value("   ") is False


# --- ATL-109 OAuth-awareness regression (commit e1a8362) -------------------- #

def test_literal_header_still_counts_as_auth_for_atl109(tmp_path):
    # The header is a committed credential (ATL-157) but the endpoint IS
    # authenticated: the plaintext-remote rule must not also fire on https.
    ids = _ids(_remote(tmp_path, {"Authorization": "Bearer sk-live-1a2b3c4d"}))
    assert "ATL-157" in ids and "ATL-109" not in ids


def test_oauth_https_endpoint_with_no_headers_stays_quiet(tmp_path):
    # Spec-compliant OAuth remote: no static credential in config, no finding.
    (tmp_path / "mcp.json").write_text(
        json.dumps({"mcpServers": {"hosted": {"url": "https://mcp.hosted.example/mcp"}}})
    )
    ids = _ids(str(tmp_path))
    assert "ATL-157" not in ids and "ATL-109" not in ids


def test_benign_authed_remote_corpus_stays_clean():
    # The benchmark's benign case uses ${GITHUB_MCP_TOKEN} indirection; the new
    # rule must keep it at zero findings.
    assert "ATL-157" not in ids_for(ROOT / "evaluation" / "corpus" / "benign-authed-remote")
