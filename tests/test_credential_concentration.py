"""ATL-164: one MCP server holding standing credentials for many providers is
the LiteLLM-class credential-concentration blast radius (CB4A TM-1). The rule
keys on the number of DISTINCT providers, not on any single secret, so it is
high-signal and stays out of ATL-104's lane."""
import json
from pathlib import Path

from attestral.ingest import build_model
from attestral.ingest.mcp import _credential_provider_families
from _helpers import ids_for

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _write(tmp_path: Path, servers: dict) -> str:
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": servers}))
    return str(tmp_path)


def test_multi_provider_gateway_fires_atl_164():
    assert "ATL-164" in ids_for(str(EXAMPLES / "credential-concentration"))


def test_single_provider_server_does_not_fire(tmp_path):
    # One provider is a normal server, not a concentration target.
    ids = ids_for(_write(tmp_path, {
        "notes": {"command": "npx", "args": ["-y", "@notion/mcp@1.0.0"],
                  "env": {"NOTION_API_KEY": "${NOTION_API_KEY}"}},
    }))
    assert "ATL-164" not in ids


def test_three_providers_are_below_the_threshold(tmp_path):
    # The threshold is 4: a 2-3 service agent is common and benign, so flagging
    # it would be noise. Concentration is the aggregator/gateway shape (4+).
    ids = ids_for(_write(tmp_path, {
        "agent": {"command": "npx", "args": ["-y", "agent@1.0.0"],
                  "env": {"OPENAI_API_KEY": "${OPENAI_API_KEY}",
                          "GITHUB_TOKEN": "${GITHUB_TOKEN}",
                          "SLACK_BOT_TOKEN": "${SLACK_BOT_TOKEN}"}},
    }))
    assert "ATL-164" not in ids


def test_four_providers_cross_the_threshold(tmp_path):
    ids = ids_for(_write(tmp_path, {
        "gw": {"command": "npx", "args": ["-y", "gw@1.0.0"],
               "env": {"OPENAI_API_KEY": "${OPENAI_API_KEY}",
                       "ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}",
                       "GEMINI_API_KEY": "${GEMINI_API_KEY}",
                       "GROQ_API_KEY": "${GROQ_API_KEY}"}},
    }))
    assert "ATL-164" in ids


def test_non_secret_provider_vars_do_not_inflate_the_count():
    # Config values (base URLs, org ids) carry a provider marker but are not
    # secret-shaped, so they never count toward concentration.
    fams = _credential_provider_families(
        ["OPENAI_BASE_URL", "OPENAI_ORG_ID", "ANTHROPIC_LOG_LEVEL"]
    )
    assert fams == []


def test_many_keys_for_one_provider_count_once():
    # Two AWS keys are one blast surface, not two - concentration counts
    # distinct providers, not env vars.
    fams = _credential_provider_families(
        ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]
    )
    assert fams == ["aws"]


def test_provider_families_are_the_distinct_vendors():
    fams = _credential_provider_families([
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
        "AWS_SECRET_ACCESS_KEY", "GROQ_API_KEY",
    ])
    assert set(fams) == {"openai", "anthropic", "google-ai", "aws", "groq"}


def test_the_concentration_attribute_is_set_on_the_component():
    model = build_model(str(EXAMPLES / "credential-concentration"))
    gateway = next(s for s in model.by_type("mcp_server") if s.name == "llm-gateway")
    assert gateway.attr("_credential_concentration") is True
    assert len(gateway.attr("_credential_providers")) >= 3
