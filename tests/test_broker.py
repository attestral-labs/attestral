"""`attestral broker`: strip a standing credential, generate the JIT broker.

The active-governor half of the credential rules - detection becomes a generated
CB4A Model A broker route that mints a per-call, provider-scoped token, so the
agent process holds no reusable key.
"""
import yaml
from click.testing import CliRunner

from attestral.broker import (
    broker_plans,
    render_broker_config,
    render_broker_plan,
)
from attestral.cli import main
from attestral.ingest import build_model
from attestral.ingest.mcp import ingest_mcp
from attestral.model import SystemModel


def _model(cfg_json: str, tmp_path) -> SystemModel:
    p = tmp_path / "mcp.json"
    p.write_text(cfg_json)
    return ingest_mcp(p, SystemModel())


def test_plan_strips_the_secret_env_keys_and_scopes_to_providers():
    # vulnerable-agent's jira server holds three provider credentials at once.
    model = build_model("examples/vulnerable-agent")
    plans = broker_plans(model)
    jira = next(p for p in plans if p.name == "jira")
    assert set(jira.stripped) == {"JIRA_API_TOKEN", "OPENAI_API_KEY", "SLACK_BOT_TOKEN"}
    assert set(jira.providers) == {"atlassian", "openai", "slack"}


def test_generated_config_is_a_default_deny_broker_never_inlining_a_secret(tmp_path):
    model = _model(
        '{"mcpServers": {"crm": {"command": "npx", "args": ["crm-mcp"], '
        '"env": {"SALESFORCE_TOKEN": "sf-live-abc123", "STRIPE_SECRET_KEY": "sk_live_xyz"}}}}',
        tmp_path,
    )
    plans = broker_plans(model)
    cfg = render_broker_config(plans)
    # the standing secret VALUES never appear - the broker references, never inlines
    assert "sf-live-abc123" not in cfg and "sk_live_xyz" not in cfg
    doc = yaml.safe_load(cfg)
    route = doc["binds"][0]["listeners"][0]["routes"][0]
    assert route["name"] == "crm"
    assert route["policies"]["jwtAuth"]["mode"] == "strict"          # default-deny front door
    ex = route["backends"][0]["backendAuth"]["oauthTokenExchange"]
    assert "secretRef" in ex["clientAuth"] and "clientSecret" not in ex["clientAuth"]
    assert "provider:salesforce" in ex["scope"] and "provider:stripe" in ex["scope"]


def test_concentration_server_is_flagged_and_sorted_first(tmp_path):
    model = _model(
        '{"mcpServers": {'
        '"gw": {"command": "npx", "args": ["gw"], "env": {'
        '"OPENAI_API_KEY": "x", "ANTHROPIC_API_KEY": "x", "AWS_SECRET_ACCESS_KEY": "x", '
        '"GITHUB_TOKEN": "x", "SLACK_BOT_TOKEN": "x"}},'
        '"lite": {"command": "npx", "args": ["lite"], "env": {"NOTION_TOKEN": "x"}}}}',
        tmp_path,
    )
    plans = broker_plans(model)
    assert plans[0].name == "gw" and plans[0].concentration      # widest blast first
    out = render_broker_plan(model, color=False)
    assert "concentration" in out
    assert "OPENAI_API_KEY" in out and "AWS_SECRET_ACCESS_KEY" in out


def test_no_secrets_reports_nothing_to_broker(tmp_path):
    model = _model(
        '{"mcpServers": {"notes": {"command": "npx", "args": ["fs", "/srv/notes"]}}}',
        tmp_path,
    )
    assert broker_plans(model) == []
    assert "No standing credentials" in render_broker_plan(model, color=False)


def test_cli_broker_prints_plan_and_writes_only_with_output(tmp_path):
    r = CliRunner().invoke(main, ["broker", "examples/vulnerable-agent"])
    assert r.exit_code == 0, r.output
    assert "Credential-broker remediation" in r.output
    assert "strip:" in r.output

    out = tmp_path / "gw.yaml"
    r2 = CliRunner().invoke(main, ["broker", "examples/vulnerable-agent", "-o", str(out)])
    assert r2.exit_code == 0
    assert out.exists()
    assert "credential-broker config" in r2.output


def test_cli_broker_writes_nothing_without_output(tmp_path):
    # Terminal-first: the plan prints, no file appears.
    before = set(tmp_path.iterdir())
    r = CliRunner().invoke(main, ["broker", "examples/vulnerable-agent"])
    assert r.exit_code == 0
    assert set(tmp_path.iterdir()) == before
