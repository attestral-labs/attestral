"""P2 v2: the broker-backed fix - a standing-credential finding compiles to the
exact env keys to strip plus the CB4A route that replaces them, and the
verification is real: the model copy has the keys removed, its credential
attributes re-derived through the ingester's own classifiers, and the rule
engine confirms the finding no longer fires.
"""
import yaml
from click.testing import CliRunner

from attestral.broker import (
    BROKER_FIX_RULES,
    plan_for,
    strip_standing_credentials,
)
from attestral.cli import main
from attestral.fix import broker_plans_for, fix_for_finding, fixes_for, render_fixes
from attestral.ingest import build_model
from attestral.ingest.mcp import ingest_mcp
from attestral.model import Finding, Severity, SystemModel
from attestral.rules import RuleEngine

FIXTURE = "examples/vulnerable-agent"


def _model_findings(fixture=FIXTURE):
    model = build_model(fixture)
    return model, RuleEngine().evaluate(model)


def _finding(findings, rule_id):
    return next(f for f in findings if f.rule_id == rule_id)


def _mcp_model(cfg_json: str, tmp_path) -> SystemModel:
    p = tmp_path / "mcp.json"
    p.write_text(cfg_json)
    return ingest_mcp(p, SystemModel())


def test_env_secret_finding_compiles_to_a_broker_backed_fix():
    model, findings = _model_findings()
    fx = fix_for_finding(model, _finding(findings, "ATL-104"), chain_head="abc")
    assert fx.strip_env == ["JIRA_API_TOKEN", "OPENAI_API_KEY", "SLACK_BOT_TOKEN"]
    assert fx.broker_plan is not None and fx.broker_plan.name == "jira"
    assert fx.verification == "re-synthesized"
    assert fx.verified          # proven: ATL-104 no longer fires once stripped
    # the mcp-guard slice keeps the proxy backstop
    assert fx.control["servers"]["jira"]["constraints"]["forbid_env_secrets"] is True


def test_strip_verification_rederives_not_hand_clears():
    # The stripped copy must re-derive every env-derived credential attribute,
    # so ALL standing-credential rules stop firing on that server - not just the
    # one being fixed - while the rest of the model is untouched.
    model, findings = _model_findings()
    before = {f.rule_id for f in findings
              if f.component_id == "mcp_server.jira" and f.rule_id in BROKER_FIX_RULES}
    assert before                    # the fixture must exercise the family
    stripped = strip_standing_credentials(model, "mcp_server.jira")
    after = {f.rule_id for f in RuleEngine().evaluate(stripped)
             if f.component_id == "mcp_server.jira" and f.rule_id in BROKER_FIX_RULES}
    assert not after
    # untouched: the original model still fires them (no in-place mutation)
    again = {f.rule_id for f in RuleEngine().evaluate(model)
             if f.component_id == "mcp_server.jira" and f.rule_id in BROKER_FIX_RULES}
    assert again == before


def test_cloud_only_credential_is_strippable_and_verified(tmp_path):
    # KUBECONFIG carries no secret-shaped token, so it is invisible to the
    # _SECRET_HINTS test - the standing-key union must still strip it and the
    # re-derivation must clear _has_cloud_credentials so ATL-112 stops firing.
    model = _mcp_model(
        '{"mcpServers": {"k8s": {"command": "npx", "args": ["k8s-mcp"], '
        '"env": {"KUBECONFIG": "/home/x/.kube/config"}}}}',
        tmp_path,
    )
    findings = RuleEngine().evaluate(model)
    f = _finding(findings, "ATL-112")
    fx = fix_for_finding(model, f)
    assert fx.strip_env == ["KUBECONFIG"]
    assert fx.verified
    plan = plan_for(model, f.component_id)
    assert plan is not None and plan.stripped == ["KUBECONFIG"]


def test_concentration_fix_is_verified_by_strip():
    model, findings = _model_findings("examples/credential-concentration")
    fx = fix_for_finding(model, _finding(findings, "ATL-164"))
    assert fx.verification == "re-synthesized" and fx.verified
    assert len(fx.strip_env) >= 4


def test_model_level_broker_bypass_stays_design_only():
    # ATL-221 names the system model, not one server - its fix IS the per-server
    # strips, so it must not pretend to compile a control of its own.
    model = build_model(FIXTURE)
    f = Finding("ATL-221", "broker bypassed", Severity.HIGH, "model:broker_bypass",
                "d", "r")
    assert fix_for_finding(model, f) is None


def test_broker_plans_for_dedupes_by_server():
    # ATL-104 + ATL-112 + ATL-115 on the same server produce one route, not three.
    model, findings = _model_findings()
    fixes = fixes_for(model, findings)
    plans = broker_plans_for(fixes)
    names = [p.name for p in plans]
    assert len(names) == len(set(names))


def test_render_shows_strip_and_route():
    model, findings = _model_findings()
    out = render_fixes(model, findings, color=False)
    assert "strip:" in out and "JIRA_API_TOKEN" in out
    assert "--broker-output" in out


# --- CLI --------------------------------------------------------------------

def test_fix_cli_broker_output_writes_the_routes(tmp_path):
    out = tmp_path / "broker.yaml"
    r = CliRunner().invoke(main, ["fix", FIXTURE, "--broker-output", str(out)])
    assert r.exit_code == 0, r.output
    assert out.exists()
    cfg = out.read_text()
    doc = yaml.safe_load(cfg)
    routes = doc["binds"][0]["listeners"][0]["routes"]
    names = {rt["name"] for rt in routes}
    assert "jira" in names
    for rt in routes:
        assert rt["policies"]["jwtAuth"]["mode"] == "strict"
        auth = rt["backends"][0]["backendAuth"]["oauthTokenExchange"]["clientAuth"]
        assert "secretRef" in auth and "clientSecret" not in auth


def test_fix_cli_broker_output_refuses_an_empty_write(tmp_path):
    clean = tmp_path / "design"
    clean.mkdir()
    (clean / ".mcp.json").write_text(
        '{"mcpServers": {"docs": {"command": "npx", "args": ["docs@1.2.3"]}}}'
    )
    out = tmp_path / "broker.yaml"
    r = CliRunner().invoke(main, ["fix", str(clean), "--broker-output", str(out)])
    assert r.exit_code == 0, r.output
    assert not out.exists()
    assert "no standing-credential fixes" in r.output
