"""ASI07 inter-agent depth: A2A auth-required precision (ATL-123) and the
external-reach cross-boundary rule (ATL-208)."""
import json

from attestral.ingest import build_model
from attestral.ingest.agent_config import ingest_agent_config
from attestral.model import SystemModel
from attestral.rules import RuleEngine
from _helpers import evaluate, rule_ids

FIXTURE = "examples/a2a-exposure"






def _card(tmp_path, card: dict, servers: dict | None = None):
    wk = tmp_path / ".well-known"
    wk.mkdir(parents=True, exist_ok=True)
    (wk / "agent-card.json").write_text(json.dumps(card))
    if servers is not None:
        (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": servers}))
    return build_model(tmp_path)


def test_a2a_exposure_wave_fires():
    assert {"ATL-123", "ATL-208"} <= rule_ids(build_model(FIXTURE))


def test_schemes_defined_but_not_required_is_derived():
    model = ingest_agent_config(FIXTURE, SystemModel())
    (card,) = model.by_type("a2a_agent")
    assert card.attr("_auth_defined_not_required") is True
    assert card.attr("_effectively_public") is True
    assert card.attr("_no_auth_declared") is False   # schemes ARE declared
    assert card.attr("_skills") == ["lookup_customer"]


def test_external_reach_names_endpoint_and_capability():
    (f,) = [f for f in evaluate(build_model(FIXTURE)) if f.rule_id == "ATL-208"]
    assert "support-concierge" in f.description
    assert "customer-db" in f.description and "database" in f.description


def test_required_auth_card_is_clean(tmp_path):
    # securitySchemes AND a non-empty security requirement -> not public.
    model = _card(
        tmp_path,
        {"name": "svc", "url": "https://a.example/a2a",
         "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
         "security": [{"bearer": []}]},
        {"db": {"command": "npx", "args": ["@modelcontextprotocol/server-postgres@1.0.0"]}},
    )
    ids = rule_ids(model)
    assert "ATL-123" not in ids and "ATL-208" not in ids and "ATL-121" not in ids


def test_public_endpoint_without_sensitive_fleet_does_not_reach(tmp_path):
    # Unauthenticated card, but the only server is network-only (not a
    # sensitive capability): ATL-121 fires, ATL-208 must not.
    model = _card(
        tmp_path,
        {"name": "svc", "url": "https://a.example/a2a"},
        {"web": {"command": "uvx", "args": ["mcp-server-fetch"]}},
    )
    ids = rule_ids(model)
    assert "ATL-121" in ids           # no auth declared at all
    assert "ATL-208" not in ids       # network alone is not a sensitive reach


def test_external_reach_spec_fails_closed(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n"
        "  - {id: X-1, title: bad, severity: high, target: model,\n"
        '     match: {model_external_agent_reach: "shell"}}\n'   # str, not list
        "  - {id: X-2, title: bad, severity: high, target: model,\n"
        "     match: {model_external_agent_reach: []}}\n"        # empty list
    )
    ids = {f.rule_id for f in RuleEngine(rule_paths=[rules]).evaluate(build_model(FIXTURE))}
    assert "X-1" not in ids and "X-2" not in ids


def test_multiagent_fixture_now_flags_external_reach():
    # The existing multi-agent fixture pairs an unauthenticated A2A card with a
    # filesystem + shell fleet, so the reachability rule fires there too.
    assert "ATL-208" in rule_ids(build_model("examples/multi-agent"))
