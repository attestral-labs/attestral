"""ASI07/ASI03 depth: the external -> A2A -> cloud reachability path (ATL-209)."""
import json

from attestral.ingest import build_model
from attestral.rules import RuleEngine
from _helpers import evaluate, rule_ids

FIXTURE = "examples/a2a-cloud-reach"






def _build(tmp_path, card: dict, servers: dict):
    wk = tmp_path / ".well-known"
    wk.mkdir(parents=True, exist_ok=True)
    (wk / "agent-card.json").write_text(json.dumps(card))
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": servers}))
    return build_model(tmp_path)


_AWS = {"AWS_ACCESS_KEY_ID": "AKIA...", "AWS_SECRET_ACCESS_KEY": "secret..."}


def test_external_cloud_reach_fires():
    assert "ATL-209" in rule_ids(build_model(FIXTURE))


def test_finding_names_endpoint_and_cloud_server():
    (f,) = [f for f in evaluate(build_model(FIXTURE)) if f.rule_id == "ATL-209"]
    assert "ops-copilot" in f.description
    assert "aws-tools" in f.description and "AWS_ACCESS_KEY_ID" in f.description


def test_authenticated_endpoint_does_not_reach_cloud(tmp_path):
    # A card that actually requires auth is not effectively public -> no path.
    model = _build(
        tmp_path,
        {"name": "svc", "url": "https://a.example/a2a",
         "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
         "security": [{"bearer": []}]},
        {"aws-tools": {"command": "npx", "args": ["@acme/aws-mcp@1.0.0"], "env": _AWS}},
    )
    ids = rule_ids(model)
    assert "ATL-209" not in ids
    assert "ATL-112" in ids            # the cloud-cred server is still flagged alone


def test_public_endpoint_without_cloud_creds_does_not_reach(tmp_path):
    # Public card, but no server holds cloud credentials -> ATL-209 must not fire.
    model = _build(
        tmp_path,
        {"name": "svc", "url": "https://a.example/a2a"},
        {"notes": {"command": "npx",
                   "args": ["@modelcontextprotocol/server-filesystem@1.4.2", "/srv"]}},
    )
    ids = rule_ids(model)
    assert "ATL-121" in ids            # no auth declared at all
    assert "ATL-209" not in ids        # no cloud credential in the fleet


def test_external_cloud_reach_fails_closed(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n"
        "  - {id: X-1, title: bad, severity: high, target: model,\n"
        '     match: {model_external_cloud_reach: "yes"}}\n'    # not the bool True
        "  - {id: X-2, title: bad, severity: high, target: model,\n"
        "     match: {model_external_cloud_reach: [true]}}\n"
    )
    ids = {f.rule_id for f in RuleEngine(rule_paths=[rules]).evaluate(build_model(FIXTURE))}
    assert "X-1" not in ids and "X-2" not in ids
