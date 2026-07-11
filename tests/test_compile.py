from attestral.compile import compile_policy, render_policy_yaml
from attestral.ingest import build_model
from attestral.rules import RuleEngine


def _policy():
    model = build_model("examples/demo-project")
    findings = RuleEngine().evaluate(model)
    return compile_policy(model, findings, chain_head="abc123")


def test_default_deny():
    assert _policy()["default"] == "deny"


def test_shell_server_denied_with_reason():
    servers = _policy()["servers"]
    assert servers["shell"]["allow"] is False
    assert "ATL-103" in servers["shell"]["reason"]


def test_broad_filesystem_root_denied():
    servers = _policy()["servers"]
    assert servers["filesystem"]["allow"] is False
    assert "ATL-102" in servers["filesystem"]["reason"]


def test_non_tls_server_denied():
    servers = _policy()["servers"]
    assert servers["internal-api"]["allow"] is False
    assert "ATL-101" in servers["internal-api"]["reason"]


def test_metadata_binds_review():
    meta = _policy()["metadata"]
    assert meta["review_chain_head"] == "abc123"
    assert len(meta["model_hash"]) == 64


def test_yaml_renders_with_provenance_header():
    text = render_policy_yaml(_policy())
    assert text.startswith("# mcp-guard policy") and "default: deny" in text
