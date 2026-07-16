"""Rules for the trust/supply signals derived from agent settings, A2A cards,
and registry manifests: ATL-141 (unrestricted allow), ATL-142 (static API-key
auth), ATL-143 (mutable registry pin)."""
from attestral.ingest import build_model
from attestral.rules import RuleEngine

FIXTURE = "examples/agent-supply-trust"


def _ids(path=FIXTURE):
    model = build_model(path)
    return {f.rule_id for f in RuleEngine().evaluate(model)}


def test_fixture_fires_exactly_the_three_new_rules():
    assert _ids() == {"ATL-141", "ATL-142", "ATL-143"}


# --- ATL-141: unrestricted allow -------------------------------------------

def test_permissive_allow_signal(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        '{"permissions": {"allow": ["Bash(*)"]}}')
    model = build_model(str(tmp_path))
    c = model.by_type("agent_config")[0]
    assert c.attr("_permissive_allow") is True
    assert "Bash(*)" in c.attr("_permissive_allow_entries")
    assert "ATL-141" in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_scoped_allow_is_not_flagged(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        '{"permissions": {"allow": ["Bash(git status)", "Read(*)", "Bash(npm test)"]}}')
    model = build_model(str(tmp_path))
    c = model.by_type("agent_config")[0]
    assert c.attr("_permissive_allow") is False   # scoped commands are fine
    assert "ATL-141" not in {f.rule_id for f in RuleEngine().evaluate(model)}


# --- ATL-142: static API-key auth ------------------------------------------

def test_apikey_required_is_weak_auth(tmp_path):
    wk = tmp_path / ".well-known"
    wk.mkdir()
    (wk / "agent-card.json").write_text(
        '{"name":"a","url":"https://x/a2a",'
        '"securitySchemes":{"k":{"type":"apiKey","in":"header","name":"X"}},'
        '"security":[{"k":[]}]}')
    model = build_model(str(tmp_path))
    c = model.by_type("a2a_agent")[0]
    assert c.attr("_weak_auth_scheme") is True
    assert "ATL-142" in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_oauth_scheme_is_not_weak(tmp_path):
    wk = tmp_path / ".well-known"
    wk.mkdir()
    (wk / "agent-card.json").write_text(
        '{"name":"a","url":"https://x/a2a",'
        '"securitySchemes":{"o":{"type":"oauth2","flows":{}}},'
        '"security":[{"o":[]}]}')
    model = build_model(str(tmp_path))
    c = model.by_type("a2a_agent")[0]
    assert c.attr("_weak_auth_scheme") is False
    assert "ATL-142" not in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_apikey_defined_but_not_required_is_not_142(tmp_path):
    # No `security` requirement -> that is ATL-123's job, not the weak-scheme one.
    wk = tmp_path / ".well-known"
    wk.mkdir()
    (wk / "agent-card.json").write_text(
        '{"name":"a","url":"https://x/a2a",'
        '"securitySchemes":{"k":{"type":"apiKey","in":"header","name":"X"}}}')
    model = build_model(str(tmp_path))
    assert model.by_type("a2a_agent")[0].attr("_weak_auth_scheme") is False


# --- ATL-143: mutable registry pin -----------------------------------------

def test_mutable_pin_signal(tmp_path):
    (tmp_path / "server.json").write_text(
        '{"$schema":"https://static.modelcontextprotocol.io/schemas/2025-12-11/server.json",'
        '"name":"io.x/s","packages":[{"registryType":"npm","identifier":"p","version":"latest"}]}')
    model = build_model(str(tmp_path))
    c = model.by_type("mcp_registry_manifest")[0]
    assert c.attr("_has_mutable_pin") is True
    assert "p" in c.attr("_mutable_pin_packages")
    assert "ATL-143" in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_pinned_version_is_not_mutable(tmp_path):
    (tmp_path / "server.json").write_text(
        '{"$schema":"https://static.modelcontextprotocol.io/schemas/2025-12-11/server.json",'
        '"name":"io.x/s","packages":[{"registryType":"npm","identifier":"p","version":"1.4.2"}]}')
    model = build_model(str(tmp_path))
    c = model.by_type("mcp_registry_manifest")[0]
    assert c.attr("_has_mutable_pin") is False
    assert "ATL-143" not in {f.rule_id for f in RuleEngine().evaluate(model)}
