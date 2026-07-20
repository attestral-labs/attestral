"""ATL-152: a committed settings file that auto-trusts a plugin marketplace
(extraKnownMarketplaces / enabledPlugins) is a supply-chain grant - a plugin
silently bundles hooks, MCP servers, and subagents."""
import json
from pathlib import Path

from attestral.ingest import build_model
from attestral.ingest.agent_config import _marketplace_plugins
from attestral.rules import RuleEngine

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _ids(root: str) -> set[str]:
    return {f.rule_id for f in RuleEngine().evaluate(build_model(root))}


def _settings(tmp_path: Path, data: dict) -> str:
    d = tmp_path / ".claude"
    d.mkdir(parents=True)
    (d / "settings.json").write_text(json.dumps(data))
    return str(tmp_path)


# --- the extractor, unit-level --------------------------------------------- #

def test_extra_marketplaces_and_remote_source_are_detected():
    mkt = _marketplace_plugins({"extraKnownMarketplaces": {
        "org": {"source": {"source": "github", "repo": "acme/plugins"}},
        "remote": {"source": {"source": "url", "url": "https://evil.example/m.json"}},
    }})
    assert mkt["names"] == ["org", "remote"]
    assert mkt["remote"] is True


def test_github_only_marketplace_is_not_flagged_remote():
    mkt = _marketplace_plugins({"extraKnownMarketplaces": {
        "org": {"source": {"source": "github", "repo": "acme/plugins"}}}})
    assert mkt["names"] == ["org"] and mkt["remote"] is False


def test_enabled_plugins_alone_is_a_signal():
    mkt = _marketplace_plugins({"enabledPlugins": {"deploy@org": True}})
    assert mkt["plugins"] == ["deploy@org"]


# --- the rule -------------------------------------------------------------- #

def test_marketplace_fixture_fires_atl_152():
    assert "ATL-152" in _ids(str(EXAMPLES / "plugin-marketplace-trust"))


def test_a_settings_file_without_marketplaces_does_not_fire(tmp_path):
    assert "ATL-152" not in _ids(_settings(tmp_path, {"permissions": {"defaultMode": "acceptEdits"}}))


def test_enabled_plugins_only_fires(tmp_path):
    assert "ATL-152" in _ids(_settings(tmp_path, {"enabledPlugins": {"deploy-helper@market": True}}))
