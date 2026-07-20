"""ATL-219: confusable tool-name collision across MCP servers - the homoglyph /
typosquat form of shadowing that ATL-204's exact match cannot see."""
import json
from pathlib import Path

from attestral.ingest import build_model
from attestral.rules import RuleEngine
from attestral.rules.engine import _normalize_tool_name
from _helpers import ids_for

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"




def _write(tmp_path: Path, servers: dict) -> str:
    (tmp_path / "mcp.json").write_text(
        json.dumps({"mcpServers": servers}, ensure_ascii=False), encoding="utf-8")
    return str(tmp_path)


# --- the fold, unit-level -------------------------------------------------- #

def test_homoglyph_case_and_zero_width_fold_to_the_same_identifier():
    base = "send_email"
    assert _normalize_tool_name("send_emаil") == base   # Cyrillic a
    assert _normalize_tool_name("Send_Email") == base        # case
    assert _normalize_tool_name("send_email​") == base  # trailing zero-width
    assert _normalize_tool_name("ｓｅｎｄ＿ｅｍａｉｌ") == base     # full-width (NFKC)


def test_genuinely_different_names_do_not_fold_together():
    assert _normalize_tool_name("list") != _normalize_tool_name("lists")
    assert _normalize_tool_name("get_user") != _normalize_tool_name("get_users")


# --- the rule, on the shipped fixture -------------------------------------- #

def test_confusable_fixture_fires_atl_219_and_not_the_exact_matcher():
    ids = ids_for(str(EXAMPLES / "tool-shadowing-confusable"))
    assert "ATL-219" in ids       # look-alike collision caught
    assert "ATL-204" not in ids   # raw strings differ, so no exact clash


def test_finding_names_both_raw_spellings_and_both_servers():
    model = build_model(str(EXAMPLES / "tool-shadowing-confusable"))
    f = next(f for f in RuleEngine().evaluate(model) if f.rule_id == "ATL-219")
    assert "send_email" in f.description and "send_emаil" in f.description
    assert "mail" in f.description and "helper-tools" in f.description


# --- false-positive and fail-closed guards --------------------------------- #

def test_exact_collision_stays_atl_204_not_double_counted(tmp_path):
    ids = ids_for(_write(tmp_path, {
        "a": {"command": "npx", "args": ["a"], "tools": [{"name": "create_issue"}]},
        "b": {"command": "npx", "args": ["b"], "tools": [{"name": "create_issue"}]},
    }))
    assert "ATL-204" in ids        # exact clash is ATL-204's job
    assert "ATL-219" not in ids    # a single raw spelling is not a confusable pair


def test_distinct_names_across_servers_do_not_fire(tmp_path):
    ids = ids_for(_write(tmp_path, {
        "a": {"command": "npx", "args": ["a"], "tools": [{"name": "list_issues"}]},
        "b": {"command": "npx", "args": ["b"], "tools": [{"name": "create_issue"}]},
    }))
    assert "ATL-219" not in ids


def test_confusable_variants_on_one_server_are_not_cross_server_shadowing(tmp_path):
    ids = ids_for(_write(tmp_path, {
        "solo": {"command": "npx", "args": ["s"],
                 "tools": [{"name": "send_email"}, {"name": "send_emаil"}]},
    }))
    assert "ATL-219" not in ids    # needs >=2 servers to shadow


def test_malformed_confusable_spec_fails_closed(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n"
        "  - {id: X-9, title: bad, severity: high, target: model,\n"
        '     match: {model_tool_name_confusable_collision: "yes"}}\n'
    )
    model = build_model(str(EXAMPLES / "tool-shadowing-confusable"))
    ids = {f.rule_id for f in RuleEngine(rule_paths=[rules]).evaluate(model)}
    assert "X-9" not in ids
