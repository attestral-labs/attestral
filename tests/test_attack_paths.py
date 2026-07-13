"""Attack-path synthesis (ATL-210): the assembled external kill chain."""
import json

from attestral.ingest import build_model
from attestral.paths import external_attack_paths
from attestral.report_terminal import render_attack_paths, render_scan
from attestral.rules import RuleEngine

FIXTURE = "examples/attack-path"


def _ids(model):
    return {f.rule_id for f in RuleEngine().evaluate(model)}


def _build(tmp_path, card: dict | None, servers: dict):
    if card is not None:
        wk = tmp_path / ".well-known"
        wk.mkdir(parents=True, exist_ok=True)
        (wk / "agent-card.json").write_text(json.dumps(card))
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": servers}))
    return build_model(tmp_path)


_PUBLIC_CARD = {"name": "svc", "url": "https://a.example/a2a"}
_SHELL = {"ops": {"command": "bash", "args": ["-c", "shell-server"]}}
_WEB = {"web": {"command": "uvx", "args": ["mcp-server-fetch"]}}


def test_attack_path_fires_on_full_chain():
    assert "ATL-210" in _ids(build_model(FIXTURE))


def test_path_names_all_three_stages():
    model = build_model(FIXTURE)
    (path,) = external_attack_paths(model)
    assert path.entry.components == ["partner-ops"]
    assert path.pivot.components == ["ops-shell"]
    assert path.impact.components == ["web"]
    desc = path.describe()
    assert "partner-ops" in desc and "ops-shell" in desc and "web" in desc
    assert "→ code execution →".replace(" ", "") not in desc  # stages carry components


def test_no_external_entry_no_path(tmp_path):
    # Shell + web egress, but no A2A endpoint at all -> internal only, no ATL-210.
    model = _build(tmp_path, None, {**_SHELL, **_WEB})
    assert external_attack_paths(model) == []
    assert "ATL-210" not in _ids(model)
    assert "ATL-203" in _ids(model)   # the internal shell+network pair still fires


def test_no_pivot_no_path(tmp_path):
    # Public endpoint + egress, but nothing can execute code -> no complete chain.
    model = _build(tmp_path, _PUBLIC_CARD, _WEB)
    assert external_attack_paths(model) == []
    assert "ATL-210" not in _ids(model)


def test_no_impact_no_path(tmp_path):
    # Public endpoint + shell, but no egress and no cloud sink -> no way OUT.
    model = _build(tmp_path, _PUBLIC_CARD, _SHELL)
    assert external_attack_paths(model) == []
    assert "ATL-210" not in _ids(model)


def test_cloud_credential_counts_as_impact(tmp_path):
    # Public endpoint + shell + a cloud-credentialed tool (no egress) still
    # completes the chain via the cloud sink.
    model = _build(tmp_path, _PUBLIC_CARD, {
        **_SHELL,
        "aws": {"command": "npx", "args": ["@acme/aws-mcp@1.0.0"],
                "env": {"AWS_ACCESS_KEY_ID": "AKIA...", "AWS_SECRET_ACCESS_KEY": "x"}},
    })
    (path,) = external_attack_paths(model)
    assert "aws" in path.impact.components and "cloud pivot" in path.impact.label
    assert "ATL-210" in _ids(model)


def test_attack_path_spec_fails_closed(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n"
        "  - {id: X-1, title: bad, severity: high, target: model,\n"
        '     match: {model_attack_path: "yes"}}\n'
        "  - {id: X-2, title: bad, severity: high, target: model,\n"
        "     match: {model_attack_path: [true]}}\n"
    )
    ids = {f.rule_id for f in RuleEngine(rule_paths=[rules]).evaluate(build_model(FIXTURE))}
    assert "X-1" not in ids and "X-2" not in ids


def test_render_attack_paths_block():
    text = render_attack_paths(build_model(FIXTURE), color=False)
    assert "Attack paths (1)" in text
    assert "entry:" in text and "pivot:" in text and "impact:" in text
    assert "partner-ops" in text and "ops-shell" in text and "web" in text


def test_render_attack_paths_empty_without_path(tmp_path):
    # No external entry and no pivot -> no path -> nothing rendered.
    model = _build(tmp_path, None, _WEB)
    assert render_attack_paths(model, color=False) == ""


def test_render_scan_surfaces_the_path():
    model = build_model(FIXTURE)
    text = render_scan(model, RuleEngine().evaluate(model), "attack-path", color=False)
    assert "⚡ Attack paths" in text
    # the block sits above the severity groups
    assert text.index("Attack paths") < text.index("CRITICAL")


def test_pivot_via_subagent_delegation(tmp_path):
    # The pivot can come from a subagent's tool grant, not just an MCP server:
    # public endpoint + a Bash-granted subagent + web egress = full chain.
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "runner.md").write_text("---\nname: runner\ntools: Bash\n---\nrun things\n")
    model = _build(tmp_path, _PUBLIC_CARD, _WEB)
    (path,) = external_attack_paths(model)
    assert path.pivot.components == ["runner"]   # the subagent is the code-exec rung
    assert "ATL-210" in _ids(model)
