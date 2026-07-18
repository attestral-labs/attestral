"""`attestral init` scaffolding and the Claude Code plugin (roadmap M4).

init drops a working CI gate, a pre-commit hook, a waivers file, and a Claude
Code skill into a project - so Attestral is discoverable where agents are built -
and never overwrites an existing file. The skill it writes is the same one the
installable plugin ships; these tests gate that they stay byte-identical and
that both manifests are valid.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from attestral.cli import _CLAUDE_SKILL_MD, main

REPO = Path(__file__).resolve().parents[1]
PLUGIN = REPO / "plugin"
SKILL = PLUGIN / "skills" / "attestral-review" / "SKILL.md"
MARKETPLACE = REPO / ".claude-plugin" / "marketplace.json"
PLUGIN_JSON = PLUGIN / ".claude-plugin" / "plugin.json"

SCAFFOLDED = [
    ".github/workflows/attestral.yml",
    ".pre-commit-config.yaml",
    "attestral-waivers.yaml",
    ".claude/skills/attestral-review/SKILL.md",
]


# --- init scaffolding ----------------------------------------------------------

def test_init_scaffolds_every_onboarding_file():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init"])
        assert result.exit_code == 0
        for rel in SCAFFOLDED:
            assert Path(rel).is_file(), f"init did not create {rel}"
            assert f"created {rel}" in result.output


def test_init_is_idempotent_second_run_skips_all():
    runner = CliRunner()
    with runner.isolated_filesystem():
        assert runner.invoke(main, ["init"]).exit_code == 0
        second = runner.invoke(main, ["init"])
        assert second.exit_code == 0
        assert second.output.count("skipped") == len(SCAFFOLDED)
        assert "Nothing to do" in second.output


def test_init_never_overwrites_existing_files():
    runner = CliRunner()
    with runner.isolated_filesystem():
        skill = Path(".claude/skills/attestral-review/SKILL.md")
        skill.parent.mkdir(parents=True)
        skill.write_text("do not touch")
        result = runner.invoke(main, ["init"])
        assert result.exit_code == 0
        assert skill.read_text() == "do not touch"        # preserved
        assert f"skipped {skill} (already exists)" in result.output


def test_init_scaffolded_skill_is_the_plugin_skill():
    runner = CliRunner()
    with runner.isolated_filesystem():
        runner.invoke(main, ["init"])
        written = Path(".claude/skills/attestral-review/SKILL.md").read_text()
        assert written == _CLAUDE_SKILL_MD


def test_scaffolded_workflow_and_precommit_are_valid_yaml():
    runner = CliRunner()
    with runner.isolated_filesystem():
        runner.invoke(main, ["init"])
        wf = yaml.safe_load(Path(".github/workflows/attestral.yml").read_text())
        assert "design-review" in wf["jobs"]
        pc = yaml.safe_load(Path(".pre-commit-config.yaml").read_text())
        assert pc["repos"][0]["repo"].endswith("attestral-labs/attestral")


def test_scaffolded_gate_uses_the_ci_safe_confidence_floor():
    runner = CliRunner()
    with runner.isolated_filesystem():
        runner.invoke(main, ["init"])
        wf = Path(".github/workflows/attestral.yml").read_text()
        # The hard gate should filter to the structural, zero-FP set.
        assert "--min-confidence high" in wf
        assert "--fail-on high" in wf


# --- the shipped plugin --------------------------------------------------------

def test_plugin_skill_matches_the_init_constant():
    # The plugin's skill and init's scaffold must not drift.
    assert SKILL.read_text() == _CLAUDE_SKILL_MD


def test_plugin_manifest_is_valid():
    data = json.loads(PLUGIN_JSON.read_text())
    assert data["name"] == "attestral"           # kebab-case, matches marketplace entry
    assert data["description"]                     # required, non-empty


def test_marketplace_manifest_is_valid_and_points_at_the_plugin():
    data = json.loads(MARKETPLACE.read_text())
    assert data["name"] == "attestral-labs"
    assert data["owner"]["name"]                   # owner.name is required
    entries = {p["name"]: p for p in data["plugins"]}
    assert "attestral" in entries
    src = entries["attestral"]["source"]
    assert src == "./plugin"
    # source must resolve to a real plugin dir with a manifest.
    assert (REPO / src.lstrip("./") / ".claude-plugin" / "plugin.json").is_file()


def test_bundled_skill_has_required_frontmatter():
    text = SKILL.read_text()
    assert text.startswith("---\n")
    fm = yaml.safe_load(text.split("---\n")[1])
    assert fm["description"]                        # skills require a description
    assert fm["name"] == "attestral-review"
