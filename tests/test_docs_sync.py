"""Docs-sync gate: the README diagrams and CHANGELOG are enforced artifacts.

Attestral's product is detecting drift between an attested design and reality;
this test applies the same bar to the repo itself. It fails when:
  - a pipeline module exists that no README diagram represents,
  - a CLI command is not documented in the README,
  - the package version has no CHANGELOG entry.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text()
MERMAID = "\n".join(re.findall(r"```mermaid\n(.*?)```", README, re.DOTALL))

# module (relative to attestral/) -> the diagram text that represents it.
# When you ADD a module: draw it into the right README diagram, then map it
# here. When you RENAME diagram text: keep these keywords in the diagram.
DIAGRAM_KEYWORDS = {
    "ingest/terraform.py": "Terraform",
    "ingest/kubernetes.py": "Kubernetes",
    "ingest/mcp.py": "MCP",
    "ingest/prompts.py": "prompt",
    "ingest/local_config.py": "scan --local",
    "ingest/agent_config.py": "hooks",
    "ingest/scan.py": "SystemModel",
    "model.py": "SystemModel",
    "rules/engine.py": "Deterministic rules",
    "paths.py": "attack path",
    "redteam.py": "exploit path",
    "manifest.py": "manifest",
    "ml.py": "ML",
    "llm.py": "LLM",
    "judge.py": "judge",
    "waivers.py": "Waivers",
    "evidence.py": "Evidence",
    "sarif.py": "SARIF",
    "aibom.py": "AI-BOM",
    "report_terminal.py": "Terminal",
    "compile.py": "compile",
    "drift.py": "drift",
}
# Wiring, not pipeline stages: no diagram box expected.
EXEMPT_BASENAMES = {"__init__.py", "cli.py"}


def _pipeline_modules() -> list[str]:
    pkg = ROOT / "attestral"
    files = list(pkg.glob("*.py")) + list(pkg.glob("ingest/*.py")) + list(pkg.glob("rules/*.py"))
    return sorted(
        str(f.relative_to(pkg)) for f in files if f.name not in EXEMPT_BASENAMES
    )


def test_every_pipeline_module_is_diagrammed():
    unmapped = [m for m in _pipeline_modules() if m not in DIAGRAM_KEYWORDS]
    assert not unmapped, (
        f"New pipeline module(s) {unmapped} are not in any README diagram. "
        "Draw the stage into the README mermaid diagram, then map the module "
        "to its diagram text in DIAGRAM_KEYWORDS."
    )


def test_diagram_keywords_present_in_mermaid():
    assert MERMAID, "README.md has no mermaid diagrams"
    missing = {m: kw for m, kw in DIAGRAM_KEYWORDS.items() if kw not in MERMAID}
    assert not missing, (
        f"Diagram text missing for {missing} - the README diagrams no longer "
        "show these pipeline stages. Update the diagram (or the keyword map "
        "if the stage was legitimately renamed)."
    )


def test_every_cli_command_is_documented():
    from attestral.cli import main as cli

    undocumented = [name for name in cli.commands if f"attestral {name}" not in README]
    assert not undocumented, (
        f"CLI command(s) {undocumented} are not documented in README.md "
        "(expected an 'attestral <command>' usage example)."
    )


def test_changelog_covers_current_version():
    import attestral

    changelog = (ROOT / "CHANGELOG.md").read_text()
    assert "## [Unreleased]" in changelog, "CHANGELOG.md needs an [Unreleased] section"
    assert f"## [{attestral.__version__}]" in changelog, (
        f"attestral.__version__ = {attestral.__version__} has no CHANGELOG.md "
        "entry - a release without a changelog entry loses the project's history."
    )
