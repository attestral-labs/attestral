"""Guard against fixture-README drift.

Several fixture READMEs pin the exact scan summary line
("N components · M findings · X critical · ..."). When a rule wave changes a
fixture's findings, that line silently goes stale and is only caught late, by
hand, at release. This test scans every fixture and asserts the plain-scan
summary its README documents matches the live scan, so drift fails the moment
it happens.

ML-tier counts (any summary line under an `--ml` command) are deliberately not
checked: they are tier-dependent by design, so pinning them would be wrong.
"""
import re
from pathlib import Path

from attestral.ingest import build_model
from attestral.report_terminal import render_scan
from attestral.rules import RuleEngine

ROOT = Path(__file__).resolve().parents[1]
SUMMARY_RE = re.compile(r'^\d+ components? · \d+ findings?(?: · .+)?$')


def _live_summary(fixture_dir: Path) -> str:
    model = build_model(str(fixture_dir))
    findings = RuleEngine().evaluate(model)
    rendered = render_scan(model, findings, fixture_dir.name, color=False)
    for line in rendered.splitlines():
        if SUMMARY_RE.match(line.strip()):
            return line.strip()
    return ""  # a clean scan renders no summary line


def _documented_plain_summaries(readme: str) -> list[str]:
    """Summary lines in the README that describe a PLAIN scan, not an `--ml` one.

    A count line is attributed to the nearest `attestral scan` command above it;
    if that command carries `--ml`, the line is a tier-dependent ML count and is
    skipped.
    """
    lines = readme.splitlines()
    out: list[str] = []
    for i, line in enumerate(lines):
        if not SUMMARY_RE.match(line.strip()):
            continue
        cmd = next((lines[j] for j in range(i, -1, -1) if "attestral scan" in lines[j]), "")
        if "--ml" in cmd:
            continue
        out.append(line.strip())
    return out


def test_fixture_readme_counts_match_live_scan():
    problems: list[str] = []
    checked = 0
    for d in sorted((ROOT / "examples").iterdir()):
        readme = d / "README.md"
        if not readme.is_file():
            continue
        documented = _documented_plain_summaries(readme.read_text())
        if not documented:
            continue
        live = _live_summary(d)
        for doc in documented:
            checked += 1
            if doc != live:
                problems.append(f"{d.name}: README pins '{doc}', live scan is '{live}'")
    assert not problems, (
        "Fixture README summary lines drifted from the live scan:\n  "
        + "\n  ".join(problems)
        + "\n\nRe-scan the fixture and update its README, or fix the rule."
    )
    assert checked, "no fixture README pinned a summary line; the guard matched nothing"
