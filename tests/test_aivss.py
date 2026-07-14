"""OWASP AIVSS - Agentic AI Risk Score (AARS)."""
from pathlib import Path

from attestral.aivss import render_aivss, score, scored
from attestral.ingest import build_model
from attestral.rules import RuleEngine

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _findings(fixture: str):
    model = build_model(str(EXAMPLES / fixture))
    return model, RuleEngine().evaluate(model)


def test_aars_in_range_and_only_agentic_findings_scored():
    model, findings = _findings("vulnerable-agent")
    rows = scored(model, findings)
    assert rows, "vulnerable-agent has agentic findings to score"
    for a, f in rows:
        assert 0.0 <= a.score <= 10.0
        assert 0.5 <= a.threat_multiplier <= 1.0
        assert a.factors          # only findings with an amplification factor are scored
        assert a.category         # every scored finding maps to an ASI/LLM category


def test_fleet_finding_outranks_a_minor_one():
    # The compositional lethal-trifecta risk must outrank a single mutable-tag
    # finding on the agentic axis - that is the whole point of AIVSS over CVSS.
    model, findings = _findings("vulnerable-agent")
    top = {}
    for a, f in scored(model, findings):
        top.setdefault(f.rule_id, a.score)
    assert top.get("ATL-202", 0) >= 8.0
    assert top["ATL-202"] > top.get("ATL-106", 0)


def test_render_block_and_clean_fixture_scores_nothing():
    model, findings = _findings("vulnerable-agent")
    block = render_aivss(model, findings, color=False)
    assert "OWASP AIVSS" in block and "AARS" in block
    # a cloud-only fixture has no agentic surface, so nothing is scored
    clean_m, clean_f = _findings("aws-pack")
    assert render_aivss(clean_m, clean_f, color=False) == ""


def test_score_is_deterministic():
    model, findings = _findings("vulnerable-agent")
    f = findings[0]
    assert score(model, f).score == score(model, f).score
