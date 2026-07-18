"""CI floor for the threat-labelled external recall set (M-EVAL v2).

Guards the known-CVE mechanism against regression: every design-visible advisory
in evaluation/external/cases.yaml (an MCP server pinned to a known-vulnerable
version) must keep firing its expected rule. Unlike the self-labelled benchmark,
the labels here come from published advisories, so a drop is a real coverage
loss, not a fixture bookkeeping change.

The full-set coverage number is deliberately NOT asserted at 100% - it is allowed
to be low (dependency/runtime advisories are out of design-time scope). This test
only pins the floor: design-visible advisories do not silently stop being caught.
"""
from __future__ import annotations

from evaluation.score_external import load_cases, run, taxonomy_coverage


def test_every_design_visible_advisory_fires():
    r = run()
    assert not r["missed"], (
        "design-visible advisories no longer detected (known-CVE table regressed): "
        f"{r['missed']}"
    )
    assert r["design_visible_recall"] == 1.0


def test_external_set_has_real_advisories():
    cases = load_cases()
    assert len(cases) >= 8
    for c in cases:
        assert c["advisory"].startswith("CVE-"), c["id"]
        assert c["ref"].startswith("http"), c["id"]
        assert c["scope"] in {"design-visible", "dependency", "runtime"}, c["id"]
        if c["scope"] == "design-visible":
            assert c["expect"], f"{c['id']}: a design-visible case must name an expected rule"


def test_full_coverage_is_reported_and_honest():
    # The whole point: full-set coverage is below 100% (out-of-scope advisories
    # exist and are counted). A regression to "100%" would mean we stopped
    # counting the hard cases.
    r = run()
    assert r["out_of_scope"] >= 1
    assert r["full_coverage"] < 1.0


def test_taxonomy_denominator_is_external_and_has_gaps():
    t = taxonomy_coverage()
    assert t["total"] >= 20
    # Honest by construction: real gaps must exist, or the taxonomy was trimmed.
    gaps = t["by_status"].get("needs-ingester", 0) + t["by_status"].get("out-of-scope", 0)
    assert gaps >= 1
