"""Skill-manifest deception rules over the deceptive-skill fixture.

ATL-169 fires on the claim/grant mismatch (`_skill_deceptive_readonly`): the
frontmatter description promises read-only behavior while allowed-tools grants
shell - a deceptive capability claim, distinct from ATL-116 which fires on the
broad grant alone. ATL-170 fires on `_skill_persists_instructions`: the skill
body directs a write into a standing agent-memory file, escalating an invoked
skill into persistent, every-session context. The benign changelog-helper skill
(scoped grant, negated memory guidance) must stay clean - the ingester attrs
are presence-only, so the rules inherit its precision.
"""
from _helpers import findings_for

FIXTURE = "examples/deceptive-skill"

DECEPTIVE = "agent_instruction.safe-auditor"
BENIGN = "agent_instruction.changelog-helper"


def test_deceptive_readonly_claim_fires_atl_169():
    findings = findings_for(FIXTURE)
    hits = [f for f in findings if f.rule_id == "ATL-169"]
    assert [f.component_id for f in hits] == [DECEPTIVE]


def test_memory_persistence_directive_fires_atl_170():
    findings = findings_for(FIXTURE)
    hits = [f for f in findings if f.rule_id == "ATL-170"]
    assert [f.component_id for f in hits] == [DECEPTIVE]


def test_broad_grant_still_fires_atl_116_alongside():
    """ATL-116 (the grant alone) and ATL-169 (the claim over the grant) are
    deliberately two findings - both must land on the same skill."""
    findings = findings_for(FIXTURE)
    ids_on_skill = {f.rule_id for f in findings if f.component_id == DECEPTIVE}
    assert {"ATL-116", "ATL-169", "ATL-170"} <= ids_on_skill


def test_benign_skill_stays_clean():
    findings = findings_for(FIXTURE)
    assert not [f for f in findings if f.component_id == BENIGN]


def test_fixture_total_is_exactly_three_deterministic_findings():
    findings = findings_for(FIXTURE)
    assert sorted(f.rule_id for f in findings) == ["ATL-116", "ATL-169", "ATL-170"]
