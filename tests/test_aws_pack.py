"""Coverage for the AWS rule pack (rules/aws_pack.yaml, ATL-027..ATL-054).

Mirrors tests/test_multicloud_rules.py: build a model from the fixture and
assert every new AWS id fires, then guard id uniqueness across the whole
loaded ruleset.
"""
from _helpers import ids_for

from attestral.rules import RuleEngine

FIXTURE = "examples/aws-pack"

# The original pack band, ATL-027 through ATL-054 inclusive.
PACK_IDS = {f"ATL-{n:03d}" for n in range(27, 55)}
# The AWS checks that live in core_rules.yaml (001-026); the aws-pack fixture
# must never drift into these.
CORE_AWS_IDS = {f"ATL-{n:03d}" for n in range(1, 27)}


def test_all_aws_pack_rules_fire():
    fired = ids_for(FIXTURE)
    missing = sorted(PACK_IDS - fired)
    assert not missing, f"pack rules that did not fire: {missing}"


def test_aws_pack_fixture_triggers_no_unexpected_core_rules():
    # The fixture is comprehensively insecure, so it fires its own band and may
    # also fire later service-coverage rules (ATL-055+). The guard that matters:
    # it must never drift into a CORE AWS check (001-026), which would mean a
    # fixture resource overlapped a core rule.
    fired = ids_for(FIXTURE)
    assert PACK_IDS <= fired, f"pack rules stopped firing: {sorted(PACK_IDS - fired)}"
    drifted = fired & CORE_AWS_IDS
    assert not drifted, f"aws-pack fixture drifted into core AWS rules: {sorted(drifted)}"


def test_aws_pack_ids_are_the_expected_band():
    engine = RuleEngine()
    pack_rule_ids = {r["id"] for r in engine.rules if r["id"] in PACK_IDS}
    assert pack_rule_ids == PACK_IDS


def test_no_duplicate_ids_across_all_packs():
    ids = [r["id"] for r in RuleEngine().rules]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"duplicate rule ids across packs: {dupes}"
    assert len(ids) == len(set(ids))


def test_aws_pack_rules_are_well_formed():
    engine = RuleEngine()
    for r in engine.rules:
        if r["id"] not in PACK_IDS:
            continue
        assert r["severity"] in {"critical", "high", "medium", "low"}
        assert str(r["target"]).startswith("aws_")
        assert r.get("match"), f"{r['id']} has no matcher"
        assert r.get("description") and r.get("recommendation")
        assert r.get("frameworks"), f"{r['id']} cites no control"
