"""Coverage for the GCP rule pack (rules/gcp_pack.yaml, ATL-414..ATL-433).

Mirrors tests/test_aws_pack.py: build a model from the fixture and assert every
new GCP id fires, then guard id uniqueness across the whole loaded ruleset.
"""
from attestral.ingest import build_model
from attestral.rules import RuleEngine

FIXTURE = "examples/gcp-pack"

# Every id the pack ships, ATL-414 through ATL-433 inclusive.
PACK_IDS = {f"ATL-{n:03d}" for n in range(414, 434)}

# Core GCP rules that legitimately co-fire on this fixture via by_type() prefix
# matching. ATL-413 (target google_kms_crypto_key, attr_missing rotation_period)
# prefix-matches the google_kms_crypto_key_iam_member resource, which carries no
# rotation_period. This is core behaviour we intentionally do not fight.
ALLOWED_CORE_CO_FIRES = {"ATL-413"}


def _ids():
    model = build_model(FIXTURE)
    return {f.rule_id for f in RuleEngine().evaluate(model)}


def test_all_gcp_pack_rules_fire():
    fired = _ids()
    missing = sorted(PACK_IDS - fired)
    assert not missing, f"pack rules that did not fire: {missing}"


def test_gcp_pack_fixture_triggers_no_unexpected_rules():
    # The fixture is authored so only pack ids fire (plus the documented ATL-413
    # prefix co-fire). Any other id firing means a fixture resource drifted into
    # overlapping a core check, which we want to know about.
    fired = _ids()
    unexpected = fired - PACK_IDS - ALLOWED_CORE_CO_FIRES
    assert not unexpected, f"unexpected rules fired: {sorted(unexpected)}"


def test_gcp_pack_ids_are_the_expected_band():
    engine = RuleEngine()
    pack_rule_ids = {r["id"] for r in engine.rules if r["id"] in PACK_IDS}
    assert pack_rule_ids == PACK_IDS


def test_no_duplicate_ids_across_all_packs():
    ids = [r["id"] for r in RuleEngine().rules]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"duplicate rule ids across packs: {dupes}"
    assert len(ids) == len(set(ids))


def test_gcp_pack_rules_are_well_formed():
    engine = RuleEngine()
    for r in engine.rules:
        if r["id"] not in PACK_IDS:
            continue
        assert r["severity"] in {"critical", "high", "medium", "low"}
        assert str(r["target"]).startswith("google_")
        assert r.get("match"), f"{r['id']} has no matcher"
        assert r.get("description") and r.get("recommendation")
        assert r.get("frameworks"), f"{r['id']} cites no control"
