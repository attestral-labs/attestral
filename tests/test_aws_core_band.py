"""Coverage for the core-pack AWS band ATL-008..ATL-018 (core_rules.yaml).

These eleven checks predate the per-provider packs and had no fixture that
triggered them. Mirrors tests/test_aws_pack.py: build a model from the fixture
and assert every id fires, and only these ids fire.
"""
from _helpers import ids_for

FIXTURE = "examples/aws-core-band"

BAND_IDS = {f"ATL-{n:03d}" for n in range(8, 19)}




def test_all_core_band_rules_fire():
    fired = ids_for(FIXTURE)
    missing = sorted(BAND_IDS - fired)
    assert not missing, f"core-band rules that did not fire: {missing}"


def test_fixture_triggers_exactly_the_band():
    # The fixture is hardened so no neighbouring core or aws-pack rule
    # co-fires; anything extra here means a fixture resource drifted into
    # overlapping another check.
    assert ids_for(FIXTURE) == BAND_IDS
