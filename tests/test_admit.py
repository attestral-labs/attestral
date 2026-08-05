"""attestral admit: admission control for the agent loadout - decide whether a
proposed tool may be loaded, and prove why with the security delta of admitting
it. The risk of a new tool lives in the fleet it joins, so the verdict is a
whole-system property, not a rule on the tool.
"""
from click.testing import CliRunner

from attestral.admit import admit
from attestral.cli import main

BASE = "examples/admit-base"
DENY = "examples/admit-add-deny"
ALLOW = "examples/admit-add-allow"


def test_deny_names_the_cost_of_admitting():
    v = admit(BASE, DENY)
    assert v.allowed is False
    assert v.added == ["web-fetch"]
    # the confused-deputy path only exists once the fetcher joins the cred-holding
    # fleet - proof the credential-reach edges were re-derived across base+added.
    assert "web-fetch -> aws_s3_bucket.customer_data" in v.reach_granted
    ids = {f.rule_id for f in v.delta.new_findings}
    assert "ATL-222" in ids
    assert any("ATL-222" in r for r in v.reasons)
    assert v.delta.blast_after >= v.delta.blast_before


def test_allow_when_the_addition_grants_nothing():
    v = admit(BASE, ALLOW)
    assert v.allowed is True
    assert v.added == ["clock"]
    assert v.reach_granted == []


def test_nothing_to_admit_when_server_already_present():
    v = admit(BASE, BASE)          # admitting the design into itself adds nothing
    assert v.allowed is True
    assert "nothing to admit" in v.note


def test_reach_granted_is_the_delta_not_the_absolute():
    # The base already has aws-deploy reaching the cloud directly; admitting the
    # fetcher must report only the NEW (laundered) reach, not aws-deploy's own.
    v = admit(BASE, DENY)
    assert all(r.startswith("web-fetch ->") for r in v.reach_granted)


# --- CLI --------------------------------------------------------------------

def test_cli_deny_gates_only_with_flag():
    r = CliRunner().invoke(main, ["admit", BASE, "--add", DENY])
    assert r.exit_code == 0                       # reports, does not gate by default
    assert "DENY" in r.output and "web-fetch" in r.output
    assert "aws_s3_bucket.customer_data" in r.output
    gated = CliRunner().invoke(main, ["admit", BASE, "--add", DENY, "--fail-on-deny"])
    assert gated.exit_code == 1


def test_cli_allow_and_json_output(tmp_path):
    r = CliRunner().invoke(main, ["admit", BASE, "--add", ALLOW, "--fail-on-deny"])
    assert r.exit_code == 0 and "ALLOW" in r.output
    out = tmp_path / "verdict.json"
    r2 = CliRunner().invoke(main, ["admit", BASE, "--add", DENY, "-o", str(out)])
    assert r2.exit_code == 0 and out.exists()
    import json
    data = json.loads(out.read_text())
    assert data["verdict"] == "deny"
    assert "ATL-222" in data["new_findings"]
    assert data["blast_after"] >= data["blast_before"]
