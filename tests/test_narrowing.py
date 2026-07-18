"""Policy-narrowing check (M7): a re-attestation is a narrowing or an expansion."""
from pathlib import Path

import yaml
from click.testing import CliRunner

from attestral.cli import main
from attestral.compile import compile_policy
from attestral.ingest import build_model
from attestral.narrowing import classify
from attestral.rules import RuleEngine

REPO = Path(__file__).resolve().parents[1]


def _pol(servers):
    return {"servers": servers}


def test_identical_policy_is_equal():
    p = _pol({"db": {"allow": True, "capabilities": ["database"]}})
    assert classify(p, p).overall == "equal"


def test_added_server_is_expansion():
    prior = _pol({"db": {"allow": True, "capabilities": ["database"]}})
    new = _pol({"db": {"allow": True, "capabilities": ["database"]},
                "sh": {"allow": True, "capabilities": ["shell"]}})
    r = classify(prior, new)
    assert r.is_expansion and any("not present" in e for e in r.expansions)


def test_removed_server_is_narrowing():
    prior = _pol({"db": {"allow": True}, "fetch": {"allow": True}})
    new = _pol({"db": {"allow": True}})
    assert classify(prior, new).overall == "narrowing"


def test_gained_capability_is_expansion():
    prior = _pol({"s": {"allow": True, "capabilities": ["network"]}})
    new = _pol({"s": {"allow": True, "capabilities": ["network", "shell"]}})
    assert classify(prior, new).is_expansion


def test_dropped_capability_is_narrowing():
    prior = _pol({"s": {"allow": True, "capabilities": ["network", "shell"]}})
    new = _pol({"s": {"allow": True, "capabilities": ["network"]}})
    assert classify(prior, new).overall == "narrowing"


def test_deny_to_allow_is_expansion():
    prior = _pol({"s": {"allow": False, "reason": "denied"}})
    new = _pol({"s": {"allow": True}})
    assert classify(prior, new).is_expansion


def test_dropped_manifest_pin_is_expansion():
    prior = _pol({"s": {"allow": True, "manifest_sha256": "abc123"}})
    new = _pol({"s": {"allow": True}})
    assert classify(prior, new).is_expansion


def test_changed_manifest_pin_is_expansion():
    prior = _pol({"s": {"allow": True, "manifest_sha256": "abc"}})
    new = _pol({"s": {"allow": True, "manifest_sha256": "def"}})
    assert classify(prior, new).is_expansion


def test_broadened_and_narrowed_roots():
    prior = _pol({"fs": {"allow": True, "constraints": {"root_paths": ["/app"]}}})
    wider = _pol({"fs": {"allow": True, "constraints": {"root_paths": ["/app", "/etc"]}}})
    tighter = _pol({"fs": {"allow": True, "constraints": {"root_paths": []}}})
    dropped = _pol({"fs": {"allow": True, "constraints": {}}})
    assert classify(prior, wider).is_expansion
    assert classify(prior, tighter).overall == "narrowing"
    assert classify(prior, dropped).is_expansion  # unconstrained = widest


def test_dropped_secret_constraint_is_expansion():
    prior = _pol({"s": {"allow": True, "constraints": {"forbid_env_secrets": True}}})
    new = _pol({"s": {"allow": True, "constraints": {}}})
    assert classify(prior, new).is_expansion


def test_cli_against_own_policy_passes(tmp_path):
    # A design re-attested against its own policy is unchanged: exit 0.
    reviewed = compile_policy(*_scan("examples/vulnerable-agent"))
    prior = tmp_path / "prior.yaml"
    prior.write_text(yaml.safe_dump(reviewed))
    runner = CliRunner()
    with runner.isolated_filesystem():
        res = runner.invoke(main, ["compile", str(REPO / "examples/vulnerable-agent"),
                                   "-o", "out.yaml", "--against", str(prior)])
    assert res.exit_code == 0, res.output
    assert "NARROWING" not in res.output and "EXPANSION" not in res.output


def test_cli_expansion_fails_the_gate(tmp_path):
    # Drop a server from the prior policy: the current design now grants a server
    # the reviewed policy did not, so it is an expansion and the gate fails.
    reviewed = compile_policy(*_scan("examples/vulnerable-agent"))
    reduced = {**reviewed, "servers": dict(list(reviewed["servers"].items())[:-1])}
    prior = tmp_path / "prior.yaml"
    prior.write_text(yaml.safe_dump(reduced))
    runner = CliRunner()
    with runner.isolated_filesystem():
        res = runner.invoke(main, ["compile", str(REPO / "examples/vulnerable-agent"),
                                   "-o", "out.yaml", "--against", str(prior)])
    assert res.exit_code == 1
    assert "EXPANSION" in res.output


def _scan(path):
    from attestral.reachability import annotate_reachability
    model = build_model(str(REPO / path) if not str(path).startswith("/") else path)
    findings = RuleEngine().evaluate(model)
    annotate_reachability(model, findings)
    return model, findings
