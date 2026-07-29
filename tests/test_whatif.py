"""Counterfactual design review (`attestral whatif`): the security delta of a
hypothetical change before it is made. Reuses the model, rules, reachability, and
blast-radius, so the answer is the tool's own reasoning against a hypothetical,
and it never mutates the real design (only a copy)."""
from click.testing import CliRunner

from attestral.cli import main
from attestral.ingest import build_model
from attestral.whatif import deny_capability, remove_component, whatif

FIXTURE = "examples/vulnerable-agent"


def test_remove_a_server_resolves_its_findings_and_leaves_the_original_intact():
    model = build_model(FIXTURE)
    n_before = len(model.components)
    delta, note = whatif(model, remove="shell")
    assert note == ""
    resolved = {f.rule_id for f in delta.resolved_findings}
    assert "ATL-103" in resolved            # the shell-server finding is gone
    assert not delta.new_findings           # removing a server introduces nothing
    assert len(model.components) == n_before  # the base model is untouched


def test_denying_the_egress_capability_breaks_the_lethal_trifecta():
    # The design-assistant payoff: scoping the web server's network capability
    # away resolves the composition finding, which no per-server edit reveals.
    model = build_model(FIXTURE)
    delta, _ = whatif(model, deny=("web", "network"))
    assert "ATL-202" in {f.rule_id for f in delta.resolved_findings}
    assert delta.closed_paths                # at least one attack path closes


def test_a_change_that_matches_nothing_is_reported_not_silently_empty():
    model = build_model(FIXTURE)
    d1, n1 = whatif(model, remove="does-not-exist")
    assert d1 is None and "nothing to remove" in n1
    d2, n2 = whatif(model, deny=("web", "shell"))   # web has no shell capability
    assert d2 is None and "nothing to scope" in n2


def test_remove_component_returns_none_when_unmatched():
    assert remove_component(build_model(FIXTURE), "nope") is None


def test_deny_capability_actually_recomputes_flows():
    model = build_model(FIXTURE)
    head = deny_capability(model, "web", "network")
    assert head is not None
    web = next(c for c in head.by_type("mcp_server") if c.name == "web")
    assert "network" not in (web.attr("_capabilities") or [])


def test_cli_whatif_reports_the_improvement():
    r = CliRunner().invoke(main, ["whatif", FIXTURE, "--deny", "web:network"])
    assert r.exit_code == 0, r.output
    assert "what-if: deny web:network" in r.output
    assert "resolved" in r.output
    assert "blast radius" in r.output


def test_cli_whatif_rejects_a_bad_deny_spec():
    r = CliRunner().invoke(main, ["whatif", FIXTURE, "--deny", "no-colon"])
    assert r.exit_code != 0
    assert "NAME:CAPABILITY" in r.output


def test_cli_whatif_reports_an_unmatched_change():
    r = CliRunner().invoke(main, ["whatif", FIXTURE, "--remove", "ghost"])
    assert r.exit_code != 0
    assert "nothing to remove" in r.output
