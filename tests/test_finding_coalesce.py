"""Finding coalescing: render several restatements of one reachability flow as a
single ranked issue, without deleting or mutating any finding (display only)."""
from pathlib import Path

from attestral.ingest import build_model
from attestral.injection_reach import annotate_injection_reach
from attestral.ml import MLConfig
from attestral.ml import scan as ml_scan
from attestral.model import Component, Finding, Severity, SystemModel
from attestral.report_terminal import _flow_signature, render_scan
from attestral.rules import RuleEngine

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _scanned(fixture: str):
    model = build_model(str(EXAMPLES / fixture))
    findings = RuleEngine().evaluate(model)
    ml, _ = ml_scan(model, MLConfig(engine="heuristic"))
    findings += ml
    annotate_injection_reach(model, findings)
    return model, findings


def _inj(cid: str, sinks: list[str]) -> Finding:
    f = Finding(rule_id="ATL-ML-001", title="Prompt-injection text", severity=Severity.CRITICAL,
                component_id=cid, description="", recommendation="fix")
    f.reachability = "injection reach: src -> " + ", ".join(f"{s} (1h)" for s in sinks)
    f.reachability_role = "injection-source"
    return f


# --- the coalescing key ---------------------------------------------------- #

def test_flow_signature_keys_on_sink_set_not_surface():
    a = _inj("srv.a", ["database", "network egress"])
    b = _inj("srv.b", ["network egress", "database"])  # same sinks, declared other order
    c = _inj("srv.c", ["shell"])
    assert _flow_signature(a) == _flow_signature(b)     # one flow, two surfaces
    assert _flow_signature(a) != _flow_signature(c)     # different sinks, different flow


def test_a_non_injection_finding_has_no_flow_signature():
    f = Finding(rule_id="ATL-103", title="shell", severity=Severity.CRITICAL,
                component_id="x", description="", recommendation="")
    assert _flow_signature(f) is None


# --- rendering, on the shipped fixture ------------------------------------- #

def test_two_surfaces_one_flow_render_as_one_block():
    model, findings = _scanned("injection-reach-demo")
    out = render_scan(model, findings, "demo", color=False)
    assert "Prompt-injection flow reaching database, network egress" in out
    assert "2 injection findings across 2 surfaces" in out
    assert "mcp_server.summarizer" in out and "agent_instruction.CLAUDE" in out
    # honest header: distinct-issue count and raw finding count both shown.
    assert "CRITICAL (2 issues · 3 findings)" in out


def test_coalescing_deletes_nothing_from_the_finding_set():
    # display only: both ML findings remain in the list handed to the chain.
    _, findings = _scanned("injection-reach-demo")
    ml = [f for f in findings if f.rule_id == "ATL-ML-001"]
    assert len(ml) == 2
    assert all(f.reachability_role == "injection-source" for f in ml)


def test_a_lone_injection_surface_is_not_coalesced():
    model = SystemModel()
    model.add(Component(id="mcp_server.x", type="mcp_server", name="x", source="mcp.json"))
    out = render_scan(model, [_inj("mcp_server.x", ["database", "network egress"])],
                      "solo", color=False)
    assert "one exfiltration flow" not in out   # a single surface is not a cluster
    assert "ATL-ML-001" in out                   # it still renders as an ordinary finding
    assert "CRITICAL (1)" in out                 # no distinct-vs-total split for a singleton


def test_two_different_flows_do_not_coalesce():
    model = SystemModel()
    for i in ("a", "b"):
        model.add(Component(id=f"mcp_server.{i}", type="mcp_server", name=i, source="m"))
    findings = [_inj("mcp_server.a", ["database"]), _inj("mcp_server.b", ["shell"])]
    out = render_scan(model, findings, "t", color=False)
    assert "one exfiltration flow" not in out   # different sink sets, two separate issues
    assert "CRITICAL (2)" in out
