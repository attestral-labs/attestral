"""The reference fleet is a realistic (not deliberately-broken) two-repo agentic
system. This pins the grounded benchmark: the per-repo findings a single scan
raises, and the cross-repo flow only `attestral fleet` surfaces."""
from attestral.fleet import build_fleet_model
from attestral.ingest import build_model
from attestral.reachability import annotate_reachability
from attestral.rules import RuleEngine
from _helpers import ids_for

SUPPORT = "examples/reference-fleet/support-agent"
OPS = "examples/reference-fleet/ops-agent"




def test_support_agent_findings_are_real():
    ids = ids_for(SUPPORT)
    assert "ATL-202" in ids   # lethal trifecta across its tools
    assert "ATL-104" in ids   # env secrets


def test_ops_agent_findings_are_real():
    ids = ids_for(OPS)
    assert "ATL-001" in ids   # public S3 bucket
    assert "ATL-003" in ids   # wildcard IAM
    assert "ATL-103" in ids   # shell runbook server
    assert "ATL-056" in ids   # RDS without IAM auth (a v0.17.0 rule)


def test_neither_repo_completes_the_chain_alone():
    from attestral.paths import all_attack_paths
    assert all_attack_paths(build_model(SUPPORT)) == []  # entry+exit, no pivot
    assert all_attack_paths(build_model(OPS)) == []       # pivot, no untrusted entry


def test_fleet_surfaces_the_cross_repo_flow():
    model, labels = build_fleet_model([SUPPORT, OPS])
    findings = RuleEngine().evaluate(model)
    annotate_reachability(model, findings)
    ids = {f.rule_id for f in findings}
    assert "ATL-213" in ids                       # the cross-repo toxic flow
    assert set(labels) == {"support-agent", "ops-agent"}
    from attestral.paths import all_attack_paths
    assert all_attack_paths(model)                # the chain now exists, spanning repos
