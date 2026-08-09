"""Amazon Bedrock AgentCore hardening rules (ATL-070..073).

The AWS agent-runtime moat, expressed as pure data rules over the terraform-
flattened `bedrockagentcore_*` attributes (no ingester change). Asserts recall
(each rule fires on its `_weak` resource) and precision (the `_hardened`
counterparts stay silent).
"""
from _helpers import ids_for

from attestral.ingest import build_model
from attestral.rules import RuleEngine

FIXTURE = "examples/agentcore-hardening"
AGENTCORE_RULES = {"ATL-070", "ATL-071", "ATL-072", "ATL-073"}


def test_agentcore_rules_fire():
    assert AGENTCORE_RULES <= ids_for(FIXTURE)


def test_each_rule_fires_once_on_the_weak_resource_only():
    model = build_model(FIXTURE)
    findings = [f for f in RuleEngine().evaluate(model)
                if f.rule_id in AGENTCORE_RULES]
    # exactly one per rule, and always the *_weak resource - the hardened
    # counterparts (VPC, CMK, FAIL_ON_ANY_FINDINGS, ENFORCE) never fire.
    assert len(findings) == 4
    assert {f.rule_id for f in findings} == AGENTCORE_RULES
    assert all("_weak" in f.component_id for f in findings)
