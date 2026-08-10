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
AGENTCORE_RULES = {"ATL-070", "ATL-071", "ATL-072", "ATL-073", "ATL-074"}


def test_agentcore_rules_fire():
    assert AGENTCORE_RULES <= ids_for(FIXTURE)


def test_rules_fire_on_the_weak_resources_only():
    model = build_model(FIXTURE)
    findings = [f for f in RuleEngine().evaluate(model)
                if f.rule_id in AGENTCORE_RULES]
    # every rule fires, and always on a *_weak resource - the hardened
    # counterparts (VPC, CMK, FAIL_ON_ANY_FINDINGS, ENFORCE, allowed_clients)
    # never fire. The weak gateway trips two (LOG_ONLY + open JWT), so five
    # findings across five rules.
    assert len(findings) == 5
    assert {f.rule_id for f in findings} == AGENTCORE_RULES
    assert all("_weak" in f.component_id for f in findings)


def test_jwt_allowlist_derivation():
    # the derived attr is set only on the CUSTOM_JWT gateway with no allowlist
    model = build_model(FIXTURE)
    weak = next(c for c in model.by_type("aws_bedrockagentcore_gateway")
                if c.name == "tools_weak")
    hardened = next(c for c in model.by_type("aws_bedrockagentcore_gateway")
                    if c.name == "tools_hardened")
    assert weak.attr("_jwt_open_to_any_client") is True
    assert hardened.attr("_jwt_open_to_any_client") is None
