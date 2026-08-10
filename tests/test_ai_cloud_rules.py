"""Cross-cloud AI agent-runtime hardening rules (GCP Vertex + Azure Foundry).

Completes the AI-cloud moat begun with Bedrock AgentCore (ATL-070..074): the same
agent-runtime hardening on the other two clouds, as pure data rules over
terraform-flattened attributes (plus one derived flag to keep the Azure AI
Services rule agent-scoped). Asserts recall on the `_weak` resources and
precision on the `_hardened` ones.
"""
from _helpers import ids_for

from attestral.ingest import build_model
from attestral.rules import RuleEngine

GCP_FIXTURE = "examples/vertex-ai-hardening"
AZURE_FIXTURE = "examples/azure-ai-hardening"


def test_vertex_rules_fire():
    assert {"ATL-435", "ATL-436"} <= ids_for(GCP_FIXTURE)


def test_azure_ai_rules_fire():
    assert {"ATL-339", "ATL-340", "ATL-341"} <= ids_for(AZURE_FIXTURE)


def test_gcp_fires_on_weak_only():
    model = build_model(GCP_FIXTURE)
    findings = [f for f in RuleEngine().evaluate(model)
                if f.rule_id in {"ATL-435", "ATL-436"}]
    assert len(findings) == 2
    assert all("_weak" in f.component_id for f in findings)


def test_azure_fires_on_weak_only():
    model = build_model(AZURE_FIXTURE)
    findings = [f for f in RuleEngine().evaluate(model)
                if f.rule_id in {"ATL-339", "ATL-340", "ATL-341"}]
    # weak account (no CMK) + weak hub (public + no CMK) = 3 findings
    assert len(findings) == 3
    assert all("_weak" in f.component_id for f in findings)


def test_aiservices_cmk_derivation_is_gated_on_kind():
    # the derived flag is set only on the AIServices account with no key; the
    # hardened one (with a CMK) is not stamped.
    model = build_model(AZURE_FIXTURE)
    weak = next(c for c in model.by_type("azurerm_cognitive_account")
                if c.name == "agents_weak")
    hardened = next(c for c in model.by_type("azurerm_cognitive_account")
                    if c.name == "agents_hardened")
    assert weak.attr("_aiservices_no_cmk") is True
    assert hardened.attr("_aiservices_no_cmk") is None
