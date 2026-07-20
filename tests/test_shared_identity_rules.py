"""Shared-identity reachability (ATL-211) and the Azure AI Search pack rule
(ATL-336) from the identity-and-RAG wave.

ATL-211 is model-level by nature: a public A2A endpoint means many distinct
external callers, and a data-access server reached through one static env
credential means every one of those callers reads with the same downstream
identity - so per-caller entitlements can never be enforced at the store.
Neither component is the finding alone; only the assembled system model shows
the identity-propagation gap.
"""
from attestral.ingest import build_model
from attestral.model import Component, SystemModel
from attestral.rules import RuleEngine
from _helpers import evaluate, rule_ids

FIXTURE = "examples/rag-shared-identity"






def _public_endpoint(name="front"):
    return Component(
        id=f"a2a_agent.{name}", type="a2a_agent", name=name, source="test",
        attributes={"_effectively_public": True, "url": "https://a.example/a2a"},
        trust_boundary="agent_runtime",
    )


def _shared_credential_server(name="kb", ctype="mcp_server"):
    return Component(
        id=f"{ctype}.{name}", type=ctype, name=name, source="test",
        attributes={"_shared_static_credential": True, "_capabilities": ["memory"]},
        trust_boundary="agent_runtime",
    )


def _model(*components):
    m = SystemModel()
    for c in components:
        m.add(c)
    return m


# --- ATL-211 on the fixture ---------------------------------------------------

def test_atl_211_fires_on_rag_fixture_and_attributes_the_flagged_server():
    hits = [f for f in evaluate(build_model(FIXTURE)) if f.rule_id == "ATL-211"]
    assert len(hits) == 1, "exactly one flagged data server -> exactly one finding"
    (f,) = hits
    assert f.component_id == "mcp_server.qdrant"
    # The detail names both sides of the crossing.
    assert "knowledge-assistant" in f.description
    assert "qdrant" in f.description


def test_atl_211_does_not_flag_the_scoped_docs_server():
    hits = [f for f in evaluate(build_model(FIXTURE)) if f.rule_id == "ATL-211"]
    assert all(f.component_id != "mcp_server.docs" for f in hits)


def test_atl_211_does_not_fire_on_vulnerable_agent():
    # No a2a_agent in that fixture: one side of the pair is absent.
    assert "ATL-211" not in rule_ids(build_model("examples/vulnerable-agent"))


# --- single-sided models never fire --------------------------------------------

def test_public_endpoint_alone_does_not_fire():
    assert "ATL-211" not in rule_ids(_model(_public_endpoint()))


def test_shared_credential_server_alone_does_not_fire():
    assert "ATL-211" not in rule_ids(_model(_shared_credential_server()))


def test_non_public_endpoint_with_flagged_server_does_not_fire():
    quiet = Component(
        id="a2a_agent.internal", type="a2a_agent", name="internal", source="test",
        attributes={"_effectively_public": False},
        trust_boundary="agent_runtime",
    )
    assert "ATL-211" not in rule_ids(_model(quiet, _shared_credential_server()))


def test_both_sides_fire_and_subagents_count_as_the_credential_side():
    ids = rule_ids(_model(_public_endpoint(), _shared_credential_server()))
    assert "ATL-211" in ids
    ids = rule_ids(_model(
        _public_endpoint(), _shared_credential_server(name="delegate", ctype="subagent"),
    ))
    assert "ATL-211" in ids


# --- fail-closed matcher spec ---------------------------------------------------

def test_shared_identity_spec_fails_closed(tmp_path):
    # Anything but a literal `true` never fires, even on a model where both
    # sides of the pair are present.
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n"
        "  - {id: X-1, title: bad, severity: high, target: model,\n"
        '     match: {model_shared_identity_reach: "true"}}\n'   # str, not bool
        "  - {id: X-2, title: bad, severity: high, target: model,\n"
        "     match: {model_shared_identity_reach: [true]}}\n"   # list
        "  - {id: X-3, title: bad, severity: high, target: model,\n"
        "     match: {model_shared_identity_reach: {on: true}}}\n"  # mapping
    )
    model = _model(_public_endpoint(), _shared_credential_server())
    ids = {f.rule_id for f in RuleEngine(rule_paths=[rules]).evaluate(model)}
    assert not {"X-1", "X-2", "X-3"} & ids


# --- ATL-336: Azure AI Search public network access ------------------------------

def test_atl_336_fires_on_azure_pack_fixture():
    hits = [
        f for f in evaluate(build_model("examples/azure-pack"))
        if f.rule_id == "ATL-336"
    ]
    assert len(hits) == 1
    assert hits[0].component_id == "azurerm_search_service.rag"


def test_atl_336_stays_quiet_when_public_access_is_disabled():
    private = Component(
        id="azurerm_search_service.private", type="azurerm_search_service",
        name="private", source="test",
        attributes={"public_network_access_enabled": False},
        trust_boundary="cloud",
    )
    assert "ATL-336" not in rule_ids(_model(private))
