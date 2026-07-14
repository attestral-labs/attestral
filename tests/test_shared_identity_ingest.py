"""Identity-propagation gap ingestion: `_shared_static_credential` marks a
data-access MCP server (database / memory / saas_data) reached through one
static env credential, so per-caller entitlements cannot be enforced
downstream. A model-level rule consumes it alongside an exposed A2A card."""
from attestral.ingest import build_model
from attestral.ingest.mcp import component_from_server

FIXTURE = "examples/rag-shared-identity"


def _server(model, name):
    return next(c for c in model.by_type("mcp_server") if c.name == name)


def test_qdrant_server_gets_shared_static_credential():
    model = build_model(FIXTURE)
    qdrant = _server(model, "qdrant")
    assert "memory" in qdrant.attr("_capabilities")
    assert qdrant.attr("_shared_static_credential")


def test_scoped_docs_server_is_not_flagged():
    model = build_model(FIXTURE)
    docs = _server(model, "docs")
    assert not docs.attr("_shared_static_credential")


def test_fixture_exposes_a2a_agent():
    model = build_model(FIXTURE)
    cards = model.by_type("a2a_agent")
    assert cards, "the .well-known agent card must ingest as an a2a_agent"


def test_data_server_without_secret_env_is_not_flagged():
    # Database capability alone is fine: with no static credential in env,
    # the server may resolve identity per caller (or hold no identity at all).
    comp = component_from_server(
        "postgres",
        {"command": "npx", "args": ["@modelcontextprotocol/server-postgres"]},
        "test",
    )
    assert "database" in comp.attr("_capabilities")
    assert not comp.attr("_shared_static_credential")


def test_non_data_server_with_secret_env_is_not_flagged():
    # A network server holding a secret is a different risk class (deputy /
    # egress), not a shared-identity path into a data store.
    comp = component_from_server(
        "fetch",
        {
            "command": "npx",
            "args": ["@modelcontextprotocol/server-fetch"],
            "env": {"PROXY_API_KEY": "px_live_0011223344556677"},
        },
        "test",
    )
    assert comp.attr("_env_has_secrets")
    assert "network" in comp.attr("_capabilities")
    assert not comp.attr("_shared_static_credential")


def test_pgvector_hint_classifies_as_memory():
    comp = component_from_server(
        "kb",
        {"command": "uvx", "args": ["mcp-pgvector-server"]},
        "test",
    )
    assert "memory" in comp.attr("_capabilities")
