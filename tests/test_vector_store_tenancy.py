"""ATL-149: a vector/memory store reached through one static credential has no
per-tenant boundary (OWASP LLM08 cross-tenant embedding leakage)."""
import json
from pathlib import Path

from attestral.ingest import build_model
from _helpers import ids_for

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"




def _write(tmp_path: Path, servers: dict) -> str:
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": servers}))
    return str(tmp_path)


def test_vector_store_with_shared_credential_fires_atl_149():
    assert "ATL-149" in ids_for(str(EXAMPLES / "vector-store-tenancy"))


def test_the_attribute_is_scoped_to_memory_capability():
    model = build_model(str(EXAMPLES / "vector-store-tenancy"))
    server = next(iter(model.by_type("mcp_server")))
    assert "memory" in (server.attr("_capabilities") or [])
    assert server.attr("_shared_memory_credential") is True


def test_a_memory_store_without_a_credential_does_not_fire(tmp_path):
    # A local, credential-free memory server has no shared static key, so there
    # is nothing to share across tenants.
    ids = ids_for(_write(tmp_path, {
        "mem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory@1.0.0"]},
    }))
    assert "ATL-149" not in ids


def test_a_database_credential_alone_does_not_fire(tmp_path):
    # ATL-149 is memory-scoped: a database server with a secret is the broader
    # _shared_static_credential case, not this vector/embedding one.
    ids = ids_for(_write(tmp_path, {
        "db": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres@1.0.0"],
               "env": {"PGPASSWORD": "s3cr3t"}},
    }))
    assert "ATL-149" not in ids
