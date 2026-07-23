"""ATL-159: a registry server.json whose reverse-DNS namespace domain matches
neither the repository host nor any remote host - the statically visible shape
of namespace squatting. Matching namespaces, forge (io.github.*) namespaces,
same-org forge repos, and manifests with nothing to compare must never fire."""
from pathlib import Path

from attestral.ingest.mcp import (
    _namespace_domain,
    _url_matches_namespace,
    registry_component_from_manifest,
)
from attestral.model import SystemModel
from attestral.rules import RuleEngine
from _helpers import ids_for

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _ids_for_manifest(data: dict) -> set[str]:
    model = SystemModel()
    model.add(registry_component_from_manifest(data, "server.json"))
    return {f.rule_id for f in RuleEngine().evaluate(model)}


def test_fixture_fires_atl159():
    assert "ATL-159" in ids_for(EXAMPLES / "registry-namespace-mismatch")


def test_mismatch_attrs_surfaced():
    comp = registry_component_from_manifest({
        "name": "com.acmepay/payments-mcp",
        "remotes": [{"type": "streamable-http", "url": "https://mcp.zylo-labs.dev/mcp"}],
    }, "server.json")
    assert comp.attr("_namespace_domain") == "acmepay.com"
    assert comp.attr("_namespace_mismatch") is True


def test_matching_remote_host_does_not_fire():
    ids = _ids_for_manifest({
        "name": "com.acme/tools",
        "remotes": [{"type": "streamable-http", "url": "https://mcp.acme.com/mcp"}],
    })
    assert "ATL-159" not in ids


def test_forge_namespace_is_never_compared():
    # io.github.* is account-verified; a remote on any host is consistent.
    ids = _ids_for_manifest({
        "name": "io.github.acme/data-bridge",
        "repository": {"url": "https://github.com/acme/data-bridge"},
        "remotes": [{"type": "streamable-http", "url": "https://bridge.elsewhere.example/mcp"}],
    })
    assert "ATL-159" not in ids


def test_same_org_forge_repo_does_not_fire():
    # com.zylo + github.com/zylo/... is the normal open-source layout.
    ids = _ids_for_manifest({
        "name": "com.zylo/payments-mcp",
        "repository": {"url": "https://github.com/zylo/payments-mcp"},
        "packages": [{"registryType": "npm", "identifier": "@zylo/payments-mcp",
                      "version": "2.3.1", "transport": {"type": "stdio"}}],
    })
    assert "ATL-159" not in ids


def test_nothing_to_compare_fails_closed():
    # No repository, no remotes: no comparable source, no finding.
    ids = _ids_for_manifest({
        "name": "com.example/tools",
        "packages": [{"registryType": "npm", "identifier": "x", "version": "1.0.0",
                      "transport": {"type": "stdio"}}],
    })
    assert "ATL-159" not in ids


def test_existing_registry_fixtures_unaffected():
    assert "ATL-159" not in ids_for(EXAMPLES / "mcp-registry")
    assert "ATL-159" not in ids_for(EXAMPLES / "ecosystem-composite")
    assert "ATL-159" not in ids_for(EXAMPLES / "agent-supply-trust")


def test_namespace_domain_derivation():
    assert _namespace_domain("com.example/x") == "example.com"
    assert _namespace_domain("com.example.tools/x") == "tools.example.com"
    assert _namespace_domain("io.github.acme/x") == ""       # forge: skipped
    assert _namespace_domain("my-server") == ""               # not reverse-DNS
    assert _namespace_domain("") == ""


def test_url_match_rules():
    assert _url_matches_namespace("https://mcp.acme.com/mcp", "acme.com") is True
    assert _url_matches_namespace("https://acme.com", "acme.com") is True
    # Sub-namespace of a domain the source sits on (com.acme.tools + acme.com).
    assert _url_matches_namespace("https://acme.com/x", "tools.acme.com") is True
    # A look-alike suffix must not pass.
    assert _url_matches_namespace("https://acme.com.evil.example/mcp", "acme.com") is False
    # Forge owner match, and a non-matching owner.
    assert _url_matches_namespace("https://github.com/acme/repo", "acme.com") is True
    assert _url_matches_namespace("https://github.com/other/repo", "acme.com") is False
    # Unparseable / hostless values fail closed.
    assert _url_matches_namespace("not a url", "acme.com") is False
