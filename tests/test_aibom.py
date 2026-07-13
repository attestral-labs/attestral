"""AI-BOM export: CycloneDX 1.6 inventory of the agent stack."""
import json
import re
from pathlib import Path

from click.testing import CliRunner

from attestral.aibom import build_aibom
from attestral.cli import main
from attestral.ingest import build_model

REPO = Path(__file__).resolve().parent.parent
MULTI = REPO / "examples" / "multi-agent"


def _bom(path):
    return build_aibom(build_model(path), str(path))


def test_bom_skeleton_is_valid_cyclonedx():
    bom = _bom(MULTI)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", bom["serialNumber"])
    assert bom["metadata"]["component"]["bom-ref"] == "attestral:scan-target"
    assert bom["metadata"]["tools"]["components"][0]["name"] == "attestral"


def test_stdio_server_becomes_component_with_purl_and_manifest():
    bom = _bom(MULTI)
    (notes,) = [c for c in bom["components"] if c["name"] == "notes"]
    assert notes["type"] == "application"
    assert notes["purl"] == "pkg:npm/%40modelcontextprotocol/server-filesystem@1.4.2"
    props = {p["name"]: p["value"] for p in notes["properties"]}
    assert props["attestral:capabilities"] == "filesystem"
    assert re.fullmatch(r"[0-9a-f]{64}", props["attestral:manifest-sha256"])


def test_subagents_become_components_with_tool_grants():
    bom = _bom(MULTI)
    by_name = {c["name"]: c for c in bom["components"]}
    deploy = {p["name"]: p["value"] for p in by_name["deploy-bot"]["properties"]}
    helper = {p["name"]: p["value"] for p in by_name["helper"]["properties"]}
    assert deploy["attestral:capabilities"] == "network,shell"
    assert helper["attestral:inherits-all-tools"] == "true"


def test_a2a_endpoint_becomes_unauthenticated_service():
    bom = _bom(MULTI)
    (svc,) = bom["services"]
    assert svc["authenticated"] is False
    assert svc["x-trust-boundary"] is True
    assert svc["endpoints"] == ["http://agents.internal.example/a2a/support-triage"]


def test_remote_mcp_server_maps_to_service_with_auth_state():
    bom = _bom(REPO / "examples" / "agentic-risks")
    (metrics,) = [s for s in bom["services"] if s["name"] == "metrics"]
    assert metrics["authenticated"] is False  # ATL-109's server: no credential


def test_dependency_graph_covers_every_agent_component():
    bom = _bom(MULTI)
    refs = {c["bom-ref"] for c in bom["components"]} | {
        s["bom-ref"] for s in bom["services"]
    }
    (dep,) = bom["dependencies"]
    assert dep["ref"] == "attestral:scan-target"
    assert set(dep["dependsOn"]) == refs


def test_cloud_resources_stay_out_of_the_aibom():
    bom = _bom(REPO / "examples" / "hcl-resolution")  # Terraform-only fixture
    assert bom["components"] == [] and bom["services"] == []


def test_cli_writes_cdx_json_only_when_asked():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(
            main, ["scan", str(MULTI), "--format", "aibom", "-o", "inv", "--quiet"]
        )
        assert result.exit_code == 0
        data = json.loads(Path("inv.cdx.json").read_text())
        assert data["bomFormat"] == "CycloneDX"
        assert not Path("inv.md").exists() and not Path("inv.json").exists()
