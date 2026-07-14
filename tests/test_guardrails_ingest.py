"""NeMo Guardrails config ingestion: the guardrails_config attribute contract.

Rails govern the dialog channel only - the MCP tool fleet is invisible to
them. These tests pin the derived attributes the guardrails-vs-tool-fleet
contradiction rules consume, and prove detection fails closed on the other
YAML dialects a repo scan wades through.
"""
from attestral.ingest import build_model
from attestral.ingest.agent_config import _guardrails_data, ingest_agent_config
from attestral.model import SystemModel

FIXTURE = "examples/guardrails-gap"


def test_guardrails_config_ingested_with_contract():
    model = build_model(FIXTURE)
    configs = model.by_type("guardrails_config")
    assert len(configs) == 1
    cfg = configs[0]
    # Named after the parent directory (not the generic file stem "config").
    assert cfg.name == "guardrails"
    assert cfg.id == "guardrails_config.guardrails"
    assert cfg.trust_boundary == "agent_runtime"
    assert cfg.attr("_has_input_rails") is True
    assert cfg.attr("_has_output_rails") is False
    # Input railed, output not: the single-key contradiction signal.
    assert cfg.attr("_output_unrailed") is True
    assert cfg.attr("_input_rails") == ["self check input"]
    assert cfg.attr("_output_rails") == []
    assert cfg.attr("_colang_files") >= 1
    assert cfg.attr("engines") == ["openai"]


def test_shell_server_contract_for_contradiction_rules():
    # The other half of the contradiction: an un-railed execution surface.
    model = build_model(FIXTURE)
    shell = model.get("mcp_server.shell")
    assert shell is not None
    assert shell.attr("_auto_approve")
    assert "shell" in (shell.attr("_capabilities") or [])


def test_generic_config_dir_falls_back_to_stem_and_defaults(tmp_path):
    d = tmp_path / "config"
    d.mkdir()
    (d / "bot-rails.yml").write_text("colang_version: \"1.0\"\n")
    model = ingest_agent_config(tmp_path, SystemModel())
    configs = model.by_type("guardrails_config")
    assert len(configs) == 1
    cfg = configs[0]
    assert cfg.name == "bot-rails"
    # List/bool attrs are always set, even when the config declares nothing.
    assert cfg.attr("_input_rails") == []
    assert cfg.attr("_output_rails") == []
    assert cfg.attr("_has_input_rails") is False
    assert cfg.attr("_has_output_rails") is False
    # No input rails at all: nothing asymmetric to flag.
    assert cfg.attr("_output_unrailed") is False
    assert cfg.attr("_colang_files") == 0
    assert cfg.attr("engines") == []


def test_both_channels_railed_is_not_output_unrailed(tmp_path):
    d = tmp_path / "assistant"
    d.mkdir()
    (d / "config.yml").write_text(
        "colang_version: \"1.0\"\n"
        "rails:\n"
        "  input:\n"
        "    flows:\n"
        "      - self check input\n"
        "  output:\n"
        "    flows:\n"
        "      - self check output\n"
    )
    model = ingest_agent_config(tmp_path, SystemModel())
    configs = model.by_type("guardrails_config")
    assert len(configs) == 1
    cfg = configs[0]
    assert cfg.attr("_has_input_rails") is True
    assert cfg.attr("_has_output_rails") is True
    assert cfg.attr("_output_unrailed") is False


def test_kubernetes_manifest_not_detected(tmp_path):
    f = tmp_path / "deploy.yaml"
    f.write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: rails-app\n"
        "spec:\n  template:\n    spec:\n      containers:\n"
        "        - name: web\n          image: rails:7\n"
    )
    assert _guardrails_data(f) is None


def test_compose_file_not_detected(tmp_path):
    f = tmp_path / "docker-compose.yml"
    f.write_text(
        "services:\n  api:\n    image: api:1.2\n"
        "    environment:\n      DB_ENGINE: postgres\n"
    )
    assert _guardrails_data(f) is None


def test_waiver_file_not_detected(tmp_path):
    f = tmp_path / "attestral-waivers.yaml"
    f.write_text(
        "waivers:\n  - rule_id: ATL-101\n    reason: guardrails accepted\n"
        "    expires: 2027-01-01\n"
    )
    assert _guardrails_data(f) is None


def test_models_list_without_engine_not_detected(tmp_path):
    # A bare models: list is not distinctive; the engine: requirement is.
    f = tmp_path / "models.yml"
    f.write_text("models:\n  - name: bert-base\n  - name: gpt2\n")
    assert _guardrails_data(f) is None


def test_unparseable_yaml_fails_closed(tmp_path):
    f = tmp_path / "config.yml"
    f.write_text("rails:\n  input:\n    flows: ['self check input'\n")
    assert _guardrails_data(f) is None


def test_yaml_heavy_fixture_yields_no_guardrails_components():
    model = build_model("examples/k8s-pack")
    assert model.by_type("guardrails_config") == []
