"""ATL-168: a docker-compose service or a .env file concentrating standing
credentials for many providers (CB4A TM-1). The deployment-surface counterpart to
ATL-164/165, and the one the holistic corpus sweep showed matters most, because
credential concentration lives in the deployment (compose, .env), not in a
committed MCP config."""
from pathlib import Path

from attestral.ingest import build_model
from attestral.ingest.deployment_env import ingest_deployment_env
from attestral.model import SystemModel
from _helpers import ids_for

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
FIXTURE = str(EXAMPLES / "deployment-concentration")


def _ids_of(tmp_path) -> set[str]:
    m = SystemModel()
    ingest_deployment_env(str(tmp_path), m)
    from attestral.rules import RuleEngine
    return {f.rule_id for f in RuleEngine().evaluate(m)}


def test_compose_and_dotenv_both_fire_atl_168():
    assert "ATL-168" in ids_for(FIXTURE)


def test_it_fires_on_the_gateway_and_env_not_the_single_provider_service():
    model = build_model(FIXTURE)
    surfaces = {c.name: c.attr("_credential_concentration") for c in model.by_type("deployment_env")}
    assert surfaces["llm-gateway"] is True
    assert surfaces[".env"] is True
    assert surfaces["notes"] is False


def test_a_compose_list_style_environment_is_parsed(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  gw:\n"
        "    image: x\n"
        "    environment:\n"
        "      - OPENAI_API_KEY=a\n"
        "      - ANTHROPIC_API_KEY=b\n"
        "      - GEMINI_API_KEY=c\n"
        "      - GROQ_API_KEY=d\n"
    )
    assert "ATL-168" in _ids_of(tmp_path)


def test_a_dotenv_below_the_threshold_is_silent(tmp_path):
    (tmp_path / ".env").write_text("OPENAI_API_KEY=a\nGITHUB_TOKEN=b\nLOG_LEVEL=info\n")
    assert "ATL-168" not in _ids_of(tmp_path)


def test_a_dotenv_template_is_not_ingested(tmp_path):
    # .env.example documents the shape but is not the deployment's real key set,
    # so it is skipped - a template must not be flagged as a live concentration.
    (tmp_path / ".env.example").write_text(
        "OPENAI_API_KEY=\nANTHROPIC_API_KEY=\nGEMINI_API_KEY=\nGROQ_API_KEY=\n"
    )
    m = SystemModel()
    ingest_deployment_env(str(tmp_path), m)
    assert not m.by_type("deployment_env")


def test_a_surface_with_no_provider_credentials_makes_no_component(tmp_path):
    (tmp_path / ".env").write_text("LOG_LEVEL=info\nPORT=8080\nDEBUG=true\n")
    m = SystemModel()
    ingest_deployment_env(str(tmp_path), m)
    assert not m.by_type("deployment_env")
