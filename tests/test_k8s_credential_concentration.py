"""ATL-165: a Kubernetes workload whose container env concentrates standing
credentials for many providers is the deployment-manifest counterpart to ATL-164
(CB4A TM-1). The LiteLLM-class gateway lives here, in a Deployment's env, which is
where the holistic corpus sweep showed the concentration pattern actually deploys,
not in a committed MCP config."""
from pathlib import Path

from attestral.ingest import build_model
from _helpers import ids_for

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
FIXTURE = str(EXAMPLES / "k8s-credential-concentration")


def test_multi_provider_container_fires_atl_165():
    assert "ATL-165" in ids_for(FIXTURE)


def test_it_fires_on_the_gateway_container_only():
    model = build_model(FIXTURE)
    gw = next(c for c in model.by_type("k8s_container") if "litellm" in c.id)
    side = next(c for c in model.by_type("k8s_container") if "notes" in c.id)
    assert gw.attr("_credential_concentration") is True
    assert len(gw.attr("_credential_providers")) >= 4
    # a single-provider sidecar in the same pod is not a concentration target
    assert side.attr("_credential_concentration") is False


def test_the_signal_reuses_the_same_provider_families_as_the_mcp_layer():
    # ATL-164 (mcp_server) and ATL-165 (k8s_container) must agree on what a
    # provider is, so a gateway is flagged the same whether declared in .mcp.json
    # or a Deployment. The k8s ingester imports the MCP layer's classifier.
    from attestral.ingest.kubernetes import _env_signals
    sig = _env_signals({"env": [
        {"name": "OPENAI_API_KEY", "valueFrom": {"secretKeyRef": {"name": "k", "key": "o"}}},
        {"name": "ANTHROPIC_API_KEY", "valueFrom": {"secretKeyRef": {"name": "k", "key": "a"}}},
        {"name": "GEMINI_API_KEY", "valueFrom": {"secretKeyRef": {"name": "k", "key": "g"}}},
        {"name": "GROQ_API_KEY", "valueFrom": {"secretKeyRef": {"name": "k", "key": "q"}}},
    ]})
    assert sig["_credential_concentration"] is True
    assert set(sig["_credential_providers"]) == {"openai", "anthropic", "google-ai", "groq"}


def test_three_providers_stay_below_the_threshold():
    from attestral.ingest.kubernetes import _env_signals
    sig = _env_signals({"env": [
        {"name": "OPENAI_API_KEY", "value": "x"},
        {"name": "GITHUB_TOKEN", "value": "x"},
        {"name": "SLACK_BOT_TOKEN", "value": "x"},
    ]})
    assert sig["_credential_concentration"] is False
