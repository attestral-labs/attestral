"""agentgateway credential-broker review (CB4A job b: does the declared broker
actually kill the standing credential). ATL-166 fail-open inbound auth (TM-9),
ATL-167 inlined client secret (TM-1). The ingester recognizes both the standalone
`binds` config and the Kubernetes AgentgatewayPolicy CRD, and a well-configured
route stays silent."""
from pathlib import Path

import yaml

from attestral.ingest import build_model
from attestral.ingest.agentgateway import ingest_agentgateway
from attestral.model import SystemModel
from _helpers import ids_for

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
FIXTURE = str(EXAMPLES / "agentgateway-broker")


def test_fail_open_route_fires_atl_166():
    assert "ATL-166" in ids_for(FIXTURE)


def test_inline_client_secret_fires_atl_167():
    assert "ATL-167" in ids_for(FIXTURE)


def test_the_well_configured_route_is_silent():
    model = build_model(FIXTURE)
    good = next(c for c in model.by_type("agentgateway_route") if c.name == "well-configured")
    assert good.attr("_fail_open") is False
    assert good.attr("_inline_client_secret") is False
    assert good.attr("_brokers_credential") is True   # it still brokers, just correctly


def _write(tmp_path, text):
    (tmp_path / "gw.yaml").write_text(text)
    m = SystemModel()
    ingest_agentgateway(str(tmp_path), m)
    return m


def test_crd_form_is_recognized(tmp_path):
    m = _write(tmp_path, yaml.safe_dump({
        "apiVersion": "agentgateway.dev/v1alpha1",
        "kind": "AgentgatewayPolicy",
        "metadata": {"name": "okta"},
        "spec": {"backend": {"auth": {"oauthTokenExchange": {
            "clientAuth": {"clientId": "gw", "clientSecret": "literal-secret-value"}}}}},
    }))
    route = next(iter(m.by_type("agentgateway_route")))
    assert route.attr("_brokers_credential") is True
    assert route.attr("_inline_client_secret") is True
    # a CRD does not express inbound auth, so fail-open is not asserted here
    assert route.attr("_fail_open") is False


def test_env_reference_and_secret_ref_are_not_inline_secrets(tmp_path):
    m = _write(tmp_path, yaml.safe_dump({
        "binds": [{"port": 3000, "listeners": [{"routes": [{
            "name": "r", "policies": {"jwtAuth": {"mode": "strict"}},
            "backends": [{"backendAuth": {"oauthTokenExchange": {
                "clientAuth": {"clientId": "gw", "clientSecret": "${OAUTH_SECRET}"}}}}],
        }]}]}],
    }))
    route = next(iter(m.by_type("agentgateway_route")))
    assert route.attr("_inline_client_secret") is False   # env ref is the good pattern
    assert route.attr("_fail_open") is False               # strict inbound auth


def test_a_bare_listener_with_no_backend_is_not_a_route(tmp_path):
    m = _write(tmp_path, yaml.safe_dump({
        "binds": [{"port": 8080, "listeners": [{"routes": [{
            "name": "healthz", "matches": [{"path": {"pathPrefix": "/healthz"}}],
        }]}]}],
    }))
    # no backend is fronted, so there is no credential-broker surface to review
    assert not list(m.by_type("agentgateway_route"))
