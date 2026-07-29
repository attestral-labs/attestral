"""compile --target agentgateway: the attested design compiled into a
default-deny credential-broker policy (CB4A Model A/B). The moat closed on the
credential layer - the review IS the broker policy."""
import yaml

from attestral.compile import TARGETS, compile_policy, render_agentgateway
from attestral.ingest import build_model
from attestral.ingest.agentgateway import ingest_agentgateway
from attestral.model import SystemModel
from attestral.rules import RuleEngine


def _policy(fixture: str) -> dict:
    model = build_model(fixture)
    findings = RuleEngine().evaluate(model)
    return compile_policy(model, findings, chain_head="deadbeef")


def _routes(text: str) -> list[dict]:
    doc = yaml.safe_load(text)
    return doc["binds"][0]["listeners"][0]["routes"]


def test_agentgateway_is_a_registered_target():
    assert "agentgateway" in TARGETS
    renderer, filename = TARGETS["agentgateway"]
    assert filename.endswith(".yaml")


def test_only_attested_allowed_servers_are_routable():
    policy = _policy("examples/vulnerable-agent")
    allowed = {n for n, e in policy["servers"].items() if e.get("allow")}
    denied = {n for n, e in policy["servers"].items() if not e.get("allow")}
    assert allowed and denied  # the fixture has both, or the test proves nothing
    routes = {r["name"] for r in _routes(render_agentgateway(policy))}
    assert routes == allowed          # default-deny: denied servers are not emitted
    assert not (routes & denied)


def test_every_route_is_strict_auth_and_a_secret_ref():
    policy = _policy("examples/vulnerable-agent")
    for r in _routes(render_agentgateway(policy)):
        assert r["policies"]["jwtAuth"]["mode"] == "strict"
        auth = r["backends"][0]["backendAuth"]["oauthTokenExchange"]["clientAuth"]
        assert "secretRef" in auth
        assert "clientSecret" not in auth   # never inline


def test_the_header_binds_the_policy_to_the_review():
    text = render_agentgateway(_policy("examples/vulnerable-agent"))
    assert "COMPILED FROM AN ATTESTED DESIGN REVIEW" in text
    assert "model_hash:" in text and "chain_head:" in text


def test_the_compiler_does_not_emit_a_broken_broker(tmp_path):
    # Round-trip: scan the compiler's own output back through the ingester and
    # rules. A policy that compiles to a fail-open or inline-secret broker would
    # be a bug; the review must never produce a config it would itself flag.
    text = render_agentgateway(_policy("examples/vulnerable-agent"))
    (tmp_path / "agentgateway.yaml").write_text(text)
    model = SystemModel()
    ingest_agentgateway(str(tmp_path), model)
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-166" not in ids   # strict inbound auth, never fail-open
    assert "ATL-167" not in ids   # secretRef, never an inline secret
    # and it did emit routes to review in the first place
    assert model.by_type("agentgateway_route")


def test_a_fully_denied_design_compiles_to_an_empty_broker():
    # If the review denies everything, the broker routes nothing - default-deny
    # all the way down, not a broker that quietly allows the denied servers.
    policy = {"metadata": {"model_hash": "h" * 64, "review_chain_head": ""},
              "servers": {"bad": {"allow": False}}}
    routes = _routes(render_agentgateway(policy))
    assert routes == []
