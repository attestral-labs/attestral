"""ATL-151: a secret hard-coded in an agent-instruction file (OWASP LLM07)."""
from pathlib import Path

import pytest

from attestral.ingest import build_model
from attestral.ingest.prompts import _embedded_secret
from attestral.rules import RuleEngine

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _ids(fixture_dir: str) -> set[str]:
    return {f.rule_id for f in RuleEngine().evaluate(build_model(fixture_dir))}


# --- the detector, unit-level ---------------------------------------------- #

@pytest.mark.parametrize("text,kind", [
    ("token: ghp_1a2b3c4d5e6f7g8h9i0jKLMNOPqrstuvwxyZ", "github-token"),
    ("key AKIAIOSFODNN7EXAMPLE is set", "aws-access-key"),
    ("url = postgres://u:reallysecret99@db.internal/prod", "db-uri-with-credentials"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIE...", "private-key-block"),
    ("api_key = Ax93kfLZ0qWmn4Rt7Yp2Vc8Bd6He1Su", "credential-assignment"),
])
def test_credential_shapes_are_detected(text, kind):
    assert kind in _embedded_secret(text)


@pytest.mark.parametrize("benign", [
    "Set your API key with `export DEPLOY_API_KEY=...` before running.",
    "Store the token in a secret manager; never hardcode it: api_key: <your-key-here>.",
    "The password must be at least 12 characters and rotated every 90 days.",
    "Reads DATABASE_URL from the environment. Do not commit real credentials.",
    "A JWT has three base64url parts separated by dots.",
    "api_key = your_api_key_here_placeholder",
])
def test_benign_prompt_text_does_not_fire(benign):
    assert _embedded_secret(benign) == []


# --- the rule, on the shipped fixture -------------------------------------- #

def test_embedded_secret_fixture_fires_atl_151():
    assert "ATL-151" in _ids(str(EXAMPLES / "prompt-embedded-secret"))


def test_the_kinds_are_recorded_on_the_component():
    model = build_model(str(EXAMPLES / "prompt-embedded-secret"))
    comp = next(c for c in model.components if c.attr("_embedded_secret"))
    assert comp.type == "agent_instruction"
    assert "github-token" in comp.attr("_embedded_secret_kinds")
