"""Adversarial self-play: proof-of-exploit per reachable path (issue #82)."""
from pathlib import Path

from attestral.ingest import build_model
from attestral.paths import all_attack_paths
from attestral.selfplay import check_faithfulness, emit_proof_test, proofs_of_exploit

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
TARGET = str(EXAMPLES / "vulnerable-agent")
# vulnerable-agent's path: entry [jira, web] -> pivot [deploy, shell] -> impact [web].
# `filesystem` is a tool surface in the model but NOT on that path - the off-path
# control for the hallucination guard.


def _model_and_path():
    model = build_model(TARGET)
    paths = all_attack_paths(model)
    assert paths, "vulnerable-agent has a reachable path"
    return model, paths[0]


def test_a_scenario_that_stays_on_the_path_is_faithful():
    model, path = _model_and_path()
    good = "web ingests the injected instruction, deploy runs a shell payload, then web exfiltrates the data."
    v = check_faithfulness(good, path, model)
    assert v.on_path and not v.off_path
    assert "pivot" in v.covers and "impact" in v.covers


def test_a_scenario_naming_an_off_path_surface_is_rejected():
    # The hallucination guard: `filesystem` is in the model but not on this path.
    model, path = _model_and_path()
    bad = "filesystem reads the secret key, deploy runs it, and web sends it out."
    v = check_faithfulness(bad, path, model)
    assert not v.on_path
    assert "filesystem" in v.off_path


def test_a_generic_scenario_missing_the_rungs_is_rejected():
    model, path = _model_and_path()
    v = check_faithfulness("An attacker injects a prompt and something bad happens.", path, model)
    assert not v.on_path


def test_the_emitted_test_asserts_a_path_that_truly_exists():
    model, path = _model_and_path()
    src = emit_proof_test(path, TARGET)
    assert "ATTESTRAL_PROOF" in src and "all_attack_paths" in src
    assert repr(path.describe()) in src
    # the assertion the generated test makes is a true statement about the model.
    reachable = {p.describe() for p in all_attack_paths(model)}
    assert path.describe() in reachable


def test_without_a_key_it_still_ships_the_path_and_the_gated_test():
    model = build_model(TARGET)
    proofs = proofs_of_exploit(model, TARGET, query=None)
    assert proofs
    p = proofs[0]
    assert not p.scenario_available
    assert "def test_" in p.test_source and p.path


def test_injected_llm_faithful_vs_hallucinating():
    model = build_model(TARGET)
    faithful = proofs_of_exploit(
        model, TARGET, query=lambda _: "web ingests it, deploy runs a shell, then web exfiltrates.")
    assert faithful[0].scenario_available and faithful[0].faithful.on_path

    hallucinating = proofs_of_exploit(
        model, TARGET, query=lambda _: "filesystem reads the secret, deploy runs it, web exfiltrates.")
    assert not hallucinating[0].faithful.on_path
    assert "filesystem" in hallucinating[0].faithful.off_path
