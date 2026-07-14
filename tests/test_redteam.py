"""Tier-0 adversarial validation: symbolic proof-of-traversability.

Every proof must (a) assemble only from a complete attack path the model
already exposes, (b) name the mechanism at each rung, and (c) land in the
evidence chain as a `redteam`-origin finding. A design with no complete path
proves nothing - the empty result is itself attestable.
"""
from pathlib import Path

from attestral import redteam
from attestral.evidence import audit_chain, verify_chain
from attestral.ingest import build_model
from attestral.model import Severity
from attestral.paths import all_attack_paths
from attestral.redteam import build_proofs, proof_findings

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_internal_chain_is_proven():
    model = build_model(str(EXAMPLES / "vulnerable-agent"))
    proofs = build_proofs(model)
    assert proofs, "vulnerable-agent has a complete internal chain"
    internal = [p for p in proofs if p.kind == "internal"]
    assert internal
    p = internal[0]
    roles = {s.role for s in p.steps}
    assert roles == {"entry", "pivot", "impact"}
    assert any(s.role == "pivot" and "shell" in s.via for s in p.steps)
    assert p.outcome == "traversable"
    assert p.severity == Severity.HIGH


def test_external_chain_names_public_entry():
    model = build_model(str(EXAMPLES / "attack-path"))
    proofs = build_proofs(model)
    external = [p for p in proofs if p.kind == "external"]
    assert external, "attack-path exposes a public A2A endpoint chain"
    p = external[0]
    assert p.severity == Severity.CRITICAL
    entry = next(s for s in p.steps if s.role == "entry")
    assert "public A2A" in entry.via
    assert any("internet" in b for b in p.boundaries)


def test_clean_design_proves_nothing():
    model = build_model(str(EXAMPLES / "aws-pack"))
    assert build_proofs(model) == []


def test_proofs_land_in_evidence_chain():
    model = build_model(str(EXAMPLES / "attack-path"))
    findings = proof_findings(model)
    assert findings
    assert all(f.origin == "redteam" for f in findings)
    assert all(f.rule_id.startswith("ATL-RT-") for f in findings)
    chain = audit_chain(findings)
    assert verify_chain(chain), "proofs must verify as a tamper-evident chain"


def test_action_space_enumerates_more_than_the_collapsed_chain():
    model = build_model(str(EXAMPLES / "vulnerable-agent"))
    seqs = redteam.action_space(model)
    assert seqs
    assert all(s.entry and s.pivot and s.impact for s in seqs)
    assert len(seqs) >= len(all_attack_paths(model))


def test_verified_remediations_are_proven_by_resynthesis():
    model = build_model(str(EXAMPLES / "vulnerable-agent"))
    rems = redteam.verified_remediations(model)
    assert rems
    # at least one fix drops the path count to zero, verified by re-synthesis
    assert any(r.eliminates_all and r.verified for r in rems)
    assert all(r.paths_before > 0 for r in rems)
    # a fix must not raise the agentic risk posture, and at least one lowers it
    assert all(r.aars_after <= r.aars_before for r in rems)
    assert any(r.aars_after < r.aars_before for r in rems)


def test_remediation_never_mutates_the_original_model():
    model = build_model(str(EXAMPLES / "vulnerable-agent"))
    before = len(all_attack_paths(model))
    redteam.verified_remediations(model)
    assert len(all_attack_paths(model)) == before


def test_sandbox_execution_moves_the_canary_deterministically():
    model = build_model(str(EXAMPLES / "vulnerable-agent"))
    path = all_attack_paths(model)[0]
    run = redteam.execute_in_sandbox(model, path)
    assert run.exfiltrated
    assert len(run.steps) == 3                       # entry, pivot, impact
    assert run.canary in run.steps[-1].observed      # canary reached the sink
    assert run.canary.startswith("ATTESTRAL-CANARY-")
    # deterministic: same path -> same canary, no randomness
    assert redteam.execute_in_sandbox(model, path).canary == run.canary


def test_generative_tier_uses_injectable_query_and_skips_without_key():
    import os

    model = build_model(str(EXAMPLES / "vulnerable-agent"))
    path = all_attack_paths(model)[0]
    draft = redteam.draft_exploit(model, path, query=lambda p: "PREDICTED " + path.kind)
    assert "PREDICTED" in draft.text and draft.note == "predicted, not executed"
    saved = {k: os.environ.pop(k, None) for k in ("ANTHROPIC_API_KEY", "ATTESTRAL_LLM_API_KEY")}
    try:
        skip = redteam.draft_exploit(model, path)
        assert skip.text == "" and "skipped" in skip.note
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
