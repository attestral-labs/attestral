"""Tier-0 adversarial validation: symbolic proof-of-traversability.

Every proof must (a) assemble only from a complete attack path the model
already exposes, (b) name the mechanism at each rung, and (c) land in the
evidence chain as a `redteam`-origin finding. A design with no complete path
proves nothing - the empty result is itself attestable.
"""
from pathlib import Path

from attestral.evidence import audit_chain, verify_chain
from attestral.ingest import build_model
from attestral.model import Severity
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
