"""Signed agent-capability-posture predicate: what the agent CAN do, attested.

A conformance attestation (`attest.py`) says "the running system matches the
reviewed design." A capability-posture predicate answers a different, earlier
question a platform or another agent asks *before* it trusts a tool: what is this
agent's capability envelope, does its tool fleet form a lethal trifecta, and what
named cloud infrastructure can it reach? It binds that posture to the design
digest and signs it, so a gate - a Kyverno policy, a cosign verifier, an
admission controller - can verify the agent's declared capabilities offline,
without trusting the runtime or re-running the scanner.

This is an in-toto predicate (predicateType
`https://attestral.dev/predicate/agent-capability-posture/v1`) in the same DSSE
envelope `attest`/`sign` use, so it slots into the SLSA / in-toto / Sigstore
tooling that already verifies image and provenance attestations. The vocabulary -
a structured, signed statement of an agent's capability posture - is the
contribution: a per-resource linter has no capability model to attest, and a
runtime guardrail has nothing to sign. Zero dependencies for the structure and
every re-derivation; only the signature step needs the `attestral[sign]` extra,
so an unsigned posture (all fields still bound to the design digest) needs no
install.
"""
from __future__ import annotations

from attestral import __version__
from attestral.attest import STATEMENT_TYPE, VERIFIER_ID, _model_hash, _review

POSTURE_PREDICATE_TYPE = "https://attestral.dev/predicate/agent-capability-posture/v1"


def _cross_boundary_reach(model) -> list[str]:
    """The agent->named-cloud reaches in the design as stable `entry -> sink`
    strings (ATL-222's substrate), so the posture names the infrastructure an
    injectable surface can be laundered into. Empty when the design has none."""
    from attestral.cloudreach import cross_boundary_reaches

    out: set[str] = set()
    for r in cross_boundary_reaches(model):
        for s in r.sinks:
            out.add(f"{r.entry} -> {s}")
    return sorted(out)


def _posture_predicate(model, findings, head, signer, generated_at, version) -> dict:
    """The capability posture: per-surface capabilities, the fleet-wide envelope,
    and the two capability-risk verdicts (lethal trifecta, cross-boundary reach).
    Deterministic and re-derivable, so verify can recompute it from the design."""
    surfaces = sorted(
        (
            {
                "name": c.name,
                "type": c.type,
                "capabilities": sorted(c.attr("_capabilities") or []),
            }
            for c in model.tool_surfaces()
        ),
        key=lambda s: (s["type"], s["name"]),
    )
    envelope = sorted({cap for s in surfaces for cap in s["capabilities"]})
    trifecta = "ATL-202" in {f.rule_id for f in findings}
    reach = _cross_boundary_reach(model)
    return {
        "designDigest": {"sha256": _model_hash(model)},
        "reviewChainHead": head,
        "toolSurfaces": surfaces,
        "toolSurfaceCount": len(surfaces),
        "capabilityEnvelope": envelope,
        "lethalTrifecta": trifecta,
        "crossBoundaryReach": reach,
        # The capability-risk verdict a gate keys on: a fleet that forms a lethal
        # trifecta or reaches named infrastructure is a posture worth refusing.
        "posture": "flagged" if (trifecta or reach) else "clean",
        "verifier": {"id": VERIFIER_ID, "version": {"attestral": version}},
        "signer": signer,
        "generated_at": generated_at,
    }


def build_posture_statement(
    path: str, signer: str = "", version: str = __version__, generated_at: str = "",
) -> dict:
    """The in-toto Statement for the agent's capability posture (no signature).
    `generated_at` and `signer` are recorded, never recomputed by verify."""
    model, findings, _chain, head = _review(path)
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": path, "digest": {"sha256": _model_hash(model)}}],
        "predicateType": POSTURE_PREDICATE_TYPE,
        "predicate": _posture_predicate(
            model, findings, head, signer, generated_at, version
        ),
    }


def build_posture_bundle(
    path: str, private_pem: str | None = None, signer: str = "",
    version: str = __version__, generated_at: str = "",
) -> dict:
    """`{statement, envelope}`. Unsigned when no key is given (envelope null, all
    fields still bound to the design digest - the zero-dep graceful degrade)."""
    statement = build_posture_statement(
        path, signer=signer, version=version, generated_at=generated_at
    )
    envelope = None
    if private_pem:
        from attestral.signing import sign_statement

        envelope = sign_statement(statement, private_pem, signer=signer)
    return {"statement": statement, "envelope": envelope}


# Predicate fields excluded from re-derivation equality: recorded, not recomputed.
_RECORDED_ONLY = {"signer", "generated_at"}


def verify_posture(
    bundle: dict, path: str, public_pem: str | None = None,
) -> tuple[bool, list[str]]:
    """Re-derive the posture from the SUPPLIED design and compare every bound
    field; check the signature if a key is given. Returns (passed, failing_steps).
    Fail-closed: any mismatch fails. A design that gained a capability, formed a
    trifecta, or opened a cross-boundary reach since signing fails to verify."""
    failures: list[str] = []
    statement = bundle.get("statement") or {}
    predicate = statement.get("predicate") or {}

    if statement.get("_type") != STATEMENT_TYPE:
        failures.append("statement._type")
    if statement.get("predicateType") != POSTURE_PREDICATE_TYPE:
        failures.append("statement.predicateType")

    model, findings, _chain, head = _review(path)
    recomputed = _posture_predicate(
        model, findings, head,
        predicate.get("signer", ""), predicate.get("generated_at", ""),
        # version is recorded under verifier; compare the whole recomputed block
        predicate.get("verifier", {}).get("version", {}).get("attestral", __version__),
    )
    # subject digest binds the design itself.
    subject = (statement.get("subject") or [{}])[0]
    if subject.get("digest", {}).get("sha256") != _model_hash(model):
        failures.append("subject.digest")
    for key, want in recomputed.items():
        if key in _RECORDED_ONLY:
            continue
        if predicate.get(key) != want:
            failures.append(f"predicate.{key}")

    if public_pem is not None:
        from attestral.signing import envelope_payload, verify_envelope

        envelope = bundle.get("envelope")
        if not envelope:
            failures.append("signature")
        else:
            sig_ok = verify_envelope(envelope, public_pem)
            bound_ok = envelope_payload(envelope) == statement
            if not (sig_ok and bound_ok):
                failures.append("signature")

    return (not failures, failures)


def posture_delta(prior: dict, current: dict) -> dict:
    """How the current capability posture WIDENS a prior one. Widening is the only
    direction that matters for a gate: an agent that gained a capability class,
    newly formed a lethal trifecta, or opened a cross-boundary reach it did not
    have when the prior posture was signed must be re-reviewed and re-attested. A
    narrowing (capabilities removed) is always safe and never fails. Both args are
    posture PREDICATE dicts."""
    prior_env = set(prior.get("capabilityEnvelope") or [])
    cur_env = set(current.get("capabilityEnvelope") or [])
    prior_reach = set(prior.get("crossBoundaryReach") or [])
    cur_reach = set(current.get("crossBoundaryReach") or [])
    added_caps = sorted(cur_env - prior_env)
    added_reach = sorted(cur_reach - prior_reach)
    trifecta_formed = bool(current.get("lethalTrifecta")) and not prior.get("lethalTrifecta")
    return {
        "addedCapabilities": added_caps,
        "trifectaFormed": trifecta_formed,
        "addedReach": added_reach,
        "widened": bool(added_caps or trifecta_formed or added_reach),
    }


def render_posture_delta(delta: dict, *, color: bool | None = None) -> str:
    from attestral.report_terminal import _dim, _paint, supports_color

    if color is None:
        color = supports_color()
    if not delta["widened"]:
        return _paint("POSTURE: NARROWING or UNCHANGED - the agent gained no "
                      "capability, trifecta, or reach.", "1;32", color)
    lines = [_paint("POSTURE: WIDENED - the agent gained capability since the "
                    "attested posture:", "1;31", color), ""]
    if delta["addedCapabilities"]:
        lines.append(f"  {_dim('new capability classes:', color)} "
                     + ", ".join(delta["addedCapabilities"]))
    if delta["trifectaFormed"]:
        lines.append(f"  {_dim('newly forms a', color)} "
                     + _paint("lethal trifecta", "1;31", color))
    if delta["addedReach"]:
        lines.append(f"  {_dim('new cross-boundary reach:', color)}")
        for r in delta["addedReach"][:6]:
            lines.append(f"    {r}")
        if len(delta["addedReach"]) > 6:
            lines.append(f"    (+{len(delta['addedReach']) - 6} more)")
    lines.append("")
    lines.append(_dim("Re-review and re-sign the posture, or revert the change. A "
                      "widening must not slip past a signed capability baseline.", color))
    return "\n".join(lines)


def verify_posture_runtime(statement: dict, events: list[dict]) -> tuple[bool, list[dict]]:
    """Check the runtime stayed within the attested capability envelope. A telemetry
    event that positively exercised a modeled capability class the posture never
    attested is a violation: the agent did more than its attested posture allows.
    Fleet-level complement to drift's per-server DRF-008, sharing the same
    fail-closed comparison (`model.capabilities_outside_envelope`) so the two never
    disagree - only a positively observed, MODELED token outside the envelope
    fires; an absent, unknown, or malformed `capabilities` field never fires.

    This trusts the `capabilityEnvelope` in the supplied statement; it does NOT
    verify the signature - authenticity is the caller's job (`verify_posture` with
    a `--public-key`, which re-derives the envelope from the design and would catch
    a tampered field). Returns (ok, violations)."""
    from attestral.model import capabilities_outside_envelope

    envelope = (statement.get("predicate") or {}).get("capabilityEnvelope") or []
    violations: list[dict] = []
    for i, ev in enumerate(events, 1):
        for cap in capabilities_outside_envelope(ev.get("capabilities"), envelope):
            violations.append({
                "event": i,
                "server": str(ev.get("server", "")),
                "capability": cap,
            })
    return (not violations, violations)


def render_posture(statement: dict, *, color: bool | None = None) -> str:
    from attestral.report_terminal import _bold, _dim, _paint, supports_color

    if color is None:
        color = supports_color()
    p = statement.get("predicate") or {}
    posture = p.get("posture", "?")
    head_color = "1;31" if posture == "flagged" else "1;32"
    lines = [_paint(f"AGENT CAPABILITY POSTURE: {posture.upper()}", head_color, color), ""]
    env = p.get("capabilityEnvelope") or []
    lines.append(f"  {_dim('capability envelope:', color)} "
                 + (", ".join(env) if env else "(none)"))
    lines.append(f"  {_dim('tool surfaces:', color)} {p.get('toolSurfaceCount', 0)}")
    lines.append(f"  {_dim('lethal trifecta:', color)} "
                 + (_bold("YES", color) if p.get("lethalTrifecta") else "no"))
    reach = p.get("crossBoundaryReach") or []
    if reach:
        lines.append(f"  {_dim('cross-boundary reach:', color)}")
        for r in reach[:6]:
            lines.append(f"    {r}")
        if len(reach) > 6:
            lines.append(f"    (+{len(reach) - 6} more)")
    signed = "signed" if statement.get("_envelope_present") else "unsigned"
    lines.append("")
    lines.append(_dim(
        "A signed, offline-verifiable statement of what this agent can do "
        f"(predicateType agent-capability-posture/v1). {signed}. A gate can verify "
        "it with cosign / Kyverno without trusting the runtime.", color))
    return "\n".join(lines)
