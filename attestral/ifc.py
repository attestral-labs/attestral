"""Information-flow lattice over the system model (roadmap M6).

The lethal-trifecta (ATL-202) and taint-flow (ATL-207) findings are heuristic:
named capability groups co-occurring in one agent session. This layer attaches
confidentiality and integrity labels to each tool surface by capability, so the
same flow becomes a defensible *property* rather than a severity with an opinion:

- confidentiality: a HIGH source (reads private data) can reach a LOW egress sink
  (data leaves the trust boundary) with no declassifier on the path;
- integrity: a LOW source (attacker-influenceable input) can reach a HIGH sink
  (a trust-critical action) with no endorser on the path.

This is the classic Denning lattice specialized to an agent's tool fleet, and it
is what makes the finding citable (FIDES, CaMeL) instead of "these capabilities
co-occur". A declassifier / endorser is a modeled mitigation step that breaks the
flow. The first one is now detected: an egress sink constrained to an allowlist
(mcp.py's `_egress_allowlisted`, the fix ATL-202 recommends) declassifies the
confidentiality half, so ATL-217 clears that flow while the coarse ATL-202/207
still fire on the raw capability co-occurrence - the precise-vs-heuristic
difference the lattice exists for. The integrity half still fires whenever the
flow exists: an endorser (validation / human approval on the trust-critical sink)
is not modeled yet, and egress allowlisting does not clear it, because an
allowlisted fetch tool still ingests untrusted content.
"""
from __future__ import annotations

from dataclasses import dataclass

from attestral.model import SystemModel

# Capability -> lattice position.
# Confidentiality dimension: reads secret data (source) vs. lets data leave (sink).
_CONF_SOURCE = frozenset({"filesystem", "database", "saas_data", "memory"})
_EGRESS_SINK = frozenset({"network", "messaging"})
# Integrity dimension: ingests untrusted content (source) vs. acts on trust (sink).
_UNTRUSTED_SOURCE = frozenset({"network", "saas_data", "memory"})
_TRUSTED_SINK = frozenset({"shell"})
# Modeled mitigations that break a flow. None emitted yet; kept as the extension
# point so the lattice is future-correct rather than always-on.
@dataclass(frozen=True)
class Violation:
    kind: str              # "confidentiality" | "integrity"
    sources: tuple[str, ...]
    sinks: tuple[str, ...]
    justification: str


def _surfaces(model: SystemModel):
    """(component, capability set) over every tool surface, composing the
    delegation hop the same way the capability rules do."""
    return [(c, set(c.attr("_capabilities") or [])) for c in model.tool_surfaces()]


def _names(surfaces, cap_filter, *, exclude_allowlisted=False) -> tuple[str, ...]:
    out = set()
    for c, caps in surfaces:
        if not caps & cap_filter:
            continue
        if exclude_allowlisted and c.attr("_egress_allowlisted"):
            continue  # egress constrained to an allowlist: declassified, skip
        out.add(c.name)
    return tuple(sorted(out))


def declassified_egress(model: SystemModel) -> tuple[str, ...]:
    """Egress sinks whose outbound reach is constrained to an allowlist - the
    declassifier ATL-202 recommends, which breaks the confidentiality flow."""
    return tuple(sorted(
        c.name for c, caps in _surfaces(model)
        if caps & _EGRESS_SINK and c.attr("_egress_allowlisted")
    ))


def has_declassifier(model: SystemModel) -> bool:
    """True if any egress sink is allowlist-declassified."""
    return bool(declassified_egress(model))


def violations(model: SystemModel) -> list[Violation]:
    """Every information-flow lattice violation. A confidentiality violation
    clears when every egress sink is allowlist-declassified; integrity fires
    whenever the flow exists (no endorser signal is modeled yet)."""
    surfaces = _surfaces(model)
    out: list[Violation] = []

    # Confidentiality: a high source can reach an OPEN (non-allowlisted) egress.
    csrc = _names(surfaces, _CONF_SOURCE)
    open_egress = _names(surfaces, _EGRESS_SINK, exclude_allowlisted=True)
    if csrc and open_egress:
        declassed = declassified_egress(model)
        note = (f" (allowlist-declassified egress [{', '.join(declassed)}] excluded)"
                if declassed else "")
        out.append(Violation(
            "confidentiality", csrc, open_egress,
            f"High-confidentiality source(s) [{', '.join(csrc)}] can reach "
            f"low-confidentiality egress sink(s) [{', '.join(open_egress)}] with no "
            f"declassifier on the path, so confidential data can leave the boundary{note}.",
        ))

    # Integrity: no endorser (validation / approval) signal is modeled yet, so
    # this fires whenever the labelled flow exists. Egress allowlisting does not
    # clear it - an allowlisted fetch tool still ingests untrusted content.
    isrc = _names(surfaces, _UNTRUSTED_SOURCE)
    tsink = _names(surfaces, _TRUSTED_SINK)
    if isrc and tsink:
        out.append(Violation(
            "integrity", isrc, tsink,
            f"Low-integrity source(s) [{', '.join(isrc)}] can reach high-integrity "
            f"sink(s) [{', '.join(tsink)}] with no endorser on the path, so untrusted "
            "input can drive a trust-critical action.",
        ))
    return out
