"""Classify a re-attestation as a narrowing or an expansion of a prior policy.

`attestral compile` turns the reviewed design into a default-deny mcp-guard
policy. This answers the question that makes the compile -> drift loop a
confinement guarantee rather than a one-shot snapshot: is a NEW design's policy a
faithful *narrowing* of the last reviewed one, or does it grant more ambient
capability - a new server, a new capability, a loosened constraint, a dropped or
changed manifest pin - that a human must re-review before it runs?

This is a structural, fail-closed check over the policy envelope, NOT an SMT
proof: SMT-level confinement (Progent) is a future strengthening. Anything the
check cannot classify as clearly narrower is treated as an expansion, so a
re-attestation never silently widens what was reviewed.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Constraint keys whose PRESENCE tightens the envelope. Dropping one (present in
# the prior policy, absent in the new) loosens the server, so it is an expansion.
_TIGHTENING_FLAGS = ("transport", "forbid_env_secrets")


@dataclass
class ServerVerdict:
    name: str
    verdict: str                       # added | removed | expanded | narrowed | equal
    expansions: list[str] = field(default_factory=list)
    narrowings: list[str] = field(default_factory=list)


@dataclass
class NarrowingResult:
    overall: str                       # expansion | narrowing | equal
    servers: list[ServerVerdict]

    @property
    def is_expansion(self) -> bool:
        return self.overall == "expansion"

    @property
    def expansions(self) -> list[str]:
        return [f"{s.name}: {r}" for s in self.servers for r in s.expansions]


def _servers(policy: dict) -> dict[str, dict]:
    return policy.get("servers", {}) if isinstance(policy, dict) else {}


def _roots(entry: dict) -> set[str] | None:
    """The attested filesystem roots, or None when the server is unconstrained
    (which is the widest possible - any root)."""
    c = entry.get("constraints") or {}
    r = c.get("root_paths")
    return set(r) if isinstance(r, list) else None


def _compare_server(prior: dict, new: dict) -> ServerVerdict:
    exp: list[str] = []
    nar: list[str] = []

    # allow / deny. A previously denied server now allowed is the widest expansion.
    p_allow, n_allow = bool(prior.get("allow")), bool(new.get("allow"))
    if n_allow and not p_allow:
        exp.append("was denied by the reviewed design, now allowed")
    elif p_allow and not n_allow:
        nar.append("was allowed, now denied")

    # Capability set.
    p_caps, n_caps = set(prior.get("capabilities") or []), set(new.get("capabilities") or [])
    gained, dropped = sorted(n_caps - p_caps), sorted(p_caps - n_caps)
    if gained:
        exp.append(f"gained capability {gained}")
    if dropped:
        nar.append(f"dropped capability {dropped}")

    # Tightening flags: dropping one loosens the server.
    pc, nc = prior.get("constraints") or {}, new.get("constraints") or {}
    for flag in _TIGHTENING_FLAGS:
        if flag in pc and flag not in nc:
            exp.append(f"dropped the {flag} constraint")
        elif flag not in pc and flag in nc:
            nar.append(f"added the {flag} constraint")

    # Filesystem roots. None = unconstrained (widest). A superset, or dropping the
    # constraint entirely, is an expansion; a strict subset is a narrowing.
    pr, nr = _roots(prior), _roots(new)
    if pr is not None and nr is None:
        exp.append("dropped the filesystem-root constraint (now any root)")
    elif pr is not None and nr is not None:
        if nr - pr:
            exp.append(f"broadened filesystem roots to include {sorted(nr - pr)}")
        elif pr - nr:
            nar.append(f"narrowed filesystem roots (removed {sorted(pr - nr)})")
    elif pr is None and nr is not None:
        nar.append("added a filesystem-root constraint")

    # Manifest pin. A dropped or changed pin means the served tool surface is no
    # longer the reviewed one - re-review it (expansion). A newly-added pin narrows.
    p_pin, n_pin = prior.get("manifest_sha256"), new.get("manifest_sha256")
    if p_pin and not n_pin:
        exp.append("dropped the manifest pin (tool surface no longer bound)")
    elif p_pin and n_pin and p_pin != n_pin:
        exp.append("manifest pin changed (a different tool surface than reviewed)")
    elif not p_pin and n_pin:
        nar.append("added a manifest pin")

    verdict = "expanded" if exp else ("narrowed" if nar else "equal")
    return ServerVerdict(new.get("_name", ""), verdict, exp, nar)


def classify(prior_policy: dict, new_policy: dict) -> NarrowingResult:
    """Classify new_policy against prior_policy. Expansion if any server is added
    or gains ambient capability; narrowing if some server is removed/tightened and
    none expand; equal otherwise. Fail-closed on any per-server expansion."""
    prior, new = _servers(prior_policy), _servers(new_policy)
    verdicts: list[ServerVerdict] = []
    for name in sorted(set(prior) | set(new)):
        if name in new and name not in prior:
            verdicts.append(ServerVerdict(
                name, "added", ["server not present in the reviewed policy"]))
        elif name in prior and name not in new:
            verdicts.append(ServerVerdict(name, "removed", narrowings=["server removed"]))
        else:
            v = _compare_server(prior[name], new[name])
            v.name = name
            verdicts.append(v)

    if any(v.verdict in ("added", "expanded") for v in verdicts):
        overall = "expansion"
    elif any(v.verdict in ("removed", "narrowed") for v in verdicts):
        overall = "narrowing"
    else:
        overall = "equal"
    return NarrowingResult(overall, verdicts)
