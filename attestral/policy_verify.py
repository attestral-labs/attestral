"""Property verification over the compiled policy: prove security properties, or
find a counterexample.

`compile` emits the attested design as a policy. `narrowing.classify` proves a
re-attestation does not WIDEN a prior. This proves ABSOLUTE security properties
of a single policy - the questions a security reviewer actually asks of an
allow-list:

  - no-secret-exfiltration : the allowed servers do not combine a secret-holding
                             server with an outbound channel (no credential exfil)
  - no-code-exec-egress    : the allowed servers do not combine code execution
                             with an outbound channel (no command-and-control)
  - default-deny           : the policy denies anything not attested
  - remote-allows-are-tls  : every allowed server is TLS-constrained, never plain http

Each property is checked over the compiled policy and reported PROVED, or
VIOLATED with the exact servers that form the counterexample - a witness, not a
vibe. The default-deny posture matters here: a property is proved over the
ALLOWED set, so denying the offending server is always a way to make a violated
property hold.

Structural now, formal next. The Cedar target (`compile --target cedar`) has an
SMT-backed symbolic analyzer that can prove these same properties over all
inputs. When that external analyzer is installed, `cedar_analyzer_available()`
reports it so a formal pass can be layered on; when it is absent - the common
case - the property is evaluated STRUCTURALLY over the compiled policy here,
deterministically and with zero dependencies. "Proved" means over the modeled
policy (scoped to what the policy expresses), never the real world. The method
is always labelled, so a structural check is never mistaken for a formal proof.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field

# Capability classes grouped by the role they play in a toxic flow.
_PRIVATE_DATA = {"database", "saas_data", "memory", "filesystem"}
_EGRESS = {"network", "messaging"}
_CODE_EXEC = {"shell"}


@dataclass
class PropertyResult:
    """One security property, checked over a policy."""
    name: str
    description: str
    holds: bool
    counterexample: list[str] = field(default_factory=list)  # the witness (servers/notes)
    method: str = "structural"                                # structural | cedar-smt


def cedar_analyzer_available() -> bool:
    """True when Cedar's symbolic analyzer CLI is on PATH, so these properties
    could be proved formally rather than structurally."""
    return shutil.which("cedar") is not None


def _allowed(policy: dict) -> dict[str, dict]:
    return {n: e for n, e in (policy.get("servers") or {}).items() if e.get("allow")}


def _caps(entry: dict) -> set[str]:
    return set(entry.get("capabilities") or [])


def _servers_with(allowed: dict[str, dict], capset: set[str]) -> list[str]:
    return sorted(n for n, e in allowed.items() if _caps(e) & capset)


def _secret_holders(allowed: dict[str, dict]) -> list[str]:
    return sorted(
        n for n, e in allowed.items()
        if (e.get("constraints") or {}).get("forbid_env_secrets"))


def _combination(a: list[str], b: list[str]) -> list[str]:
    """The witness for a two-sided toxic-flow property: both sides must be
    non-empty for a flow to exist, and the witness names every server on it."""
    return sorted(set(a) | set(b)) if a and b else []


def _p_no_secret_exfiltration(policy: dict) -> list[str]:
    allowed = _allowed(policy)
    return _combination(_secret_holders(allowed), _servers_with(allowed, _EGRESS))


def _p_no_code_exec_egress(policy: dict) -> list[str]:
    allowed = _allowed(policy)
    return _combination(_servers_with(allowed, _CODE_EXEC), _servers_with(allowed, _EGRESS))


def _p_default_deny(policy: dict) -> list[str]:
    return [] if policy.get("default") == "deny" else [f"default={policy.get('default')!r}"]


def _p_remote_allows_are_tls(policy: dict) -> list[str]:
    bad = []
    for n, e in _allowed(policy).items():
        transport = (e.get("constraints") or {}).get("transport")
        if transport is not None and transport != "tls_only":
            bad.append(n)
    return sorted(bad)


_PROPERTIES = [
    ("no-secret-exfiltration",
     "no allowed server holding a secret can reach an outbound channel",
     _p_no_secret_exfiltration),
    ("no-code-exec-egress",
     "no allowed server with code execution can reach an outbound channel",
     _p_no_code_exec_egress),
    ("default-deny",
     "anything not attested is denied by default",
     _p_default_deny),
    ("remote-allows-are-tls",
     "every allowed server is TLS-constrained, never plain http",
     _p_remote_allows_are_tls),
]


def verify_policy(policy: dict) -> list[PropertyResult]:
    """Check every security property over the compiled policy. Deterministic;
    each result carries its counterexample when violated."""
    # The shipped evaluator is structural; the formal (cedar-smt) path is the
    # opt-in extension documented in the module docstring.
    method = "structural"
    out = []
    for name, desc, fn in _PROPERTIES:
        witness = fn(policy)
        out.append(PropertyResult(name, desc, holds=not witness,
                                  counterexample=witness, method=method))
    return out


def render_verification(results: list[PropertyResult], *, color: bool | None = None) -> str:
    """A proved/violated block for the terminal, with counterexamples."""
    from attestral.report_terminal import _bold, _dim, _paint, supports_color
    if color is None:
        color = supports_color()
    if not results:
        return ""
    proved = sum(1 for r in results if r.holds)
    lines = [_paint(
        f"Policy property verification - {proved}/{len(results)} proved (structural)",
        "1;36", color)]
    for r in results:
        if r.holds:
            tag = _paint("PROVED  ", "32", color)
            lines.append(f"  {tag} {_bold(r.name, color)} {_dim('- ' + r.description, color)}")
        else:
            tag = _paint("VIOLATED", "1;31", color)
            lines.append(f"  {tag} {_bold(r.name, color)} {_dim('- ' + r.description, color)}")
            lines.append(f"           {_dim('counterexample:', color)} {', '.join(r.counterexample)}")
    if cedar_analyzer_available():
        lines.append(_dim(
            "  the Cedar symbolic analyzer is available; these properties can also be "
            "proved formally over the .cedar policy.", color))
    else:
        lines.append(_dim(
            "  structural proof over the compiled policy; install the Cedar analyzer "
            "for a formal (SMT) proof. Proved means over the modeled policy.", color))
    return "\n".join(lines)
