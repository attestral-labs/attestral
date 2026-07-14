"""OWASP AIVSS - Agentic AI Risk Score (AARS).

Standard CVSS scores the underlying flaw; it does not capture the risk an
*autonomous agent* adds by acting on that flaw. The OWASP AIVSS framework layers
an agentic score on top. This is Attestral's implementation of the AIVSS AARS
model: because Attestral reviews design rather than CVEs, the CVSS base is taken
from the finding's severity band, and the Agentic Risk Amplification Factors
(AARFs) are read from the modeled component's capabilities and the finding's
framework tags.

    AARS = min(10, (10 - cvss_base + factor_sum) * threat_multiplier)

    10 - cvss_base    : the amplification headroom autonomy adds (a low-CVSS but
                        highly-agentic finding still scores high - that is the
                        point AIVSS makes that CVSS alone misses).
    factor_sum (0-10) : the Agentic Risk Amplification Factors that apply.
    threat_multiplier : 0.6-1.0 for live exploit maturity; a path that
                        `attestral validate` has *proven* traversable scores 1.0.

AARS is a different axis from severity - it measures agentic amplification, so a
finding whose AARS outranks its CVSS severity is exactly the one CVSS-only triage
would under-rate. Off by default; surfaced with `attestral scan --aivss`.

Frameworks: OWASP AIVSS (AARS), OWASP Top 10 for Agentic Applications (ASI),
OWASP Top 10 for LLM Applications (LLM).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from attestral.model import Finding, SystemModel

# Severity band -> a CVSS-base proxy (Attestral scores design, not CVEs).
_CVSS = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "info": 1.0}

# OWASP Top 10 for Agentic Applications (ASI) and for LLM Applications (LLM).
_ASI = {
    "ASI01": "Agent Goal Hijack", "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse", "ASI04": "Agentic Supply Chain",
    "ASI05": "Unexpected Code Execution", "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication", "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation", "ASI10": "Rogue Agents",
}
_LLM = {
    "LLM01": "Prompt Injection", "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain", "LLM04": "Data & Model Poisoning",
    "LLM05": "Improper Output Handling", "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage", "LLM08": "Vector & Embedding Weaknesses",
    "LLM09": "Misinformation", "LLM10": "Unbounded Consumption",
}


@dataclass
class AARS:
    """An Agentic AI Risk Score for one finding."""
    score: float
    cvss_base: float
    factor_sum: float
    threat_multiplier: float
    factors: list[str] = field(default_factory=list)
    category: str = ""            # e.g. "ASI02 Tool Misuse & Exploitation"


def _factors(model: "SystemModel", f: "Finding") -> list[str]:
    """The Agentic Risk Amplification Factors that apply to a finding. For a
    component finding they are read from that component; for a model-level
    (fleet) finding they are read from the whole fleet, because a compositional
    risk like the lethal trifecta *is* the whole fleet acting together."""
    out: list[str] = []
    servers = list(model.by_type("mcp_server"))
    if f.component_id == "model":
        caps: set[str] = set()
        for c in servers + list(model.by_type("subagent")):
            caps |= set(c.attr("_capabilities") or [])
        auto = any(c.attr("_auto_approve") for c in servers)
        cloud = any(c.attr("_has_cloud_credentials") for c in servers)
        out.append("Compositional (fleet-level) risk")
    else:
        c = model.get(f.component_id)
        caps = set(c.attr("_capabilities") or []) if c else set()
        auto = bool(c and c.attr("_auto_approve"))
        cloud = bool(c and c.attr("_has_cloud_credentials"))
    fw = " ".join(f.framework_refs).upper()
    if "shell" in caps:
        out.append("Rogue actions / tool misuse")
    if caps & {"network", "messaging"}:
        out.append("Autonomous egress channel")
    if "memory" in caps:
        out.append("Memory & context poisoning")
    if caps & {"database", "saas_data", "filesystem"}:
        out.append("Sensitive-data access")
    if auto:
        out.append("No human checkpoint")
    if cloud:
        out.append("Identity & privilege abuse")
    if f.origin == "ml" or "LLM01" in fw or "INJECTION" in fw:
        out.append("Prompt-injection exposure")
    if any(k in fw for k in ("ASI04", "SUPPLY", "CVE")):
        out.append("Agentic supply chain")
    if any(k in fw for k in ("ASI07", "ASI08", "A2A")):
        out.append("Multi-agent / cascading")
    return out


def _category(f: "Finding", factors: list[str]) -> str:
    """The finding's primary OWASP Agentic/LLM Top-10 category: read from an
    explicit framework tag, else inferred from the dominant factor."""
    fw = " ".join(f.framework_refs).upper()
    for code, name in {**_ASI, **_LLM}.items():
        if code in fw:
            return f"{code} {name}"
    joined = " ".join(factors)
    if f.origin == "ml" or "injection" in joined.lower():
        return "LLM01 Prompt Injection"
    if "Identity" in joined:
        return "ASI03 Identity & Privilege Abuse"
    if "Memory" in joined:
        return "ASI06 Memory & Context Poisoning"
    if "Rogue" in joined or "checkpoint" in joined:
        return "ASI05 Unexpected Code Execution"
    if "egress" in joined or "Sensitive" in joined:
        return "ASI02 Tool Misuse & Exploitation"
    return "LLM06 Excessive Agency"


def score(model: "SystemModel", f: "Finding") -> AARS:
    """Compute the Agentic AI Risk Score (AARS) for one finding."""
    cvss = _CVSS.get(f.severity.value, 5.0)
    factors = _factors(model, f)
    factor_sum = min(10.0, len(factors) * 2.0)
    proven = f.origin == "redteam" or f.rule_id.startswith("ATL-RT")
    cve = "CVE" in " ".join(f.framework_refs).upper()
    thm = 1.0 if (proven or cve) else (0.85 if factors else 0.6)
    aars = min(10.0, (10.0 - cvss + factor_sum) * thm)
    return AARS(round(aars, 1), cvss, factor_sum, thm, factors, _category(f, factors))


def scored(model: "SystemModel", findings: list["Finding"]) -> list[tuple[AARS, "Finding"]]:
    """Every non-waived agentic finding (one with at least one AARF), ranked by
    AARS descending. Findings with no agentic factor are not scored."""
    out = [(score(model, f), f) for f in findings if not f.waived]
    out = [(a, f) for a, f in out if a.factors]
    out.sort(key=lambda x: x[0].score, reverse=True)
    return out


def render_aivss(model: "SystemModel", findings: list["Finding"], *,
                 color: bool | None = None, limit: int = 8) -> str:
    """A ranked Agentic AI Risk Score block for the terminal report. Empty when
    no finding carries an agentic amplification factor."""
    from attestral.report_terminal import _SEV_COLOR, _bold, _dim, _paint, supports_color
    if color is None:
        color = supports_color()
    rows = scored(model, findings)
    if not rows:
        return ""
    lines = [_paint(f"Agentic AI Risk Score (OWASP AIVSS) - top {min(limit, len(rows))} of {len(rows)}",
                    _SEV_COLOR["critical"], color)]
    for a, f in rows[:limit]:
        band = "critical" if a.score >= 9 else "high" if a.score >= 7 else "medium" if a.score >= 4 else "low"
        badge = _paint(f"AARS {a.score:>4.1f}", _SEV_COLOR[band], color)
        lines.append(f"  {badge}  {_bold(f.rule_id, color)}  {_dim(a.category, color)}")
        lines.append(f"    {_dim('factors:', color)} {', '.join(a.factors)}")
    lines.append(_dim(
        "  AARS = min(10, (10 - CVSS_base + factor_sum) * threat) - agentic "
        "amplification, a different axis from CVSS severity", color))
    return "\n".join(lines)
