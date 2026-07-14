"""SARIF 2.1.0 export.

Renders findings as SARIF so they surface in GitHub Code Scanning (the
Security tab and inline PR annotations) and any other SARIF consumer. The
mapping is deterministic: same findings in, same document out.
"""
from __future__ import annotations

import json

from attestral import __version__
from attestral.model import Finding, Severity, SystemModel

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/attestral-labs/attestral"
HELP_URI = "https://attestral.vercel.app/docs.html"

# SARIF result level. SARIF has four: error, warning, note, none.
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub Code Scanning buckets findings by a numeric `security-severity`
# (0.0-10.0): critical >=9.0, high 7.0-8.9, medium 4.0-6.9, low <4.0.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _uri(source: str) -> str:
    """Normalize a finding's source into a SARIF artifact URI.

    Component findings carry a file path; model-level findings carry a
    non-path label (e.g. "system model"). Every SARIF result needs a
    location, so non-path sources fall back to a stable placeholder.
    """
    s = (source or "").strip().replace("\\", "/")
    if s.startswith("./"):
        s = s[2:]
    if not s or " " in s:
        return "SYSTEM-MODEL"
    return s


def render_sarif(model: SystemModel, findings: list[Finding], target: str) -> str:
    # Rules are deduplicated in first-seen order; results reference them by index.
    rule_index: dict[str, int] = {}
    rules: list[dict] = []
    for f in findings:
        if f.rule_id in rule_index:
            continue
        rule_index[f.rule_id] = len(rules)
        rules.append(
            {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "helpUri": HELP_URI,
                "help": {"text": f.recommendation or f.description or f.title},
                "defaultConfiguration": {"level": _LEVEL[f.severity]},
                "properties": {
                    "tags": ["security", f.origin, *f.framework_refs],
                    "security-severity": _SECURITY_SEVERITY[f.severity],
                },
            }
        )

    from attestral.aivss import score as aivss_score
    results: list[dict] = []
    for f in findings:
        message = f"{f.title}: {f.description}" if f.description else f.title
        if f.recommendation:
            message = f"{message}  Recommendation: {f.recommendation}"
        result = {
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": _LEVEL[f.severity],
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _uri(f.source)},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [
                        {"name": f.component_id, "kind": "resource"}
                    ],
                }
            ],
            # Stable across runs so Code Scanning dedupes the same finding.
            "partialFingerprints": {
                "attestralFindingV1": f"{f.rule_id}:{f.component_id}"
            },
            "properties": {"frameworks": f.framework_refs, "origin": f.origin},
        }
        if f.judge_verdict:
            result["properties"]["judgeVerdict"] = f.judge_verdict
            result["properties"]["judgeConfidence"] = f.judge_confidence
        # Agentic findings carry an OWASP AIVSS Agentic AI Risk Score. SARIF
        # `rank` (0-100) surfaces it in Code Scanning ordering; the full score
        # lands in properties for downstream consumers.
        aars = aivss_score(model, f)
        if aars.factors:
            result["rank"] = round(aars.score * 10, 1)
            result["properties"]["aivss"] = {
                "aars": aars.score,
                "category": aars.category,
                "factors": aars.factors,
                "cvssBase": aars.cvss_base,
                "threatMultiplier": aars.threat_multiplier,
            }
        # A waived finding is a SARIF suppression: Code Scanning shows it as
        # dismissed, with the justification, instead of an open alert.
        if f.waived:
            result["suppressions"] = [
                {"kind": "external", "justification": f.waiver_reason}
            ]
        results.append(result)

    document = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Attestral",
                        "informationUri": INFO_URI,
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {"target": target},
            }
        ],
    }
    return json.dumps(document, indent=2)
