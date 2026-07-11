"""Optional LLM threat elicitation layer.

Runs only when --llm is passed and ANTHROPIC_API_KEY is set. Findings from
this layer are tagged origin="llm" and never mixed silently with the
deterministic layer - regulated buyers need to know which is which.
"""
from __future__ import annotations

import json
import os

from attestral.model import Finding, Severity, SystemModel

_SYSTEM = (
    "You are a principal security engineer performing a design review. "
    "Given a JSON system model (components, edges, trust boundaries), identify "
    "design-level threats the deterministic rules would miss: authn/authz gaps, "
    "trust-boundary violations, agentic risks (prompt-injection paths, tool "
    "permission escalation, handoff confusion). Respond ONLY with a JSON array; "
    "each item: {\"title\", \"severity\" (critical|high|medium|low|info), "
    "\"component_id\", \"description\", \"recommendation\"}. No markdown, no preamble."
)


def elicit(model: SystemModel, max_findings: int = 10) -> list[Finding]:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return []
    try:
        import anthropic
    except ImportError:
        return []
    client = anthropic.Anthropic()
    msg = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2000,
        system=_SYSTEM,
        messages=[{"role": "user", "content": model.to_json()[:100_000]}],
    )
    text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
    text = text.replace("```json", "").replace("```", "").strip()
    try:
        items = json.loads(text)
    except json.JSONDecodeError:
        return []
    findings = []
    for i, item in enumerate(items[:max_findings]):
        try:
            findings.append(
                Finding(
                    rule_id=f"ATL-LLM-{i+1:03d}",
                    title=str(item.get("title", "LLM finding")),
                    severity=Severity(str(item.get("severity", "info")).lower()),
                    component_id=str(item.get("component_id", "model")),
                    description=str(item.get("description", "")),
                    recommendation=str(item.get("recommendation", "")),
                    source="llm-elicitation",
                    origin="llm",
                )
            )
        except (ValueError, TypeError):
            continue
    return findings
