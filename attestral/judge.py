"""LLM-as-judge: an independent verifier over findings.

Optional layer (needs an API key). Each finding is shown to a judge model
together with its component context; the judge returns a structured verdict
(confirmed | false_positive | needs_review) with a confidence and reasoning.
Verdicts are recorded on the finding and carried into the evidence chain, so
the judgment is auditable. With a panel, N independent judges vote and the
majority verdict wins.

The judge never deletes a finding. By default it only annotates. With
suppress=True, a high-confidence false_positive becomes a machine-generated
waiver whose reason is the judge's reasoning: suppressed from the gate, but
kept on the record like any human waiver. That keeps the fail-safe posture,
a wrong judge can only downgrade with an on-record justification, never
silently erase.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass

from attestral.model import Finding, SystemModel

VERDICTS = ("confirmed", "false_positive", "needs_review")

_SYSTEM = (
    "You are an adversarial security reviewer auditing another tool's finding. "
    "Given the finding and the component it targets, decide whether it is a real, "
    "actionable risk in THIS context. Be skeptical of false positives, but never "
    "dismiss a genuine risk. Respond ONLY with JSON: "
    '{"verdict": "confirmed"|"false_positive"|"needs_review", '
    '"confidence": 0.0-1.0, "reasoning": "one or two sentences"}. '
    "No markdown, no preamble."
)


@dataclass
class JudgeConfig:
    model: str = "claude-sonnet-4-6"
    panel: int = 1                       # judges per finding; majority vote
    suppress: bool = False               # auto-waive high-confidence false positives
    suppress_min_confidence: float = 0.7


def api_key() -> str | None:
    return os.environ.get("ATTESTRAL_JUDGE_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")


def build_context(model: SystemModel, finding: Finding) -> dict:
    """The exact payload a judge sees: the finding plus its component."""
    c = model.get(finding.component_id)
    return {
        "finding": {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "description": finding.description,
        },
        "component": None if c is None else {
            "id": c.id,
            "type": c.type,
            "attributes": c.attributes,
            "trust_boundary": c.trust_boundary,
        },
    }


def decide(votes: list[dict]) -> tuple[str, float, str]:
    """Majority verdict, mean confidence of the winners, and one winner's reasoning."""
    tally = Counter(v["verdict"] for v in votes)
    verdict, _ = tally.most_common(1)[0]
    winners = [v for v in votes if v["verdict"] == verdict]
    confidence = round(sum(v["confidence"] for v in winners) / len(winners), 2)
    reasoning = next((v["reasoning"] for v in winners if v.get("reasoning")), "")
    return verdict, confidence, reasoning


def apply_verdict(finding: Finding, verdict: str, confidence: float, reasoning: str,
                  cfg: JudgeConfig) -> None:
    """Record the verdict; optionally machine-waive a confident false positive."""
    finding.judge_verdict = verdict
    finding.judge_confidence = confidence
    if cfg.suppress and verdict == "false_positive" and confidence >= cfg.suppress_min_confidence:
        finding.waived = True
        finding.waiver_reason = f"[llm-judge:{cfg.model}] {reasoning}".strip()


def _parse_verdict(text: str) -> dict | None:
    text = text.replace("```json", "").replace("```", "").strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    verdict = str(data.get("verdict", "")).lower()
    if verdict not in VERDICTS:
        return None
    return {
        "verdict": verdict,
        "confidence": max(0.0, min(1.0, float(data.get("confidence", 0.0)))),
        "reasoning": str(data.get("reasoning", "")),
    }


def _default_query(cfg: JudgeConfig):
    """Build the Anthropic-backed query, or return a skip note (as a str)."""
    if not api_key():
        return "judge skipped: set ATTESTRAL_JUDGE_API_KEY or ANTHROPIC_API_KEY"
    try:
        import anthropic
    except ImportError:
        return 'judge skipped: pip install "attestral[llm]"'
    client = anthropic.Anthropic(api_key=api_key())

    def query(payload: str) -> str:
        msg = client.messages.create(
            model=cfg.model, max_tokens=400, system=_SYSTEM,
            messages=[{"role": "user", "content": payload}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")

    return query


def judge_findings(model: SystemModel, findings: list[Finding],
                   cfg: JudgeConfig | None = None, query=None) -> list[str]:
    """Annotate findings with judge verdicts in place. Returns skip/status notes.

    `query` is an injectable `(payload: str) -> str` callable; when None, a
    real Anthropic-backed query is built (needs an API key + the package).
    Injecting a fake makes the whole orchestration testable offline.
    """
    cfg = cfg or JudgeConfig()
    if query is None:
        query = _default_query(cfg)
        if isinstance(query, str):        # a skip note, not a callable
            return [query]
    for f in findings:
        if f.waived:                      # a human waiver already accepted this
            continue
        payload = json.dumps(build_context(model, f))
        votes: list[dict] = []
        for _ in range(max(1, cfg.panel)):
            try:
                text = query(payload)
            except Exception:
                continue
            vote = _parse_verdict(text)
            if vote:
                votes.append(vote)
        if votes:
            apply_verdict(f, *decide(votes), cfg)
    return []
