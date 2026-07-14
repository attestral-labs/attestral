"""LLM-as-judge: an independent verifier over findings.

Optional layer (needs an API key). Each finding is shown to a judge model
together with its component context; the judge returns a structured verdict
(confirmed | false_positive | needs_review) with a confidence and reasoning.
Verdicts are recorded on the finding and carried into the evidence chain, so
the judgment is auditable. With a panel, N independent judges vote and the
majority verdict wins - and each panelist reviews through a different
adversarial lens, so the votes actually diverge instead of echoing one prompt.

The judge never deletes a finding. By default it only annotates. With
suppress=True, a high-confidence false_positive becomes a machine-generated
waiver whose reason is the judge's reasoning: suppressed from the gate, but
kept on the record like any human waiver. That keeps the fail-safe posture,
a wrong judge can only downgrade with an on-record justification, never
silently erase.

Robustness: the model is asked for a schema-constrained verdict (structured
outputs on models that support it), so a well-formed reply is guaranteed
rather than parsed hopefully. Errors are never swallowed - a fatal error
(bad key, no model access) stops the run and is reported with the real
message, and any finding a transient error left unverified is surfaced too.
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
    "actionable risk in THIS context. Reason from the component's actual attributes "
    "and trust boundary, not from the rule's title alone. Be skeptical of false "
    "positives, but never dismiss a genuine risk. If a review lens is provided, "
    "weigh it, but still return your overall verdict. Respond ONLY with JSON: "
    '{"verdict": "confirmed"|"false_positive"|"needs_review", '
    '"confidence": 0.0-1.0, "reasoning": "one or two sentences"}. '
    "No markdown, no preamble."
)

# Verdict schema for structured outputs. No numeric bounds on confidence:
# structured-output schemas reject minimum/maximum, so it is clamped in
# _parse_verdict instead.
_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": list(VERDICTS)},
        "confidence": {"type": "number"},
        "reasoning": {"type": "string"},
    },
    "required": ["verdict", "confidence", "reasoning"],
    "additionalProperties": False,
}

# Models that accept adaptive thinking and structured outputs. A judge model
# outside these sets still works - it just falls back to a plain JSON-instructed
# request parsed by _parse_verdict, degrading gracefully rather than erroring.
_ADAPTIVE_MODELS = frozenset({
    "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6",
    "claude-sonnet-5", "claude-sonnet-4-6", "claude-fable-5",
})
_STRUCTURED_MODELS = frozenset({
    "claude-opus-4-8", "claude-sonnet-5", "claude-haiku-4-5",
    "claude-fable-5", "claude-opus-4-5", "claude-opus-4-1",
})

# Distinct adversarial lenses for a multi-judge panel. Polling the same prompt
# N times gives N near-identical votes (modern models expose no temperature
# knob); giving each panelist a different angle is what makes the vote a real
# cross-examination.
_LENSES = (
    "Exploitability: could an attacker actually reach and abuse this in the "
    "deployment exactly as described?",
    "False-positive case: is there a compensating control or a context detail "
    "here that neutralizes the risk the rule assumes?",
    "Blast radius: if this were exploited, how severe is the realistic worst "
    "case given what this component can reach?",
)


@dataclass
class JudgeConfig:
    model: str = "claude-opus-4-8"       # judgment quality matters more than cost here
    panel: int = 1                       # judges per finding; majority vote
    effort: str = "medium"               # low | medium | high | xhigh | max
    max_tokens: int = 4096               # room for adaptive thinking + the small verdict
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


def _frame(payload: str, lens: str) -> str:
    """Attach a per-panelist review lens to the base payload."""
    return f"{payload}\n\nReview lens for this pass: {lens}"


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
    # Tolerate a model that wraps the JSON in prose: take the first {...} span.
    if not text.startswith("{"):
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            text = text[start:end + 1]
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


def _is_fatal(exc: Exception) -> bool:
    """A request-level error that will recur on every finding (bad key, no
    model access, malformed request) - stop rather than hammer the API. HTTP
    408/409/429 and 5xx are transient and not treated as fatal."""
    status = getattr(exc, "status_code", None)
    return status in (400, 401, 403, 404)


def _default_query(cfg: JudgeConfig):
    """Build the Anthropic-backed query, or return a skip note (as a str)."""
    if not api_key():
        return "judge skipped: set ATTESTRAL_JUDGE_API_KEY or ANTHROPIC_API_KEY"
    try:
        import anthropic
    except ImportError:
        return 'judge skipped: pip install "attestral[llm]"'
    client = anthropic.Anthropic(api_key=api_key())

    # effort always applies; format (guaranteed-valid JSON) and adaptive
    # thinking are added only for models that accept them.
    output_config: dict = {"effort": cfg.effort}
    if cfg.model in _STRUCTURED_MODELS:
        output_config["format"] = {"type": "json_schema", "schema": _SCHEMA}
    extra: dict = {}
    if cfg.model in _ADAPTIVE_MODELS:
        extra["thinking"] = {"type": "adaptive"}

    def query(payload: str) -> str:
        msg = client.messages.create(
            model=cfg.model, max_tokens=cfg.max_tokens, system=_SYSTEM,
            output_config=output_config,
            messages=[{"role": "user", "content": payload}],
            **extra,
        )
        # Text blocks only; adaptive-thinking blocks (empty by default) are skipped.
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")

    return query


def judge_findings(model: SystemModel, findings: list[Finding],
                   cfg: JudgeConfig | None = None, query=None) -> list[str]:
    """Annotate findings with judge verdicts in place. Returns skip/status notes.

    `query` is an injectable `(payload: str) -> str` callable; when None, a
    real Anthropic-backed query is built (needs an API key + the package).
    Injecting a fake makes the whole orchestration testable offline.

    Notes are the layer's voice to the operator: a skip reason, the actual
    error if the run failed, or a count of findings a transient error left
    unverified. Silence means every unwaived finding got a verdict.
    """
    cfg = cfg or JudgeConfig()
    if query is None:
        query = _default_query(cfg)
        if isinstance(query, str):        # a skip note, not a callable
            return [query]

    panel = max(1, cfg.panel)
    unverified = 0
    last_error = ""
    for f in findings:
        if f.waived:                      # a human waiver already accepted this
            continue
        base = json.dumps(build_context(model, f))
        votes: list[dict] = []
        for i in range(panel):
            payload = base if panel == 1 else _frame(base, _LENSES[i % len(_LENSES)])
            try:
                text = query(payload)
            except Exception as e:        # noqa: BLE001 - classify, then decide
                if _is_fatal(e):
                    # Recurs on every finding; report the real reason and stop.
                    return [f"judge failed ({type(e).__name__}): {e}"]
                last_error = str(e)
                continue
            vote = _parse_verdict(text)
            if vote:
                votes.append(vote)
        if votes:
            apply_verdict(f, *decide(votes), cfg)
        else:
            unverified += 1

    notes: list[str] = []
    if unverified:
        note = f"judge: {unverified} finding(s) could not be verified"
        if last_error:
            note += f" (last error: {last_error})"
        notes.append(note)
    return notes
