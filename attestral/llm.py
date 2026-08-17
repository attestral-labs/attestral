"""Optional LLM threat elicitation layer.

Runs only when --llm is passed and ANTHROPIC_API_KEY is set. Findings from
this layer are tagged origin="llm" and never mixed silently with the
deterministic layer - regulated buyers need to know which is which.

Design contract, kept consistent with the ML and judge layers:

- **Structured first.** On models that support structured outputs the reply is
  schema-constrained (a guaranteed-valid findings array), not parsed hopefully;
  older models degrade to a JSON-instructed request through the same parser.
- **Lens passes.** One general pass by default (cost parity with a single
  request). ``LLMConfig(deep=True)`` (CLI ``--llm-deep``) fans the elicitation
  out across four adversarial lenses - injection paths, privilege escalation,
  exfiltration, supply chain - and dedups the union, the same
  diversity-beats-repetition principle as the judge panel.
- **Stable finding ids.** ``ATL-LLM-<digest>`` is derived from the finding's
  title, not its position in the reply, so the same elicited threat keeps the
  same id across runs and waivers/SARIF suppressions stay attached.
- **Grounded component ids.** A finding must point at a component that exists
  in the model; an unresolvable id is re-homed to the model-level pseudo
  component instead of shipping a dangling reference.
- **Errors are notes, never silence.** A missing key, a missing package, or an
  API error comes back as an operator-visible note (the judge-layer contract);
  the old behavior of returning an empty list with no explanation is gone.
- **Injectable query.** ``elicit(model, cfg, query=fake)`` runs the whole
  orchestration offline, so the layer is unit-testable without a key.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

from attestral.judge import _ADAPTIVE_MODELS, _STRUCTURED_MODELS, _is_fatal
from attestral.model import Finding, Severity, SystemModel

_SYSTEM = (
    "You are a principal security engineer performing a design review. "
    "Given a JSON system model (components, edges, trust boundaries), identify "
    "design-level threats the deterministic rules would miss: authn/authz gaps, "
    "trust-boundary violations, agentic risks (prompt-injection paths, tool "
    "permission escalation, handoff confusion). Every finding must name the "
    "component_id of a component that appears in the model, or \"model\" for a "
    "system-level threat. Respond ONLY with JSON: {\"findings\": [{\"title\", "
    "\"severity\" (critical|high|medium|low|info), \"component_id\", "
    "\"description\", \"recommendation\"}, ...]}. No markdown, no preamble."
)

# Findings-array schema for structured outputs, so a capable model returns a
# guaranteed-valid reply instead of one we parse hopefully.
_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "component_id": {"type": "string"},
                    "description": {"type": "string"},
                    "recommendation": {"type": "string"},
                },
                "required": ["title", "severity", "component_id",
                             "description", "recommendation"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["findings"],
    "additionalProperties": False,
}

# Adversarial lenses for the deep pass. One general pass elicits the model's
# top-of-mind threats; four focused passes surface the ones that only show up
# when the reviewer is told which axis to attack - the same reason the judge
# panel gives each panelist a different lens instead of polling one prompt.
_LENSES = (
    "Prompt-injection and tool-poisoning paths: which natural-language "
    "surfaces steer the agent, and what can a poisoned surface reach?",
    "Privilege and permission escalation: over-broad capabilities, "
    "confused-deputy chains, missing authorization between components.",
    "Data exfiltration: secrets and private data that can cross a trust "
    "boundary, and the egress channels available to move them.",
    "Supply chain and lifecycle: unpinned or mutable dependencies, "
    "install-time code execution, update channels an attacker can own.",
)


@dataclass
class LLMConfig:
    model: str = "claude-opus-4-8"   # elicitation quality is the product here
    effort: str = "medium"           # low | medium | high | xhigh | max
    max_tokens: int = 8192           # room for adaptive thinking + the array
    max_findings: int = 10           # cap per elicitation (post-dedup)
    deep: bool = False               # fan out across the adversarial lenses
    max_model_chars: int = 100_000   # system-model JSON budget per request

    @classmethod
    def from_env(cls, **overrides) -> "LLMConfig":
        base = dict(model=os.environ.get("ATTESTRAL_LLM_MODEL", cls.model))
        base.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**base)


def _finding_id(title: str) -> str:
    """Content-derived id: the same elicited threat keeps the same id across
    runs (positional ids reshuffle whenever the model reorders its reply,
    detaching waivers and SARIF suppressions). 8 hex chars, not 4 - a waiver
    keys on the rule id with a wildcard component, so a title-hash collision
    would let one threat's waiver silently suppress a different finding."""
    digest = hashlib.sha1(" ".join(title.lower().split()).encode()).hexdigest()
    return f"ATL-LLM-{digest[:8].upper()}"


def _payload(model_json: str, cfg: LLMConfig, lens: str | None) -> str:
    """The user message: the system model, truncated honestly if oversized."""
    body = model_json
    if len(body) > cfg.max_model_chars:
        body = body[: cfg.max_model_chars] + "\n[model JSON truncated at budget]"
    if lens:
        return f"{body}\n\nReview lens for this pass: {lens}"
    return body


def _default_query(cfg: LLMConfig):
    """Build the Anthropic-backed query, or return a skip note (as a str)."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return "llm elicitation skipped: set ANTHROPIC_API_KEY"
    try:
        import anthropic
    except ImportError:
        return 'llm elicitation skipped: pip install "attestral[llm]"'
    client = anthropic.Anthropic()

    # Every param is capability-gated: effort and adaptive thinking are only
    # accepted by the reasoning-tier models (haiku, e.g., is in _STRUCTURED_MODELS
    # but 400s on `effort`), and structured-output format only by the models that
    # support it. Sending an unsupported param is a hard 400, so gate each one.
    output_config: dict = {}
    if cfg.model in _ADAPTIVE_MODELS:      # the effort-capable set (excludes haiku)
        output_config["effort"] = cfg.effort
    if cfg.model in _STRUCTURED_MODELS:
        output_config["format"] = {"type": "json_schema", "schema": _SCHEMA}
    extra: dict = {}
    if cfg.model in _ADAPTIVE_MODELS:
        extra["thinking"] = {"type": "adaptive"}
    if output_config:
        extra["output_config"] = output_config

    def query(payload: str) -> str:
        msg = client.messages.create(
            model=cfg.model, max_tokens=cfg.max_tokens, system=_SYSTEM,
            messages=[{"role": "user", "content": payload}],
            **extra,
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")

    return query


def _parse_findings(text: str) -> list[dict]:
    """Items from a structured or plain reply. Tolerates the bare-array shape
    older prompts produced and a model that wraps *or trails* the JSON with
    prose, and never raises - a scalar/`null`/malformed reply yields []."""
    text = text.replace("```json", "").replace("```", "").strip()

    def _load(s: str) -> tuple[object, bool]:
        try:
            return json.loads(s), True
        except json.JSONDecodeError:
            return None, False

    data, ok = _load(text)
    if not ok:
        # Prose before AND/OR after the JSON: take the outermost {...}/[...] span.
        # (The old code only span-extracted when the text did not *start* with a
        # brace, so a valid object followed by "Hope this helps" silently dropped.)
        start = min((i for i in (text.find("{"), text.find("[")) if i != -1),
                    default=-1)
        end = max(text.rfind("}"), text.rfind("]"))
        if start != -1 and end > start:
            data, ok = _load(text[start:end + 1])
    if not ok:
        return []
    items = data.get("findings", []) if isinstance(data, dict) else data
    if not isinstance(items, list):       # `null`, a scalar, or {"findings": 5}
        return []
    return [i for i in items if isinstance(i, dict)]


def elicit(
    model: SystemModel,
    cfg: LLMConfig | None = None,
    query=None,
) -> tuple[list[Finding], list[str]]:
    """Elicit design-level threats from the system model. Returns (findings, notes).

    `query` is an injectable `(payload: str) -> str` callable; when None, a
    real Anthropic-backed query is built (needs an API key + the package).
    Notes are the layer's voice to the operator: a skip reason or the actual
    error - this layer never fails silently.
    """
    cfg = cfg or LLMConfig.from_env()
    if query is None:
        query = _default_query(cfg)
        if isinstance(query, str):        # a skip note, not a callable
            return [], [query]

    model_json = model.to_json()
    known_ids = {c.id for c in model.components}
    passes: tuple[str | None, ...] = tuple(_LENSES) if cfg.deep else (None,)

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    notes: list[str] = []
    for lens in passes:
        try:
            text = query(_payload(model_json, cfg, lens))
        except Exception as e:            # noqa: BLE001 - classify, then decide
            notes.append(f"llm elicitation failed ({type(e).__name__}): {e}")
            if _is_fatal(e):
                break                     # recurs on every pass; stop hammering
            continue
        items = _parse_findings(text)
        if text.strip() and not items:
            # A non-empty reply we could not turn into findings is reported, not
            # dropped in silence - the layer's contract is notes, never silence.
            notes.append("llm elicitation: a reply could not be parsed into findings")
        for item in items:
            title = str(item.get("title", "")).strip()
            if not title:
                continue
            try:
                severity = Severity(str(item.get("severity", "info")).lower())
            except ValueError:
                continue                  # parse severity BEFORE claiming the dedup
                                          # key, or a malformed item suppresses the
                                          # same threat from every later lens
            component_id = str(item.get("component_id", "model")) or "model"
            if component_id not in known_ids:
                component_id = "model"    # never ship a dangling reference
            key = (component_id, title.lower())
            if key in seen:
                continue                  # same threat from another lens
            seen.add(key)
            findings.append(Finding(
                rule_id=_finding_id(title),
                title=title,
                severity=severity,
                component_id=component_id,
                description=str(item.get("description", "")),
                recommendation=str(item.get("recommendation", "")),
                source="llm-elicitation",
                origin="llm",
            ))
    findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return findings[: cfg.max_findings], notes
