"""Optional ML layer: prompt-injection detection on agentic text surfaces.

The deterministic rules score *structure* (a flag, a CIDR, a capability). This
layer scores *language* - the natural-language surfaces an agent actually
reads and can be steered by: MCP tool/server descriptions, and system-prompt /
agent-instruction files. It emits `origin="ml"` findings for content that
reads as prompt injection, a jailbreak, or tool poisoning.

The layer is TIERED so the very first `attestral scan --ml` is instant and
needs no extra install, with two opt-in accuracy upgrades that share ONE model:

- **Heuristic detector (default, zero-dependency).** Pure Python + stdlib
  ``re``: a curated pattern bank over known injection / jailbreak / tool-
  poisoning phrasings, plus hidden-channel checks (zero-width & bidi unicode,
  HTML comments, base64-smuggled instructions). Runs in microseconds with no
  model download and no torch.
- **ONNX classifier (recommended upgrade: accurate but light).** When
  `attestral[onnx]` (onnxruntime + a transformers tokenizer, NO torch/optimum)
  is installed, the same DeBERTa prompt-injection model (default:
  protectai/deberta-v3-base-prompt-injection-v2) runs through a raw
  onnxruntime session with a plain-numpy softmax - model-grade accuracy at a
  fraction of the torch tier's footprint, and no torch at all. (Producing the
  ONNX weights is a one-time maintenance step: see scripts/export_onnx.py.)
- **DeBERTa / torch classifier (heavy, fine-tunable).** When `attestral[ml]`
  (transformers + torch) is installed, the same model runs through a torch
  pipeline. Heavier, but the tier to pick when you want to fine-tune locally.

All three emit findings of byte-identical *schema* - same rule id
(``ATL-ML-001``), same ``threshold`` gate, same ``origin="ml"``, same severity
bands - so the evidence chain and SARIF are unchanged whichever tier does the
scoring. This is a contract about finding *shape*, NOT about the *set* of
findings: the heuristic is a curated pattern bank and the ONNX/DeBERTa tiers are
a learned model, so on a borderline surface they can legitimately disagree on
whether the score clears the threshold. Same schema, possibly different verdict -
that divergence is the whole reason the tier is a user-selectable knob.

Engine selection (see ``MLConfig.engine`` / ``ATTESTRAL_ML_ENGINE``):
- ``auto`` (default): prefer ONNX when importable, else DeBERTa/torch, else
  transparently fall back to the heuristic detector. A missing extra is never
  an error - each tier catches ImportError and falls through.
- ``heuristic``: force the zero-dependency detector (never touches a model).
- ``onnx``: force the ONNX classifier; if onnxruntime/optimum (or the ONNX
  weights) are unavailable it still degrades to the heuristic detector.
- ``deberta`` / ``transformer``: force the torch model; same graceful degrade.

Design contract, kept consistent with the LLM and judge layers:
- Heavy deps (transformers, torch) are imported lazily; with them absent this
  layer degrades to the heuristic detector and still returns findings.
- The model is pinned by revision for reproducibility, and once cached the
  layer runs fully offline (set HF_HUB_OFFLINE=1).
- The scorer is injectable: `scan(model, cfg, classifier=fake)` runs the whole
  orchestration with no download and no network, so it is unit-testable.
"""
from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass
from typing import Callable, Iterator

from attestral.model import Component, Finding, Severity, SystemModel

_DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
# Pin to a specific revision in production (a commit sha or immutable tag) so
# the classifier that reviewed the design is the classifier that runs. Override
# with ATTESTRAL_ML_REVISION or MLConfig(revision=...).
_DEFAULT_REVISION = "main"

RULE_ID = "ATL-ML-001"
_FRAMEWORKS = ["OWASP LLM01 Prompt Injection", "MITRE ATLAS AML.T0051", "OWASP-AgSec TOOL-3"]

# A classifier maps a text to the injection probability in [0.0, 1.0].
Classifier = Callable[[str], float]
# An engine maps a text to (probability, matched-pattern evidence). The
# transformer path carries no pattern evidence; the heuristic path does.
_Engine = Callable[[str], "tuple[float, list[str]]"]


@dataclass
class MLConfig:
    model: str = _DEFAULT_MODEL
    revision: str = _DEFAULT_REVISION
    engine: str = "auto"            # auto | heuristic | onnx | deberta (see module doc)
    threshold: float = 0.5          # min injection probability to report
    max_chars: int = 1200           # window size fed to the scorer
    overlap: int = 200              # window overlap so a split can't hide a payload
    device: int = -1                # -1 CPU, >=0 CUDA device index

    @classmethod
    def from_env(cls, **overrides) -> "MLConfig":
        base = dict(
            model=os.environ.get("ATTESTRAL_ML_MODEL", _DEFAULT_MODEL),
            revision=os.environ.get("ATTESTRAL_ML_REVISION", _DEFAULT_REVISION),
            engine=os.environ.get("ATTESTRAL_ML_ENGINE", "auto"),
        )
        base.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**base)


@dataclass
class TextSurface:
    """One natural-language surface an agent can read, pulled from the model."""
    component_id: str
    source: str
    label: str
    text: str


def gather_surfaces(model: SystemModel) -> list[TextSurface]:
    """Extract every scored text surface from the system model."""
    out: list[TextSurface] = []
    for c in model.components:
        _collect_component_surfaces(c, out)
    return out


def _collect_component_surfaces(c: Component, out: list[TextSurface]) -> None:
    content = c.attr("content")
    if content:
        out.append(TextSurface(c.id, c.source, f"{c.type} '{c.name}'", str(content)))
    desc = c.attr("description")
    if desc:
        out.append(
            TextSurface(c.id, c.source, f"{c.type} '{c.name}' description", str(desc))
        )
    for t in c.attr("_tool_descriptions") or []:
        tname = t.get("name", "") if isinstance(t, dict) else ""
        tdesc = t.get("description", "") if isinstance(t, dict) else str(t)
        if tdesc:
            out.append(
                TextSurface(c.id, c.source, f"tool '{tname}' description", str(tdesc))
            )


def _chunks(text: str, size: int, overlap: int) -> Iterator[str]:
    text = text or ""
    if len(text) <= size:
        yield text
        return
    step = max(1, size - overlap)
    for i in range(0, len(text), step):
        yield text[i : i + size]
        if i + size >= len(text):
            break


def _severity(prob: float) -> Severity:
    if prob >= 0.9:
        return Severity.HIGH
    if prob >= 0.7:
        return Severity.MEDIUM
    return Severity.LOW


def _snippet(text: str, n: int = 160) -> str:
    flat = " ".join(text.split())
    return flat[:n] + ("…" if len(flat) > n else "")


def _finding(surface: TextSurface, prob: float, evidence: list[str] | None = None) -> Finding:
    evidence = evidence or []
    if evidence:
        cats = ", ".join(sorted({e.split(":", 1)[0] for e in evidence}))
        how = (
            f"A heuristic pattern detector matched known prompt-injection / jailbreak "
            f"signatures on this agentic surface (score={prob:.2f}; categories: {cats}). "
            f"Matched evidence: {'; '.join(evidence)}. "
        )
    else:
        how = (
            f"An ML classifier flagged natural-language content on this agentic surface "
            f"as prompt-injection / jailbreak text (p={prob:.2f}). "
        )
    return Finding(
        rule_id=RULE_ID,
        title=f"Prompt-injection text detected in {surface.label}",
        severity=_severity(prob),
        component_id=surface.component_id,
        description=how + f'Snippet: "{_snippet(surface.text)}"',
        recommendation=(
            "Treat this surface as untrusted input. Remove or neutralize the "
            "instruction-like content; never let tool or description text override the "
            "agent's system instructions or drive tool-call decisions."
        ),
        source=surface.source,
        framework_refs=list(_FRAMEWORKS),
        origin="ml",
    )


# --------------------------------------------------------------------------- #
# Tier 1: zero-dependency heuristic detector (pure Python + stdlib re)
# --------------------------------------------------------------------------- #
#
# Each category holds high-precision regexes for a family of real injection /
# jailbreak / tool-poisoning phrasings. A surface's score is the noisy-OR over
# the categories it matches: score = 1 - Π(1 - weight_c). This stays in [0, 1],
# fires on a single strong signal, and compounds when several families hit at
# once - without any single category being able to exceed its own weight.

_CATEGORIES: list[tuple[str, list[re.Pattern[str]]]] = [
    ("instruction_override", [
        re.compile(
            r"\bignore\s+(?:all\s+|any\s+|the\s+)*(?:previous|prior|above|preceding|"
            r"earlier|foregoing)\s+(?:instruction|instructions|prompt|prompts|"
            r"direction|directions|message|messages|context|rule|rules)", re.I),
        re.compile(
            r"\bdisregard\s+(?:all\s+|any\s+|the\s+)*(?:previous|prior|above|preceding|"
            r"earlier|foregoing|system|prior\s+instruction)", re.I),
        re.compile(r"\bforget\s+(?:everything|all|any|your|the\s+|previous|prior)", re.I),
        re.compile(
            r"\boverride\s+(?:the\s+|your\s+|all\s+)*(?:previous\s+|system\s+)*"
            r"(?:instruction|instructions|prompt|prompts|rule|rules|setting|settings)", re.I),
        re.compile(
            r"\b(?:these\s+are\s+your\s+)?(?:new|updated|revised|real|actual|true)\s+"
            r"(?:instruction|instructions|directive|directives|system\s+prompt)s?\b", re.I),
        re.compile(r"\bnow\s+ignore\b", re.I),
    ]),
    ("jailbreak_persona", [
        re.compile(r"\bdo\s+anything\s+now\b", re.I),
        re.compile(r"\byou\s+are\s+(?:now\s+)?DAN\b", re.I),
        re.compile(r"\b(?:enable|enter|activate)\s+developer\s+mode\b|\bdeveloper\s+mode\s+"
                   r"(?:enabled|on)\b", re.I),
        re.compile(r"\bjailbreak\b|\bjailbroken\b", re.I),
        re.compile(r"\bunfiltered\s+(?:mode|responses?|ai|assistant|answers?)\b", re.I),
        re.compile(
            r"\bwithout\s+(?:any\s+)?(?:restrictions?|filters?|rules?|censorship|"
            r"limitations?|ethics|ethical\s+guidelines?|moral\s+guidelines?)\b", re.I),
        re.compile(
            r"\bignore\s+your\s+(?:guidelines?|programming|training|rules?|safety|"
            r"policies|policy|content\s+policy|instructions)\b", re.I),
        re.compile(
            r"\bbypass\s+(?:your\s+|the\s+|all\s+)*(?:safety|content|security|"
            r"guardrails?|filters?|restrictions?|policy|policies|moderation)\b", re.I),
        re.compile(r"\bact\s+as\s+(?:if\s+you\s+are\s+)?(?:DAN\b|an?\s+unrestricted|"
                   r"a\s+jailbroken)", re.I),
        re.compile(r"\bpretend\s+(?:that\s+)?you\s+(?:are|have|can)\b[^.\n]{0,40}"
                   r"\b(?:no|not|any|unrestricted)\b", re.I),
    ]),
    ("data_exfiltration", [
        re.compile(
            r"\b(?:send|exfiltrate|upload|post|forward|transmit|e-?mail|paste|copy|"
            r"deliver|ship|leak)\b[^\n]{0,80}?"
            r"(?:https?://|ftp://|webhook|[\w.+-]+@[\w-]+\.[a-z]{2,}|attacker|"
            r"external\s+(?:server|endpoint|url))", re.I),
        re.compile(
            r"\b(?:send|exfiltrate|upload|post|forward|transmit|leak|reveal|dump|steal)"
            r"\b[^\n]{0,80}?\b(?:api[\s_-]?keys?|secrets?|tokens?|passwords?|"
            r"credentials?|private\s+keys?|\.env\b|environment\s+variables?|"
            r"session\s+cookies?)\b", re.I),
    ]),
    ("system_prompt_exfil", [
        re.compile(
            r"\b(?:reveal|show|print|repeat|display|output|reproduce|leak|tell\s+me|"
            r"give\s+me)\b[^.\n]{0,40}\b(?:your\s+|the\s+)?(?:system\s+|initial\s+|"
            r"original\s+)?(?:prompt|instructions|guidelines)\b", re.I),
        re.compile(r"\brepeat\s+(?:the\s+)?(?:words|text|everything|all)\s+(?:above|before|"
                   r"you\s+were\s+given)", re.I),
        re.compile(r"\bwhat\s+(?:are|were)\s+your\s+(?:original\s+|initial\s+|exact\s+|"
                   r"first\s+)?(?:instructions|system\s+prompt|directives)", re.I),
    ]),
    ("secrecy", [
        re.compile(r"\bdo\s+not\s+(?:tell|inform|notify|alert|warn)\s+(?:the\s+)?user", re.I),
        re.compile(r"\bdon'?t\s+(?:tell|inform|let|notify|alert)\s+(?:the\s+)?user", re.I),
        re.compile(r"\bwithout\s+(?:telling|informing|notifying|alerting|the\s+user\s+"
                   r"knowing|letting\s+the\s+user)", re.I),
        re.compile(r"\bkeep\s+this\s+(?:secret|confidential|hidden|to\s+yourself|"
                   r"between\s+us)", re.I),
        re.compile(r"\bdo\s+not\s+(?:mention|reveal|disclose|reference|acknowledge)\b"
                   r"[^.\n]{0,30}\b(?:this|instruction|prompt|to\s+the\s+user)", re.I),
        re.compile(r"\b(?:hide|conceal)\s+(?:this\s+)?(?:from\s+the\s+user|the\s+fact)", re.I),
    ]),
    ("tool_poisoning", [
        re.compile(
            r"\b(?:when|whenever|before|after)\s+(?:you\s+(?:are\s+)?)?(?:called|invoked|"
            r"used|asked|running|responding|answering)\b[^.\n]{0,70}\b(?:also|first|"
            r"secretly|silently|always|must|send|call|include|append|execute|run)\b", re.I),
        re.compile(r"\b(?:always|secretly|silently|first)\s+(?:call|invoke|use|run|"
                   r"execute|include|append|forward|send|read)\b", re.I),
        re.compile(r"\bin\s+addition\s+to\s+(?:your|the)\s+(?:task|instructions?|request|"
                   r"normal)", re.I),
    ]),
    ("injected_control_tags", [
        re.compile(r"</?(?:system|assistant|instructions?|important|admin|developer|"
                   r"override|prompt|im_start|im_end)\s*>", re.I),
        re.compile(r"\[(?:/?\s*)(?:system|inst|instructions?|important|admin)\s*\]", re.I),
        re.compile(r"<\|(?:system|im_start|im_end|endoftext)\|>", re.I),
    ]),
]

# Categories emitted by the hidden-channel and encoded-payload checks below.
_WEIGHTS: dict[str, float] = {
    "instruction_override": 0.90,
    "jailbreak_persona": 0.85,
    "data_exfiltration": 0.85,
    "encoded_hidden_instruction": 0.85,
    "system_prompt_exfil": 0.80,
    "hidden_unicode": 0.80,
    "tool_poisoning": 0.75,
    "injected_control_tags": 0.70,
    "secrecy": 0.70,
    "html_comment_instruction": 0.65,
}

# Zero-width & bidi/override control characters used to smuggle instructions
# past a human reviewer while an LLM still reads them.
_HIDDEN_UNICODE = re.compile(
    "["
    "\u200b-\u200f"   # zero-width space/joiner, LRM/RLM marks
    "\u202a-\u202e"   # bidi embedding / override controls
    "\u2060-\u2064"   # word joiner, invisible separators
    "\u2066-\u2069"   # bidi isolates (LRI/RLI/FSI/PDI)
    "\ufeff"           # zero-width no-break space / BOM
    "]"
)
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
# A contiguous base64-looking run long enough to smuggle a real instruction.
_B64_BLOB = re.compile(r"(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2,3}={0,2})?")
# Imperative injection verbs, used to judge whether an HTML comment is carrying
# a hidden instruction rather than an ordinary code/note comment.
_IMPERATIVE = re.compile(
    r"\b(?:ignore|disregard|forget|override|send|exfiltrate|forward|reveal|"
    r"do\s+not|don'?t|must|always|execute|run|delete|leak|bypass)\b", re.I)


def _clip(s: str, n: int = 80) -> str:
    flat = " ".join(str(s).split())
    return (flat[:n] + "…") if len(flat) > n else flat


def _match_categories(text: str) -> dict[str, str]:
    """Return {category: first matched snippet} for every pattern family that hits."""
    found: dict[str, str] = {}
    for cat, patterns in _CATEGORIES:
        for p in patterns:
            m = p.search(text)
            if m:
                found[cat] = _clip(m.group(0))
                break
    return found


def _decoded_payloads(text: str, limit: int = 12) -> list[str]:
    """Decode base64-looking blobs that resolve to printable text (hidden payloads)."""
    out: list[str] = []
    for m in _B64_BLOB.finditer(text):
        if len(out) >= limit:
            break
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob, validate=True)
            dec = raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if dec.isprintable() or any(ch in dec for ch in "\n\t "):
            out.append(dec)
    return out


def _describe_hidden_unicode(text: str) -> str:
    seen = {f"U+{ord(ch):04X}" for ch in text if _HIDDEN_UNICODE.match(ch)}
    return "zero-width/bidi control chars " + ", ".join(sorted(seen))


def heuristic_score(text: str) -> tuple[float, list[str]]:
    """Score `text` for prompt-injection language. Returns (score in [0,1], evidence).

    Zero-dependency: pure stdlib. `evidence` is a list of ``"category: snippet"``
    strings naming the matched pattern families, for the finding's audit trail.
    """
    if not text:
        return 0.0, []
    hits: dict[str, str] = {}

    # Hidden-channel checks first, so a payload smuggled out of plain sight is
    # not missed just because the visible text looks clean.
    if _HIDDEN_UNICODE.search(text):
        hits["hidden_unicode"] = _describe_hidden_unicode(text)
    for cm in _HTML_COMMENT.finditer(text):
        body = cm.group(1)
        if _match_categories(body) or _IMPERATIVE.search(body):
            hits["html_comment_instruction"] = _clip(body)
            break
    for dec in _decoded_payloads(text):
        if _match_categories(dec) or _IMPERATIVE.search(dec):
            hits["encoded_hidden_instruction"] = _clip(dec)
            break

    # Visible-text pattern families.
    hits.update(_match_categories(text))

    if not hits:
        return 0.0, []
    prod = 1.0
    for cat in hits:
        prod *= 1.0 - _WEIGHTS.get(cat, 0.5)
    score = round(1.0 - prod, 4)
    evidence = [f"{cat}: {snip}" for cat, snip in sorted(hits.items())]
    return score, evidence


def _heuristic_engine(text: str) -> tuple[float, list[str]]:
    return heuristic_score(text)


# --------------------------------------------------------------------------- #
# Tier 2: opt-in DeBERTa / transformer classifier
# --------------------------------------------------------------------------- #

def _transformer_classifier(cfg: MLConfig) -> Classifier | None:
    """Build a real transformer-backed classifier, or None if deps are absent."""
    try:
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            TextClassificationPipeline,
        )
    except ImportError:
        return None
    tok = AutoTokenizer.from_pretrained(cfg.model, revision=cfg.revision)
    mdl = AutoModelForSequenceClassification.from_pretrained(cfg.model, revision=cfg.revision)
    pipe = TextClassificationPipeline(
        model=mdl, tokenizer=tok, truncation=True, max_length=512,
        top_k=None, device=cfg.device,
    )

    def classify(text: str) -> float:
        out = pipe(text)
        scores = out[0] if out and isinstance(out[0], list) else out
        for entry in scores:
            if "inject" in str(entry.get("label", "")).lower():
                return float(entry["score"])
        return 0.0

    return classify


# --------------------------------------------------------------------------- #
# Tier 3: opt-in ONNX classifier (same model, onnxruntime instead of torch)
# --------------------------------------------------------------------------- #

def _resolve_onnx_weights(cfg: MLConfig) -> str | None:
    """Locate the exported ONNX graph for ``cfg.model``, or None if not found.

    Supports both shapes the ONNX tier is fed:
    - a **local directory** (what ``scripts/export_onnx.py`` writes, or an
      ``ATTESTRAL_ML_MODEL=/path`` override) containing ``model.onnx``;
    - an **HF repo id** that ships ONNX weights, fetched from the conventional
      ``onnx/model.onnx`` / ``model.onnx`` locations via ``huggingface_hub``.
    """
    from pathlib import Path

    p = Path(cfg.model)
    if p.is_dir():
        for name in ("model.onnx", "onnx/model.onnx"):
            if (p / name).is_file():
                return str(p / name)
        found = sorted(p.glob("*.onnx")) or sorted(p.glob("onnx/*.onnx"))
        return str(found[0]) if found else None

    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        return None
    for fname in ("onnx/model.onnx", "model.onnx"):
        try:
            return hf_hub_download(cfg.model, fname, revision=cfg.revision)
        except Exception:
            continue
    return None


def _onnx_classifier(cfg: MLConfig) -> Classifier | None:
    """Build an onnxruntime-backed classifier, or None if deps/weights absent.

    Runs the SAME DeBERTa prompt-injection classifier as the torch tier, but
    through a raw ``onnxruntime.InferenceSession`` with a plain-numpy softmax -
    NO torch and NO optimum (both of which drag in torch's hundreds of MB). The
    only heavy deps are onnxruntime + a transformers tokenizer, so the installed
    footprint is a fraction of the torch tier. Two failure modes both degrade to
    ``None`` so the caller can fall through to the next tier and ``--ml`` never
    hard-fails:

    - ImportError: the ``attestral[onnx]`` extra (onnxruntime + transformers)
      isn't installed.
    - Weights/model load error: no ONNX graph is cached and none can be fetched
      (offline, or the repo ships no ONNX). Run ``scripts/export_onnx.py`` once
      to produce them, then point ``ATTESTRAL_ML_MODEL`` at the output dir.
    """
    try:
        import numpy as np
        import onnxruntime as ort
        from transformers import AutoConfig, AutoTokenizer
    except ImportError:
        return None

    try:
        onnx_path = _resolve_onnx_weights(cfg)
        if onnx_path is None:
            return None
        tok = AutoTokenizer.from_pretrained(cfg.model, revision=cfg.revision)
        conf = AutoConfig.from_pretrained(cfg.model, revision=cfg.revision)
        session = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
    except Exception:
        # No ONNX weights cached / no network / bad graph: degrade, don't crash.
        return None

    # Locate the "injection" logit by label so the score matches the torch tier.
    labels = getattr(conf, "id2label", {}) or {}
    inj_idx = next(
        (int(i) for i, lbl in labels.items() if "inject" in str(lbl).lower()), None
    )
    # Feed only the inputs the exported ONNX graph actually declares (deberta-v3
    # may or may not carry token_type_ids depending on how it was exported).
    graph_inputs = {i.name for i in session.get_inputs()}

    def classify(text: str) -> float:
        enc = tok(text, truncation=True, max_length=512, return_tensors="np")
        feed = {k: v.astype(np.int64) for k, v in enc.items() if k in graph_inputs}
        logits = np.asarray(session.run(None, feed)[0], dtype="float64")[0]
        exp = np.exp(logits - logits.max())
        probs = exp / exp.sum()
        idx = inj_idx if inj_idx is not None else int(probs.argmax())
        return float(probs[idx])

    return classify


# --------------------------------------------------------------------------- #
# Tier resolution: auto walks onnx -> deberta/torch -> heuristic
# --------------------------------------------------------------------------- #

# Accepted spellings for each explicit engine choice.
_HEURISTIC_ALIASES = ("heuristic", "heuristics", "regex", "rules")
_ONNX_ALIASES = ("onnx", "ort", "onnxruntime")
_DEBERTA_ALIASES = ("deberta", "transformer", "transformers", "model", "torch")


def _fallback_note(choice: str) -> str:
    """Informational note when a requested model tier degraded to the heuristic."""
    if choice in _ONNX_ALIASES:
        return (
            'attestral[onnx] not installed - ATTESTRAL_ML_ENGINE requested the ONNX '
            "classifier but onnxruntime/transformers (or the ONNX weights) are "
            "unavailable; using the built-in heuristic prompt-injection detector."
        )
    if choice in _DEBERTA_ALIASES:
        return (
            'attestral[ml] not installed - ATTESTRAL_ML_ENGINE requested the DeBERTa '
            "model but transformers/torch are unavailable; using the built-in "
            "heuristic prompt-injection detector."
        )
    return (  # auto
        "using the built-in zero-dependency heuristic prompt-injection detector "
        '(install "attestral[onnx]" for the light, model-grade ONNX classifier, '
        'or "attestral[ml]" for the heavier fine-tunable DeBERTa/torch tier).'
    )


def _resolve_engine(cfg: MLConfig) -> tuple[_Engine, list[str]]:
    """Pick the scoring engine, degrading gracefully. Returns (engine, notes).

    ``auto`` walks the whole ladder (onnx -> deberta/torch -> heuristic); an
    explicit ``onnx``/``deberta`` tries just its own tier, then still degrades
    to the heuristic detector. Every model tier catches ImportError (and model-
    load errors) and returns None, so ``--ml`` never hard-fails on a thin install.
    """
    choice = (cfg.engine or "auto").strip().lower()
    if choice in _HEURISTIC_ALIASES:
        return _heuristic_engine, []

    if choice in _ONNX_ALIASES:
        ladder = (_onnx_classifier,)
    elif choice in _DEBERTA_ALIASES:
        ladder = (_transformer_classifier,)
    else:  # auto: prefer the light ONNX tier, then the heavy torch tier.
        ladder = (_onnx_classifier, _transformer_classifier)

    for build in ladder:
        clf = build(cfg)
        if clf is not None:
            return (lambda t, _c=clf: (_c(t), [])), []

    return _heuristic_engine, [_fallback_note(choice)]


def scan(
    model: SystemModel,
    cfg: MLConfig | None = None,
    classifier: Classifier | None = None,
) -> tuple[list[Finding], list[str]]:
    """Score every text surface. Returns (findings, notes).

    With no `classifier` injected the engine is resolved from `cfg.engine`:
    the DeBERTa model when `attestral[ml]` is installed, otherwise a transparent
    fall-back to the zero-dependency heuristic detector (torch missing is never
    an error). `notes` carries an informational message when that fall-back
    happens. `classifier` is injectable so the orchestration runs offline in
    tests.
    """
    cfg = cfg or MLConfig()
    surfaces = gather_surfaces(model)
    if not surfaces:
        return [], []
    if classifier is None:
        engine, notes = _resolve_engine(cfg)
    else:
        engine, notes = (lambda t: (classifier(t), [])), []
    findings: list[Finding] = []
    for s in surfaces:
        best_prob, best_ev = 0.0, []  # type: tuple[float, list[str]]
        for chunk in _chunks(s.text, cfg.max_chars, cfg.overlap):
            prob, ev = engine(chunk)
            if prob > best_prob:
                best_prob, best_ev = prob, ev
        if best_prob >= cfg.threshold:
            findings.append(_finding(s, best_prob, best_ev))
    findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return findings, notes
