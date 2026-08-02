"""System-prompt / agent-instruction ingestion.

Agentic systems are steered by natural-language instructions - system
prompts, tool descriptions, agent playbooks. Those are a first-class attack
surface (prompt injection, jailbreaks, tool-poisoning text) that the
deterministic rules cannot see, because the risk is in the *words*, not in a
config flag. This ingester pulls that text into the model as `system_prompt`
components carrying a `content` attribute; the optional ML layer
(`attestral[ml]`) is what scores that content.

Patterns are deliberately tight so a scan does not sweep every Markdown file
in a repo into the model. A file qualifies if it is under a `prompts/`
directory, has a `.prompt[.txt|.md]` extension, or its name marks it as a
system prompt / agent instruction set.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from attestral.model import Component, SystemModel

# High-precision credential shapes for detecting a secret hard-coded in prompt
# text. Provider-prefixed tokens and key blocks are near-zero false-positive; the
# generic assignment requires a long high-entropy value that is not a placeholder.
_SECRET_PATTERNS: list[tuple[str, "re.Pattern[str]"]] = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe-key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b")),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("db-uri-with-credentials", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^\s:/@]+:[^\s:/@]{3,}@", re.I)),
    ("credential-assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key|"
        r"client[_-]?secret|auth[_-]?token)\b\s*[:=]\s*['\"]?([A-Za-z0-9/+_\-]{20,})['\"]?")),
]
_PLACEHOLDER = re.compile(
    r"(?i)your|example|placeholder|changeme|xxx+|redacted|dummy|<[^>]+>|\.\.\.|"
    r"insert|todo|fake|sample|test[_-]?key|xoxb-your")


# A fetch-remote-and-execute one-liner (curl | sh, wget | bash, iex(iwr ...)):
# remote code pulled and run in one step. Baked into a standing instruction or
# skill file, it is code the agent may run every session, from a URL that can
# change under you. High precision - the pipe-into-a-shell shape is specific.
_REMOTE_EXEC = re.compile(
    r"(?is)(?:curl|wget|iwr|invoke-webrequest|fetch)\b[^\n|]{0,200}\|\s*"
    r"(?:sudo\s+)?(?:sh|bash|zsh|python[0-9.]*|node|iex|pwsh|powershell)\b"
    r"|(?:sudo\s+)?(?:sh|bash|zsh)\s+<\(\s*(?:curl|wget)\b"
    r"|iex\s*\(\s*(?:iwr|new-object\s+net\.webclient)")


def _remote_exec_oneliner(content: str) -> bool:
    return bool(_REMOTE_EXEC.search(content))


def _embedded_secret(content: str) -> list[str]:
    """Credential-shaped values hard-coded in prompt text. Prompts are logged,
    shared, and version-controlled, so a real secret in one leaks (OWASP LLM07
    System Prompt Leakage / LLM02). Returns the kinds found; empty for benign
    text. The generic assignment requires a long, high-entropy, non-placeholder
    value, so `api_key: <your-key-here>` never fires."""
    kinds: list[str] = []
    for kind, pat in _SECRET_PATTERNS:
        m = pat.search(content)
        if not m:
            continue
        if kind == "credential-assignment":
            val = m.group(1)
            if _PLACEHOLDER.search(val) or len(set(val)) < 8:
                continue
        kinds.append(kind)
    return sorted(set(kinds))

# Cap so a runaway file can never dominate context / a classifier window.
_MAX_CHARS = 20_000

_NAME_HINTS = ("system-prompt", "system_prompt", "systemprompt")

# Standing agent-instruction files: memory/context that steers the agent on
# every run (OWASP ASI06). Poisoning one of these is persistent, not
# per-session. Matched by exact filename (case-insensitive).
_INSTRUCTION_FILES = {
    "claude.md", "agents.md", "agent.md", ".cursorrules", ".windsurfrules",
    ".github/copilot-instructions.md", "copilot-instructions.md",
    ".clinerules", ".aider.conf.yml", "gemini.md", "codex.md",
}


def _is_instruction_file(f: Path) -> bool:
    name = f.name.lower()
    if name in _INSTRUCTION_FILES:
        return True
    # copilot-instructions.md lives under .github/; match on the tail.
    return name == "copilot-instructions.md"


def _is_skill_file(f: Path) -> bool:
    """A packaged agent skill (Claude/Cursor): a SKILL.md manifest, usually at
    <root>/skills/<name>/SKILL.md. Standing, auto-loaded instructions that can
    also declare tool grants - so it is both a poisoning surface and an
    excessive-agency surface."""
    return f.name.lower() == "skill.md"


def _skill_frontmatter(content: str) -> dict | None:
    """Parse a SKILL.md YAML frontmatter block into its mapping. Fails closed:
    a missing fence, malformed YAML, or a non-mapping document yields None - we
    never guess a manifest's intent from broken metadata."""
    if not content.startswith("---"):
        return None
    end = content.find("\n---", 3)
    if end == -1:
        return None
    import yaml
    try:
        meta = yaml.safe_load(content[3:end])
    except yaml.YAMLError:
        return None
    return meta if isinstance(meta, dict) else None


def _skill_body(content: str) -> str:
    """The instruction text after the closing frontmatter fence - the part the
    agent actually executes. A file with no fence is all body."""
    if not content.startswith("---"):
        return content
    end = content.find("\n---", 3)
    if end == -1:
        return content
    nl = content.find("\n", end + 4)
    return content[nl + 1:] if nl != -1 else ""


def _skill_tool_grant(meta: dict | None) -> bool | None:
    """An `allowed-tools` grant that hands the skill shell/exec or wildcard
    tool access. Returns True/False when the grant is declared, or None when it
    is not (we never guess - absent or unparseable frontmatter yields None, not
    a finding)."""
    if meta is None:
        return None
    grant = meta.get("allowed-tools", meta.get("allowed_tools"))
    if grant is None:
        return None
    tokens = grant if isinstance(grant, list) else str(grant).replace(",", " ").split()
    return any(
        t == "*" or "bash" in t or "shell" in t or t.startswith("exec")
        for t in (str(x).lower() for x in tokens)
    )


# Read-only / no-side-effects promises a skill description can make. Phrase-level
# and word-bounded so ordinary prose ("reads the config, then updates it") never
# matches.
_READONLY_CLAIM = re.compile(
    r"(?i)\b(?:read[\s-]?only|only\s+reads|"
    r"never\s+(?:writes?|modif(?:y|ies)|changes?|executes?|runs?)|"
    r"does\s+not\s+(?:write|modify|execute|run)|"
    r"no\s+side[\s-]effects?|non[\s-]?destructive)\b"
)


def _skill_deceptive_readonly(meta: dict | None, grant: bool | None) -> bool:
    """A read-only/no-side-effects description over a shell-grade tool grant.
    The description is what the operator and the invoking agent trust when the
    skill loads, and here it contradicts what the manifest actually grants - a
    deceptive capability claim (tool poisoning via manifest). Feeds
    `_skill_deceptive_readonly`; requires the grant to be affirmatively broad
    (True), never inferred from an absent or unparseable one (None)."""
    if not grant or meta is None:
        return False
    desc = meta.get("description")
    return isinstance(desc, str) and bool(_READONLY_CLAIM.search(desc))


# Standing agent-memory / instruction files an agent auto-loads every session.
_MEMORY_FILE_TOKENS = (
    r"(?:\bCLAUDE\.md\b|\bMEMORY\.md\b|\bSOUL\.md\b|\bAGENTS\.md\b|\bGEMINI\.md\b|"
    r"\bcopilot-instructions\.md\b|\.cursorrules\b|\.windsurfrules\b)"
)
_PERSIST_VERBS = (
    r"(?:write|writes|writing|append(?:s|ed|ing)?|add(?:s|ed|ing)?|"
    r"insert(?:s|ed|ing)?|save(?:s|d)?|saving|update(?:s|d)?|updating|"
    r"edit(?:s|ed|ing)?|modif(?:y|ies|ied|ying)|create(?:s|d)?|creating|"
    r"cop(?:y|ies|ied|ying))"
)
# A write-verb shortly before a standing memory file. The window excludes
# sentence breaks so a verb in one sentence never pairs with a file named in
# the next.
_PERSIST_WRITE = re.compile(
    r"(?i)\b" + _PERSIST_VERBS + r"\b[^.\n]{0,80}?" + _MEMORY_FILE_TOKENS
)
# "Never write to CLAUDE.md" is guidance, not persistence: a negation just
# before the write-verb, with no sentence break between, suppresses the hit.
_PERSIST_NEGATION = re.compile(
    r"(?i)\b(?:never|don['’]?t|do\s+not|avoid|must\s+not|should\s+not)\b[^.\n]{0,40}$"
)


def _skill_persists_instructions(body: str) -> bool:
    """The skill body directs the agent to write into an always-loaded
    memory/instruction file (CLAUDE.md, MEMORY.md, .cursorrules, ...). That
    escalates an invoked, per-session surface into a persistent one -
    self-persistence / memory poisoning (OWASP ASI06). Feeds
    `_skill_persists_instructions`."""
    for m in _PERSIST_WRITE.finditer(body):
        if _PERSIST_NEGATION.search(body, max(0, m.start() - 80), m.start()):
            continue
        return True
    return False


def _world_writable(f: Path) -> bool:
    """True if any user on the host can rewrite the file (or its dir) - a
    standing-instruction file anyone can edit is a persistent poisoning vector.
    Fail-closed: an unstattable file is not reported as writable."""
    try:
        if os.stat(f).st_mode & stat.S_IWOTH:
            return True
        return bool(os.stat(f.parent).st_mode & stat.S_IWOTH)
    except OSError:
        return False


def _qualifies(f: Path) -> bool:
    name = f.name.lower()
    if name.endswith((".prompt", ".prompt.txt", ".prompt.md")):
        return True
    if any(h in name for h in _NAME_HINTS):
        return True
    return "prompts" in {part.lower() for part in f.parent.parts}


def ingest_prompts(path: str | Path, model: SystemModel) -> SystemModel:
    p = Path(path)
    if p.is_file():
        files = [p] if (_qualifies(p) or _is_instruction_file(p) or _is_skill_file(p)) else []
    else:
        seen: set[Path] = set()
        files = []
        for pattern in ("*.txt", "*.md", "*.prompt", "*.cursorrules", "*.windsurfrules"):
            for f in p.rglob(pattern):
                if f not in seen and (_qualifies(f) or _is_instruction_file(f) or _is_skill_file(f)):
                    seen.add(f)
                    files.append(f)
        # Dotfile instruction sets (.cursorrules, .windsurfrules, .clinerules)
        # are not caught by the extension globs above.
        for f in p.rglob(".*rules"):
            if f.is_file() and f not in seen and _is_instruction_file(f):
                seen.add(f)
                files.append(f)
        files.sort()
    for f in files:
        try:
            content = f.read_text(errors="ignore")[:_MAX_CHARS]
        except OSError:
            continue
        if not content.strip():
            continue
        skill = _is_skill_file(f)
        instruction = skill or _is_instruction_file(f)
        ctype = "agent_instruction" if instruction else "system_prompt"
        attrs: dict = {"content": content}
        secret_kinds = _embedded_secret(content)
        if secret_kinds:
            attrs["_embedded_secret"] = True
            attrs["_embedded_secret_kinds"] = secret_kinds
        if _remote_exec_oneliner(content):
            attrs["_remote_install_oneliner"] = True
        if instruction:
            # Deterministic ASI06 signal: a standing-instruction file the whole
            # host can rewrite is a persistent poisoning vector (ATL-113). The
            # poisoning *text* itself is the ML layer's job, via `content`.
            attrs["_world_writable"] = _world_writable(f)
        if skill:
            attrs["_is_skill"] = True
            meta = _skill_frontmatter(content)
            grant = _skill_tool_grant(meta)
            if grant is not None:
                attrs["_skill_broad_tools"] = grant  # ATL-116
            # Read-only claim over a shell grant: deceptive capability claim.
            if _skill_deceptive_readonly(meta, grant):
                attrs["_skill_deceptive_readonly"] = True
            # Body writes into standing memory files: self-persistence.
            if _skill_persists_instructions(_skill_body(content)):
                attrs["_skill_persists_instructions"] = True
        # Skills are all named SKILL.md, so key the component on their folder.
        comp_name = f.parent.name if skill else (f.stem or f.name)
        model.add(
            Component(
                id=f"{ctype}.{comp_name}",
                type=ctype,
                name=comp_name,
                source=str(f),
                attributes=attrs,
                trust_boundary="agent_runtime",
            )
        )
    return model
