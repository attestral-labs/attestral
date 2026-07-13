"""Agent settings, hooks, subagents, and A2A agent-card ingestion.

Three delegation-and-config surfaces of a multi-agent workspace:

* `.claude/settings.json` (and friends) can define HOOKS that execute shell
  commands around tool use - the config-injection class behind CVE-2025-59536.
  Surfaced as `agent_config` components (ATL-118).
* `.claude/agents/*.md` SUBAGENT definitions: delegates the main agent can
  invoke, whose frontmatter `tools:` grants built-in capabilities (Bash,
  WebFetch, ...) that exist entirely outside the MCP server fleet. Surfaced
  as `subagent` components with derived `_capabilities`, so the fleet-level
  combination rules (ATL-202/203/207) see through the delegation hop. A
  definition with no `tools:` key (or `*`) inherits everything - that is
  flagged as excessive agency (ATL-120) but deliberately contributes NO
  capabilities: an unknown grant is never guessed into a finding.
* `.well-known/agent-card.json` (A2A protocol, v1 - also the older
  `agent.json`): this repo exposes an agent endpoint to other agents.
  Surfaced as `a2a_agent` components; a card with no `securitySchemes` /
  `security` / `authentication` is a public agent (ATL-121).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from attestral.model import Component, SystemModel

_SETTINGS_NAMES = ("settings.json", "settings.local.json")
_AGENT_CARD_NAMES = ("agent-card.json", "agent.json")

# Built-in agent tools -> the capability class they hand a delegate. Only
# unambiguous grants are mapped; anything unrecognized maps to nothing.
_BUILTIN_TOOL_CAPS = {
    "bash": "shell",
    "webfetch": "network",
    "websearch": "network",
    "read": "filesystem",
    "write": "filesystem",
    "edit": "filesystem",
    "notebookedit": "filesystem",
    "glob": "filesystem",
    "grep": "filesystem",
}


def _hook_commands(hooks) -> list[str]:
    """Every shell command declared in a Claude-Code-style hooks block, which
    nests as {event: [{matcher, hooks: [{type: command, command: "..."}]}]}.
    Tolerant of shape drift: a `command` on either nesting level counts."""
    out: list[str] = []
    if not isinstance(hooks, dict):
        return out
    for entries in hooks.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("command"):
                out.append(str(entry["command"]))
            inner = entry.get("hooks")
            if isinstance(inner, list):
                for h in inner:
                    if isinstance(h, dict) and h.get("command"):
                        out.append(str(h["command"]))
    return out


def _is_settings_file(f: Path) -> bool:
    return f.name in _SETTINGS_NAMES and ".claude" in {p.lower() for p in f.parts}


def _frontmatter(text: str) -> dict:
    """The YAML frontmatter of a subagent definition. Falls back to a
    line-based scan of the keys we need when the YAML is malformed - a broken
    file must degrade to partial data, never to a crash or a guess."""
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    block = text[3:end]
    try:
        data = yaml.safe_load(block)
        if isinstance(data, dict):
            return data
    except yaml.YAMLError:
        pass
    out: dict = {}
    for m in re.finditer(r"^(name|description|tools)\s*:\s*(.+)$", block, re.MULTILINE):
        out[m.group(1)] = m.group(2).strip()
    return out


def _subagent_component(f: Path) -> Component:
    fm = _frontmatter(f.read_text(errors="ignore"))
    name = str(fm.get("name") or f.stem)
    raw_tools = fm.get("tools")
    if isinstance(raw_tools, str):
        tools = [t.strip() for t in raw_tools.split(",") if t.strip()]
    elif isinstance(raw_tools, list):
        tools = [str(t).strip() for t in raw_tools if str(t).strip()]
    else:
        tools = []
    # No tools key (or an explicit *) = the delegate inherits every tool the
    # main agent has. Flagged by ATL-120; contributes no capabilities.
    wildcard = "tools" not in fm or "*" in tools
    caps = (
        []
        if wildcard
        else sorted({
            _BUILTIN_TOOL_CAPS[t.lower()]
            for t in tools
            if t.lower() in _BUILTIN_TOOL_CAPS
        })
    )
    attrs: dict = {
        "_tools": tools,
        "_wildcard_tools": wildcard,
        "_capabilities": caps,
    }
    if fm.get("description"):
        attrs["description"] = str(fm["description"])
    return Component(
        id=f"subagent.{name}",
        type="subagent",
        name=name,
        source=str(f),
        attributes=attrs,
        trust_boundary="agent_runtime",
    )


def _a2a_component(f: Path) -> Component | None:
    try:
        data = json.loads(f.read_text(errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    name = str(data.get("name") or f.stem)
    schemes = data.get("securitySchemes")
    # A2A spec: `securitySchemes` DEFINES auth methods; `security` (a non-empty
    # list of requirement objects) says which are REQUIRED. Schemes with no
    # requirement is a public agent that merely looks protected - a distinct,
    # more precise finding (ATL-123) than declaring nothing at all (ATL-121).
    no_auth = not (schemes or data.get("security") or data.get("authentication"))
    defined_not_required = bool(schemes) and not data.get("security")
    skills = data.get("skills")
    skill_names = (
        [str(s.get("id") or s.get("name") or "") for s in skills if isinstance(s, dict)]
        if isinstance(skills, list) else []
    )
    attrs: dict = {
        "url": str(data.get("url", "")),
        "_no_auth_declared": no_auth,
        "_auth_defined_not_required": defined_not_required,
        # "effectively public" = any external agent can invoke it: either no
        # auth at all, or schemes defined but none required. This is what the
        # cross-boundary reachability rule (ATL-208) keys on.
        "_effectively_public": no_auth or defined_not_required,
        "_skills": [s for s in skill_names if s],
    }
    if data.get("description"):
        attrs["description"] = str(data["description"])
    return Component(
        id=f"a2a_agent.{name}",
        type="a2a_agent",
        name=name,
        source=str(f),
        attributes=attrs,
        trust_boundary="agent_runtime",
    )


def _is_subagent_file(f: Path) -> bool:
    return (
        f.suffix == ".md"
        and f.parent.name == "agents"
        and ".claude" in {p.lower() for p in f.parts}
    )


def _is_agent_card(f: Path) -> bool:
    return f.name in _AGENT_CARD_NAMES and f.parent.name == ".well-known"


def ingest_agent_config(path: str | Path, model: SystemModel) -> SystemModel:
    p = Path(path)
    if p.is_file():
        settings = [p] if _is_settings_file(p) else []
        subagents = [p] if _is_subagent_file(p) else []
        cards = [p] if _is_agent_card(p) else []
    else:
        settings = sorted(
            {f for name in _SETTINGS_NAMES for f in p.rglob(f".claude/{name}")}
        )
        subagents = sorted(p.rglob(".claude/agents/*.md"))
        cards = sorted(
            {f for name in _AGENT_CARD_NAMES for f in p.rglob(f".well-known/{name}")}
        )
    for f in settings:
        try:
            data = json.loads(f.read_text(errors="ignore"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        cmds = _hook_commands(data.get("hooks"))
        # Name the component after the directory holding .claude, so two repos'
        # settings files never collide on one id.
        anchor = f.parent.parent.name or f.parent.name
        model.add(
            Component(
                id=f"agent_config.{anchor}.{f.stem}",
                type="agent_config",
                name=f.name,
                source=str(f),
                attributes={"_hook_runs_commands": bool(cmds), "_hook_commands": cmds},
                trust_boundary="agent_runtime",
            )
        )
    for f in subagents:
        model.add(_subagent_component(f))
    for f in cards:
        card = _a2a_component(f)
        if card is not None:
            model.add(card)
    return model
