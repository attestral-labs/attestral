"""GitHub Actions workflow ingestion.

Reads `.github/workflows/*.yml|yaml` and emits one `ci_workflow` component per
job, flattening the four signals of the CI confused-deputy shape behind
CVE-2026-54316 (Novee Security, Black Hat USA 2026): an AI coding agent wired
into CI, reachable from an unprivileged trigger (a GitHub issue), with runner
secrets in scope and a shell under the agent. Each signal is a plain derived
attribute so a cross-boundary rule can join them with the standard matcher
vocabulary - no signal alone is a finding; the *combination* is, and only a
system model sees the combination.

Uses pyyaml, which is already a core dependency; no extra install needed.
Fail-closed throughout: a malformed workflow, an unexpected node shape, or an
ambiguous configuration contributes nothing - a signal is only ever stamped
true on positive evidence.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from attestral.model import Component, SystemModel

# Triggers an unprivileged outsider can fire while the workflow still runs in
# the base-repo context (write-capable GITHUB_TOKEN + repository secrets).
# A plain `pull_request` from a fork is deliberately NOT counted: it runs with
# a read-only token and no secrets by default, so it lacks the privileged half
# of the confused deputy. `pull_request_target`, the issue events, and
# `workflow_run` are the high-signal untrusted triggers - attacker-controlled
# content in, privileged context out (the CVE-2026-54316 entry point).
# Feeds the `_untrusted_trigger` half of the CI confused-deputy risk chain.
_UNTRUSTED_TRIGGERS = ("issues", "issue_comment", "pull_request_target", "workflow_run")

# Curated AI-coding-agent actions (owner/repo, matched exactly after stripping
# the @ref pin). Feeds `_invokes_ai_agent`: an agent here means issue/PR text
# reaches an LLM that can act inside the runner.
_AI_AGENT_ACTIONS = frozenset({
    "anthropics/claude-code-action",
    "anthropics/claude-code-base-action",
    "google-github-actions/run-gemini-cli",
    "openai/codex-action",
})

# Curated agentic CLIs, matched only in command position of a `run:` line
# (never bare substring) so `pytest` or a path fragment can't false-positive.
_AI_AGENT_CLIS = frozenset({
    "claude", "claude-code", "gemini", "codex", "aider", "cursor-agent", "opencode",
})

# Package runners whose *second* token is the real command (`npx claude-code`).
_CLI_RUNNERS = frozenset({"npx", "pnpx", "bunx", "uvx", "pipx"})

# `${{ secrets.NAME }}` references in the job subtree. The implicit
# GITHUB_TOKEN is excluded (every job has it); its *write grants* are picked up
# via `permissions:` below instead. Feeds `_secrets_in_scope`.
_SECRET_REF_RE = re.compile(r"\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}")

# GITHUB_TOKEN permission scopes whose `write` grant makes the default token a
# theft-worthy secret on its own (push code / rewrite PRs from CI).
_WRITE_SCOPES = ("contents", "pull-requests")

# `with:` keys that can hand an agent action a shell. `bash:` is a boolean
# toggle; `allowed_tools`/`tools` are tool LISTS. `claude_args` is free-text CLI
# args (which may carry a prompt), so it is handled specially below - never
# scanned as prose.
_TOOL_LIST_KEYS = frozenset({"allowed_tools", "allowedtools", "tools"})
_SHELL_BOOL_KEYS = frozenset({"bash"})
# A shell-granting TOOL TOKEN, matched at a word boundary so it fires on a tool
# grant (`Bash`, `Bash(git:*)`, `shell`) but NOT on the word "bash" inside a
# free-text prompt ("flag unsafe bash usage") - the confirmed false positive.
_SHELL_TOOL_RE = re.compile(r"\b(?:bash|shell)\b", re.I)
# The CLI flag that grants tools inside a `claude_args` string; only when it is
# present AND names a shell tool does claude_args imply a shell.
_ALLOWED_TOOLS_FLAG_RE = re.compile(r"--allowed[-_]?tools\b", re.I)


def _trigger_names(doc: dict) -> list[str]:
    """Every trigger name on the workflow's `on:` block, tolerating all three
    syntaxes (scalar, list, mapping). YAML 1.1 parses an unquoted `on` key as
    boolean True, so both spellings are read. Unrecognized shape -> nothing."""
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return [on]
    if isinstance(on, list):
        return [str(t) for t in on if isinstance(t, str)]
    if isinstance(on, dict):
        return [str(k) for k in on]
    return []


def _strings_in(node: Any):
    """Yield every string value in a YAML subtree (keys skipped: a `${{ }}`
    expression can only appear in a value)."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _strings_in(v)
    elif isinstance(node, list):
        for item in node:
            yield from _strings_in(item)


def _action_ref(uses: Any) -> str:
    """The owner/repo of a `uses:` reference, lowercased, @ref stripped."""
    return str(uses or "").split("@", 1)[0].strip().lower()


def _run_agent_cli(run_text: Any) -> str | None:
    """The first curated agentic CLI invoked by a `run:` script, or None.

    Only a token in command position counts: the first word of each
    `&&`/`||`/`;`/`|`-separated segment (one hop through a package runner like
    npx), basename'd and version-stripped. Never a bare substring match."""
    for line in str(run_text or "").splitlines():
        for segment in re.split(r"&&|\|\||[;|]", line):
            tokens = segment.strip().split()
            if not tokens:
                continue
            head = tokens[0].rsplit("/", 1)[-1].lower()
            if head in _CLI_RUNNERS and len(tokens) > 1:
                head = tokens[1].rsplit("/", 1)[-1].lower()
            head = head.split("@", 1)[0]
            if head in _AI_AGENT_CLIS:
                return head
    return None


def _with_grants_shell(with_block: Any) -> bool:
    """True only when an agent action's `with:` block clearly hands the agent a
    shell: a `bash:` boolean set true, an `allowed_tools`/`tools` list that
    names a shell tool token, or a `claude_args` that carries an
    `--allowed-tools` flag granting one. A shell/bash word inside a free-text
    prompt does NOT count. Anything ambiguous -> False (fail closed)."""
    if not isinstance(with_block, dict):
        return False
    for key, value in with_block.items():
        norm = str(key).strip().lower().replace("-", "_")
        if norm in _SHELL_BOOL_KEYS:
            if value is True:      # only an explicit boolean toggle, not a string
                return True
        elif norm in _TOOL_LIST_KEYS:
            if _SHELL_TOOL_RE.search(str(value)):   # a tool token, word-bounded
                return True
        elif norm == "claude_args":
            # Free-text CLI args: shell only via an explicit tool-grant flag that
            # names a shell tool - never from a prompt that mentions "bash".
            s = str(value)
            if _ALLOWED_TOOLS_FLAG_RE.search(s) and _SHELL_TOOL_RE.search(s):
                return True
    return False


def _permission_grants(perms: Any) -> list[str]:
    """The risky GITHUB_TOKEN grants in a `permissions:` block, as evidence
    strings (`permissions:write-all`, `permissions:contents:write`, ...).
    Unknown shape or read-only grants -> nothing."""
    grants: list[str] = []
    if isinstance(perms, str):
        if perms.strip().lower() == "write-all":
            grants.append("permissions:write-all")
    elif isinstance(perms, dict):
        for scope in _WRITE_SCOPES:
            if str(perms.get(scope, "")).strip().lower() == "write":
                grants.append(f"permissions:{scope}:write")
    return grants


def _agent_signals(job: dict) -> tuple[str | None, bool, list[dict]]:
    """(matched agent, agent step is shell-capable, agent step dicts).

    A `run:` invocation of an agentic CLI is inherently shell-capable (the run
    IS a shell). An agent *action* is shell-capable only when its `with:` block
    proves it. The first match names the agent; shell is true if ANY
    agent-bearing step is shell-capable. The agent step list is returned so the
    caller can scope secret-reachability to the steps the agent actually runs in
    (not a secret used only by a sibling step). Feeds `_invokes_ai_agent`,
    `_ai_agent`, `_agent_step_has_shell`, and `_secrets_in_scope`."""
    agent: str | None = None
    shell = False
    agent_steps: list[dict] = []
    steps = job.get("steps")
    for step in steps if isinstance(steps, list) else []:
        if not isinstance(step, dict):
            continue
        if _action_ref(step.get("uses")) in _AI_AGENT_ACTIONS:
            agent = agent or _action_ref(step.get("uses"))
            shell = shell or _with_grants_shell(step.get("with"))
            agent_steps.append(step)
        cli = _run_agent_cli(step.get("run"))
        if cli:
            agent = agent or cli
            shell = True
            agent_steps.append(step)
    return agent, shell, agent_steps


def _job_component(f: Path, doc: dict, job_key: str, job: dict) -> Component:
    triggers = _trigger_names(doc)
    untrusted = [t for t in triggers if t in _UNTRUSTED_TRIGGERS]
    agent, shell, agent_steps = _agent_signals(job)

    # Secrets the AGENT can actually reach, not any secret in the job. GitHub
    # only injects a `${{ secrets.X }}` reference into the step that names it, so
    # a secret used solely by a sibling step is not agent-reachable. The reachable
    # set is: the agent step(s)' own subtree, plus workflow- and job-level `env:`
    # (injected into every step, the agent's included). A write-grant on the
    # GITHUB_TOKEN is always agent-reachable (the token is present in every step).
    scope_nodes = [*agent_steps, doc.get("env"), job.get("env")]
    secret_refs = sorted({
        name for text in _strings_in(scope_nodes)
        for name in _SECRET_REF_RE.findall(text)
        if name.upper() != "GITHUB_TOKEN"
    })
    perms = job["permissions"] if "permissions" in job else doc.get("permissions")
    secret_refs += _permission_grants(perms)

    name = job.get("name")
    attrs: dict[str, Any] = {
        "workflow": f.name,
        "triggers": triggers,
        # The four halves of the CI confused-deputy chain (CVE-2026-54316):
        # untrusted actor -> agent -> secrets/shell. Each is fail-closed.
        "_untrusted_trigger": bool(untrusted),
        "_untrusted_triggers": untrusted,
        "_invokes_ai_agent": agent is not None,
        "_secrets_in_scope": bool(secret_refs),
        "_secret_refs": secret_refs,
        "_agent_step_has_shell": bool(agent) and shell,
    }
    # Omitted when no agent matched, so `attr_missing` keeps its meaning.
    if agent is not None:
        attrs["_ai_agent"] = agent
    return Component(
        id=f"ci_workflow.{f.stem}.{job_key}",
        type="ci_workflow",
        name=str(name) if isinstance(name, str) and name else job_key,
        source=str(f),
        attributes=attrs,
        trust_boundary="ci",
    )


def _is_workflow(doc: Any) -> bool:
    """A GitHub Actions workflow: a mapping with a `jobs:` mapping and an
    `on:` trigger block (either spelling - see _trigger_names)."""
    return (
        isinstance(doc, dict)
        and isinstance(doc.get("jobs"), dict)
        and ("on" in doc or True in doc)
    )


def ingest_github_actions(path: str | Path, model: SystemModel) -> SystemModel:
    p = Path(path)
    if p.is_file():
        files = [p]
    else:
        files = sorted(
            list(p.rglob(".github/workflows/*.yml"))
            + list(p.rglob(".github/workflows/*.yaml"))
        )
    for f in files:
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            continue  # malformed workflow: skipped, never crashes the scan
        if not _is_workflow(doc):
            continue
        for job_key, job in doc["jobs"].items():
            if isinstance(job, dict):
                model.add(_job_component(f, doc, str(job_key), job))
    return model
