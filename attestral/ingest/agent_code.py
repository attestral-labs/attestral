"""Ingest agents defined in code, not just config.

Most real agents are wired in Python - LangGraph, CrewAI, AutoGen, the OpenAI
Agents SDK, Pydantic AI, and raw Anthropic / MCP tool definitions - so a
config-only scanner sees a minority of deployments. This ingester AST-parses
Python and models each file's agent surface as a `code_agent` component whose
`_capabilities` are read from the tools it defines, in the SAME vocabulary the
MCP ingester uses. The moment those capabilities land in the model, the fleet
rules, attack-path synthesis, reachability escalation, and AIVSS all light up on
agent *code* with zero new rules - the toxic flow across a shell tool and an
egress tool is the same flow whether it was declared in `.mcp.json` or a
`@tool`-decorated function.

Precision over recall (the north star): a file is only modeled when it imports a
known agent framework AND defines at least one tool or agent, so an ordinary
Python script is never misread as an agent. Capability is inferred from the
symbols a tool's body actually uses (subprocess -> shell, requests -> network,
open -> filesystem, a DB driver -> database, a messaging SDK -> messaging) and,
for schema-only Anthropic/MCP tool dicts we have no body for, from the tool's
name and description. Parsing is fail-open: a file that will not parse is
skipped, never fatal to the scan.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from attestral.model import Component, Edge, SystemModel

# Top-level modules whose import marks a file as an agent surface. Requiring one
# of these is the low-false-positive gate: no framework import, not an agent.
_AGENT_FRAMEWORKS = {
    "anthropic": "anthropic", "openai": "openai", "agents": "openai-agents",
    "langchain": "langchain", "langchain_core": "langchain",
    "langchain_community": "langchain", "langgraph": "langgraph",
    "crewai": "crewai", "autogen": "autogen", "autogen_agentchat": "autogen",
    "pydantic_ai": "pydantic-ai", "llama_index": "llama-index",
    "mcp": "mcp", "fastmcp": "fastmcp", "semantic_kernel": "semantic-kernel",
}

# Decorator names (final attribute or bare name) that mark a function as a tool.
_TOOL_DECORATORS = {"tool", "function_tool", "tool_plugin", "kernel_function", "ai_function"}

# Symbol -> capability. Matched against the dotted callee/attribute names and the
# imported module roots a tool's body references. Kept in step with the MCP
# ingester's capability classes so a code agent and an MCP server are comparable.
_SYMBOL_CAPS: dict[str, tuple[str, ...]] = {
    "shell": ("subprocess", "os.system", "os.popen", "pty", "commands", "sh.",
              "eval", "exec", "compile", "Popen", "check_output", "check_call",
              "getoutput", "getstatusoutput"),
    "network": ("requests", "httpx", "urllib", "aiohttp", "socket", "http.client",
                "urllib3", "websockets", "ftplib", "boto3", "botocore",
                "google.cloud", "googleapiclient", "azure", "paramiko", "fabric"),
    "filesystem": ("open", "pathlib", "shutil", "aiofiles", "os.remove",
                   "os.unlink", "os.walk", "os.listdir", "glob"),
    "database": ("psycopg", "psycopg2", "sqlite3", "sqlalchemy", "pymongo",
                 "redis", "mysql", "asyncpg", "snowflake", "bigquery", "clickhouse"),
    "messaging": ("slack_sdk", "slack", "smtplib", "sendgrid", "discord",
                  "telegram", "twilio", "mailgun"),
    "saas_data": ("github", "gitlab", "notion_client", "notion", "jira",
                  "atlassian", "gspread"),
    "memory": ("chromadb", "pinecone", "weaviate", "qdrant", "mem0",
               "vectorstores", "faiss", "pgvector"),
}

# Text hints (tool name + description), for schema-only tool dicts we cannot see
# the body of. Coarser than symbol matching, so used only as a fallback.
_TEXT_CAPS: dict[str, tuple[str, ...]] = {
    "shell": ("shell", "command", "bash", "execute", "run_code", "terminal", "subprocess"),
    "network": ("fetch", "http", "url", "browse", "download", "webhook", "request", "crawl"),
    "filesystem": ("file", "read_file", "write_file", "filesystem", "directory", "path"),
    "database": ("sql", "query", "database", "db_"),
    "messaging": ("email", "slack", "message", "send_mail", "sms", "notify"),
    "saas_data": ("github", "jira", "notion", "gdrive", "drive", "confluence"),
    "memory": ("memory", "vector", "embedding", "recall", "knowledge"),
}

# Directories never worth parsing as first-party agent code.
_SKIP_DIRS = {".venv", "venv", "env", "node_modules", "research", "__pycache__",
              ".git", "build", "dist", "site-packages", ".tox", ".mypy_cache",
              "tests", "test"}


def _dotted(node: ast.AST) -> str:
    """Best-effort dotted name for an attribute/name/call target."""
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}".lstrip(".")
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _symbols_used(node: ast.AST) -> set[str]:
    """Every dotted callee and attribute name referenced under `node` - the
    symbols a tool's body touches, which is what its capability is read from."""
    out: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            name = _dotted(sub.func)
            if name:
                out.add(name)
        elif isinstance(sub, ast.Attribute):
            name = _dotted(sub)
            if name:
                out.add(name)
    return out


def _caps_from_symbols(symbols: set[str]) -> set[str]:
    caps: set[str] = set()
    joined = " ".join(symbols)
    for cap, hints in _SYMBOL_CAPS.items():
        if any(h in joined for h in hints):
            caps.add(cap)
    return caps


def _caps_from_text(text: str) -> set[str]:
    caps: set[str] = set()
    low = text.lower()
    for cap, hints in _TEXT_CAPS.items():
        if any(h in low for h in hints):
            caps.add(cap)
    return caps


def _decorator_name(dec: ast.AST) -> str:
    """The final name of a decorator, whether `@tool`, `@x.tool`, or `@tool(...)`."""
    if isinstance(dec, ast.Call):
        dec = dec.func
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Name):
        return dec.id
    return ""


def _frameworks(tree: ast.AST) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                root = a.name.split(".")[0]
                if root in _AGENT_FRAMEWORKS:
                    found.add(_AGENT_FRAMEWORKS[root])
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root in _AGENT_FRAMEWORKS:
                found.add(_AGENT_FRAMEWORKS[root])
    return found


def _tool_functions(tree: ast.AST) -> list[tuple[str, set[str]]]:
    """(tool name, capabilities) for every @tool-decorated function."""
    out: list[tuple[str, set[str]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_decorator_name(d) in _TOOL_DECORATORS for d in node.decorator_list):
            continue
        caps = _caps_from_symbols(_symbols_used(node))
        doc = ast.get_docstring(node) or ""
        caps |= _caps_from_text(f"{node.name} {doc}")
        out.append((node.name, caps))
    return out


def _tool_dicts(tree: ast.AST) -> list[tuple[str, set[str]]]:
    """(tool name, capabilities) for Anthropic/MCP schema tool dicts - list
    literals of dicts carrying a `name` and a schema/description. We have no
    body, so capability is read from the name and description text."""
    out: list[tuple[str, set[str]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        keys = {k.value for k in node.keys if isinstance(k, ast.Constant)
                and isinstance(k.value, str)}
        if "name" not in keys or not (keys & {"input_schema", "description", "parameters"}):
            continue
        name = desc = ""
        for k, v in zip(node.keys, node.values):
            if not (isinstance(k, ast.Constant) and isinstance(v, ast.Constant)):
                continue
            if k.value == "name" and isinstance(v.value, str):
                name = v.value
            elif k.value == "description" and isinstance(v.value, str):
                desc = v.value
        if name:
            out.append((name, _caps_from_text(f"{name} {desc}")))
    return out


def _agent_name(tree: ast.AST, default: str) -> str:
    """A representative agent variable name if the file constructs one
    (`agent = Agent(...)`, `graph = StateGraph(...)`), else the file stem."""
    ctors = {"Agent", "StateGraph", "Crew", "AssistantAgent", "Swarm", "Graph"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if _dotted(node.value.func).split(".")[-1] in ctors:
                tgt = node.targets[0]
                if isinstance(tgt, ast.Name):
                    return tgt.id
    return default


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-") or "agent"


def _alloc_id(name: str, taken: set[str]) -> str:
    """A collision-free `code_agent.<slug>` id, suffixed `#2`, `#3`... on clash."""
    slug = _slug(name)
    cid = f"code_agent.{slug}"
    suffix = 1
    while cid in taken:
        suffix += 1
        cid = f"code_agent.{slug}#{suffix}"
    taken.add(cid)
    return cid


def _crewai_agents(tree: ast.AST, tool_caps: dict[str, set[str]]) -> list[tuple[str, set[str]]]:
    """(role, capabilities) for each CrewAI `Agent(role=..., tools=[...])`.

    An agent's capabilities are the union of the tools it is handed, resolved by
    name against the file's @tool functions. A `role` is required (CrewAI agents
    always carry one), so a bare `Agent()` without a role is never split out - the
    precision-over-recall gate for the multi-agent path.
    """
    agents: list[tuple[str, set[str]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _dotted(node.func).split(".")[-1] != "Agent":
            continue
        role: str | None = None
        tool_names: list[str] = []
        for kw in node.keywords:
            if kw.arg == "role" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                role = kw.value.value
            elif kw.arg == "tools" and isinstance(kw.value, (ast.List, ast.Tuple)):
                for el in kw.value.elts:
                    if isinstance(el, ast.Name):
                        tool_names.append(el.id)
                    elif isinstance(el, ast.Call) and isinstance(el.func, ast.Name):
                        tool_names.append(el.func.id)
                    elif isinstance(el, ast.Attribute):
                        tool_names.append(el.attr)
        if not role:
            continue
        caps: set[str] = set()
        for tn in tool_names:
            caps |= tool_caps.get(tn, set())
        agents.append((role, caps))
    return agents


_GRAPH_SENTINELS = {"__start__", "__end__"}


def _edge_endpoint(node: ast.AST) -> str | None:
    """A LangGraph edge endpoint's node name - a string literal, minus the
    START/END sentinels (both the `START`/`END` Names and their `__start__`/
    `__end__` string forms), which are graph boundaries, not nodes."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return None if node.value in _GRAPH_SENTINELS else node.value
    return None  # START/END Names and non-literals are not real nodes


def _parse_add_node(call: ast.Call) -> tuple[str | None, ast.AST | None]:
    """(node name, action target) from `builder.add_node("name", fn)`,
    `add_node(fn)` (name taken from the function), or the `node=`/`action=` kwargs."""
    name: str | None = None
    target: ast.AST | None = None
    if call.args:
        first = call.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            name = first.value
            target = call.args[1] if len(call.args) > 1 else None
        else:
            target = first
    for kw in call.keywords:
        if kw.arg == "node" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            name = kw.value.value
        elif kw.arg in ("action", "runnable"):
            target = kw.value
    if name is None and target is not None:
        if isinstance(target, ast.Name):
            name = target.id
        elif isinstance(target, ast.Attribute):
            name = target.attr
    return name, target


def _tool_list_caps(node: ast.AST, funcs: dict[str, ast.AST], tool_caps: dict[str, set[str]]) -> set[str]:
    """Capabilities from a `tools=[...]` list - each element resolved by name
    against the file's @tool functions, plain functions, and its own text."""
    caps: set[str] = set()
    if not isinstance(node, (ast.List, ast.Tuple)):
        return caps
    for el in node.elts:
        nm = ""
        if isinstance(el, ast.Name):
            nm = el.id
        elif isinstance(el, ast.Attribute):
            nm = el.attr
        elif isinstance(el, ast.Call):
            nm = _dotted(el.func).split(".")[-1]
        if not nm:
            continue
        caps |= tool_caps.get(nm, set())
        fn = funcs.get(nm)
        if fn is not None:
            caps |= _caps_from_symbols(_symbols_used(fn))
        caps |= _caps_from_text(nm)
    return caps


def _node_caps(name: str, target: ast.AST | None, funcs: dict[str, ast.AST],
               tool_caps: dict[str, set[str]]) -> set[str]:
    """A LangGraph node's capabilities: the node name's text, plus - when the
    action is a function in this file - that function's body symbols and
    docstring, plus any tools handed to a `create_react_agent`/`ToolNode(...)`."""
    caps = _caps_from_text(name)
    if isinstance(target, ast.Name):
        fn = funcs.get(target.id)
        if fn is not None:
            caps |= _caps_from_symbols(_symbols_used(fn))
            caps |= _caps_from_text(ast.get_docstring(fn) or "")
        elif target.id in tool_caps:
            caps |= tool_caps[target.id]
    elif isinstance(target, ast.Attribute):
        caps |= _caps_from_text(target.attr)
    elif isinstance(target, ast.Call):
        for arg in target.args:
            caps |= _tool_list_caps(arg, funcs, tool_caps)
        for kw in target.keywords:
            if kw.arg == "tools":
                caps |= _tool_list_caps(kw.value, funcs, tool_caps)
    return caps


def _conditional_targets(call: ast.Call) -> list[str]:
    """Destination node names of `add_conditional_edges(src, router, path_map)`,
    where path_map is the `{branch: node}` dict or `[node, ...]` list (3rd
    positional arg or the `path_map=` kwarg)."""
    cand: ast.AST | None = call.args[2] if len(call.args) >= 3 else None
    for kw in call.keywords:
        if kw.arg == "path_map":
            cand = kw.value
    out: list[str] = []
    if isinstance(cand, ast.Dict):
        for v in cand.values:
            t = _edge_endpoint(v)
            if t:
                out.append(t)
    elif isinstance(cand, (ast.List, ast.Tuple)):
        for el in cand.elts:
            t = _edge_endpoint(el)
            if t:
                out.append(t)
    return out


def _langgraph_topology(tree: ast.AST, funcs: dict[str, ast.AST],
                        tool_caps: dict[str, set[str]]) -> tuple[list[tuple[str, set[str]]], list[tuple[str, str]]]:
    """(node, capabilities) for every `add_node` plus the `invokes` edges between
    them from `add_edge`/`add_conditional_edges`. Mirrors the CrewAI split: a
    StateGraph becomes one component per node so a toxic flow spanning nodes
    (untrusted-input node -> shell node -> egress node) is a real cross-node path.
    """
    node_caps: dict[str, set[str]] = {}
    order: list[str] = []
    edges: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        meth = _dotted(node.func).split(".")[-1]
        if meth == "add_node":
            name, target = _parse_add_node(node)
            if not name:
                continue
            if name not in node_caps:
                node_caps[name] = set()
                order.append(name)
            node_caps[name] |= _node_caps(name, target, funcs, tool_caps)
        elif meth == "add_edge" and len(node.args) >= 2:
            a, b = _edge_endpoint(node.args[0]), _edge_endpoint(node.args[1])
            if a and b:
                edges.append((a, b))
        elif meth == "add_conditional_edges" and node.args:
            src = _edge_endpoint(node.args[0])
            if src:
                edges.extend((src, t) for t in _conditional_targets(node))
    members = [(n, node_caps[n]) for n in order]
    edges = [(a, b) for a, b in edges if a in node_caps and b in node_caps]
    return members, edges


def _emit_topology(members: list[tuple[str, set[str]]], edges: list[tuple[str, str]],
                   framework: str, edge_via: str, node_flag: str,
                   model: SystemModel, rel: str, taken: set[str]) -> None:
    """Emit one `code_agent` component per member and an `invokes` edge per
    connection - the shared body of the multi-agent (crew / graph) split."""
    name_to_id: dict[str, str] = {}
    for name, caps in members:
        cid = _alloc_id(name, taken)
        name_to_id[name] = cid
        model.add(Component(
            id=cid, type="code_agent", name=name, source=rel,
            attributes={"_capabilities": sorted(caps), "_framework": [framework], node_flag: True},
            trust_boundary="agent_runtime",
        ))
    seen: set[tuple[str, str]] = set()
    for a, b in edges:
        if a != b and a in name_to_id and b in name_to_id and (a, b) not in seen:
            seen.add((a, b))
            model.edges.append(Edge(source_id=name_to_id[a], target_id=name_to_id[b],
                                    kind="invokes", attributes={"via": edge_via}))


def _ingest_file(pyfile: Path, root: Path, model: SystemModel, taken: set[str]) -> None:
    try:
        tree = ast.parse(pyfile.read_text(encoding="utf-8", errors="replace"))
    except (SyntaxError, ValueError, OSError):
        return  # fail open: an unparseable file is skipped, never fatal
    frameworks = _frameworks(tree)
    if not frameworks:
        return

    try:
        rel = str(pyfile.relative_to(root))
    except ValueError:
        rel = str(pyfile)

    tool_fns = _tool_functions(tree)
    tool_caps = {name: tcaps for name, tcaps in tool_fns}

    # LangGraph multi-node: split a StateGraph into one component per node.
    # Checked BEFORE the tool gate because node actions are plain callables, not
    # @tool-decorated - a graph can spread a full trifecta across nodes with no
    # @tool in the file at all, which the tool gate would otherwise drop entirely.
    # The node functions' bodies (subprocess -> shell, requests -> network) give
    # each node its capability, and add_edge/add_conditional_edges give the
    # `invokes` structure. Only when >= 2 nodes resolve; a trivial graph is not a
    # topology and falls through to the one-surface path below.
    if "langgraph" in frameworks:
        funcs = {n.name: n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        members, edges = _langgraph_topology(tree, funcs, tool_caps)
        if len(members) >= 2:
            _emit_topology(members, edges, "langgraph", "graph edge", "_graph_node",
                           model, rel, taken)
            return

    tools = tool_fns + _tool_dicts(tree)

    # CrewAI multi-agent: split a crew into one component per agent, so a toxic
    # flow that spans agents (an untrusted-input agent that delegates to a shell
    # agent and an egress agent) is a real cross-agent attack path instead of a
    # single blob that hides the structure. Only when >= 2 role-bearing agents
    # resolve; a single-agent crew falls through to the one-surface path below.
    if "crewai" in frameworks:
        crew = _crewai_agents(tree, tool_caps)
        if len(crew) >= 2:
            ids = [_alloc_id(role, taken) for role, _ in crew]
            for cid, (role, acaps) in zip(ids, crew):
                model.add(Component(
                    id=cid, type="code_agent", name=role, source=rel,
                    attributes={
                        "_capabilities": sorted(acaps),
                        "_framework": ["crewai"],
                        "_crew_agent": True,
                    },
                    trust_boundary="agent_runtime",
                ))
            for a, b in zip(ids, ids[1:]):
                model.edges.append(Edge(source_id=a, target_id=b, kind="invokes",
                                        attributes={"via": "crew delegation"}))
            return

    if not tools:
        return

    caps: set[str] = set()
    for _, tcaps in tools:
        caps |= tcaps

    base = _agent_name(tree, pyfile.stem)
    cid = f"code_agent.{base}"
    suffix = 1
    while cid in taken:
        suffix += 1
        cid = f"code_agent.{base}#{suffix}"
    taken.add(cid)

    model.add(Component(
        id=cid,
        type="code_agent",
        name=base,
        source=rel,
        attributes={
            "_capabilities": sorted(caps),
            "_tool_names": [name for name, _ in tools],
            "_tool_count": len(tools),
            "_framework": sorted(frameworks),
        },
        trust_boundary="agent_runtime",
    ))


def ingest_agent_code(path: str | Path, model: SystemModel) -> SystemModel:
    """Model every Python file that defines an agent (imports a known framework
    and declares at least one tool) as a `code_agent` capability surface."""
    root = Path(path)
    if root.is_file():
        if root.suffix == ".py":
            _ingest_file(root, root.parent, model, set())
        return model
    taken: set[str] = set()
    for pyfile in sorted(root.rglob("*.py")):
        if any(part in _SKIP_DIRS for part in pyfile.parts):
            continue
        _ingest_file(pyfile, root, model, taken)
    return model
