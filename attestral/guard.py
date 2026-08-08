"""The enforcement point: make the attested design refuse a tool at runtime.

`compile` turns a reviewed design into a default-deny policy and `drift` reads a
runtime event stream back against it, but between them sat a gap the review could
not close on its own: nothing a user already runs actually CONSULTED the verdict.
`admit` could say DENY and the MCP client would load the server anyway. `guard`
closes that gap without depending on any external proxy.

`attestral guard` is a stdio Model Context Protocol pass-through. It sits between
an MCP client (Claude Code, Cursor, an SDK host) and the real server it wraps,
relays the JSON-RPC line protocol verbatim, and enforces the compiled policy at
two points:

  * load time - a server the review DENIED, or one absent from the attested
    design at all, never starts. The child process is not spawned and the guard
    exits non-zero. This is the "may this agent load this tool" decision made
    real: the answer is no, so the tool does not run.
  * call time - every `tools/call` is judged against the policy before it reaches
    the server. A call that escapes the attested filesystem roots or downgrades a
    TLS-only transport is refused with a JSON-RPC error; the request is never
    forwarded.

The decision is not a second implementation of the rules. `guard` calls
`drift.evaluate_event`, the very function the drift detector uses, so what the
guard BLOCKS is exactly what drift would later FLAG. Detection never forks from
enforcement, and a compromised runtime cannot argue its way past a policy the
guard did not author.

Every decision - allow or deny, at load or per call, plus the live tool surface
observed on `tools/list` - is appended to a telemetry JSONL in the exact schema
`drift`, `lockdown`, and `incident` consume. So the guard is also the loop's
first honest event source: run it, and the runtime half of the design-to-runtime
loop has real events to reason over instead of a hand-written fixture.

Standard library only. No new dependency, so the enforcement point installs
wherever Python does.
"""
from __future__ import annotations

import datetime as _dt
import json
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

from attestral.drift import evaluate_event

# The per-call verdicts a single tools/call event can justify BLOCKING at the
# proxy. DRF-001 (server not in the attested design) and DRF-002 (server the
# review denied) are load- and call-time denials; DRF-003 (path outside attested
# roots) and DRF-004 (plaintext transport) are per-call denials. The remaining
# drift rules need cross-event state (handle replay, budgets) or telemetry the
# proxy enriches rather than gates on (manifest, capability, broker), so they are
# EMITTED for drift to catch offline, never used to block a live call here.
BLOCKING_RULES = frozenset({"DRF-001", "DRF-002", "DRF-003", "DRF-004"})

# A private JSON-RPC error code for a guard denial, outside the reserved
# -32768..-32000 range so it never collides with a protocol-level error.
GUARD_DENIED = -31001


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


class TelemetryWriter:
    """Append-only, thread-safe JSONL writer - the guard's decision journal.

    One JSON object per line, in the schema `attestral drift` consumes: `ts`,
    `server`, `tool`, `args`, `decision`, and the optional enrichments (`url`,
    `manifest`, `env_secrets`). Writes are locked so the two relay threads never
    interleave a line, and a failed write never propagates into the request path
    (telemetry must not be able to break the proxy it observes).
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: dict) -> None:
        line = json.dumps(event, separators=(",", ":")) + "\n"
        try:
            with self._lock, self.path.open("a") as f:
                f.write(line)
        except OSError:
            pass  # never let a telemetry write break the relayed request


def _file_uri_to_path(s: str) -> str | None:
    """The filesystem path a `file://` URI names, or None if it is not one. A
    resource read carries its target as a URI (`file:///etc/passwd`), so it is
    normalized to the bare path the attested-roots check (DRF-003) reasons over.
    `file://host/p` (a UNC/remote form) is left alone - only a local `file:///p`
    resolves to a path."""
    low = s.lower()
    if not low.startswith("file://"):
        return None
    rest = s[len("file://"):]
    if rest.startswith("/"):          # file:///abs -> /abs  (empty authority)
        return rest
    return None                       # file://host/... : not a local path


def extract_paths_and_url(arguments) -> tuple[list[str], str]:
    """Pull the path-like and url-like leaf strings out of a request's argument
    object, so a single call becomes a drift-shaped event the shared evaluator can
    judge. MCP arguments are arbitrary nested JSON, and a filesystem tool may
    carry its target under any key (`path`, `file`, `paths[]`, or a resource
    `uri`), so every string leaf is inspected: one beginning with `/` or `~`, or a
    `file://` URI, is a filesystem path (feeds DRF-003 against the attested roots),
    and the first `http://`/`https://` value is the transport url (feeds DRF-004).
    Fail-open on extraction only: a value we cannot classify is simply not a path
    or a url, never a crash."""
    paths: list[str] = []
    url = ""

    def walk(v) -> None:
        nonlocal url
        if isinstance(v, str):
            s = v.strip()
            file_path = _file_uri_to_path(s)
            if file_path is not None:
                paths.append(file_path)
            elif s.startswith(("/", "~")):
                paths.append(s)
            elif not url and s.lower().startswith(("http://", "https://")):
                url = s
        elif isinstance(v, dict):
            for item in v.values():
                walk(item)
        elif isinstance(v, (list, tuple)):
            for item in v:
                walk(item)

    walk(arguments)
    return paths, url


@dataclass
class Decision:
    """The verdict on one load or call, with the drift rule ids behind it."""
    allow: bool
    rules: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    event: dict = field(default_factory=dict)

    @property
    def reason_text(self) -> str:
        return "; ".join(self.reasons) if self.reasons else "denied by attested design review"


def _decide(policy: dict, event: dict) -> Decision:
    """Run one event through the shared drift evaluator and reduce its findings to
    an allow/deny at the proxy. Only BLOCKING_RULES deny; any other finding is
    informational here (it still rode into telemetry via the caller)."""
    findings = evaluate_event(policy, event)
    blocking = [f for f in findings if f.rule_id in BLOCKING_RULES]
    if not blocking:
        return Decision(allow=True, event=event)
    return Decision(
        allow=False,
        rules=sorted({f.rule_id for f in blocking}),
        reasons=[f"{f.rule_id}: {f.description.split(': ', 1)[-1]}" for f in blocking],
        event=event,
    )


def decide_load(policy: dict, server: str) -> Decision:
    """The load-time verdict: may this server run at all? An event with no tool
    exercises exactly DRF-001 (absent from the design) and DRF-002 (denied by the
    review); nothing else can fire without call arguments."""
    return _decide(policy, {"server": server})


def decide_call(policy: dict, server: str, tool: str, arguments) -> Decision:
    """The per-call verdict for one tools/call, from its extracted paths and url."""
    paths, url = extract_paths_and_url(arguments)
    event = {"server": server, "tool": tool, "args": paths}
    if url:
        event["url"] = url
    return _decide(policy, event)


class GuardProxy:
    """The message router. Kept free of real I/O so the routing is unit-testable:
    `handle_client_line` and `handle_server_line` take one protocol line and
    return the list of (destination, payload) actions to perform, where
    destination is "server" (forward downstream) or "client" (write upstream).
    The threaded `run` loop is a thin driver over these two methods."""

    def __init__(self, policy: dict, server: str, writer: TelemetryWriter | None,
                 *, enforce: bool = True) -> None:
        self.policy = policy
        self.server = server
        self.writer = writer
        self.enforce = enforce
        self._toolslist_ids: set = set()
        self._lock = threading.Lock()
        #: set True once a denial has been enforced, for the caller's exit code.
        self.denied_any = False

    # -- telemetry -------------------------------------------------------------
    def _emit(self, tool: str, decision: str, event: dict | None = None,
              extra: dict | None = None) -> None:
        if self.writer is None:
            return
        rec = {
            "ts": _now(),
            "server": self.server,
            "tool": tool,
            "args": list((event or {}).get("args", [])),
            "decision": decision,
        }
        url = (event or {}).get("url")
        if url:
            rec["url"] = url
        if extra:
            rec.update(extra)
        self.writer.emit(rec)

    # -- client -> server ------------------------------------------------------
    def handle_client_line(self, line: str) -> list[tuple[str, str]]:
        obj = _parse(line)
        if not isinstance(obj, dict):
            return [("server", line)]  # not a JSON-RPC object: relay untouched

        method = obj.get("method")
        if method == "tools/list" and obj.get("id") is not None:
            with self._lock:
                self._toolslist_ids.add(_id_key(obj.get("id")))
            return [("server", line)]

        target = _gate_target(method, obj.get("params") or {})
        if target is None:
            return [("server", line)]  # not a capability-exercising request: relay

        tool, arguments = target
        decision = decide_call(self.policy, self.server, tool, arguments)

        if decision.allow:
            self._emit(tool, "allow", decision.event)
            return [("server", line)]

        # Denied. Record it, and either block (enforce) or let it pass while
        # recording the verdict it WOULD have blocked (observe / dry-run).
        self.denied_any = True
        self._emit(tool, "deny", decision.event, {"rules": decision.rules})
        if not self.enforce:
            return [("server", line)]
        rpc_id = obj.get("id")
        if rpc_id is None:
            return []  # a tools/call with no id cannot be answered; drop it
        return [("client", _error_response(rpc_id, self.server, tool, decision))]

    # -- server -> client ------------------------------------------------------
    def handle_server_line(self, line: str) -> list[tuple[str, str]]:
        obj = _parse(line)
        if isinstance(obj, dict) and _id_key(obj.get("id")) in self._toolslist_ids:
            with self._lock:
                self._toolslist_ids.discard(_id_key(obj.get("id")))
            self._emit_manifest(obj)
        return [("client", line)]  # server output is always relayed verbatim

    def _emit_manifest(self, response: dict) -> None:
        """On a tools/list response, record the LIVE tool surface as a manifest
        event, so drift's DRF-005 can catch a rug-pull (the served tools drifting
        from what was attested) offline against the same policy. The guard does
        not tear down the session on a mismatch; it observes and lets the loop's
        detector adjudicate, which keeps a benign server upgrade from being killed
        mid-call by the proxy."""
        result = response.get("result")
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            return
        self._emit("tools/list", "allow", {"args": []},
                   {"manifest": {"tools": tools}})

    # -- threaded driver -------------------------------------------------------
    def run(self, client_in, client_out, server_in, server_out) -> None:
        """Relay both directions until either stream closes. `*_in`/`*_out` are
        binary or text line-iterable/writable streams; a real run wires them to
        this process's stdio and the child's pipes."""
        out_lock = threading.Lock()

        def write(stream, payload: str) -> None:
            with out_lock:
                stream.write(_as_out(stream, payload))
                stream.flush()

        def pump(src, handler) -> None:
            try:
                for raw in src:
                    line = raw.decode() if isinstance(raw, bytes) else raw
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    for dest, payload in handler(line):
                        write(server_in if dest == "server" else client_out, payload)
            except (ValueError, OSError):
                pass  # a closed pipe ends the pump

        t_up = threading.Thread(target=pump, args=(client_in, self.handle_client_line),
                                daemon=True)
        t_down = threading.Thread(target=pump, args=(server_out, self.handle_server_line),
                                  daemon=True)
        t_up.start()
        t_down.start()
        t_down.join()  # the child exiting ends the session


def _gate_target(method, params: dict) -> tuple[str, object] | None:
    """The (label, arguments) a gated request exercises, or None if the method is
    not capability-exercising and should be relayed untouched. Two MCP methods
    reach real capability and carry a path/uri worth checking against the attested
    scope: `tools/call` (a tool invocation) and `resources/read` (a direct read of
    a server resource, which a filesystem server exposes as `file://` URIs). Both
    flow through the same per-call decision, so a resource read that escapes the
    attested roots is refused exactly as an out-of-scope tool call is."""
    if method == "tools/call":
        return str(params.get("name", "")), params.get("arguments")
    if method == "resources/read":
        # the whole params object is walked; it carries the target `uri`
        return "resources/read", params
    return None


def _parse(line: str):
    try:
        return json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None


def _id_key(rpc_id) -> str:
    """A hashable, type-stable key for a JSON-RPC id (int or str per spec)."""
    return f"{type(rpc_id).__name__}:{rpc_id}"


def _error_response(rpc_id, server: str, tool: str, decision: Decision) -> str:
    payload = {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {
            "code": GUARD_DENIED,
            "message": (f"attestral guard denied '{tool}' on server '{server}': "
                        f"{decision.reason_text}"),
            "data": {"attestral": "guard", "server": server, "tool": tool,
                     "rules": decision.rules},
        },
    }
    return json.dumps(payload, separators=(",", ":"))


def _as_out(stream, payload: str):
    """Serialize one line for a text or binary stream, always newline-terminated."""
    data = payload if payload.endswith("\n") else payload + "\n"
    mode = getattr(stream, "mode", "")
    if "b" in mode:
        return data.encode()
    return data


def sanitized_env(policy_entry: dict, base_env: dict) -> tuple[dict, list[str]]:
    """The child's environment with standing credentials removed when the attested
    design says this server must run credential-free (`forbid_env_secrets`, or a
    `broker_required` server whose traffic the broker carries). Reuses the broker's
    own standing-key classifier so the guard strips exactly what the fix would, and
    returns the stripped names so the caller can emit them (a positively clean env
    is what lets DRF-012 distinguish "cleaned" from "unknown"). Lazy import keeps
    the ingest layer out of the guard's hot path."""
    constraints = policy_entry.get("constraints", {}) or {}
    if not (policy_entry.get("broker_required") or constraints.get("forbid_env_secrets")):
        return dict(base_env), []
    from attestral.broker import _standing_env_keys
    standing = set(_standing_env_keys(list(base_env.keys())))
    clean = {k: v for k, v in base_env.items() if k not in standing}
    return clean, sorted(standing)


def load_policy(path: str | Path) -> dict:
    """Load a compiled mcp-guard policy (the YAML `attestral compile` writes)."""
    import yaml
    return yaml.safe_load(Path(path).read_text()) or {}


def default_telemetry_path(policy_path: str | Path) -> Path:
    return Path(str(policy_path) + ".telemetry.jsonl")


def wrapped_config_stanza(policy_path: str, server: str, command: list[str]) -> dict:
    """The `.mcp.json` server entry that reroutes a client through the guard: the
    same server, but launched as `attestral guard ... -- <original command>`, so
    installing enforcement is a one-line config rewrite the client already
    understands. This is how the admission verdict binds to a runtime people run:
    the client keeps launching a server by name; that server is now the guard."""
    args = ["guard", "--policy", policy_path, "--server", server, "--"] + command
    return {server: {"command": "attestral", "args": args}}


def run_guard(policy: dict, server: str, command: list[str], *,
              telemetry_path: str | Path, enforce: bool = True) -> int:
    """Spawn the wrapped server behind the guard and relay until it exits.

    Returns a process exit code: a load-time denial never spawns the child and
    returns non-zero (the tool did not run); otherwise the guard's code follows
    the child's, or signals that at least one call was denied during the session.
    """
    writer = TelemetryWriter(telemetry_path)
    entry = (policy.get("servers", {}) or {}).get(server)

    load = decide_load(policy, server)
    if not load.allow:
        writer.emit({"ts": _now(), "server": server, "tool": "", "args": [],
                     "decision": "deny", "rules": load.rules})
        sys.stderr.write(
            f"attestral guard: refusing to load server '{server}' - {load.reason_text}. "
            "The attested design does not permit it, so it will not run.\n")
        return 3

    import os
    child_env, stripped = sanitized_env(entry or {}, dict(os.environ))
    if stripped:
        writer.emit({"ts": _now(), "server": server, "tool": "", "args": [],
                     "decision": "allow", "env_stripped": stripped, "env_secrets": []})
        sys.stderr.write(
            f"attestral guard: stripped standing credential(s) from '{server}' env "
            f"before launch: {', '.join(stripped)}\n")

    proc = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None,
        env=child_env, bufsize=1, text=True,
    )
    proxy = GuardProxy(policy, server, writer, enforce=enforce)
    try:
        proxy.run(sys.stdin, sys.stdout, proc.stdin, proc.stdout)
    finally:
        if proc.poll() is None:
            proc.terminate()
    code = proc.wait()
    if code == 0 and proxy.denied_any and enforce:
        return 2  # session clean-exited but the guard blocked at least one call
    return code
