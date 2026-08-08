"""`attestral guard` - the runtime enforcement point.

Proves the guard blocks exactly what the design denied: a server the review
denied (or one absent from the design) never loads, a tools/call that escapes the
attested filesystem roots or downgrades the transport is refused before it
reaches the server, and every decision lands in the telemetry stream `drift`
consumes. The routing core is exercised directly; one end-to-end test relays a
real tools/call through the proxy in front of a fake stdio MCP server.
"""
import json
import os
import threading

from click.testing import CliRunner

from attestral.cli import main
from attestral.compile import compile_policy
from attestral.drift import detect_drift
from attestral.guard import (GUARD_DENIED, GuardProxy, TelemetryWriter,
                             decide_call, decide_load, extract_paths_and_url,
                             sanitized_env, wrapped_config_stanza)
from attestral.ingest import build_model
from attestral.rules.engine import RuleEngine

FIXTURE = "examples/guard-runtime"


def _policy():
    model = build_model(FIXTURE)
    findings = RuleEngine().evaluate(model)
    return compile_policy(model, findings)


# -- the compiled fixture: docs allowed (scoped to /srv/docs), root-files denied --

def test_fixture_compiles_to_one_allowed_one_denied():
    p = _policy()["servers"]
    assert p["docs"]["allow"] is True
    assert p["docs"]["constraints"]["root_paths"] == ["/srv/docs"]
    assert p["root-files"]["allow"] is False


# -- load-time decisions (DRF-001 / DRF-002) --

def test_denied_server_refused_at_load():
    d = decide_load(_policy(), "root-files")
    assert d.allow is False and "DRF-002" in d.rules


def test_unknown_server_refused_at_load():
    d = decide_load(_policy(), "not-in-the-design")
    assert d.allow is False and "DRF-001" in d.rules


def test_allowed_server_loads():
    assert decide_load(_policy(), "docs").allow is True


# -- per-call decisions (DRF-003 path escape, DRF-004 transport downgrade) --

def test_call_within_attested_roots_allowed():
    d = decide_call(_policy(), "docs", "read_file", {"path": "/srv/docs/readme.md"})
    assert d.allow is True


def test_call_escaping_attested_roots_denied():
    d = decide_call(_policy(), "docs", "read_file", {"path": "/etc/passwd"})
    assert d.allow is False and "DRF-003" in d.rules


def test_nested_argument_path_is_extracted_and_gated():
    # the path is buried in a list under an arbitrary key: still caught
    d = decide_call(_policy(), "docs", "read_many",
                    {"targets": [{"file": "/etc/shadow"}]})
    assert d.allow is False and "DRF-003" in d.rules


def test_plaintext_transport_downgrade_denied():
    policy = {"servers": {"api": {"allow": True,
                                  "constraints": {"transport": "tls_only"}}}}
    d = decide_call(policy, "api", "fetch", {"url": "http://insecure.example/x"})
    assert d.allow is False and "DRF-004" in d.rules


def test_extract_paths_and_url():
    paths, url = extract_paths_and_url(
        {"path": "/etc/passwd", "home": "~/.aws", "u": "https://ok.example", "n": 3})
    assert paths == ["/etc/passwd", "~/.aws"] and url == "https://ok.example"


# -- proxy routing: a denied call never reaches the server --

def _call(rpc_id, tool, arguments):
    return json.dumps({"jsonrpc": "2.0", "id": rpc_id, "method": "tools/call",
                       "params": {"name": tool, "arguments": arguments}})


def test_denied_call_answered_to_client_never_forwarded():
    proxy = GuardProxy(_policy(), "docs", None, enforce=True)
    actions = proxy.handle_client_line(_call(1, "read_file", {"path": "/etc/passwd"}))
    assert len(actions) == 1
    dest, payload = actions[0]
    assert dest == "client"
    err = json.loads(payload)["error"]
    assert err["code"] == GUARD_DENIED and "DRF-003" in err["data"]["rules"]
    assert proxy.denied_any is True


def test_allowed_call_forwarded_to_server():
    proxy = GuardProxy(_policy(), "docs", None, enforce=True)
    actions = proxy.handle_client_line(_call(2, "read_file", {"path": "/srv/docs/a"}))
    assert actions == [("server", _call(2, "read_file", {"path": "/srv/docs/a"}))]
    assert proxy.denied_any is False


def _read(rpc_id, uri):
    return json.dumps({"jsonrpc": "2.0", "id": rpc_id, "method": "resources/read",
                       "params": {"uri": uri}})


def test_resource_read_escaping_roots_denied():
    proxy = GuardProxy(_policy(), "docs", None, enforce=True)
    actions = proxy.handle_client_line(_read(1, "file:///etc/passwd"))
    dest, payload = actions[0]
    assert dest == "client"
    assert "DRF-003" in json.loads(payload)["error"]["data"]["rules"]


def test_resource_read_within_roots_forwarded():
    proxy = GuardProxy(_policy(), "docs", None, enforce=True)
    assert proxy.handle_client_line(_read(2, "file:///srv/docs/a"))[0][0] == "server"


def test_file_uri_extraction():
    paths, _ = extract_paths_and_url({"uri": "file:///etc/passwd"})
    assert paths == ["/etc/passwd"]
    # a remote file://host/... form is not a local path and is left alone
    paths, _ = extract_paths_and_url({"uri": "file://host/share/x"})
    assert paths == []


def test_non_tool_call_messages_relayed_verbatim():
    proxy = GuardProxy(_policy(), "docs", None, enforce=True)
    init = json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                       "params": {}})
    assert proxy.handle_client_line(init) == [("server", init)]


def test_malformed_line_relayed_verbatim():
    proxy = GuardProxy(_policy(), "docs", None, enforce=True)
    assert proxy.handle_client_line("not json at all") == [("server", "not json at all")]


def test_observe_mode_forwards_but_records_the_denial():
    writer_events = []

    class _W:
        def emit(self, ev):
            writer_events.append(ev)

    proxy = GuardProxy(_policy(), "docs", _W(), enforce=False)
    actions = proxy.handle_client_line(_call(3, "read_file", {"path": "/etc/passwd"}))
    assert actions[0][0] == "server"          # observe: forwarded anyway
    assert proxy.denied_any is True           # but the verdict is recorded
    assert writer_events[-1]["decision"] == "deny"


# -- tools/list surface becomes a manifest event for drift (DRF-005 source) --

def test_tools_list_response_emitted_as_manifest_event():
    events = []

    class _W:
        def emit(self, ev):
            events.append(ev)

    proxy = GuardProxy(_policy(), "docs", _W(), enforce=True)
    # client asks for the tool list; proxy tracks the id
    proxy.handle_client_line(json.dumps({"jsonrpc": "2.0", "id": 9,
                                         "method": "tools/list"}))
    resp = json.dumps({"jsonrpc": "2.0", "id": 9,
                       "result": {"tools": [{"name": "read_file",
                                             "description": "read a file"}]}})
    out = proxy.handle_server_line(resp)
    assert out == [("client", resp)]          # response still relayed verbatim
    manifest_events = [e for e in events if "manifest" in e]
    assert manifest_events and manifest_events[0]["manifest"]["tools"][0]["name"] == "read_file"


# -- telemetry the guard writes is exactly what drift reads back --

def test_guard_telemetry_round_trips_through_drift(tmp_path):
    policy = _policy()
    tpath = tmp_path / "t.jsonl"
    writer = TelemetryWriter(tpath)
    proxy = GuardProxy(policy, "docs", writer, enforce=True)
    proxy.handle_client_line(_call(1, "read_file", {"path": "/srv/docs/ok"}))    # allow
    proxy.handle_client_line(_call(2, "read_file", {"path": "/etc/passwd"}))     # DRF-003

    events = [json.loads(line) for line in tpath.read_text().splitlines()]
    assert [e["decision"] for e in events] == ["allow", "deny"]
    # the same stream, replayed through the detector, reproduces the escape finding
    findings = detect_drift(policy, events)
    assert any(f.rule_id == "DRF-003" for f in findings)


# -- env stripping honours the attested clean-env expectation --

def test_sanitized_env_strips_standing_keys_when_broker_required():
    entry = {"allow": True, "broker_required": True}
    env = {"PATH": "/usr/bin", "GITHUB_TOKEN": "ghp_secret", "HOME": "/home/x"}
    clean, stripped = sanitized_env(entry, env)
    assert "GITHUB_TOKEN" not in clean and "PATH" in clean
    assert stripped == ["GITHUB_TOKEN"]


def test_sanitized_env_untouched_without_clean_env_expectation():
    entry = {"allow": True}
    env = {"GITHUB_TOKEN": "ghp_secret"}
    clean, stripped = sanitized_env(entry, env)
    assert clean == env and stripped == []


# -- CLI surface --

def test_cli_refuses_denied_server_at_load(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    CliRunner().invoke(main, ["compile", FIXTURE, "-o", str(policy_file)])
    r = CliRunner().invoke(main, ["guard", str(policy_file), "--server", "root-files",
                                  "--", "echo", "should-not-run"])
    assert r.exit_code == 3
    assert "refusing to load" in r.output or "refusing to load" in (r.stderr or "")


def test_cli_print_config_emits_wrapped_stanza(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    CliRunner().invoke(main, ["compile", FIXTURE, "-o", str(policy_file)])
    r = CliRunner().invoke(main, ["guard", str(policy_file), "--server", "docs",
                                  "--print-config", "--", "npx", "server-filesystem", "/srv/docs"])
    assert r.exit_code == 0
    stanza = json.loads(r.output)["mcpServers"]["docs"]
    assert stanza["command"] == "attestral"
    assert stanza["args"][:2] == ["guard", "--policy"] and stanza["args"][-1] == "/srv/docs"


def test_cli_requires_a_wrapped_command(tmp_path):
    policy_file = tmp_path / "policy.yaml"
    CliRunner().invoke(main, ["compile", FIXTURE, "-o", str(policy_file)])
    r = CliRunner().invoke(main, ["guard", str(policy_file), "--server", "docs"])
    assert r.exit_code != 0
    assert "server launch command" in r.output


def test_wrapped_config_stanza_shape():
    stanza = wrapped_config_stanza("p.yaml", "docs", ["npx", "srv", "/srv/docs"])
    assert stanza == {"docs": {"command": "attestral",
                               "args": ["guard", "--policy", "p.yaml", "--server", "docs",
                                        "--", "npx", "srv", "/srv/docs"]}}


# -- end to end: relay a real tools/call through the proxy over pipes --

class _FakeServer:
    """A minimal stdio MCP server for the relay test: replies to every request
    with a trivial result, and closes its stdout after answering a tools/call so
    the proxy's session ends deterministically."""

    def __init__(self, stdin_r, stdout_w):
        self.stdin_r = stdin_r
        self.stdout_w = stdout_w
        self.saw = []

    def serve(self):
        try:
            for line in self.stdin_r:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                self.saw.append(obj)
                if obj.get("id") is not None:
                    self.stdout_w.write(json.dumps(
                        {"jsonrpc": "2.0", "id": obj["id"], "result": {"ok": True}}) + "\n")
                    self.stdout_w.flush()
                if obj.get("method") == "tools/call":
                    self.stdout_w.close()
                    return
        except (ValueError, OSError):
            pass


def test_end_to_end_relay_blocks_escape_and_forwards_allowed(tmp_path):
    policy = _policy()

    c_r, c_w = os.pipe()          # test -> proxy (client requests)
    co_r, co_w = os.pipe()        # proxy -> test (client-facing output)
    si_r, si_w = os.pipe()        # proxy -> server (forwarded)
    so_r, so_w = os.pipe()        # server -> proxy

    client_in = os.fdopen(c_r, "r")
    client_out = os.fdopen(co_w, "w")
    client_reader = os.fdopen(co_r, "r")
    server_in = os.fdopen(si_w, "w")
    server_stdin_r = os.fdopen(si_r, "r")
    server_out = os.fdopen(so_r, "r")
    server_stdout_w = os.fdopen(so_w, "w")

    fake = _FakeServer(server_stdin_r, server_stdout_w)
    writer = TelemetryWriter(tmp_path / "e2e.jsonl")
    proxy = GuardProxy(policy, "docs", writer, enforce=True)

    server_thread = threading.Thread(target=fake.serve, daemon=True)
    proxy_thread = threading.Thread(
        target=proxy.run, args=(client_in, client_out, server_in, server_out),
        daemon=True)
    server_thread.start()
    proxy_thread.start()

    # a denied call (escapes roots) then an allowed call (within roots)
    with os.fdopen(c_w, "w") as cw:
        cw.write(_call(1, "read_file", {"path": "/etc/passwd"}) + "\n")
        cw.write(_call(2, "read_file", {"path": "/srv/docs/ok"}) + "\n")
        cw.flush()

    proxy_thread.join(timeout=5)
    server_thread.join(timeout=5)
    assert not proxy_thread.is_alive(), "proxy did not terminate"
    # close the write ends the proxy held open so the reader sees EOF
    client_out.close()
    server_in.close()
    client_reader_lines = client_reader.read().splitlines()

    responses = [json.loads(x) for x in client_reader_lines if x.strip()]
    by_id = {r["id"]: r for r in responses}
    # id 1 was denied by the guard itself
    assert by_id[1]["error"]["code"] == GUARD_DENIED
    # id 2 reached the server and got its result
    assert by_id[2].get("result") == {"ok": True}
    # the server never saw the denied call
    assert all(o.get("id") != 1 for o in fake.saw)
    assert any(o.get("id") == 2 for o in fake.saw)
