"""DRF-008: unauthorized runtime capability / process spawn.

The end-to-end proof that the opaque-wrapper mitigation in
`evaluation/defense-aware.md` is demonstrated, not asserted: an innocuously named
launcher (`uvx toolrunner`) that passes static design review with an EMPTY
attested capability envelope is caught at runtime the moment it exercises a
capability the review never authorized (it spawns a shell).

The compile -> drift loop is exercised for real: build the model from the
fixture, compile it to a policy, then diff a runtime event stream against it.
Every fail-closed non-fire is asserted too, so the check cannot be widened into a
false-positive machine without a test going red.
"""
from attestral.compile import compile_policy
from attestral.drift import (
    MODELED_CAPABILITIES,
    DriftMonitor,
    Severity,
    detect_drift,
    load_events,
)
from attestral.ingest import build_model
from attestral.ingest.mcp import _CAPABILITY_HINTS
from attestral.rules import RuleEngine

WRAPPER = "examples/opaque-wrapper"


def _policy(path=WRAPPER):
    model = build_model(path)
    return compile_policy(model, RuleEngine().evaluate(model))


def _ids(policy, events):
    return [f.rule_id for f in detect_drift(policy, events)]


# --- the opaque wrapper compiles to a KNOWN, empty envelope --------------------

def test_opaque_wrapper_passes_review_with_empty_envelope():
    entry = _policy()["servers"]["toolrunner"]
    # It passes static review (no critical finding), and its envelope is present
    # (the loop modeled it) but empty (no modeled capability) - the exact state
    # that makes it distinguishable from a legacy policy with no key at all.
    assert entry["allow"] is True
    assert entry["capabilities"] == []


# --- the catch: an attested, empty-envelope server that shells out at runtime --

def test_opaque_wrapper_shell_spawn_fires_drf008():
    policy = _policy()
    events = load_events(f"{WRAPPER}/runtime-events-malicious.jsonl")
    hits = [f for f in detect_drift(policy, events) if f.rule_id == "DRF-008"]
    assert hits, "DRF-008 must fire when the empty-envelope wrapper exercises shell"
    assert hits[0].component_id == "mcp_server.toolrunner"
    assert hits[0].severity is Severity.CRITICAL
    assert "shell" in hits[0].description


def test_benign_stream_is_clean():
    policy = _policy()
    events = load_events(f"{WRAPPER}/runtime-events-benign.jsonl")
    assert "DRF-008" not in _ids(policy, events)


# --- fail-closed: every case that must NOT fire --------------------------------

def test_no_capabilities_field_does_not_fire():
    # Missing telemetry: nothing observed -> no fire.
    policy = _policy()
    assert "DRF-008" not in _ids(policy, [{"server": "toolrunner", "tool": "run"}])


def test_empty_observed_list_does_not_fire():
    policy = _policy()
    ev = {"server": "toolrunner", "tool": "run", "capabilities": []}
    assert "DRF-008" not in _ids(policy, [ev])


def test_unmodeled_token_does_not_fire():
    # "process" is not the model's word (the model says "shell"); an unmodeled
    # label is not provably outside the envelope, so it never fires.
    policy = _policy()
    ev = {"server": "toolrunner", "tool": "run", "capabilities": ["process"]}
    assert "DRF-008" not in _ids(policy, [ev])


def test_in_envelope_capability_does_not_fire():
    # An attested + allowed server exercising a capability that IS in its
    # envelope is authorized - no fire. Hand-built so the server is ALLOWED
    # (a real shell server trips ATL-103 and would be DRF-002 instead).
    policy = {"servers": {"sh": {"allow": True, "capabilities": ["shell"], "constraints": {}}}}
    ev = {"server": "sh", "tool": "run", "capabilities": ["shell"]}
    assert "DRF-008" not in _ids(policy, [ev])


def test_absent_envelope_key_never_fires():
    # A legacy / hand-written policy entry with NO `capabilities` key is an
    # UNKNOWN envelope: DRF-008 must never fire, even on a shell spawn. This is
    # why the check gates on `is not None`, not on truthiness.
    policy = {"servers": {"legacy": {"allow": True, "constraints": {}}}}
    ev = {"server": "legacy", "tool": "run", "capabilities": ["shell"]}
    assert "DRF-008" not in _ids(policy, [ev])


def test_denied_server_is_drf002_not_drf008():
    # A denied server returns early on DRF-002; DRF-008 is not its job.
    policy = {"servers": {"d": {"allow": False, "reason": "denied", "capabilities": []}}}
    ev = {"server": "d", "tool": "run", "capabilities": ["shell"]}
    ids = _ids(policy, [ev])
    assert "DRF-002" in ids and "DRF-008" not in ids


def test_singular_string_capability_is_tolerated():
    # A `capabilities: "shell"` singular emitter still works (wrapped to a list).
    policy = _policy()
    ev = {"server": "toolrunner", "tool": "run", "capabilities": "shell"}
    assert "DRF-008" in _ids(policy, [ev])


def test_one_finding_per_distinct_out_of_envelope_token():
    policy = _policy()
    ev = {"server": "toolrunner", "tool": "run",
          "capabilities": ["shell", "network", "shell"]}
    caps = [f.description for f in detect_drift(policy, [ev]) if f.rule_id == "DRF-008"]
    # shell and network each once; the duplicate shell does not double-count.
    assert len(caps) == 2
    assert any("shell" in c for c in caps) and any("network" in c for c in caps)


# --- batch == streaming: DriftMonitor.observe and detect_drift agree -----------

def test_monitor_and_batch_agree_on_the_stream():
    policy = _policy()
    events = load_events(f"{WRAPPER}/runtime-events-malicious.jsonl") + \
        load_events(f"{WRAPPER}/runtime-events-benign.jsonl")
    batch = sorted(f.rule_id for f in detect_drift(policy, events))
    mon = DriftMonitor(policy)
    streamed = []
    for ev in events:
        streamed.extend(f.rule_id for f in mon.observe(ev))
    # Both paths see the single DRF-008 from the malicious event and nothing else.
    assert "DRF-008" in batch and "DRF-008" in streamed
    assert streamed.count("DRF-008") == 1 and batch.count("DRF-008") == 1


# --- vocab guard: drift's modeled set == what the ingester can emit ------------

def test_modeled_capabilities_match_ingester_emittable_set():
    # The ingester emits "shell" plus the substring-hint classes. If either side
    # ever changes, this fails so the proof cannot desync into a silent no-fire.
    emittable = {"shell"} | set(_CAPABILITY_HINTS)
    assert set(MODELED_CAPABILITIES) == emittable
