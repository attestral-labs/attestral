"""Handle-replay drift detection (DRF-009 / DRF-010).

MCP SEP-2567/2575 ("stateless core") makes servers mint portable
task/resource handles that travel in conversation text - a handle in text is
a bearer credential any principal that sees it can spend. These tests pin the
provenance checks and, just as critically, that handle-free legacy logs
behave byte-identically to before the checks existed.
"""
from attestral.compile import compile_policy
from attestral.drift import DriftMonitor, detect_drift, load_events
from attestral.ingest import build_model
from attestral.rules import RuleEngine

HANDLE_RULES = ("DRF-009", "DRF-010")


def _policy():
    return {"servers": {
        "tasks": {"allow": True, "constraints": {}},
        "notion": {"allow": True, "constraints": {}},
    }}


def _handle_hits(events, policy=None):
    return [f for f in detect_drift(policy or _policy(), events)
            if f.rule_id in HANDLE_RULES]


def test_replay_across_principals_flagged():
    events = [
        {"server": "tasks", "tool": "create_task", "handle": "th-1", "handle_op": "mint"},
        {"server": "notion", "tool": "get_task", "handle": "th-1", "handle_op": "spend"},
    ]
    hits = _handle_hits(events)
    assert [f.rule_id for f in hits] == ["DRF-009"]
    assert hits[0].severity.value == "critical"
    assert hits[0].component_id == "mcp_server.notion"  # the spender is the suspect
    assert "'tasks'" in hits[0].description  # names the minter and the spend
    assert "SEP-2567" in hits[0].description


def test_unknown_provenance_spend_flagged():
    events = [{"server": "notion", "tool": "get_task", "handle": "th-x", "handle_op": "spend"}]
    hits = _handle_hits(events)
    assert [f.rule_id for f in hits] == ["DRF-010"]
    assert hits[0].severity.value == "high"
    assert hits[0].component_id == "mcp_server.notion"


def test_spend_before_mint_is_unknown_provenance():
    # Provenance is temporal: a mint later in the log does not launder an
    # earlier spend.
    events = [
        {"server": "notion", "tool": "get_task", "handle": "th-1", "handle_op": "spend"},
        {"server": "tasks", "tool": "create_task", "handle": "th-1", "handle_op": "mint"},
    ]
    assert [f.rule_id for f in _handle_hits(events)] == ["DRF-010"]


def test_same_principal_mint_then_spend_is_silent():
    events = [
        {"server": "tasks", "tool": "create_task", "handle": "th-1", "handle_op": "mint"},
        {"server": "tasks", "tool": "get_task", "handle": "th-1", "handle_op": "spend"},
        {"server": "tasks", "tool": "get_task", "handle": "th-1", "handle_op": "spend"},
    ]
    assert not _handle_hits(events)


def test_first_mint_wins_re_mint_does_not_launder():
    # A thief re-minting a stolen handle under its own identity must not
    # rewrite provenance - the cross-principal spend is still a replay.
    events = [
        {"server": "tasks", "tool": "create_task", "handle": "th-1", "handle_op": "mint"},
        {"server": "notion", "tool": "create_task", "handle": "th-1", "handle_op": "mint"},
        {"server": "notion", "tool": "get_task", "handle": "th-1", "handle_op": "spend"},
    ]
    hits = _handle_hits(events)
    assert [f.rule_id for f in hits] == ["DRF-009"]
    assert "'tasks'" in hits[0].description  # provenance kept the original minter


def test_replay_by_unattested_server_still_flagged():
    # Provenance is a property of the log, not the policy: the replay fires
    # alongside DRF-001 for the unattested spender.
    events = [
        {"server": "tasks", "tool": "create_task", "handle": "th-1", "handle_op": "mint"},
        {"server": "ghost", "tool": "get_task", "handle": "th-1", "handle_op": "spend"},
    ]
    findings = detect_drift(_policy(), events)
    ids = [f.rule_id for f in findings]
    assert "DRF-009" in ids and "DRF-001" in ids


def test_handle_free_legacy_log_behaves_identically():
    # The shipped demo fixture predates handle telemetry entirely; it must
    # produce zero handle findings and every pre-existing finding unchanged.
    model = build_model("examples/demo-project")
    policy = compile_policy(model, RuleEngine().evaluate(model))
    events = load_events("examples/demo-project/runtime-events.jsonl")
    assert not any("handle" in ev or "handle_op" in ev for ev in events)
    findings = detect_drift(policy, events)
    assert not [f for f in findings if f.rule_id in HANDLE_RULES]
    ids = {(f.rule_id, f.component_id) for f in findings}
    assert ("DRF-003", "mcp_server.docs") in ids
    assert ("DRF-002", "mcp_server.shell") in ids
    assert ("DRF-001", "mcp_server.jira-sync") in ids


def test_benign_handle_traffic_adds_nothing_over_stripped_log():
    # Byte-identical pin: a log whose handle usage is entirely legitimate
    # yields exactly the findings of the same log with the handle fields
    # stripped (i.e. today's behavior).
    events = [
        {"server": "tasks", "tool": "create_task", "handle": "th-1", "handle_op": "mint"},
        {"server": "tasks", "tool": "get_task", "handle": "th-1", "handle_op": "spend"},
        {"server": "ghost", "tool": "x"},  # unrelated DRF-001 must survive intact
    ]
    stripped = [{k: v for k, v in ev.items() if k not in ("handle", "handle_op")}
                for ev in events]

    def key(findings):
        return [(f.rule_id, f.component_id, f.description, f.severity.value,
                 f.recommendation) for f in findings]

    assert key(detect_drift(_policy(), events)) == key(detect_drift(_policy(), stripped))


def test_malformed_handle_fields_fail_closed():
    # No crash, no spurious finding on any malformed shape - only a non-empty
    # string handle with handle_op exactly "mint"/"spend" participates.
    events = [
        {"server": "tasks", "tool": "t", "handle": 123, "handle_op": "spend"},     # non-string
        {"server": "tasks", "tool": "t", "handle": "", "handle_op": "spend"},      # empty
        {"server": "tasks", "tool": "t", "handle": None, "handle_op": "spend"},    # null
        {"server": "tasks", "tool": "t", "handle": ["h"], "handle_op": "mint"},    # list
        {"server": "tasks", "tool": "t", "handle": {"id": "h"}, "handle_op": "mint"},  # object
        {"server": "tasks", "tool": "t", "handle": "h1", "handle_op": "SPEND"},    # unknown op
        {"server": "tasks", "tool": "t", "handle": "h1", "handle_op": ["spend"]},  # non-string op
        {"server": "tasks", "tool": "t", "handle": "h1"},                          # op missing
        {"server": "tasks", "tool": "t", "handle_op": "spend"},                    # handle missing
    ]
    findings = detect_drift(_policy(), events)  # must not raise
    assert not [f for f in findings if f.rule_id in HANDLE_RULES]


def test_streaming_monitor_matches_batch_semantics():
    # The sidecar sees the same replay the batch detector does, on the exact
    # event that spends the handle across principals.
    m = DriftMonitor(_policy())
    assert m.observe(
        {"server": "tasks", "tool": "create_task", "handle": "th-1", "handle_op": "mint"}
    ) == []
    hits = m.observe(
        {"server": "notion", "tool": "get_task", "handle": "th-1", "handle_op": "spend"}
    )
    assert [f.rule_id for f in hits] == ["DRF-009"]
    assert m.observe(
        {"server": "tasks", "tool": "get_task", "handle": "th-1", "handle_op": "spend"}
    ) == []  # same-principal spend stays silent


def test_finding_never_reprints_a_long_handle_in_full():
    # A finding is a report artifact; re-publishing a spendable credential in
    # full would recreate the leak it is reporting.
    long_handle = "task-handle-0123456789abcdef0123456789abcdef"
    events = [{"server": "notion", "tool": "t", "handle": long_handle, "handle_op": "spend"}]
    hits = _handle_hits(events)
    assert hits and long_handle not in hits[0].description
    assert long_handle[:12] in hits[0].description
