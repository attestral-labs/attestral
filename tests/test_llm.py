"""Tests for the LLM elicitation layer (attestral/llm.py).

The layer is injectable - `elicit(model, cfg, query=fake)` runs the whole
orchestration with no API key and no network - so every path here is offline.
"""
import json

from attestral.llm import (
    LLMConfig,
    _finding_id,
    _parse_findings,
    _payload,
    elicit,
)
from attestral.model import Component, SystemModel


def _model() -> SystemModel:
    m = SystemModel()
    m.add(Component(id="mcp_server.shell", type="mcp_server", name="shell",
                    source="mcp.json", attributes={"command": "bash"},
                    trust_boundary="agent_runtime"))
    m.add(Component(id="mcp_server.fetch", type="mcp_server", name="fetch",
                    source="mcp.json", attributes={},
                    trust_boundary="agent_runtime"))
    return m


def _reply(*findings: dict) -> str:
    return json.dumps({"findings": list(findings)})


def _one(component_id="mcp_server.shell", title="Shell server can be steered",
         severity="high") -> dict:
    return {"title": title, "severity": severity, "component_id": component_id,
            "description": "d", "recommendation": "r"}


def test_elicit_parses_structured_reply():
    findings, notes = elicit(_model(), query=lambda p: _reply(_one()))
    assert notes == []
    assert len(findings) == 1
    assert findings[0].origin == "llm"
    assert findings[0].component_id == "mcp_server.shell"
    assert findings[0].severity.value == "high"


def test_elicit_rehomes_unknown_component_to_model():
    reply = _reply(_one(component_id="mcp_server.ghost"))
    findings, _ = elicit(_model(), query=lambda p: reply)
    # a dangling reference is never shipped - it re-homes to the model pseudo-component
    assert findings[0].component_id == "model"


def test_elicit_finding_id_is_stable_across_runs():
    reply = _reply(_one())
    a, _ = elicit(_model(), query=lambda p: reply)
    b, _ = elicit(_model(), query=lambda p: reply)
    assert a[0].rule_id == b[0].rule_id           # content-derived, not positional
    assert a[0].rule_id.startswith("ATL-LLM-")


def test_elicit_id_reshuffle_keeps_ids_attached():
    # The same two threats returned in a different order must keep their ids -
    # this is what positional ids broke and what waivers rely on.
    t1, t2 = _one(title="threat one"), _one(title="threat two")
    fwd, _ = elicit(_model(), query=lambda p: _reply(t1, t2))
    rev, _ = elicit(_model(), query=lambda p: _reply(t2, t1))
    assert {f.rule_id for f in fwd} == {f.rule_id for f in rev}


def test_elicit_skips_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    findings, notes = elicit(_model())     # no injected query -> real path -> skip note
    assert findings == []
    assert notes and "skipped" in notes[0]


def test_elicit_reports_error_never_silent():
    def boom(_payload):
        raise RuntimeError("upstream 503")
    findings, notes = elicit(_model(), query=boom)
    assert findings == []
    assert any("upstream 503" in n for n in notes)


def test_elicit_fatal_error_stops_after_one_pass():
    class Fatal(Exception):
        status_code = 401
    calls = {"n": 0}

    def q(_payload):
        calls["n"] += 1
        raise Fatal()
    # deep mode would run four lens passes; a fatal (bad-key) error must stop after one
    elicit(_model(), LLMConfig(deep=True), query=q)
    assert calls["n"] == 1


def test_deep_mode_runs_a_pass_per_lens_and_dedups():
    passes = {"n": 0}

    def q(_payload):
        passes["n"] += 1
        return _reply(_one())              # every lens returns the SAME threat

    findings, _ = elicit(_model(), LLMConfig(deep=True), query=q)
    assert passes["n"] == 4                # one request per adversarial lens
    assert len(findings) == 1             # the duplicate threat is deduped to one


def test_elicit_caps_findings():
    many = _reply(*[_one(title=f"threat {i}") for i in range(25)])
    findings, _ = elicit(_model(), LLMConfig(max_findings=10), query=lambda p: many)
    assert len(findings) == 10


def test_elicit_sorts_by_severity():
    reply = _reply(_one(title="low one", severity="low"),
                   _one(title="crit one", severity="critical"))
    findings, _ = elicit(_model(), query=lambda p: reply)
    assert findings[0].severity.value == "critical"


def test_parse_findings_tolerates_bare_array_and_prose():
    arr = json.dumps([_one()])
    assert len(_parse_findings(arr)) == 1
    wrapped = f"Here you go:\n```json\n{arr}\n```\nhope that helps"
    assert len(_parse_findings(wrapped)) == 1
    assert _parse_findings("not json at all") == []


def test_parse_findings_never_raises_on_scalar_json():
    # `null` / a bare int / {"findings": 5} must yield [] - not a TypeError that
    # escapes elicit() and kills the whole scan.
    assert _parse_findings("null") == []
    assert _parse_findings("5") == []
    assert _parse_findings('{"findings": 5}') == []


def test_parse_findings_recovers_trailing_prose():
    # A valid object FOLLOWED by prose used to silently drop (span-extraction only
    # ran when the text did not start with a brace).
    reply = _reply(_one()) + "\nHope this helps!"
    assert len(_parse_findings(reply)) == 1


def test_elicit_survives_scalar_reply_with_note():
    findings, notes = elicit(_model(), query=lambda p: "null")
    assert findings == []                          # no crash
    assert any("could not be parsed" in n for n in notes)


def test_elicit_dedup_not_poisoned_by_malformed_earlier_lens():
    # An invalid-severity item for threat X on an early lens must NOT suppress a
    # valid item for the same threat X on a later lens.
    calls = {"n": 0}

    def q(_payload):
        calls["n"] += 1
        if calls["n"] == 1:
            return _reply(_one(title="shared threat", severity="BOGUS"))
        return _reply(_one(title="shared threat", severity="high"))

    findings, _ = elicit(_model(), LLMConfig(deep=True), query=q)
    assert len(findings) == 1                       # the valid later item survives
    assert findings[0].severity.value == "high"


def test_payload_truncates_oversized_model():
    cfg = LLMConfig(max_model_chars=50)
    body = _payload("x" * 500, cfg, lens=None)
    assert "truncated" in body
    assert len(body) < 200


def test_payload_appends_lens():
    body = _payload("{}", LLMConfig(), lens="exfiltration axis")
    assert "exfiltration axis" in body


def test_finding_id_normalizes_whitespace_and_case():
    assert _finding_id("Shell   Server") == _finding_id("shell server")


def test_finding_id_is_eight_hex_chars():
    # 8 hex, not 4 - shrinks the title-hash collision surface that a wildcard
    # waiver would otherwise turn into a cross-finding suppression.
    fid = _finding_id("some threat")
    assert fid.startswith("ATL-LLM-")
    assert len(fid) == len("ATL-LLM-") + 8


def test_deep_mode_each_pass_carries_a_distinct_lens():
    # The deep pass must actually vary the payload per lens (not send the same
    # request four times) - capture what each pass received.
    seen_lenses = []

    def q(payload):
        seen_lenses.append(payload)
        return _reply()

    elicit(_model(), LLMConfig(deep=True), query=q)
    lens_tails = {p.split("Review lens for this pass:", 1)[-1].strip()
                  for p in seen_lenses}
    assert len(seen_lenses) == 4
    assert len(lens_tails) == 4            # four genuinely different lenses
