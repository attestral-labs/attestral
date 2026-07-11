import json

from attestral.ingest import build_model
from attestral.model import Finding, Severity, SystemModel
from attestral.rules import RuleEngine
from attestral.sarif import render_sarif


def _demo():
    model = build_model("examples/demo-project")
    return model, RuleEngine().evaluate(model)


def _doc():
    model, findings = _demo()
    return json.loads(render_sarif(model, findings, "examples/demo-project")), findings


def test_valid_sarif_envelope():
    doc, _ = _doc()
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Attestral"
    assert driver["version"]  # tool version is stamped


def test_one_result_per_finding():
    doc, findings = _doc()
    assert len(doc["runs"][0]["results"]) == len(findings)


def test_rules_are_deduplicated_and_indexed():
    doc, findings = _doc()
    rules = doc["runs"][0]["results"][0]["ruleIndex"]  # smoke: index present
    assert isinstance(rules, int)
    driver_rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(driver_rules) == len({f.rule_id for f in findings})
    # every result's ruleIndex points at the matching rule id
    for result in doc["runs"][0]["results"]:
        assert driver_rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_every_result_has_a_location():
    doc, _ = _doc()
    for result in doc["runs"][0]["results"]:
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"]  # non-empty uri, never dropped by GitHub


def test_severity_maps_to_level_and_security_severity():
    model = SystemModel()
    findings = [
        Finding("X-CRIT", "c", Severity.CRITICAL, "a", "d", "r"),
        Finding("X-MED", "m", Severity.MEDIUM, "b", "d", "r"),
        Finding("X-INFO", "i", Severity.INFO, "c", "d", "r"),
    ]
    doc = json.loads(render_sarif(model, findings, "t"))
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels == {"X-CRIT": "error", "X-MED": "warning", "X-INFO": "note"}
    sev = {
        r["id"]: r["properties"]["security-severity"]
        for r in doc["runs"][0]["tool"]["driver"]["rules"]
    }
    assert float(sev["X-CRIT"]) >= 9.0  # GitHub 'critical' bucket
    assert 4.0 <= float(sev["X-MED"]) < 7.0  # 'medium' bucket


def test_model_level_source_gets_placeholder_uri():
    model = SystemModel()
    findings = [Finding("ATL-201", "cross boundary", Severity.INFO, "model", "d", "r",
                        source="system model")]
    doc = json.loads(render_sarif(model, findings, "t"))
    uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "SYSTEM-MODEL"  # non-path source never yields an empty/space uri


def test_deterministic_output():
    model, findings = _demo()
    a = render_sarif(model, findings, "examples/demo-project")
    b = render_sarif(model, findings, "examples/demo-project")
    assert a == b


def test_empty_findings_is_still_valid_sarif():
    doc = json.loads(render_sarif(SystemModel(), [], "t"))
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []
