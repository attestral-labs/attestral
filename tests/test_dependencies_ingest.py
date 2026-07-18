"""Dependency-manifest ingester: known-vulnerable pins -> ATL-145."""
from attestral.ingest import build_model
from attestral.ingest.dependencies import _dep_cve, ingest_dependencies
from attestral.model import SystemModel
from attestral.rules import RuleEngine


def test_fixture_flags_known_vulnerable_deps():
    model = build_model("examples/vulnerable-deps")
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-145" in ids
    deps = {c.attr("_known_cve") for c in model.by_type("dependency")}
    assert {"CVE-2025-68664", "CVE-2025-67644"} <= deps


def test_safe_pin_is_not_flagged(tmp_path):
    # 1.2.22 is fixed for BOTH langchain-core CVEs (68664 fixed 1.2.5, 34070
    # fixed 1.2.22); anything below 1.2.22 is still vulnerable to one of them.
    (tmp_path / "requirements.txt").write_text(
        "langchain-core==1.2.22\nrequests==2.31.0\n"
    )
    model = build_model(str(tmp_path))
    assert not model.by_type("dependency")
    assert "ATL-145" not in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_open_range_is_not_flagged(tmp_path):
    # Only an exact pin is comparable; an open range must not flag (fail closed).
    (tmp_path / "requirements.txt").write_text("langchain-core>=0.1\n")
    model = build_model(str(tmp_path))
    assert not model.by_type("dependency")


def test_version_ranges_are_branch_precise():
    # 68664 is fixed on two branches (0.3.81 and 1.2.5); a version fixed on one
    # branch must not be flagged for it.
    assert _dep_cve("langchain-core", "1.2.4") == "CVE-2025-68664"
    assert _dep_cve("langchain-core", "0.3.80") == "CVE-2025-68664"
    assert _dep_cve("langchain-core", "0.3.81") is None      # fixed on the 0.x branch
    # 1.2.5 fixes LangGrinch but is still vulnerable to the path-traversal CVE:
    assert _dep_cve("langchain-core", "1.2.5") == "CVE-2026-34070"
    assert _dep_cve("langchain-core", "1.2.21") == "CVE-2026-34070"
    assert _dep_cve("langchain-core", "1.2.22") is None       # both fixed


def test_name_normalization():
    # PEP 503: langchain_core / LangChain-Core normalize to the same package.
    assert _dep_cve("LangChain_Core", "1.2.4") == "CVE-2025-68664"


def test_pyproject_and_package_json_pins(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        'dependencies = ["langchain-core==1.2.4", "httpx==0.27.0"]\n'
    )
    model = ingest_dependencies(str(tmp_path), SystemModel())
    assert {c.attr("_known_cve") for c in model.by_type("dependency")} == {"CVE-2025-68664"}
