import json
import sys
import threading
from pathlib import Path

sys.path.insert(0, "integrations/mcp-guard")
from attestral_telemetry import TelemetryWriter  # noqa: E402

from attestral.compile import compile_policy  # noqa: E402
from attestral.drift import detect_drift, load_events  # noqa: E402
from attestral.ingest import build_model  # noqa: E402
from attestral.rules import RuleEngine  # noqa: E402


def test_emit_schema(tmp_path):
    w = TelemetryWriter(tmp_path / "e.jsonl")
    w.emit("docs", "read_file", ["/srv/docs/a.md"])
    ev = json.loads((tmp_path / "e.jsonl").read_text().strip())
    assert ev["server"] == "docs" and ev["tool"] == "read_file"
    assert ev["decision"] == "allow" and "ts" in ev


def test_thread_safety(tmp_path):
    w = TelemetryWriter(tmp_path / "e.jsonl")
    threads = [threading.Thread(target=lambda: [w.emit("s", "t") for _ in range(50)]) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    lines = (tmp_path / "e.jsonl").read_text().splitlines()
    assert len(lines) == 400 and all(json.loads(x) for x in lines)


def test_emitter_output_feeds_drift(tmp_path):
    w = TelemetryWriter(tmp_path / "e.jsonl")
    w.emit("rogue-server", "anything")           # unattested → DRF-001
    w.emit("docs", "read_file", ["/etc/shadow"]) # out of scope → DRF-003
    model = build_model("examples/demo-project")
    policy = compile_policy(model, RuleEngine().evaluate(model))
    findings = detect_drift(policy, load_events(tmp_path / "e.jsonl"))
    assert {"DRF-001", "DRF-003"} <= {f.rule_id for f in findings}


def test_rotation(tmp_path):
    w = TelemetryWriter(tmp_path / "e.jsonl", max_bytes=200)
    for _ in range(20):
        w.emit("s", "t", ["x" * 40])
    assert len(list(Path(tmp_path).glob("*.jsonl"))) >= 2
