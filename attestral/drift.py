"""Design-runtime drift detection.

Reads a JSONL stream of tool-call events (mcp-guard telemetry format:
one object per line with at least `server`, `tool`, and optionally
`args`, `url`, `ts`) and diffs each event against the compiled policy
derived from the attested design.

Fail-closed philosophy carries through: an event that references a server
absent from the attested model is CRITICAL drift - the deployed system has
grown beyond what was reviewed.
"""
from __future__ import annotations

import json
from pathlib import Path

from attestral.model import Finding, Severity

DRIFT_RULES = {
    "DRF-001": ("Unattested server observed at runtime", Severity.CRITICAL),
    "DRF-002": ("Denied server invoked at runtime", Severity.CRITICAL),
    "DRF-003": ("Filesystem access outside attested roots", Severity.HIGH),
    "DRF-004": ("Non-TLS transport observed for TLS-constrained server", Severity.HIGH),
}


def _mk(rule: str, server: str, detail: str, event_no: int) -> Finding:
    title, sev = DRIFT_RULES[rule]
    return Finding(
        rule_id=rule,
        title=title,
        severity=sev,
        component_id=f"mcp_server.{server}",
        description=f"Event #{event_no}: {detail}",
        recommendation=(
            "Either revert the runtime change, or update the design, re-run the "
            "review, and re-compile the policy so deployment and review match."
        ),
        source="runtime-telemetry",
        origin="deterministic",
    )


def _path_in_roots(path: str, roots: list[str]) -> bool:
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def detect_drift(policy: dict, events: list[dict]) -> list[Finding]:
    servers: dict[str, dict] = policy.get("servers", {})
    findings: list[Finding] = []
    for i, ev in enumerate(events, 1):
        name = str(ev.get("server", ""))
        entry = servers.get(name)

        if entry is None:
            findings.append(_mk("DRF-001", name, f"server '{name}' is not in the attested design", i))
            continue
        if not entry.get("allow", False):
            findings.append(_mk("DRF-002", name, entry.get("reason", "denied by policy"), i))
            continue

        constraints = entry.get("constraints", {})
        roots = constraints.get("root_paths")
        if roots:
            for arg in [str(a) for a in ev.get("args", []) if str(a).startswith(("/", "~"))]:
                if not _path_in_roots(arg, roots):
                    findings.append(_mk("DRF-003", name, f"path '{arg}' outside attested roots {roots}", i))
        if constraints.get("transport") == "tls_only" and str(ev.get("url", "")).startswith("http://"):
            findings.append(_mk("DRF-004", name, f"plaintext url '{ev.get('url')}'", i))
    findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return findings


def load_events(path: str | Path) -> list[dict]:
    events = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events
