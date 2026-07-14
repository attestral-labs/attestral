#!/usr/bin/env python3
"""Regenerate the data baked into the docs page.

website/docs.html embeds two generated payloads:

- `const RULES = ...`: the searchable rule index, one entry per rule across
  every built-in pack (core + provider packs);
- `const CHAIN = ...`: the first entries of a real evidence chain from a scan
  of examples/demo-project, used by the tamper-the-chain demo. Payload strings
  are Python's canonical `json.dumps(finding, sort_keys=True)` so the page's
  SHA-256 walk reproduces the CLI's hashes bit for bit.

Run it after any rule-pack change or when the demo fixture's findings change,
alongside scripts/render_codegraph.py for the architecture page.

Usage:
    .venv/bin/python3 scripts/render_docs_data.py           # rewrite in place
    .venv/bin/python3 scripts/render_docs_data.py --check   # exit 1 on drift

Needs the project environment (pyyaml, and attestral importable).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import yaml  # noqa: E402

from attestral.evidence import audit_chain  # noqa: E402
from attestral.ingest import build_model  # noqa: E402
from attestral.rules import RuleEngine  # noqa: E402

PAGE_PATH = REPO / "website" / "docs.html"
PACKS_DIR = REPO / "attestral" / "rules"
DEMO_FIXTURE = REPO / "examples" / "demo-project"
CHAIN_ENTRIES = 4  # enough to show a break propagating, small enough to read

# ATL id bands, per the rule-authoring guide in CLAUDE.md.
_BANDS = [
    (0, "AWS"), (100, "MCP / agentic"), (200, "Cross-boundary"),
    (300, "Azure"), (400, "GCP"), (500, "Kubernetes"),
]


def _domain(rule_id: str) -> str:
    m = re.match(r"ATL-(\d+)", rule_id)
    if not m:
        return "Other"
    n = int(m.group(1))
    for floor, label in reversed(_BANDS):
        if n >= floor:
            return label
    return "Other"


def build_rules() -> list[dict]:
    rules = []
    for pack in sorted(PACKS_DIR.glob("*.yaml")):
        for r in yaml.safe_load(pack.read_text())["rules"]:
            rules.append({
                "id": r["id"],
                "title": r["title"],
                "sev": r["severity"],
                "target": r["target"],
                "matcher": next(iter(r["match"])),
                "desc": r["description"],
                "rec": r["recommendation"],
                "fw": r.get("frameworks", []),
                "domain": _domain(r["id"]),
            })
    ids = [r["id"] for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        sys.exit(f"error: duplicate rule ids across packs: {sorted(dupes)}")
    return sorted(rules, key=lambda r: r["id"])


def build_chain() -> list[dict]:
    model = build_model(DEMO_FIXTURE)
    findings = RuleEngine().evaluate(model)
    # DEMO_FIXTURE is absolute, so every finding.source is this machine's path.
    # Baking it would put a local path (e.g. /Users/you/...) into each payload
    # and its hash, so the chain would only reproduce on the machine that
    # rendered it - the CI sync check fails everywhere else, and the path leaks
    # onto the public page. Relativize to REPO for reproducible, path-clean data.
    for f in findings:
        if f.source:
            try:
                f.source = str(Path(f.source).relative_to(REPO))
            except ValueError:
                pass
    chain = audit_chain(findings)
    if len(chain) < CHAIN_ENTRIES:
        sys.exit(f"error: demo fixture yields only {len(chain)} findings;"
                 f" the chain demo wants {CHAIN_ENTRIES}")
    out = []
    for e in chain[:CHAIN_ENTRIES]:
        payload = json.dumps(e["finding"], sort_keys=True)
        if any(ord(c) > 127 for c in payload):
            sys.exit(f"error: non-ASCII finding payload for {e['finding']['rule_id']};"
                     " the page's canonicalizer assumes ASCII")
        out.append({"hash": e["hash"], "prev": e["prev"], "payload": payload})
    return out


def inject(html: str, name: str, payload: list) -> str:
    # \/ is a valid JSON escape; this keeps any "</script>" in a string from
    # terminating the page's script element.
    blob = json.dumps(payload, separators=(",", ":")).replace("</", "<\\/")
    html, n = re.subn(
        rf"^const {name} = .*;$",
        lambda _m: f"const {name} = {blob};",
        html, count=1, flags=re.M,
    )
    if n != 1:
        sys.exit(f"error: no 'const {name} = ...;' line found in {PAGE_PATH.name}")
    return html


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the page no longer matches the packs/fixture")
    ap.add_argument("--page", type=Path, default=PAGE_PATH)
    args = ap.parse_args()

    html = args.page.read_text()
    rules = build_rules()
    chain = build_chain()
    new_html = inject(inject(html, "RULES", rules), "CHAIN", chain)

    if args.check:
        if new_html != html:
            print(f"{args.page.relative_to(REPO)} has drifted from the rule packs"
                  " or demo fixture; run scripts/render_docs_data.py.", file=sys.stderr)
            return 1
        print("docs page matches the rule packs and demo fixture")
        return 0

    args.page.write_text(new_html)
    sevs = {s: sum(1 for r in rules if r["sev"] == s) for s in
            ("critical", "high", "medium", "low", "info")}
    print(f"wrote {args.page.relative_to(REPO)}: {len(rules)} rules "
          f"({', '.join(f'{v} {k}' for k, v in sevs.items() if v)}), "
          f"{len(chain)} chain entries from {DEMO_FIXTURE.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
