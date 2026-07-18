"""Measure Attestral recall against a threat-labelled EXTERNAL set (M-EVAL v2).

Unlike evaluation/score.py, whose positive labels come from each fixture's own
README (a regression guard that scores 100% by construction), every case in
evaluation/external/cases.yaml is a published advisory (CVE + GHSA) labelled from
the THREAT. Recall here is therefore allowed to fall below 100% and expose real
misses, because nothing about the label was chosen to match a rule we ship.

Two numbers, because they mean different things:

- **design-visible recall** - of the advisories whose vulnerable pattern lives in
  declared config an ingester reads (here: an MCP server pinned to a known-
  vulnerable package version), how many fire the expected rule. A miss is a
  concrete known-CVE-table / rule gap we can close.
- **full-set coverage** - detected / all advisories. The shortfall is the agent-
  framework dependency and runtime code vulns a design-time model cannot see
  without new ingesters. Each is itemised as a named limitation, never counted
  as a silent pass. This is the honest headline: it is well below 100%, and it
  should be.

    python -m evaluation.score_external            # scorecard to stdout + JSON
    python -m evaluation.score_external --check    # exit 1 if a design-visible
                                                   # advisory stops firing

Deterministic and offline. Add cases as advisories land (the weekly radar feeds
it). Every case cites its advisory so anyone can re-derive the label.
"""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

import yaml

from attestral.ingest import build_model
from attestral.rules import RuleEngine

HERE = Path(__file__).resolve().parent
CASES = HERE / "external" / "cases.yaml"
RESULTS = HERE / "external" / "results.json"
TAXONOMY = HERE / "taxonomy.yaml"


def load_cases() -> list[dict]:
    return yaml.safe_load(CASES.read_text())["cases"]


def taxonomy_coverage() -> dict:
    """Coverage against the published taxonomy (an independent denominator).

    covered + partial count as 'attempted at design time'; needs-ingester and
    out-of-scope are honest gaps. A perfect score here would mean the taxonomy
    was trimmed to fit us, so the gaps are the point.
    """
    fams = yaml.safe_load(TAXONOMY.read_text())
    items = [it for fam, lst in fams.items() if isinstance(lst, list) for it in lst]
    by_status: dict[str, int] = {}
    for it in items:
        by_status[it["status"]] = by_status.get(it["status"], 0) + 1
    attempted = by_status.get("covered", 0) + by_status.get("partial", 0)
    return {
        "total": len(items),
        "attempted": attempted,
        "rate": round(attempted / len(items), 4) if items else 0.0,
        "by_status": by_status,
    }


def _fires(config: str, expect: str) -> bool:
    """Reconstruct the advisory's mcp.json in a temp dir and scan it the
    production way (build_model + RuleEngine); report whether `expect` fired."""
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "mcp.json").write_text(config)
        model = build_model(d)
        fired = {f.rule_id for f in RuleEngine().evaluate(model)}
    return expect in fired


def run() -> dict:
    rows = []
    for c in load_cases():
        if c["scope"] == "design-visible":
            outcome = "detected" if _fires(c["config"], c["expect"]) else "missed"
        else:
            outcome = f"out-of-scope:{c['scope']}"
        rows.append({"id": c["id"], "advisory": c["advisory"], "ref": c["ref"],
                     "scope": c["scope"], "expect": c.get("expect"),
                     "threat": c["threat"], "outcome": outcome})

    dv = [r for r in rows if r["scope"] == "design-visible"]
    detected = [r for r in dv if r["outcome"] == "detected"]
    missed = [r for r in dv if r["outcome"] == "missed"]
    oos = [r for r in rows if r["scope"] != "design-visible"]
    return {
        "total": len(rows),
        "design_visible": len(dv),
        "design_visible_detected": len(detected),
        "design_visible_recall": round(len(detected) / len(dv), 4) if dv else 0.0,
        "full_coverage": round(len(detected) / len(rows), 4) if rows else 0.0,
        "out_of_scope": len(oos),
        "missed": [r["id"] for r in missed],
        "rows": rows,
        "taxonomy": taxonomy_coverage(),
    }


def format_scorecard(r: dict) -> str:
    lines = [
        "# Attestral external recall (M-EVAL v2) - threat-labelled, not self-graded",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Design-visible recall (advisory in config-visible scope) | "
        f"{r['design_visible_detected']}/{r['design_visible']} "
        f"({r['design_visible_recall']:.0%}) |",
        f"| Full-set coverage (all published advisories) | "
        f"{r['design_visible_detected']}/{r['total']} ({r['full_coverage']:.0%}) |",
        f"| Out of design-time scope (needs a new ingester) | {r['out_of_scope']} |",
        f"| Taxonomy attempted (covered + partial of published items) | "
        f"{r['taxonomy']['attempted']}/{r['taxonomy']['total']} "
        f"({r['taxonomy']['rate']:.0%}) |",
        "",
        "| Advisory | Scope | Outcome |",
        "|---|---|---|",
    ]
    for row in r["rows"]:
        lines.append(f"| {row['advisory']} ({row['id']}) | {row['scope']} | {row['outcome']} |")
    if r["missed"]:
        lines += ["", f"Design-visible MISSES (close these): {', '.join(r['missed'])}"]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if any design-visible advisory stopped firing")
    args = ap.parse_args()

    r = run()
    RESULTS.write_text(json.dumps(r, indent=2) + "\n")
    print(format_scorecard(r))

    if args.check and r["missed"]:
        print(f"\nregression: design-visible advisories no longer detected: "
              f"{', '.join(r['missed'])}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
