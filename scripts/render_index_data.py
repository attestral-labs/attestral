#!/usr/bin/env python3
"""Regenerate the pack-derived data and count strings baked into the site.

website/index.html embeds interactive-widget payloads:

- `var MCP_RULES=...`: the browser-edition checker's per-server rules, every
  mcp_server rule whose match spec the page's JavaScript mirror can evaluate
  (known matcher kinds over config-derivable attributes only);
- `var FLEET_RULES=...`: the model-level capability-combo rules the checker
  and the fleet playground evaluate (ATL-202/203 style);
- the "N of M checks" count strings in the checker's window title, its output
  footer, and the section lede (spelled out in prose there).

It ALSO owns every hand-written count string on index.html AND system.html:
the coverage-section heading, the six per-band bars, the agentic/cloud note,
the animated 'security checks' metric, the labs-pillar cloud number, and the
typed-matcher prose. These previously drifted across rule waves because the
render scripts only touched the widget data, not the decorative counts, so a
stale numeral could pass --check. Now they are derived from the packs and
enforced, so this whole class of drift is impossible.

The playground's COMBOS block keeps hand-written narrative copy, so it is not
regenerated wholesale; its `groups:` and `sev:` fields are synced per rule id
and a severity change prints a reminder to re-read the armedText copy.

Run it after any rule-pack change, alongside scripts/render_docs_data.py and
scripts/render_codegraph.py.

Usage:
    .venv/bin/python3 scripts/render_index_data.py           # rewrite in place
    .venv/bin/python3 scripts/render_index_data.py --check   # exit 1 on drift

Needs the project environment (pyyaml).
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import yaml  # noqa: E402

PAGE_PATH = REPO / "website" / "index.html"
SYSTEM_PATH = REPO / "website" / "system.html"
CAPABILITIES_PATH = REPO / "website" / "capabilities.html"
PACKS_DIR = REPO / "attestral" / "rules"

# Rule-id band -> coverage bucket. 0xx AWS, 1xx MCP/agentic, 2xx cross-boundary,
# 3xx Azure, 4xx GCP, 5xx K8s. Cloud = every band except agentic + cross.
_CLOUD_BANDS = (0, 3, 4, 5)

# Matcher kinds the page's `matches()` mirror implements. Anything else fails
# closed in the engine AND is excluded here, so the page never advertises a
# check it cannot actually run.
BROWSER_MATCHERS = {
    "attr_equals", "attr_starts_with", "attr_contains",
    "attr_list_contains", "attr_list_any_of", "attr_any_contains",
}

# Attributes the page's `derive()` mirror of ingest/mcp.py produces from a
# pasted config. A rule that needs anything outside this set (say, a new
# ingester-derived flag) is excluded until the JS mirror learns to derive it.
BROWSER_ATTRS = {
    "command", "args", "url", "env_keys",
    "_env_has_secrets", "_auto_approve", "_remote_unauthed",
    "_confused_deputy", "_capabilities", "_has_known_cve",
    "_cloud_credential_keys", "_has_cloud_credentials",
}

# Spelled-out counts for the section lede. Extend if the checker ever mirrors
# more rules than this; the script fails loudly rather than writing a numeral.
_WORDS = {
    10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen",
    15: "fifteen", 16: "sixteen", 17: "seventeen", 18: "eighteen",
    19: "nineteen", 20: "twenty", 21: "twenty-one", 22: "twenty-two",
    23: "twenty-three", 24: "twenty-four", 25: "twenty-five",
    26: "twenty-six", 27: "twenty-seven", 28: "twenty-eight",
    29: "twenty-nine", 30: "thirty",
}


def load_rules() -> list[dict]:
    rules = []
    for pack in sorted(PACKS_DIR.glob("*.yaml")):
        rules.extend(yaml.safe_load(pack.read_text())["rules"])
    return rules


def split_checker_rules(rules: list[dict]) -> tuple[list[dict], list[dict], list[str]]:
    """Return (mcp_rules, fleet_rules, excluded-with-reason)."""
    mcp, fleet, excluded = [], [], []
    for r in rules:
        match = r.get("match", {})
        if r.get("target") == "mcp_server":
            bad_kind = sorted(set(match) - BROWSER_MATCHERS)
            attrs = {k for spec in match.values() if isinstance(spec, dict) for k in spec}
            bad_attr = sorted(attrs - BROWSER_ATTRS)
            if bad_kind:
                excluded.append(f"{r['id']}: matcher {bad_kind} not mirrored in JS")
            elif bad_attr:
                excluded.append(f"{r['id']}: attr {bad_attr} not derivable in the browser")
            else:
                mcp.append({"id": r["id"], "sev": r["severity"], "title": r["title"],
                            "rec": r["recommendation"], "match": match})
        elif r.get("target") == "model" and set(match) == {"model_capability_combo"}:
            fleet.append({"id": r["id"], "sev": r["severity"], "title": r["title"],
                          "rec": r["recommendation"],
                          "groups": match["model_capability_combo"]})
    return mcp, fleet, excluded


def inject_var(html: str, name: str, payload: list) -> str:
    blob = json.dumps(payload, separators=(",", ":")).replace("</", "<\\/")
    html, n = re.subn(
        rf"^(\s*)var {name}=.*;$",
        lambda m: f"{m.group(1)}var {name}={blob};",
        html, count=1, flags=re.M,
    )
    if n != 1:
        sys.exit(f"error: no 'var {name}=...;' line found in {PAGE_PATH.name}")
    return html


def inject_counts(html: str, n_checks: int, n_total: int) -> str:
    word = _WORDS.get(n_checks)
    if word is None:
        sys.exit(f"error: {n_checks} mirrored checks has no spelled-out form; extend _WORDS")

    edits = [
        # window title: "attestral · browser edition · 17 of 181 checks"
        (r"browser edition · \d+ of \d+ checks",
         f"browser edition · {n_checks} of {n_total} checks"),
        # checker footer: "17 of the pack\'s <a ...>181 checks</a> ran in this tab"
        (r"\d+ of the pack\\'s (<a[^>]*>)\d+ checks</a>",
         rf"{n_checks} of the pack\\'s \g<1>{n_total} checks</a>"),
        # section lede: "and seventeen of the agentic checks from the rule pack"
        (r"and [a-z-]+ of the agentic checks from the rule pack",
         f"and {word} of the agentic checks from the rule pack"),
    ]
    for pattern, repl in edits:
        html, n = re.subn(pattern, repl, html, count=1)
        if n != 1:
            sys.exit(f"error: count-string pattern not found in {PAGE_PATH.name}: {pattern}")
    return html


def sync_playground(html: str, fleet: list[dict]) -> tuple[str, list[str]]:
    """Sync groups and sev inside the playground COMBOS entries by rule id."""
    warnings = []
    for r in fleet:
        entry = re.search(r'\{id:"%s".*?\}' % r["id"], html, flags=re.S)
        if not entry:
            warnings.append(f"{r['id']}: fleet rule has no playground card; consider adding one")
            continue
        blob = json.dumps(r["groups"], separators=(",", ":"))
        start = entry.start()

        def in_entry(pattern: str, repl: str, label: str) -> None:
            nonlocal html, warnings
            seg = html[start:start + len(entry.group(0)) + 200]
            new_seg, n = re.subn(pattern, repl, seg, count=1, flags=re.S)
            if n != 1:
                warnings.append(f"{r['id']}: could not sync {label} in playground COMBOS")
            else:
                html = html[:start] + new_seg + html[start + len(seg):]

        old_sev = re.search(r'sev:"(\w+)"', entry.group(0))
        if old_sev and old_sev.group(1) != r["sev"]:
            warnings.append(f"{r['id']}: severity changed {old_sev.group(1)} -> {r['sev']};"
                            " re-read the card's armedText copy")
        in_entry(r'sev:"\w+"', f'sev:"{r["sev"]}"', "sev")
        in_entry(r"groups:\[.*?\]\]", f"groups:{blob}", "groups")
    return html, warnings


def band_counts(rules: list[dict]) -> collections.Counter:
    """Rule count per id band (ATL-0xx -> 0, ATL-1xx -> 1, ...)."""
    c: collections.Counter = collections.Counter()
    for r in rules:
        c[int(r["id"].split("-")[1]) // 100] += 1
    return c


def apply_edits(html: str, edits: list[tuple[str, str]], page: Path) -> str:
    """Apply each (pattern, replacement) exactly once, or fail loudly.

    A pattern that matches zero times means the page's structure changed and the
    renderer can no longer find the string it owns - that must fail, not silently
    write a numeral into the wrong place. Patterns are number-agnostic (they match
    ``\\d+`` next to a stable text anchor), so they re-derive the count from the
    packs no matter what the page currently says.
    """
    for pattern, repl in edits:
        html, n = re.subn(pattern, repl, html, count=1)
        if n != 1:
            sys.exit(f"error: coverage pattern not found in {page.name}: {pattern}")
    return html


def inject_coverage_index(html: str, rules: list[dict], n_total: int) -> str:
    """Own every hand-written count string in index.html's coverage section:
    the heading, the six per-band bars, the agentic/cloud note, the animated
    'security checks' metric, the labs-pillar cloud number, and the typed-matcher
    prose. Anchored on stable labels, so they track the pack automatically."""
    c = band_counts(rules)
    ac = c[1] + c[2]
    cloud = sum(c[b] for b in _CLOUD_BANDS)
    edits = [
        (r"(<h2>)\d+( checks, and the balance)", rf"\g<1>{n_total}\g<2>"),
        (r'(data-to=")\d+(">0</div><div class="lbl">security checks)',
         rf"\g<1>{n_total}\g<2>"),
        (r'(cov-label">MCP / Agentic<[^\n]*?data-to=")\d+', rf"\g<1>{c[1]}"),
        (r'(cov-label">Cross-boundary<[^\n]*?data-to=")\d+', rf"\g<1>{c[2]}"),
        (r'(cov-label">AWS<[^\n]*?data-to=")\d+', rf"\g<1>{c[0]}"),
        (r'(cov-label">Azure<[^\n]*?data-to=")\d+', rf"\g<1>{c[3]}"),
        (r'(cov-label">GCP<[^\n]*?data-to=")\d+', rf"\g<1>{c[4]}"),
        (r'(cov-label">Kubernetes<[^\n]*?data-to=")\d+', rf"\g<1>{c[5]}"),
        (r"<b>\d+( agentic and cross-boundary checks</b>)", rf"<b>{ac}\g<1>"),
        (r"(over <b>)\d+( cloud checks</b>)", rf"\g<1>{cloud}\g<2>"),
        (r"\d+( high-signal CIS checks)", rf"{cloud}\g<1>"),
        (r"\d+( typed YAML matchers)", rf"{n_total}\g<1>"),
    ]
    return apply_edits(html, edits, PAGE_PATH)


def inject_coverage_system(html: str, rules: list[dict], n_total: int) -> str:
    """Own system.html's count strings: the two headings and the six cov-n band
    numbers. These previously drifted the furthest (bars sat at a two-wave-old
    value) because nothing regenerated them."""
    c = band_counts(rules)
    edits = [
        (r"(<h3>)\d+( typed matchers</h3>)", rf"\g<1>{n_total}\g<2>"),
        (r"(<h2>)\d+( checks, balanced by strategy)", rf"\g<1>{n_total}\g<2>"),
        (r'(cov-l">MCP / Agentic</div>[^\n]*?cov-n">)\d+', rf"\g<1>{c[1]}"),
        (r'(cov-l">Cross-boundary</div>[^\n]*?cov-n">)\d+', rf"\g<1>{c[2]}"),
        (r'(cov-l">AWS</div>[^\n]*?cov-n">)\d+', rf"\g<1>{c[0]}"),
        (r'(cov-l">Azure</div>[^\n]*?cov-n">)\d+', rf"\g<1>{c[3]}"),
        (r'(cov-l">GCP</div>[^\n]*?cov-n">)\d+', rf"\g<1>{c[4]}"),
        (r'(cov-l">Kubernetes</div>[^\n]*?cov-n">)\d+', rf"\g<1>{c[5]}"),
    ]
    return apply_edits(html, edits, SYSTEM_PATH)


def inject_coverage_capabilities(html: str, n_total: int) -> str:
    """Own capabilities.html's four check-count strings: the hero metaline, the
    rules-stage heading, the HUD line, and the metric. The page landed
    hand-counted and drifted within a day (PR #95 was the manual true-up); now
    the pack is the only source."""
    edits = [
        (r"(<span><b>)\d+(</b> checks</span>)", rf"\g<1>{n_total}\g<2>"),
        (r"(<h2>)\d+( checks sweep the graph\.</h2>)", rf"\g<1>{n_total}\g<2>"),
        (r"(<b>)\d+(</b> checks swept)", rf"\g<1>{n_total}\g<2>"),
        (r'(class="num">)\d+(</div><div class="lbl">Checks</div>)',
         rf"\g<1>{n_total}\g<2>"),
    ]
    return apply_edits(html, edits, CAPABILITIES_PATH)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the page no longer matches the rule packs")
    ap.add_argument("--page", type=Path, default=PAGE_PATH)
    args = ap.parse_args()

    rules = load_rules()
    mcp, fleet, excluded = split_checker_rules(rules)
    n_checks, n_total = len(mcp) + len(fleet), len(rules)

    # index.html: interactive-widget vars + all count strings.
    index_html = args.page.read_text()
    new_index = inject_var(index_html, "MCP_RULES", mcp)
    new_index = inject_var(new_index, "FLEET_RULES", fleet)
    new_index = inject_counts(new_index, n_checks, n_total)
    new_index = inject_coverage_index(new_index, rules, n_total)
    new_index, warnings = sync_playground(new_index, fleet)

    # system.html: count strings only (no interactive widgets).
    system_html = SYSTEM_PATH.read_text()
    new_system = inject_coverage_system(system_html, rules, n_total)

    # capabilities.html: check-count strings only.
    cap_html = CAPABILITIES_PATH.read_text()
    new_cap = inject_coverage_capabilities(cap_html, n_total)

    for line in excluded:
        print(f"note: excluded from the browser checker: {line}")
    for line in warnings:
        print(f"warning: {line}", file=sys.stderr)

    drifted = [
        p.relative_to(REPO)
        for p, old, new in [(args.page, index_html, new_index),
                            (SYSTEM_PATH, system_html, new_system),
                            (CAPABILITIES_PATH, cap_html, new_cap)]
        if old != new
    ]

    if args.check:
        if drifted:
            print("site pages have drifted from the rule packs "
                  f"({', '.join(str(p) for p in drifted)}); "
                  "run scripts/render_index_data.py.", file=sys.stderr)
            return 1
        if warnings:
            return 1
        print(f"landing + system pages match the rule packs "
              f"({n_checks} browser checks of {n_total} total)")
        return 0

    args.page.write_text(new_index)
    SYSTEM_PATH.write_text(new_system)
    CAPABILITIES_PATH.write_text(new_cap)
    print(f"wrote {args.page.relative_to(REPO)} + {SYSTEM_PATH.relative_to(REPO)}: "
          f"{len(mcp)} mcp_server rules, {len(fleet)} fleet rules, "
          f"counts {n_checks} of {n_total}")
    return int(bool(warnings))


if __name__ == "__main__":
    raise SystemExit(main())
