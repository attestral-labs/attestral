#!/usr/bin/env python3
"""Harvest a de-duplicated MCP-server corpus from the public registries.

Two jobs this serves: a *defensible denominator* for recall / false-positive
claims (so "one in three ships the lethal trifecta" rests on a counted set, not
a vendor-inflated directory total), and a *target list* for the sandboxed
red-team work. It pulls the two cleanly-paginated sources - the official MCP
registry and PulseMCP - normalizes each record, and de-dupes by GitHub repo
(owner/repo, upgraded to the immutable numeric id when `--enrich-github` runs),
because directories double-count and repos get renamed, so a URL is not a stable
key. Directory totals are noise; a counted, de-duped, source-tagged manifest is
the number you can publish.

Stdlib only. The HTTP layer is a single injectable `get` callable, so the
normalize / de-dupe logic is unit-tested offline with canned pages.

    python3 -m evaluation.corpus_harvest                     # both sources -> research/corpus/
    python3 -m evaluation.corpus_harvest --source official --max 300
    python3 -m evaluation.corpus_harvest --enrich-github     # add last_commit + immutable id (needs GITHUB_TOKEN for scale)
    python3 -m evaluation.corpus_harvest --offline dump.json --summary-only
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

REPO = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO / "research" / "corpus" / "mcp-manifest.jsonl"

OFFICIAL_URL = "https://registry.modelcontextprotocol.io/v0/servers"
PULSEMCP_URL = "https://api.pulsemcp.com/v0beta/servers"
GITHUB_API = "https://api.github.com/repos/"

DESC_MAX = 280  # keep manifest rows compact
_GH_RE = re.compile(r"github\.com[/:]+([^/]+)/([^/#?]+)", re.IGNORECASE)

Json = Callable[[str], object]


# --- pure helpers (offline-testable) ----------------------------------------

def parse_github_repo(url: str | None) -> str | None:
    """Extract a stable `owner/repo` (lowercased) from a GitHub URL, else None.

    Tolerates git+https prefixes, a trailing `.git`, `/tree/...` sub-paths, and
    SSH-style `git@github.com:owner/repo`. Not a GitHub URL -> None.
    """
    if not url or not isinstance(url, str):
        return None
    m = _GH_RE.search(url)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo:
        return None
    return f"{owner.lower()}/{repo.lower()}"


def _clip(text: object) -> str:
    s = str(text or "").strip().replace("\n", " ")
    return s[:DESC_MAX]


def _blank_row(name: str) -> dict:
    return {
        "name": name,
        "repo": None,
        "repo_key": None,
        "repo_id": None,
        "last_commit": None,
        "description": "",
        "sources": [],
        "packages": [],
    }


def normalize_official(record: dict) -> dict | None:
    """One official-registry record -> a manifest row (None if unusable)."""
    server = record.get("server", record) if isinstance(record, dict) else None
    if not isinstance(server, dict):
        return None
    name = str(server.get("name") or "").strip()
    if not name:
        return None
    repo_url = None
    repository = server.get("repository")
    if isinstance(repository, dict):
        repo_url = repository.get("url")
    row = _blank_row(name)
    row["description"] = _clip(server.get("description"))
    row["repo_key"] = parse_github_repo(repo_url)
    row["repo"] = f"https://github.com/{row['repo_key']}" if row["repo_key"] else repo_url
    row["packages"] = [
        str(p.get("identifier") or p.get("name") or "")
        for p in (server.get("packages") or [])
        if isinstance(p, dict)
    ]
    row["sources"] = ["official"]
    return row


def normalize_pulsemcp(record: dict) -> dict | None:
    """One PulseMCP record -> a manifest row (None if unusable)."""
    if not isinstance(record, dict):
        return None
    name = str(record.get("name") or record.get("slug") or "").strip()
    if not name:
        return None
    repo_url = record.get("source_code_url") or record.get("url") or record.get("external_url")
    row = _blank_row(name)
    row["description"] = _clip(record.get("short_description") or record.get("description"))
    row["repo_key"] = parse_github_repo(repo_url)
    row["repo"] = f"https://github.com/{row['repo_key']}" if row["repo_key"] else repo_url
    row["sources"] = ["pulsemcp"]
    return row


def dedupe(rows: list[dict]) -> list[dict]:
    """Collapse rows sharing a repo (owner/repo, or numeric id if enriched).

    Rows without a repo key fall back to their name. First-seen wins for the
    fields; sources and packages are unioned, so an entry present in both
    registries carries `["official", "pulsemcp"]` and is counted once.
    """
    out: dict[str, dict] = {}
    order: list[str] = []
    for row in rows:
        key = (
            f"id:{row['repo_id']}" if row.get("repo_id")
            else f"repo:{row['repo_key']}" if row.get("repo_key")
            else f"name:{row['name'].lower()}"
        )
        if key not in out:
            out[key] = {**row, "sources": list(row.get("sources", [])),
                        "packages": list(row.get("packages", []))}
            order.append(key)
            continue
        merged = out[key]
        for src in row.get("sources", []):
            if src not in merged["sources"]:
                merged["sources"].append(src)
        for pkg in row.get("packages", []):
            if pkg and pkg not in merged["packages"]:
                merged["packages"].append(pkg)
        if not merged["description"] and row.get("description"):
            merged["description"] = row["description"]
    return [out[k] for k in order]


def summarize(rows: list[dict]) -> dict:
    with_repo = [r for r in rows if r.get("repo_key")]
    by_source: dict[str, int] = {}
    for r in rows:
        for s in r["sources"]:
            by_source[s] = by_source.get(s, 0) + 1
    return {
        "total": len(rows),
        "with_github_repo": len(with_repo),
        "no_repo": len(rows) - len(with_repo),
        "by_source": by_source,
        "in_multiple_sources": sum(1 for r in rows if len(r["sources"]) > 1),
        "enriched": sum(1 for r in rows if r.get("repo_id")),
    }


# --- HTTP (isolated so the logic above stays offline-testable) --------------

def _http_get_json(url: str) -> object:
    headers = {"User-Agent": "attestral-corpus-harvest", "Accept": "application/json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith(GITHUB_API):
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)  # noqa: S310 - fixed https hosts
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        return json.loads(resp.read().decode())


def fetch_official(get: Json = _http_get_json, max_records: int | None = None) -> list[dict]:
    """Cursor-paginate the official registry; normalize each server."""
    rows: list[dict] = []
    cursor = None
    seen_cursors: set[str] = set()
    while True:
        url = f"{OFFICIAL_URL}?limit=100" + (f"&cursor={cursor}" if cursor else "")
        data = get(url)
        if not isinstance(data, dict):
            break
        for rec in data.get("servers", []):
            row = normalize_official(rec)
            if row:
                rows.append(row)
        if max_records is not None and len(rows) >= max_records:
            return rows[:max_records]
        meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        cursor = meta.get("next_cursor") or data.get("next_cursor")
        if not cursor or cursor in seen_cursors:
            break
        seen_cursors.add(cursor)
    return rows


def fetch_pulsemcp(get: Json = _http_get_json, max_records: int | None = None) -> list[dict]:
    """Offset-paginate PulseMCP; normalize each server."""
    rows: list[dict] = []
    offset = 0
    while True:
        url = f"{PULSEMCP_URL}?count_per_page=100&offset={offset}"
        data = get(url)
        if not isinstance(data, dict):
            break
        servers = data.get("servers", [])
        if not servers:
            break
        for rec in servers:
            row = normalize_pulsemcp(rec)
            if row:
                rows.append(row)
        if max_records is not None and len(rows) >= max_records:
            return rows[:max_records]
        offset += len(servers)
        if data.get("next") in (None, "") or offset >= int(data.get("total_count", offset)):
            break
    return rows


def enrich_github(rows: list[dict], get: Json = _http_get_json,
                  limit: int | None = None) -> list[str]:
    """Add the immutable numeric id and `last_commit` (pushed_at) per repo.

    Opt-in: one GitHub API call per repo, so it is rate-limited without a
    GITHUB_TOKEN. Returns operator notes (never silent). De-dupe by numeric id
    afterwards to fold repos that were renamed since a registry indexed them.
    """
    notes: list[str] = []
    done = 0
    for row in rows:
        if not row.get("repo_key"):
            continue
        if limit is not None and done >= limit:
            notes.append(f"github enrichment capped at {limit}; {len(rows) - done} repos left un-enriched")
            break
        try:
            data = get(GITHUB_API + row["repo_key"])
        except (urllib.error.HTTPError, urllib.error.URLError, ValueError) as exc:
            notes.append(f"github enrich failed for {row['repo_key']}: {exc}")
            continue
        if isinstance(data, dict):
            row["repo_id"] = data.get("id")
            row["last_commit"] = data.get("pushed_at")
        done += 1
    return notes


def harvest(sources: list[str], get: Json = _http_get_json,
            max_per_source: int | None = None) -> list[dict]:
    rows: list[dict] = []
    if "official" in sources:
        rows += fetch_official(get, max_per_source)
    if "pulsemcp" in sources:
        rows += fetch_pulsemcp(get, max_per_source)
    return dedupe(rows)


def write_manifest(rows: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


# --- CLI ---------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", default="official,pulsemcp",
                    help="Comma list: official, pulsemcp (default both).")
    ap.add_argument("--max", type=int, default=None,
                    help="Cap records fetched per source (for a quick pull).")
    ap.add_argument("--enrich-github", action="store_true",
                    help="Add immutable numeric id + last_commit per repo (GitHub API; set GITHUB_TOKEN).")
    ap.add_argument("--enrich-limit", type=int, default=None,
                    help="Cap the number of GitHub enrichment calls.")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT,
                    help=f"Manifest path (JSONL). Default {DEFAULT_OUT.relative_to(REPO)}.")
    ap.add_argument("--offline", type=Path, default=None,
                    help="Skip the network: load a raw dump {\"official\":[...],\"pulsemcp\":[...]}.")
    ap.add_argument("--summary-only", action="store_true",
                    help="Print the summary; do not write the manifest.")
    args = ap.parse_args(argv)
    sources = [s.strip() for s in args.source.split(",") if s.strip()]

    if args.offline:
        raw = json.loads(args.offline.read_text())
        rows = dedupe(
            [r for rec in raw.get("official", []) if (r := normalize_official(rec))]
            + [r for rec in raw.get("pulsemcp", []) if (r := normalize_pulsemcp(rec))]
        )
    else:
        try:
            rows = harvest(sources, max_per_source=args.max)
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            print(f"fetch failed: {exc}", file=sys.stderr)
            return 1

    if args.enrich_github and not args.offline:
        for note in enrich_github(rows, limit=args.enrich_limit):
            print(f"  ! {note}", file=sys.stderr)
        rows = dedupe(rows)  # fold renamed repos now that numeric ids are known

    summary = summarize(rows)
    print(json.dumps(summary, indent=2))
    if not args.summary_only:
        write_manifest(rows, args.out)
        print(f"wrote {len(rows)} rows -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
