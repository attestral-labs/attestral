"""Corpus harvester: the normalize / de-dupe logic and the injectable transport.

The value is a *counted, de-duped, source-tagged* denominator (directory totals
double-count and inflate). These tests pin the pure logic offline, and drive the
paginated fetchers through a fake `get` so no network is touched.
"""
from __future__ import annotations

from evaluation.corpus_harvest import (
    dedupe,
    fetch_official,
    harvest,
    normalize_official,
    normalize_pulsemcp,
    parse_github_repo,
    summarize,
)


def test_parse_github_repo_normalizes_variants():
    cases = {
        "https://github.com/Acme/Fetch": "acme/fetch",
        "git+https://github.com/acme/shell.git": "acme/shell",
        "https://github.com/acme/tool/tree/main/src": "acme/tool",
        "git@github.com:acme/ssh-repo.git": "acme/ssh-repo",
        "https://gitlab.com/acme/nope": None,
        "": None,
        None: None,
    }
    for url, expected in cases.items():
        assert parse_github_repo(url) == expected


def test_normalize_official_and_pulsemcp():
    off = normalize_official({"server": {
        "name": "io.github.acme/fetch", "description": "fetch things",
        "repository": {"url": "https://github.com/Acme/Fetch"},
        "packages": [{"identifier": "acme-fetch"}]}})
    assert off["repo_key"] == "acme/fetch"
    assert off["repo"] == "https://github.com/acme/fetch"
    assert off["packages"] == ["acme-fetch"]
    assert off["sources"] == ["official"]

    pm = normalize_pulsemcp({"name": "Acme Fetch", "short_description": "dup",
                             "source_code_url": "https://github.com/acme/fetch/tree/main"})
    assert pm["repo_key"] == "acme/fetch"
    assert normalize_official({"server": {}}) is None  # no name -> unusable


def test_dedupe_merges_sources_and_counts_once():
    rows = [
        normalize_official({"server": {"name": "a", "repository": {"url": "https://github.com/acme/fetch"}}}),
        normalize_pulsemcp({"name": "Acme Fetch", "source_code_url": "https://github.com/acme/fetch"}),
        normalize_pulsemcp({"name": "Local Only"}),  # no repo -> keyed by name
    ]
    deduped = dedupe(rows)
    assert len(deduped) == 2  # the two github.com/acme/fetch rows collapse
    fetch_row = next(r for r in deduped if r["repo_key"] == "acme/fetch")
    assert sorted(fetch_row["sources"]) == ["official", "pulsemcp"]
    s = summarize(deduped)
    assert s["total"] == 2 and s["in_multiple_sources"] == 1 and s["no_repo"] == 1


def test_fetch_official_paginates_and_stops():
    pages = {
        None: {"servers": [{"server": {"name": "one",
                "repository": {"url": "https://github.com/o/one"}}}],
               "metadata": {"next_cursor": "c2"}},
        "c2": {"servers": [{"server": {"name": "two",
                "repository": {"url": "https://github.com/o/two"}}}],
               "metadata": {"next_cursor": None}},
    }

    def fake_get(url: str):
        cursor = url.split("cursor=")[1] if "cursor=" in url else None
        return pages[cursor]

    rows = fetch_official(fake_get)
    assert [r["repo_key"] for r in rows] == ["o/one", "o/two"]


def test_harvest_dedupes_across_sources():
    def fake_get(url: str):
        if "registry.modelcontextprotocol" in url:
            return {"servers": [{"server": {"name": "shared",
                    "repository": {"url": "https://github.com/o/shared"}}}],
                    "metadata": {"next_cursor": None}}
        return {"servers": [{"name": "Shared",
                "source_code_url": "https://github.com/o/shared"}],
                "total_count": 1, "next": None}

    rows = harvest(["official", "pulsemcp"], get=fake_get)
    assert len(rows) == 1
    assert sorted(rows[0]["sources"]) == ["official", "pulsemcp"]
