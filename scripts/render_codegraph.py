#!/usr/bin/env python3
"""Regenerate the architecture page's embedded code graph.

website/architecture.html bakes in a JSON snapshot (`const DATA = ...`) of the
package's module graph. This script re-extracts that snapshot so regeneration
is a release-routine command instead of a hand bake:

- modules, sizes, symbols, and resolved call edges come straight from the
  codegraph index (.codegraph/codegraph.db, a tree-sitter parse of the repo);
- import edges are re-swept from source with `ast`, because the index only
  records module-level imports. An import inside a function or a TYPE_CHECKING
  block is the dashed "lazy" edge on the page, and laziness is a position
  property the index does not model.

The script also refuses to emit a module the page's hand-tuned layout does not
place: add new modules to STAGES/FOUNDATION in architecture.html first.

Usage:
    python3 scripts/render_codegraph.py           # rewrite the page in place
    python3 scripts/render_codegraph.py --check   # exit 1 if the page drifted

Stdlib only; run it from any Python 3.10+.

Run `codegraph index` (a full re-index) first when regenerating after many
edits or on a fresh index: the initial bulk pass cannot resolve calls into
files it has not parsed yet, so an un-refreshed index under-reports call
edges (81 vs the real 369 when this page was first baked).
"""
from __future__ import annotations

import argparse
import ast
import datetime as _dt
import json
import re
import sqlite3
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DB_PATH = REPO / ".codegraph" / "codegraph.db"
PAGE_PATH = REPO / "website" / "architecture.html"
PKG_ROOT = REPO / "attestral"
VERSION_FILE = REPO / "attestral" / "__init__.py"

SIG_MAX = 120  # keep the embedded payload small; the panel elides anyway


def module_name(rel_path: str) -> str:
    """attestral/ingest/mcp.py -> attestral.ingest.mcp; __init__.py -> its package."""
    p = Path(rel_path)
    parts = list(p.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def read_version() -> str:
    m = re.search(r'__version__\s*=\s*"([^"]+)"', VERSION_FILE.read_text())
    if not m:
        sys.exit(f"error: no __version__ in {VERSION_FILE}")
    return m.group(1)


# ---------------------------------------------------------------- index reads

def extract_modules(con: sqlite3.Connection) -> dict[str, dict]:
    rows = con.execute(
        "SELECT path, size, node_count FROM files"
        " WHERE path LIKE 'attestral/%' AND path LIKE '%.py' ORDER BY path"
    ).fetchall()
    if not rows:
        sys.exit("error: the index holds no attestral/ files - is it initialized?")
    modules: dict[str, dict] = {}
    for path, size, node_count in rows:
        modules[module_name(path)] = {
            "functions": [], "classes": [], "bytes": size, "nodeCount": node_count,
        }
    return modules


def extract_symbols(con: sqlite3.Connection, modules: dict[str, dict]) -> None:
    rows = con.execute(
        "SELECT file_path, name, qualified_name, kind, start_line, signature"
        " FROM nodes WHERE kind IN ('function','method','class')"
        " AND file_path LIKE 'attestral/%' ORDER BY file_path, start_line"
    ).fetchall()
    for file_path, name, qname, kind, line, sig in rows:
        mod = modules.get(module_name(file_path))
        if mod is None:
            continue
        entry = {"name": name, "qname": qname, "line": line,
                 "sig": (sig or "")[:SIG_MAX], "kind": kind}
        (mod["classes"] if kind == "class" else mod["functions"]).append(entry)


def extract_calls(con: sqlite3.Connection) -> list[dict]:
    rows = con.execute(
        "SELECT s.qualified_name, s.file_path, t.qualified_name, t.file_path, e.kind"
        " FROM edges e JOIN nodes s ON e.source = s.id JOIN nodes t ON e.target = t.id"
        " WHERE e.kind IN ('calls','instantiates')"
        " AND s.file_path LIKE 'attestral/%' AND t.file_path LIKE 'attestral/%'"
        " ORDER BY s.file_path, t.file_path, s.qualified_name, t.qualified_name, e.id"
    ).fetchall()
    return [
        {"src": s, "dst": t, "srcMod": module_name(sf), "dstMod": module_name(tf),
         "kind": kind}
        for s, sf, t, tf, kind in rows
    ]


def db_import_pairs(con: sqlite3.Connection) -> set[tuple[str, str]]:
    """Module-level import edges the index resolved, for the cross-check."""
    rows = con.execute(
        "SELECT s.file_path, t.qualified_name FROM edges e"
        " JOIN nodes s ON e.source = s.id JOIN nodes t ON e.target = t.id"
        " WHERE e.kind = 'imports' AND s.file_path LIKE 'attestral/%'"
        " AND (t.qualified_name = 'attestral' OR t.qualified_name LIKE 'attestral.%')"
    ).fetchall()
    return {(module_name(f), q) for f, q in rows}


# ---------------------------------------------------------------- import sweep

def _is_type_checking(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _walk_imports(node: ast.AST, lazy: bool, out: list[tuple[ast.stmt, bool]]) -> None:
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.Import, ast.ImportFrom)):
            out.append((child, lazy))
        elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            _walk_imports(child, True, out)
        elif isinstance(child, ast.If) and _is_type_checking(child.test):
            _walk_imports(child, True, out)
        else:
            _walk_imports(child, lazy, out)


def _targets(stmt: ast.stmt, src: str, is_pkg: bool, known: set[str]) -> list[str]:
    """Resolve one import statement to the package-internal modules it names."""
    if isinstance(stmt, ast.Import):
        return sorted({a.name for a in stmt.names if a.name in known})
    assert isinstance(stmt, ast.ImportFrom)
    if stmt.level == 0:
        base = stmt.module or ""
    else:  # resolve relative to the importing module's package
        pkg_parts = src.split(".") if is_pkg else src.split(".")[:-1]
        pkg_parts = pkg_parts[: len(pkg_parts) - (stmt.level - 1)]
        base = ".".join(pkg_parts + ([stmt.module] if stmt.module else []))
    if not base:
        return []
    out = set()
    for a in stmt.names:
        sub = f"{base}.{a.name}"
        if sub in known:          # from pkg import submodule
            out.add(sub)
        elif base in known:       # from module import member
            out.add(base)
    return sorted(out)


def sweep_imports(known: set[str]) -> list[dict]:
    """AST sweep of every package file. lazy = never imported at module scope."""
    agg: dict[tuple[str, str], dict] = {}
    for f in sorted(PKG_ROOT.rglob("*.py")):
        rel = f.relative_to(REPO).as_posix()
        src = module_name(rel)
        try:
            tree = ast.parse(f.read_text(), filename=rel)
        except SyntaxError as exc:
            sys.exit(f"error: cannot parse {rel}: {exc}")
        stmts: list[tuple[ast.stmt, bool]] = []
        _walk_imports(tree, False, stmts)
        for stmt, lazy in stmts:
            for dst in _targets(stmt, src, f.name == "__init__.py", known):
                rec = agg.setdefault((src, dst), {"count": 0, "eager": False})
                rec["count"] += 1
                rec["eager"] = rec["eager"] or not lazy
    return [
        {"src": s, "dst": d, "lazy": not rec["eager"], "count": rec["count"]}
        for (s, d), rec in sorted(agg.items())
    ]


# ---------------------------------------------------------------- page checks

def layout_modules(html: str) -> set[str]:
    """Modules the page's hand-tuned STAGES/FOUNDATION layout places."""
    placed: set[str] = set()
    for block in re.findall(r"mods:\s*\[([^\]]*)\]", html):
        placed.update(re.findall(r"'([\w.]+)'", block))
    fnd = re.search(r"const FOUNDATION = \[(.*?)\];", html, re.S)
    if fnd:
        placed.update(re.findall(r"id:\s*'([\w.]+)'", fnd.group(1)))
    return placed


def render_meta(data: dict, stamp: str) -> str:
    nsym = sum(len(m["functions"]) + len(m["classes"]) for m in data["modules"].values())
    nlazy = sum(1 for e in data["imports"] if e["lazy"])
    return (
        '<div class="meta" id="meta">\n'
        f'    <span><b>{len(data["modules"])}</b> modules</span>\n'
        f'    <span><b>{len(data["imports"])}</b> import edges, <b>{nlazy}</b> lazy</span>\n'
        f'    <span><b>{nsym}</b> functions and classes</span>\n'
        f'    <span>generated {stamp}</span>\n'
        "  </div>"
    )


def inject(html: str, data: dict, stamp: str) -> str:
    # \/ is a valid JSON escape; this keeps any "</script>" in a string from
    # terminating the page's script element.
    payload = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    html, n = re.subn(
        r"^const DATA = .*;$",
        lambda _m: f"const DATA = {payload};",
        html, count=1, flags=re.M,
    )
    if n != 1:
        sys.exit("error: no 'const DATA = ...;' line found in the page")
    html, n = re.subn(
        r'<div class="meta" id="meta">.*?</div>',
        lambda _m: render_meta(data, stamp),
        html, count=1, flags=re.S,
    )
    if n != 1:
        sys.exit('error: no <div class="meta" id="meta"> block found in the page')
    return html


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the page no longer matches the index")
    ap.add_argument("--db", type=Path, default=DB_PATH)
    ap.add_argument("--page", type=Path, default=PAGE_PATH)
    args = ap.parse_args()

    if not args.db.exists():
        sys.exit(f"error: {args.db} not found - run `codegraph init` first")
    html = args.page.read_text()

    con = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    try:
        modules = extract_modules(con)
        extract_symbols(con, modules)
        calls = extract_calls(con)
        indexed_pairs = db_import_pairs(con)
    finally:
        con.close()

    imports = sweep_imports(set(modules))
    data = {"modules": modules, "imports": imports, "calls": calls}

    # The index and the sweep should agree on module-level imports; a gap
    # usually means the watcher has not caught up with a fresh edit yet.
    swept_pairs = {(e["src"], e["dst"]) for e in imports}
    for pair in sorted(indexed_pairs - swept_pairs):
        print(f"note: index has {pair[0]} -> {pair[1]} but the source sweep does not"
              " (stale index?)", file=sys.stderr)

    placed = layout_modules(html)
    missing = sorted(set(modules) - placed)
    if missing:
        sys.exit(
            "error: new modules are not placed in the page layout: "
            + ", ".join(missing)
            + "\nAdd each to STAGES or FOUNDATION in architecture.html, then re-run."
        )
    for orphan in sorted(placed - set(modules)):
        print(f"note: layout places {orphan} but the package no longer has it;"
              " remove it from STAGES/FOUNDATION.", file=sys.stderr)

    if args.check:
        # Reuse the page's existing stamp so --check flags content drift only.
        m = re.search(r"<span>generated ([^<]+)</span>", html)
        stamp = m.group(1) if m else ""
    else:
        stamp = f"{_dt.date.today().isoformat()} at v{read_version()}"

    new_html = inject(html, data, stamp)
    if args.check:
        if new_html != html:
            print(f"{args.page.relative_to(REPO)} has drifted from the code graph;"
                  " run scripts/render_codegraph.py to regenerate.", file=sys.stderr)
            return 1
        print("architecture page matches the code graph")
        return 0

    args.page.write_text(new_html)
    nlazy = sum(1 for e in imports if e["lazy"])
    importers = sum(1 for e in imports if e["dst"] == "attestral.model")
    print(f"wrote {args.page.relative_to(REPO)}: {len(modules)} modules, "
          f"{len(imports)} import edges ({nlazy} lazy), {len(calls)} call edges; "
          f"{importers} modules import attestral.model")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
