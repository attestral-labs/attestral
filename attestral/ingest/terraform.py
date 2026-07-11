"""Lightweight Terraform (HCL) ingestion.

Deliberately dependency-free: a pragmatic block/attribute scanner, not a full
HCL parser. Good enough to build a design-level model; swap in python-hcl2
later for full fidelity.
"""
from __future__ import annotations

import re
from pathlib import Path

from attestral.model import Component, SystemModel

_RESOURCE_RE = re.compile(r'resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{', re.MULTILINE)
_ATTR_RE = re.compile(r'^\s*([\w]+)\s*=\s*(.+?)\s*$', re.MULTILINE)


def _block_body(text: str, start: int) -> str:
    """Return the text of the brace-balanced block starting at `start` ('{')."""
    depth, i = 0, start
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : i]
        i += 1
    return text[start + 1 :]


def _clean(value: str):
    v = value.strip().rstrip(",")
    if v.startswith('"') and v.endswith('"'):
        return v[1:-1].replace('\\"', '"')
    if v in ("true", "false"):
        return v == "true"
    return v


def ingest_terraform(path: str | Path, model: SystemModel) -> SystemModel:
    p = Path(path)
    files = [p] if p.is_file() else sorted(p.rglob("*.tf"))
    for f in files:
        if _ingest_with_hcl2(f, model):
            continue
        _ingest_with_scanner(f, model)
    return model


# --- full parser (optional extra: pip install "attestral[terraform]") -------

def _unq(v):
    """Normalize python-hcl2 output: strip HCL string quoting, recurse containers."""
    if isinstance(v, str):
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        return v.replace('\\"', '"')
    if isinstance(v, list):
        return [_unq(x) for x in v]
    if isinstance(v, dict):
        return {_unq(k): _unq(x) for k, x in v.items() if k != "__is_block__"}
    return v


def _flatten(attrs: dict, out: dict, cidrs: list) -> None:
    for k, v in attrs.items():
        if isinstance(v, dict):
            _flatten(v, out, cidrs)
        elif isinstance(v, list) and v and isinstance(v[0], dict):
            for block in v:
                _flatten(block, out, cidrs)
        else:
            out[k] = v
            if k == "cidr_blocks" and isinstance(v, list):
                cidrs.extend(str(x) for x in v)


def _ingest_with_hcl2(f: Path, model: SystemModel) -> bool:
    try:
        import hcl2
    except ImportError:
        return False
    try:
        with f.open() as fh:
            data = hcl2.load(fh)
    except Exception:
        return False  # malformed file: let the lenient scanner have a try
    for block in _unq(data).get("resource", []):
        for rtype, instances in block.items():
            for rname, raw in instances.items():
                attrs: dict = {}
                cidrs: list[str] = []
                _flatten(raw if isinstance(raw, dict) else {}, attrs, cidrs)
                if cidrs:
                    attrs["_cidr_blocks"] = cidrs
                model.add(
                    Component(
                        id=f"{rtype}.{rname}",
                        type=rtype,
                        name=rname,
                        source=str(f),
                        attributes=attrs,
                        trust_boundary="cloud",
                    )
                )
    return True


# --- dependency-free fallback scanner ---------------------------------------

def _ingest_with_scanner(f: Path, model: SystemModel) -> None:
    text = f.read_text(errors="ignore")
    for m in _RESOURCE_RE.finditer(text):
        rtype, rname = m.group(1), m.group(2)
        body = _block_body(text, text.index("{", m.end() - 1))
        attrs = {k: _clean(v) for k, v in _ATTR_RE.findall(body)}
        cidrs = re.findall(r'cidr_blocks\s*=\s*\[([^\]]*)\]', body)
        if cidrs:
            attrs["_cidr_blocks"] = re.findall(r'"([^"]+)"', ",".join(cidrs))
        model.add(
            Component(
                id=f"{rtype}.{rname}",
                type=rtype,
                name=rname,
                source=str(f),
                attributes=attrs,
                trust_boundary="cloud",
            )
        )
