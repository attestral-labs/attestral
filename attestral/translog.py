"""Append-only transparency log for conformance attestations (issue #79).

The attestation (attest.py) makes "this runtime matches the reviewed design" a
verifiable claim about ONE moment. The transparency log makes it monitorable
over TIME: every attestation is appended as a leaf of an RFC 6962 Merkle tree,
each append records the tree root it produced (a checkpoint per entry), and
`attestral attest --verify --log` proves both that a bundle is IN the log
(inclusion proof) and that the recorded history is internally consistent
(every checkpoint recomputes). A deployment gains an auditable conformance
history: when it attested, what the verdict was, and that nobody quietly
rewrote the record.

Storage is one JSONL file, one entry per line, self-contained and zero-dep:

    {"index": 0, "logged_at": "...", "bundle_sha256": "...",
     "signer": "...", "verdict": "CONFORM", "size": 1, "root": "..."}

`size`/`root` are the checkpoint AFTER that append. Tampering with any past
entry breaks every subsequent recorded root, so a forger must rewrite the
whole suffix - which changes the head root any external witness holds.

Honest scope, stated everywhere it surfaces: a SELF-HOSTED single file proves
append-only internal consistency, not distributed witness. Truncating the log
back to a past checkpoint is undetectable from the file alone; publishing the
head root somewhere you do not control (a commit, a ticket, Sigstore Rekor -
the leaf is a plain SHA-256 of the DSSE bundle, exactly what Rekor logs) is
what makes a rewrite catchable. The inclusion proof is portable for the same
reason: (bundle, index, size, proof, root) verifies with `verify_inclusion`
alone, no log file needed - hand it to an auditor.

RFC 6962 hashing (leaf = H(0x00 || data), node = H(0x01 || l || r)) so the
proofs match what Certificate Transparency / Rekor tooling expects.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def bundle_digest(bundle: dict) -> str:
    """Canonical SHA-256 of an attestation bundle - the leaf datum. Canonical
    JSON (sorted keys, no whitespace) so the same bundle always hashes the
    same regardless of how its file was formatted."""
    payload = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """RFC 6962 split point: the largest power of two strictly less than n."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()  # RFC 6962 empty-tree hash
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return _node(_root(leaves[:k]), _root(leaves[k:]))


def _leaves(entries: list[dict]) -> list[bytes]:
    return [_leaf(str(e.get("bundle_sha256", "")).encode()) for e in entries]


def _audit_path(leaves: list[bytes], index: int) -> list[bytes]:
    """RFC 6962 inclusion path for leaves[index] toward _root(leaves)."""
    if len(leaves) <= 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return _audit_path(leaves[:k], index) + [_root(leaves[k:])]
    return _audit_path(leaves[k:], index - k) + [_root(leaves[:k])]


def inclusion_proof(entries: list[dict], index: int) -> dict:
    """A portable proof that entry `index` is in the log of these entries:
    verifiable by `verify_inclusion` with no access to the log file."""
    leaves = _leaves(entries)
    return {
        "index": index,
        "size": len(entries),
        "proof": [h.hex() for h in _audit_path(leaves, index)],
        "root": _root(leaves).hex(),
    }


def verify_inclusion(bundle_sha256: str, proof: dict) -> bool:
    """Recompute the root from the leaf up the audit path; True iff it lands
    on the proof's root. Fail-closed on any malformed piece."""
    try:
        index, size = int(proof["index"]), int(proof["size"])
        path = [bytes.fromhex(h) for h in proof["proof"]]
        want = bytes.fromhex(proof["root"])
    except (KeyError, TypeError, ValueError):
        return False
    if not (0 <= index < size):
        return False
    # Walk up: at each level the split point tells whether the sibling is on
    # the left or the right - mirror of _audit_path's recursion, iteratively.
    node = _leaf(bundle_sha256.encode())
    fn, sn = index, size
    stack: list[bool] = []  # True = sibling is on the LEFT
    while sn > 1:
        k = _split(sn)
        if fn < k:
            stack.append(False)
            sn = k
        else:
            stack.append(True)
            fn, sn = fn - k, sn - k
    if len(path) != len(stack):
        return False
    for sibling, sibling_is_left in zip(path, reversed(stack)):
        node = _node(sibling, node) if sibling_is_left else _node(node, sibling)
    return node == want


def read_log(path: str | Path) -> list[dict]:
    """Parse the JSONL log. Structural failures raise ValueError with the
    offending line - a log that cannot be parsed must never verify."""
    p = Path(path)
    if not p.exists():
        return []
    entries: list[dict] = []
    for i, line in enumerate(p.read_text().splitlines()):
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"log line {i + 1} is not valid JSON: {exc}") from exc
        if not isinstance(e, dict):
            raise ValueError(f"log line {i + 1} is not an object")
        entries.append(e)
    return entries


def verify_log(entries: list[dict]) -> tuple[bool, list[str]]:
    """Internal-consistency check: indexes are contiguous from 0, and every
    entry's recorded (size, root) checkpoint recomputes from the leaves up to
    that point. Any edit to a past entry breaks every later checkpoint.

    What this deliberately does NOT prove: that the log was never truncated
    back to an earlier checkpoint - the file alone cannot; compare the head
    root against an externally witnessed copy for that."""
    failures: list[str] = []
    leaves: list[bytes] = []
    for i, e in enumerate(entries):
        if e.get("index") != i:
            failures.append(f"entry {i}: index says {e.get('index')}")
        leaves.append(_leaf(str(e.get("bundle_sha256", "")).encode()))
        if e.get("size") != i + 1:
            failures.append(f"entry {i}: checkpoint size says {e.get('size')}")
        if e.get("root") != _root(leaves).hex():
            failures.append(f"entry {i}: recorded root does not recompute")
    return (not failures), failures


def find_entry(entries: list[dict], bundle_sha256: str) -> dict | None:
    """The FIRST entry logging this bundle digest (re-logging the same bundle
    is allowed and each append is its own entry; inclusion cites the first)."""
    for e in entries:
        if e.get("bundle_sha256") == bundle_sha256:
            return e
    return None


def append_bundle(log_path: str | Path, bundle: dict, logged_at: str) -> dict:
    """Append an attestation bundle to the log and return the new entry.

    Fail-closed on history: the existing log must verify BEFORE anything is
    appended - refusing to extend a tampered record is the whole point. Raises
    ValueError naming the failure otherwise."""
    entries = read_log(log_path)
    ok, failures = verify_log(entries)
    if not ok:
        raise ValueError(
            f"refusing to append to an inconsistent log: {failures[0]}")
    digest = bundle_digest(bundle)
    statement = bundle.get("statement") or {}
    predicate = statement.get("predicate") or {}
    runtime = predicate.get("runtime") or {}
    leaves = _leaves(entries) + [_leaf(digest.encode())]
    entry = {
        "index": len(entries),
        "logged_at": logged_at,
        "bundle_sha256": digest,
        "signer": predicate.get("signer", ""),
        "verdict": runtime.get("verdict") or "",
        "size": len(leaves),
        "root": _root(leaves).hex(),
    }
    with Path(log_path).open("a") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry
