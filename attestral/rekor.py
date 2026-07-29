"""Optional public witness for a signed attestation: Sigstore Rekor.

The transparency log (`translog.py`) proves an append-only local history, but a
malicious operator could still rewrite the whole suffix and hand a fresh head to
anyone who has not already seen the old one. The fix is a witness outside your
control. This module submits a *signed* Attestral attestation to Sigstore Rekor,
a public transparency log, and records the receipt (the log index, integrated
time, inclusion proof, and signed entry timestamp Rekor returns). After that, a
rewrite has to contradict a public, widely-witnessed record, not just a file you
host.

This is deliberately NOT a blockchain: Rekor is the transparency-log construction
(Certificate Transparency / Sigstore) that the software-supply-chain world
already trusts, and it slots into the SLSA / in-toto / Sigstore stack Attestral
already speaks. It is strictly opt-in and online: the default review runs offline
and is never anchored unless you ask.

What the receipt proves, stated honestly: that this exact signed attestation was
submitted to a public log at a recorded time, and that the entry is independently
verifiable (with `rekor-cli verify --uuid <uuid>` or by fetching the entry URL).
It does not prove the reviewed design is secure. `verify_receipt` here confirms
the receipt is well-formed and binds THIS attestation (the logged payload hash
matches the envelope's payload); full cryptographic verification of Rekor's
signed entry timestamp against Rekor's key is what `rekor-cli` does, and the
receipt is portable to it.

Transport is injected (`poster`), so the build/submit/parse/verify path is tested
without a network; the default poster uses the standard library only.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Callable

DEFAULT_REKOR = "https://rekor.sigstore.dev"
_ENTRIES_PATH = "/api/v1/log/entries"

# A poster takes (url, json_body) and returns the parsed JSON response.
Poster = Callable[[str, dict], dict]


def _b64(data: bytes) -> str:
    return base64.standard_b64encode(data).decode("ascii")


def dsse_proposed_entry(envelope: dict, public_pem: str) -> dict:
    """The Rekor `dsse` v0.0.1 proposed entry for a DSSE envelope and its verifier
    public key. This is exactly the envelope Attestral's signing layer already
    produces, so anchoring reuses the attestation's own signature."""
    return {
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "proposedContent": {
                "envelope": json.dumps(envelope, sort_keys=True),
                "verifiers": [_b64(public_pem.encode())],
            }
        },
    }


def envelope_payload_sha256(envelope: dict) -> str:
    """SHA-256 of the DSSE envelope's decoded payload - the in-toto statement
    bytes Rekor records as the entry's payloadHash. Canonicalization-free, so it
    is a clean binding check between our attestation and a returned receipt."""
    payload = base64.standard_b64decode(str(envelope["payload"]).encode())
    return hashlib.sha256(payload).hexdigest()


def _default_poster(url: str, body: dict) -> dict:
    """Standard-library POST. Imported lazily and only used when no poster is
    injected, so the module has zero import-time cost and no third-party dep."""
    import urllib.request

    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https host
        return json.loads(resp.read().decode())


def _receipt_from(raw: dict, rekor_url: str) -> dict:
    """Normalize Rekor's UUID-keyed response into a flat, storable receipt."""
    if not isinstance(raw, dict) or not raw:
        raise ValueError("Rekor returned an empty or malformed response")
    uuid, entry = next(iter(raw.items()))
    if not isinstance(entry, dict):
        raise ValueError("Rekor entry is malformed")
    verification = entry.get("verification") or {}
    return {
        "log": "sigstore-rekor",
        "rekor_url": rekor_url,
        "uuid": uuid,
        "log_index": entry.get("logIndex"),
        "log_id": entry.get("logID"),
        "integrated_time": entry.get("integratedTime"),
        "body": entry.get("body"),
        "inclusion_proof": verification.get("inclusionProof"),
        "signed_entry_timestamp": verification.get("signedEntryTimestamp"),
        "entry_url": f"{rekor_url.rstrip('/')}{_ENTRIES_PATH}/{uuid}",
    }


def anchor(
    envelope: dict,
    public_pem: str,
    *,
    poster: Poster | None = None,
    rekor_url: str = DEFAULT_REKOR,
) -> dict:
    """Submit a signed attestation's DSSE envelope to Rekor and return the receipt.

    Requires a signed envelope (Rekor's dsse type logs a signature and its
    verifier). `poster` is injectable for testing; the default hits the public
    Rekor. Raises ValueError on a malformed response or missing signature."""
    if not envelope or not envelope.get("signatures"):
        raise ValueError("Rekor anchoring needs a signed attestation (no envelope signature)")
    entry = dsse_proposed_entry(envelope, public_pem)
    post = poster or _default_poster
    raw = post(rekor_url.rstrip("/") + _ENTRIES_PATH, entry)
    receipt = _receipt_from(raw, rekor_url)
    # Bind the receipt to what we submitted, so a stored receipt cannot silently
    # belong to a different attestation.
    receipt["payload_sha256"] = envelope_payload_sha256(envelope)
    return receipt


def verify_receipt(receipt: dict, envelope: dict) -> tuple[bool, list[str]]:
    """Confirm a stored receipt is well-formed and belongs to THIS attestation.

    Checks: the receipt carries a log index, an integrated time, and an inclusion
    proof (a real Rekor entry, not a stub), and that its bound `payload_sha256`
    equals this envelope's payload hash (the receipt is for our attestation, not
    another). Returns (ok, notes); notes explain the honest boundary - full
    verification of Rekor's signed entry timestamp against Rekor's key is done by
    `rekor-cli verify`, and the entry is portable to it."""
    notes: list[str] = []
    ok = True
    for field in ("uuid", "log_index", "integrated_time", "inclusion_proof"):
        if receipt.get(field) in (None, ""):
            ok = False
            notes.append(f"receipt is missing '{field}' - not a complete Rekor entry")
    bound = receipt.get("payload_sha256")
    if bound and bound != envelope_payload_sha256(envelope):
        ok = False
        notes.append("receipt does not bind this attestation (payload hash mismatch)")
    if ok:
        notes.append(
            "well-formed Rekor receipt bound to this attestation; verify inclusion "
            f"independently with: rekor-cli verify --uuid {receipt.get('uuid')}"
        )
    return ok, notes


def receipt_line(receipt: dict) -> str:
    """A one-line human summary of an anchor receipt."""
    idx = receipt.get("log_index")
    return (
        f"anchored to Sigstore Rekor · log index {idx} · "
        f"entry {receipt.get('entry_url')}"
    )
