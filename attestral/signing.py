"""Sign the evidence chain: from tamper-evident to tamper-evident AND authentic.

The SHA-256 hash chain (`evidence.py`) is tamper-EVIDENT: edit any past finding
and every later hash, and the head, stop matching. But it is not AUTHENTIC.
Whoever holds the JSON can edit a finding, recompute the whole chain and a new
head, and `verify` still says VALID, because integrity only proves the chain is
internally consistent, not that it is the chain a specific reviewer sealed.

This module closes that gap. It signs the chain head with an Ed25519 key inside a
DSSE (Dead Simple Signing Envelope), the same envelope Sigstore and in-toto use.
Now an attacker who edits a finding must not only recompute the chain but also
forge a signature over the new head, which is infeasible without the private key.
The signed envelope binds a named signer to an exact review at an exact head.

Design invariants kept: `cryptography` is an OPTIONAL extra (`attestral[sign]`),
imported lazily inside functions, so a missing install is a clear message, never
an import error, and the rest of the tool works without it. The hash-chain
integrity check still runs with zero dependencies; only the signature step needs
the extra.
"""
from __future__ import annotations

import base64
import json
from typing import Any

# DSSE payload type for an Attestral evidence-chain head.
PAYLOAD_TYPE = "application/vnd.attestral.evidence-chain+json"


def _require_crypto():
    """The Ed25519 primitives, or a clear install hint (never an ImportError)."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "signing needs the crypto extra: pip install \"attestral[sign]\""
        ) from exc
    return ed25519, serialization


def _b64(b: bytes) -> str:
    return base64.standard_b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.standard_b64decode(s.encode("ascii"))


def _pae(payload_type: bytes, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding: what is actually signed, so the type and
    the body cannot be confused or truncated."""
    return b"DSSEv1 %d %s %d %s" % (
        len(payload_type), payload_type, len(payload), payload,
    )


def generate_keypair() -> tuple[str, str]:
    """A fresh Ed25519 keypair as (private_pem, public_pem) PEM strings."""
    ed25519, serialization = _require_crypto()
    key = ed25519.Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private_pem, public_pem


def public_key_of(private_pem: str) -> str:
    ed25519, serialization = _require_crypto()
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _keyid(public_pem: str) -> str:
    import hashlib
    return hashlib.sha256(public_pem.encode()).hexdigest()[:16]


def sign_head(head: str, entries: int, target: str, private_pem: str,
              signer: str = "") -> dict[str, Any]:
    """A DSSE envelope binding `signer` to the review at `head`. The signed
    payload carries the chain head, so the signature is only valid for the exact
    chain that produced it; recomputing a tampered chain yields a different head
    the signature no longer covers."""
    ed25519, serialization = _require_crypto()
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("signing key must be Ed25519")
    payload = json.dumps(
        {"chain_head": head, "entries": entries, "target": target, "signer": signer},
        sort_keys=True,
    ).encode()
    ptype = PAYLOAD_TYPE.encode()
    sig = key.sign(_pae(ptype, payload))
    pub = public_key_of(private_pem)
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": _b64(payload),
        "signatures": [{"keyid": _keyid(pub), "sig": _b64(sig)}],
    }


def verify_envelope(envelope: dict, public_pem: str) -> bool:
    """True when a signature in the envelope verifies against `public_pem`."""
    ed25519, serialization = _require_crypto()
    try:
        pub = serialization.load_pem_public_key(public_pem.encode())
        if not isinstance(pub, ed25519.Ed25519PublicKey):
            return False
        ptype = str(envelope["payloadType"]).encode()
        payload = _unb64(str(envelope["payload"]))
        pae = _pae(ptype, payload)
    except (KeyError, ValueError, TypeError):
        return False
    for s in envelope.get("signatures", []):
        try:
            pub.verify(_unb64(str(s["sig"])), pae)
            return True
        except Exception:
            continue
    return False


def envelope_head(envelope: dict) -> str:
    """The chain head the envelope commits to (for binding it to the report)."""
    try:
        return str(json.loads(_unb64(str(envelope["payload"]))).get("chain_head", ""))
    except (KeyError, ValueError, TypeError):
        return ""
