"""Signed memory provenance: bind a memory entry's trust label to its content.

An agent's long-term memory is a poisoning target. The classic attack is
relabelling: an entry the agent should treat as untrusted gets marked trusted
(or an attacker inserts an entry claiming a trusted writer), so injected content
becomes authoritative on a future, unrelated run. The static findings see the
memory *surface* - ATL-112 (a memory store exists), ATL-113 (a world-writable
instruction file), ATL-214 (an untrusted-input-to-memory flow). This makes each
*entry* cryptographically accountable.

Each entry's trust label is part of a canonical record covered by the writer's
Ed25519 signature, using the same DSSE pre-authentication encoding as the M5
evidence-chain signature (`signing.py`). Flip the label, edit the content, or
forge a writer, and the signature stops verifying. `audit_store` checks a memory
store against a keyring of trusted writers and reports every entry that is
tampered, relabelled, signed by an unknown writer, or claims trust without proof.

`cryptography` stays an optional extra (`attestral[sign]`), imported lazily via
the signing module, so a missing install is a clear message, never an import
error.
"""
from __future__ import annotations

import json
from pathlib import Path

from attestral.model import Finding, Severity
from attestral.signing import _b64, _keyid, _pae, _unb64, public_key_of, _require_crypto

# DSSE payload type for a signed memory entry.
PAYLOAD_TYPE = "application/vnd.attestral.memory-entry+json"

# Labels that assert the entry is safe for the agent to act on as authoritative.
# Only these need to prove themselves; an entry labelled untrusted is already
# treated as untrusted, so it needs no signature.
TRUSTED_LABELS = ("trusted", "system")

# The entry fields the signature covers. Everything an attacker would flip to
# poison memory (the label) or swap under a trusted label (the content, the
# claimed writer) is inside the signed payload.
_COVERED = ("id", "content", "trust_label", "writer")


def _covered_payload(entry: dict) -> bytes:
    """Canonical JSON of the signed fields, so a byte-identical record is signed
    and verified regardless of key order or extra fields on the entry."""
    return json.dumps(
        {k: str(entry.get(k, "")) for k in _COVERED}, sort_keys=True, separators=(",", ":")
    ).encode()


def sign_entry(
    content: str, trust_label: str, writer: str, private_pem: str, entry_id: str = ""
) -> dict:
    """A memory entry with an Ed25519 signature over its covered fields. The
    returned dict is the on-disk record (one JSONL line)."""
    ed25519, serialization = _require_crypto()
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("signing key must be Ed25519")
    entry = {"id": entry_id, "content": content, "trust_label": trust_label, "writer": writer}
    sig = key.sign(_pae(PAYLOAD_TYPE.encode(), _covered_payload(entry)))
    entry["keyid"] = _keyid(public_key_of(private_pem))
    entry["sig"] = _b64(sig)
    return entry


def verify_entry(entry: dict, public_pem: str) -> bool:
    """True when the entry's signature verifies against `public_pem` - i.e. the
    covered fields are exactly what this key signed. A flipped label or edited
    content yields a payload the signature no longer covers."""
    ed25519, serialization = _require_crypto()
    sig = entry.get("sig")
    if not sig:
        return False
    try:
        pub = serialization.load_pem_public_key(public_pem.encode())
        if not isinstance(pub, ed25519.Ed25519PublicKey):
            return False
        pub.verify(_unb64(str(sig)), _pae(PAYLOAD_TYPE.encode(), _covered_payload(entry)))
        return True
    except Exception:
        return False


def load_store(path: str | Path) -> list[dict]:
    """A memory store as a list of entry dicts (JSONL, one entry per line)."""
    entries = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line:
            entries.append(json.loads(line))
    return entries


def load_keyring(path: str | Path) -> dict[str, str]:
    """Trusted writers as {writer: public_pem}. YAML mapping a writer name to a
    PEM string or a path to a `.pub` file, resolved relative to the keyring."""
    import yaml
    p = Path(path)
    data = yaml.safe_load(p.read_text()) or {}
    keyring: dict[str, str] = {}
    for writer, val in (data.get("writers") or {}).items():
        val = str(val)
        if "BEGIN PUBLIC KEY" in val:
            keyring[str(writer)] = val
        else:                                   # a path to a .pub file
            keyring[str(writer)] = (p.parent / val).read_text()
    return keyring


def _finding(rule_id: str, title: str, severity: Severity, entry: dict, detail: str) -> Finding:
    return Finding(
        rule_id=rule_id, title=title, severity=severity,
        component_id=f"memory_entry.{entry.get('id') or '?'}",
        description=detail,
        recommendation="Treat this entry as untrusted. A trusted label must be a "
                       "signature by a keyring writer over the exact content, not a "
                       "field an attacker can flip.",
        source="memory store", origin="deterministic",
    )


def audit_store(entries: list[dict], keyring: dict[str, str]) -> list[Finding]:
    """Findings for every entry that claims trust it cannot prove. A trusted-label
    entry must verify against its writer's key in the keyring; anything else is a
    poisoning signal. Untrusted-label entries are ignored - they are already
    treated as untrusted, which is the safe default."""
    findings: list[Finding] = []
    for entry in entries:
        label = str(entry.get("trust_label", "")).lower()
        if label not in TRUSTED_LABELS:
            continue                            # correctly untrusted, nothing to prove
        writer = str(entry.get("writer", ""))
        if not entry.get("sig"):
            findings.append(_finding(
                "MEM-003", "Memory entry claims trust without a signature", Severity.HIGH,
                entry, f"entry claims trust_label '{label}' but carries no signature",
            ))
            continue
        pub = keyring.get(writer)
        if pub is None:
            findings.append(_finding(
                "MEM-002", "Memory entry signed by an unknown writer", Severity.HIGH,
                entry, f"writer '{writer}' is not in the trusted keyring",
            ))
            continue
        if not verify_entry(entry, pub):
            findings.append(_finding(
                "MEM-001", "Memory entry tampered or relabelled after signing", Severity.CRITICAL,
                entry, f"signature by '{writer}' does not cover the stored content and "
                       f"label '{label}' - the entry was edited or relabelled",
            ))
    return findings
