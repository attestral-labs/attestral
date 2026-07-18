# Memory-entry provenance signing (M9)

An agent's long-term memory is a poisoning target. If the agent reads a memory
entry back and treats it as authoritative, then whoever can write to that memory
can steer the agent on a future, unrelated run. The dangerous move is not writing
new content (that is expected); it is **relabelling**: taking content the agent
should treat as untrusted and marking it trusted, so an injected instruction
becomes ground truth.

Attestral's static findings already see the memory *surface*: ATL-112 flags that
a persistent memory store exists, ATL-113 flags a world-writable instruction
file, and ATL-214 flags a flow where untrusted input can be written into memory.
What they cannot see is whether an individual entry's trust label is honest. That
is what this layer adds.

## The record

Each memory entry is a record whose trust label is bound to its content by the
writer's signature. The signature (Ed25519, inside the same DSSE pre-authentication
encoding as the M5 evidence-chain signature) covers the entry's `id`, `content`,
`trust_label`, and `writer`. An entry on disk is one JSON line:

```json
{"id": "pref-1", "content": "User prefers metric units.", "trust_label": "trusted",
 "writer": "alice", "keyid": "…", "sig": "…"}
```

Because the label is inside the signed payload, three attacks all break the
signature:

- **Relabel.** Flip `trust_label` from `untrusted` to `trusted`, and the payload
  no longer matches what the writer signed.
- **Edit.** Change `content` under a trusted label, same result.
- **Forge.** Sign with a key that is not a trusted writer's, and it verifies
  against no key in the keyring.

## Auditing a store

```bash
attestral memory verify memory.jsonl --keyring writers.yaml
```

`writers.yaml` maps each trusted writer to a public key (a PEM string, or a path
to a `.pub` file):

```yaml
writers:
  alice: alice.pub
```

Every entry that claims a trusted label must verify against its writer's key.
The audit reports:

| Finding | Severity | Meaning |
|---|---|---|
| `MEM-001` | critical | The signature does not cover the stored content and label: the entry was edited or relabelled after signing. |
| `MEM-002` | high | The entry is signed by a writer who is not in the trusted keyring. |
| `MEM-003` | high | The entry claims a trusted label but carries no signature at all. |

An entry labelled `untrusted` is the safe default and passes silently: it needs
no signature, because nothing is being asserted about it. `--fail-on-untrusted`
exits non-zero on any failure, so the audit runs as a CI or cron gate against a
memory export.

## Authoring signed entries

```bash
attestral sign --gen-key alice                      # one-time: alice.key + alice.pub
attestral memory sign --content "User prefers metric units." \
  --label trusted --writer alice --key alice.key -o memory.jsonl
```

The private key signs; only the public key goes in the keyring. See
`examples/signed-memory/` for a complete store demonstrating each failure mode,
and `examples/signed-memory/generate.py` for how it is produced.

## Scope

This is design-and-artifact-time cryptography: it makes a memory store's trust
claims verifiable by anyone holding the writers' public keys. It does not by
itself enforce that an agent runtime only reads verified entries; that is the
consuming agent's responsibility, the same way the compiled policy is enforced by
the runtime proxy, not by the scanner. What Attestral provides is the signed
record format and the audit that turns a relabelling attempt into a
cryptographic failure instead of a silent success.
