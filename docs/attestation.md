# Verifiable conformance attestation

`attestral attest` is the capstone of the loop. A `scan` produces a reviewed
design, `compile` turns it into runtime policy, and `drift` diffs runtime events
against that policy. On their own, each is a live artifact you have to trust the
tool to have produced honestly. `attest` makes "the running system conforms to
the reviewed design" a claim a **third party can verify offline**, without
trusting the runtime or the scanner.

```bash
# Produce a signed attestation binding the design, both policies, and the runtime
attestral attest ./my-project --runtime events.jsonl \
    --gen-key demo --signer "Ada L" -o attestation.json

# Verify it offline: recompute every digest, re-run drift, check the signature
attestral attest --verify ./my-project --runtime events.jsonl \
    --public-key demo.pub -o attestation.json
```

## Honest framing

This is a **tamper-evident, signature-based conformance attestation, not a formal
or mathematical proof of security** - the same class of artifact as
[SLSA's Verification Summary Attestation](https://slsa.dev/spec/v1.0/verification_summary).
It proves exactly one thing: the runtime observed matches the design that was
reviewed and the policies compiled from it. It does **not** prove the design is
safe, the rule pack is complete, or that no vulnerability exists; a clean
attestation over a weak design is still a weak design. Conformance is
correspondence, not soundness.

The novel contribution is that a third party - an auditor, a platform, another
agent - can verify offline, without trusting the runtime or the scanner, that the
running system is the one reviewed and that drift (including DRF-008) either did
not occur or is recorded honestly in the signed verdict. The honest ceiling is
"matches the reviewed design," never "is secure."

## The bundle shape

The on-disk bundle is `{"statement": <in-toto Statement>, "envelope": <DSSE
envelope>}`. The statement is an
[in-toto Statement v1](https://in-toto.io/Statement/v1); the envelope is a DSSE
envelope (the same envelope Sigstore and in-toto use) signing the canonicalized
statement with Ed25519. When produced with no key, `envelope` is `null` and only
the recomputable digests are bound - the zero-dependency graceful degrade.

```json
{
  "statement": {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [{ "name": "<scanned PATH>", "digest": { "sha256": "<model_hash>" } }],
    "predicateType": "https://attestral.dev/attestation/conformance/v1",
    "predicate": {
      "reviewChainHead": "<audit_chain head>",
      "findings": {
        "digest": "sha256:<...>",
        "summary": { "critical": 1, "high": 2, "medium": 2, "low": 0, "info": 0, "waived": 0 }
      },
      "policies": {
        "mcpGuard": { "digest": { "sha256": "<...>" } },
        "cedar":    { "digest": { "sha256": "<...>" } }
      },
      "runtime": {
        "events": { "digest": { "sha256": "<...>" }, "count": 5 },
        "verdict": "DRIFT",
        "driftRules": ["DRF-008"],
        "driftFindingsDigest": "sha256:<...>"
      },
      "verifier": { "id": "https://attestral.dev", "version": { "attestral": "<version>" } },
      "signer": "Ada L",
      "generated_at": "<RFC3339 UTC>"
    }
  },
  "envelope": { "payloadType": "application/vnd.in-toto+json", "payload": "<b64>", "signatures": [ ... ] }
}
```

The `runtime` block is present only when `--runtime` is supplied.

## What each bound digest is, and how verify recomputes it

Every digest is recomputed identically by `--verify`, with zero dependencies.
`signer` and `generated_at` are recorded and read, never recomputed, and are
excluded from every digest and every equality check.

| Field | How it is computed | A tamper that breaks it |
|---|---|---|
| `subject[0].digest.sha256` | `sha256(model.to_json())` of the design at PATH | any component, edge, or attribute change |
| `reviewChainHead` | head of `audit_chain(findings)` after `annotate_reachability` | a change that alters findings or their severity |
| `findings.digest` | `sha256` over the **ordered** `[f.to_dict()]` (order is a tamper-evidence invariant) | any finding added, removed, or edited |
| `findings.summary` | severity counts over active findings plus the waived count | a hand-edited summary |
| `policies.mcpGuard` / `policies.cedar` | `sha256` of each rendering, with `metadata.generated_at` blanked | a swapped or hand-edited policy |
| `runtime.events.digest` | `sha256(json.dumps(events, sort_keys=True))` | any doctored, added, or dropped event |
| `runtime.verdict` / `runtime.driftRules` | re-run `detect_drift`; verdict is `CONFORM`/`DRIFT`, rules derived from the finding **set** | a doctored event that flips the drift result |

`--verify` runs the checks in order and reports the **first** failing step,
exiting non-zero on any mismatch:

1. **Statement shape** - `_type` is in-toto Statement v1 and `predicateType` is
   the conformance URI (a wrong or absent URI is a hard fail).
2. **Subject** - recompute the model hash from PATH and compare.
3. **Review chain** - rebuild the chain, run `verify_chain` for internal
   integrity, and compare the head.
4. **Findings** - recompute the digest and summary and compare.
5. **Policies** - recompile both targets, re-digest each, and compare.
6. **Runtime** (only when events are supplied) - recompute the events digest,
   re-run drift, and compare verdict and rule set.
7. **Signature** (only with `--public-key`) - verify the DSSE envelope and that
   its payload is the exact statement on disk. Without a key, integrity and
   recompute still run and authenticity is reported as unproven.

### Why the policy digest blanks `generated_at`

`compile_policy` stamps `metadata.generated_at` with the wall clock, and the
Cedar renderer emits it into the policy text. Hashing the rendered bytes directly
would produce a fresh digest on every run, and a re-verification would falsely
FAIL. Both `attest` and `--verify` call one shared helper, `compile.policy_digest`,
that deep-copies the policy, blanks only `generated_at` (the binding fields
`model_hash` and `review_chain_head` stay, so a swapped design still changes the
digest), renders, and hashes. This is the load-bearing determinism property: two
builds over the same design produce identical policy digests.

## The flagship sequence

The `examples/attested-agent/` fixture is one reproducible scenario: a design a
scan flags on a cross-boundary lethal-trifecta path, a runtime stream that trips
DRF-008, an attestation recording the drift verdict, and a tamper case that fails.

```bash
# 1. Scan flags the cross-boundary path (ATL-202, lethal trifecta)
attestral scan examples/attested-agent/

# 2. Compile both policy targets from the attested design
attestral compile examples/attested-agent/ --target cedar -o attested-policy.cedar
attestral compile examples/attested-agent/ -o mcp-guard-policy.yaml

# 3. Drift: DRF-008 fires on an out-of-envelope shell capability
attestral drift mcp-guard-policy.yaml examples/attested-agent/events.jsonl

# 4. Attest: bind design + both policies + the drift verdict into one signed bundle
attestral attest examples/attested-agent/ \
    --runtime examples/attested-agent/events.jsonl \
    --gen-key demo --signer "demo@attestral.dev" -o attestation.json

# 5. Verify offline (VALID, verdict = DRIFT [DRF-008])
attestral attest --verify examples/attested-agent/ \
    --runtime examples/attested-agent/events.jsonl \
    --public-key demo.pub -o attestation.json
```

The TAMPER case:

```bash
# Drop the DRF-008 event line and re-verify against the unchanged bundle
grep -v run_indexer examples/attested-agent/events.jsonl > tampered.jsonl
attestral attest --verify examples/attested-agent/ \
    --runtime tampered.jsonl --public-key demo.pub -o attestation.json
# attestation FAILED - first failing step: runtime.events
```

Editing the design instead fails at `subject` and `reviewChainHead`; hand-editing
a compiled policy fails at `policies.*`; forging the statement without the private
key fails at `signature`.

## Zero-dependency contract

The statement assembly, every hash recompute, `verify_chain`, and every digest
comparison run with **no dependencies**. Only `sign_statement` and
`verify_envelope` need the optional `attestral[sign]` extra (`cryptography`),
lazy-imported with a clear install hint. `attestral attest` with no `--key` emits
the full unsigned bundle - all digests bound, verifiable for integrity, with
authenticity reported as unproven until a `--public-key` is supplied.

## Transparency log (`--log`)

One attestation proves one moment; the transparency log makes conformance
monitorable over time. `attestral attest PATH --log conformance.log` appends
the bundle to an append-only log: an RFC 6962 Merkle tree (leaf =
`H(0x00 || bundle-sha256)`, node = `H(0x01 || l || r)` - the Certificate
Transparency / Rekor construction) stored as one JSONL file, one entry per
line, each recording the tree root its append produced. A checkpoint per
entry means editing any past entry breaks every later recorded root, and the
log refuses to append to a history that no longer recomputes.

`attestral attest PATH --verify --log conformance.log` then proves three
things after the bundle itself verifies: the log's recorded history is
internally consistent, this bundle is in it, and the inclusion proof
recomputes to the head root. The inclusion proof is portable - `(bundle,
index, size, proof, root)` verifies with `attestral.translog.verify_inclusion`
alone, no log file needed - so an auditor can check one entry without holding
the whole record.

The honest boundary, printed in the CLI output: a self-hosted single file
proves append-only internal consistency, **not distributed witness**.
Truncating the log back to an earlier checkpoint is undetectable from the
file alone. Publish the head root somewhere you do not control - a commit, a
ticket, Sigstore Rekor (the leaf is a plain SHA-256 of the DSSE bundle,
exactly what Rekor logs) - and a rewrite has an external copy to contradict.
Zero dependencies throughout: hashing is stdlib `hashlib`, and nothing here
needs the `attestral[sign]` extra.
