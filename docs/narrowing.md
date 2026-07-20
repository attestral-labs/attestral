# Compile as a narrowing (M7)

`attestral compile` turns a reviewed design into a default-deny mcp-guard policy:
the servers that passed review, each with the constraints the review implies
(TLS-only transport, attested filesystem roots, a forbidden-env-secrets flag, a
pinned tool-manifest hash) and its attested capability set. That is a snapshot.

The question that makes it a *confinement guarantee* rather than a snapshot is:
when the design changes and you compile again, does the new policy stay inside
the envelope the last one defined, or does it grant more? A re-attestation that
silently widens the design - a new server, a tool that gains shell access, a
filesystem root that broadens, a manifest pin that is dropped or changed - is
exactly the kind of drift a review is supposed to catch, at review time, not
after it ships.

```bash
attestral compile ./project -o policy.yaml          # review 1: the baseline
# ... the design changes ...
attestral compile ./project --against policy.yaml   # is this still a narrowing?
```

`--against` compiles the current design and classifies the re-attestation:

- **NARROWING** - every server was removed or tightened (a dropped capability, a
  narrower root set, an added constraint or manifest pin), none widened. Safe: the
  running policy grants no more than what was reviewed.
- **UNCHANGED** - the envelope is identical.
- **EXPANSION** - some server was added, or gained a capability, or loosened a
  constraint, or dropped/changed its manifest pin. The command names each
  expansion and **exits non-zero**, so a CI gate blocks the widening until a human
  re-reviews and re-baselines the policy.

## What "narrowing" means here, honestly

This is a **structural containment check** over the policy envelope
(`attestral/narrowing.py`), not a formal proof. It is fail-closed: anything it
cannot classify as clearly narrower - a new server, a changed manifest, a dropped
constraint - is called an expansion, so a re-attestation never widens the design
without being flagged. It deliberately does not claim more. A full
capability-lattice proof (Progent-style SMT expansion/narrowing) is the future
strengthening; the honest name today is a narrowing *check*, and the guarantee it
gives is: no re-attestation reaches the enforced policy with more ambient
capability than the last reviewed one without failing the gate first.

That is the difference between "compile to a default-deny policy" and "compile to
a policy you can prove faithful to the review across every change" - and it is the
part of the attest-compile-drift loop a linter or a pure-LLM tool has no way to
offer.

## Absolute properties: `compile --verify`

The narrowing check is *relative* - it proves one policy does not widen another.
`compile --verify` is the *absolute* companion: it proves security properties of
a single compiled policy, the questions a reviewer asks of any allow-list.

```bash
attestral compile ./project -o policy.yaml --verify
```

Four properties are checked over the allowed set, each reported PROVED or
VIOLATED with the exact servers that form the counterexample:

- **no-secret-exfiltration** - no allowed server holding a secret can reach an
  outbound channel (no credential exfiltration).
- **no-code-exec-egress** - no allowed server with code execution can reach an
  outbound channel (no command-and-control).
- **default-deny** - anything not attested is denied.
- **remote-allows-are-tls** - every allowed server is TLS-constrained, never
  plain http.

Because a property is proved over the *allowed* set, denying the offending
server is always a way to make a violated property hold - so a shell server
denied by review turns "no command-and-control" from a hope into a proved
property. `--fail-on-violation` gates CI. The evaluation is structural and
zero-dependency today (`attestral/policy_verify.py`); the Cedar target
(`compile --target cedar`) has an SMT-backed analyzer that can prove the same
properties formally, and `cedar_analyzer_available()` reports when it is
installed. The shipped method is always labelled, so a structural check is never
mistaken for a formal proof - the same honesty the narrowing check keeps.
