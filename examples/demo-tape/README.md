# The demo tapes: the inputs, so you can run them yourself

The two tapes on the [demo page](https://attestral.vercel.app/demo.html) are
byte-verified recordings of real tool output over the files in this directory.
This fixture makes them reproducible: same inputs, same commands, same output.

`mcp.json` is the remediated config from tape one (the original, with the
lethal trifecta, ships as `examples/first-run`). It scans clean:

```bash
attestral scan examples/demo-tape
```

```
3 components · 0 findings
```

`runtime-events.jsonl` is the constructed telemetry stream both tapes run on:
five ordinary tool calls and then the three that diverge from the attested
design - a rug-pulled github tool surface, a read of `~/.ssh/id_ed25519`
outside the attested root, and the removed `fetch` server quietly reappearing.

## Tape 001, scene seven: the drift catch

```bash
cd examples/demo-tape
attestral compile .
attestral drift --remediate mcp-guard-policy.yaml runtime-events.jsonl
```

Three findings (DRF-005 rug-pull, DRF-001 unattested server, DRF-003 outside
attested roots) and a proposed quarantine that only ever narrows.

## Tape 002: the incident, end to end

```bash
attestral drift --stdin --lockdown --enforce live-policy.yaml \
    mcp-guard-policy.yaml < runtime-events.jsonl        # containment, journaled
attestral drift --replay --journal live-policy.yaml.journal.jsonl \
    mcp-guard-policy.yaml runtime-events.jsonl          # the forensic timeline
attestral incident --gen-key incident-key --journal live-policy.yaml.journal.jsonl \
    mcp-guard-policy.yaml runtime-events.jsonl -o incident.json
attestral incident --verify --public-key incident-key.pub \
    --journal live-policy.yaml.journal.jsonl \
    mcp-guard-policy.yaml runtime-events.jsonl -o incident.json
```

Edit one byte of `runtime-events.jsonl` and the last command fails, naming the
failing step. That is the tamper test the tape ends on.

`tests/test_demo_tape.py` pins all of this - the clean scan, the three drift
findings, and the sign/verify/tamper round trip - so the published recording
can never drift from what the tool actually does.
