# broker-bypass-runtime

The runtime half of CB4A TM-11 (broker bypass), and the compile -> drift loop
closed on the credential layer. A GitHub MCP server is fronted by a correctly
configured agentgateway route, so the static scan is clean of broker findings
(no ATL-166/167/221); the design says every call to `github` goes through the
broker.

```
2 components · 1 finding · 1 high
```

(The one static finding is `ATL-105`, the unpinned `npx -y` installer - unrelated
to the broker, left in so the fixture is a realistic config.)

`attestral compile` marks `github` as `broker_required` because the agentgateway
route fronts it. Then `attestral drift` diffs two runtime event streams:

- `runtime-events-benign.jsonl` - `github` called with `brokered: true`: clean.
- `runtime-events-malicious.jsonl` - `github` called with `brokered: false`: the
  call reached the server directly and skipped the broker, so **DRF-011** fires.

This is the runtime complement to the static ATL-221: even a design that looks
brokered can be bypassed at run time, and only diffing the live events against the
attested policy catches it. Fail-closed: an event with no `brokered` field is
unknown telemetry and never fires, exactly as an absent capability does not fire
DRF-008.
