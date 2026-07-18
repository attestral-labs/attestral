# Declassified information flow (ATL-217 clears, ATL-202 does not)

The same private-data-plus-egress fleet the lethal trifecta flags, with the fix
ATL-202 recommends already applied: the `fetch` tool is constrained to an
allowlist (`--allowed-hosts`), so its outbound reach is a declassifier.

```bash
attestral scan examples/ifc-declassified
```

- **ATL-202 (lethal trifecta) still fires.** The heuristic sees private data
  (`postgres`) and an outbound channel (`fetch`) in one session and flags the
  composition, because a bare capability co-occurrence is all it reasons over.
- **ATL-217 (information-flow lattice) does NOT fire.** The lattice sees that the
  only egress sink is allowlist-declassified, so the confidentiality flow is
  broken; and there is no shell tool, so there is no integrity flow. With no open
  violation, the precise finding clears.

That gap is the point of the lattice. Compare `examples/vulnerable-agent`, whose
`fetch` is unrestricted: there both ATL-202 and ATL-217 fire. Apply the
recommended egress allowlist and the precise finding clears while the heuristic
smoke alarm still sounds - which is exactly how a defensible information-flow
property should behave.

The egress allowlist is detected conservatively (`mcp.py::_egress_allowlisted`,
an egress-scoped allowlist token only), and it does not clear the integrity half:
an allowlisted fetch tool still ingests untrusted content, so a shell tool in the
same fleet would still trip the integrity violation. Detecting an integrity
endorser (input validation, human approval on the sink) is the next step.
