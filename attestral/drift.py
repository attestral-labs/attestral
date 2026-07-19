"""Design-runtime drift detection.

Reads a JSONL stream of tool-call events (mcp-guard telemetry format:
one object per line with at least `server`, `tool`, and optionally
`args`, `url`, `ts`, `capabilities`) and diffs each event against the
compiled policy derived from the attested design.

Fail-closed philosophy carries through: an event that references a server
absent from the attested model is CRITICAL drift - the deployed system has
grown beyond what was reviewed.
"""
from __future__ import annotations

import json
from pathlib import Path

from attestral.manifest import manifest_hash, normalize_tools
from attestral.model import CAPABILITY_CLASSES, Finding, Severity

# The capability vocabulary DRF-008 reasons over, sourced from the model so it
# never drifts from what the ingester can emit. Imported from model (not
# ingest/mcp.py) to keep drift free of the heavy ingest import; a guard test
# asserts the two stay identical so a future vocab change fails closed rather
# than silently disabling the check.
MODELED_CAPABILITIES = CAPABILITY_CLASSES

DRIFT_RULES = {
    "DRF-001": ("Unattested server observed at runtime", Severity.CRITICAL),
    "DRF-002": ("Denied server invoked at runtime", Severity.CRITICAL),
    "DRF-003": ("Filesystem access outside attested roots", Severity.HIGH),
    "DRF-004": ("Non-TLS transport observed for TLS-constrained server", Severity.HIGH),
    "DRF-005": ("Tool manifest changed since attestation (rug-pull)", Severity.CRITICAL),
    "DRF-006": ("Runaway tool-call loop (resource drain)", Severity.HIGH),
    "DRF-007": ("Server call volume exceeds attested budget", Severity.MEDIUM),
    "DRF-008": ("Unauthorized runtime capability / process spawn", Severity.CRITICAL),
}


def _mk(rule: str, server: str, detail: str, event_no: int) -> Finding:
    title, sev = DRIFT_RULES[rule]
    return Finding(
        rule_id=rule,
        title=title,
        severity=sev,
        component_id=f"mcp_server.{server}",
        description=(f"Event #{event_no}: {detail}" if event_no else detail),
        recommendation=(
            "Either revert the runtime change, or update the design, re-run the "
            "review, and re-compile the policy so deployment and review match."
        ),
        source="runtime-telemetry",
        origin="deterministic",
    )


def _path_in_roots(path: str, roots: list[str]) -> bool:
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def _observed_manifest(ev: dict) -> str:
    """The server manifest hash carried by an event: a precomputed
    `manifest_sha256`, or a `manifest` object re-hashed with the same
    canonicalization used at scan time. Empty string when the event carries
    neither."""
    if ev.get("manifest_sha256"):
        return str(ev["manifest_sha256"])
    if isinstance(ev.get("manifest"), dict):
        m = ev["manifest"]
        return manifest_hash(
            m.get("command", ""), m.get("args"), m.get("url", ""),
            normalize_tools(m.get("tools")),
        )
    return ""


def _per_event(servers: dict, ev: dict, event_no: int) -> list[Finding]:
    """The stateless per-event drift checks (DRF-001..005, DRF-008) for one event.
    Shared by the batch detector and the streaming monitor."""
    name = str(ev.get("server", ""))
    entry = servers.get(name)
    if entry is None:
        return [_mk("DRF-001", name, f"server '{name}' is not in the attested design", event_no)]
    if not entry.get("allow", False):
        return [_mk("DRF-002", name, entry.get("reason", "denied by policy"), event_no)]

    out: list[Finding] = []
    constraints = entry.get("constraints", {})
    roots = constraints.get("root_paths")
    if roots:
        for arg in [str(a) for a in ev.get("args", []) if str(a).startswith(("/", "~"))]:
            if not _path_in_roots(arg, roots):
                out.append(_mk("DRF-003", name, f"path '{arg}' outside attested roots {roots}", event_no))
    if constraints.get("transport") == "tls_only" and str(ev.get("url", "")).startswith("http://"):
        out.append(_mk("DRF-004", name, f"plaintext url '{ev.get('url')}'", event_no))

    attested = entry.get("manifest_sha256")
    if attested:
        observed = _observed_manifest(ev)
        if observed and observed != attested:
            out.append(_mk(
                "DRF-005", name,
                f"observed manifest {observed[:16]}… != attested {attested[:16]}… "
                "- the tool surface changed after review",
                event_no,
            ))

    # DRF-008 - an attested, allowed server exercised a capability at runtime
    # that its attested envelope never authorized (the opaque-wrapper case: a
    # launcher that declares no shell capability but spawns a child process). We
    # are past the DRF-001/002 early returns, so this only ever runs for an
    # attested + allowed server. Fail-closed and precise:
    #   * `is not None`, NOT truthiness: an empty attested list [] is a KNOWN
    #     envelope (fires on any out-of-set capability - the bare `uvx toolrunner`
    #     case); an ABSENT `capabilities` key is an UNKNOWN envelope (legacy or
    #     hand-written policy) that must never fire.
    #   * only a MODELED, positively-observed token counts; an unknown label
    #     ("process", a typo) or missing telemetry never fires.
    # One finding per distinct out-of-envelope token. Orthogonal to DRF-003,
    # which scopes an already-granted filesystem capability to roots; DRF-008
    # catches a capability CLASS the envelope never contained at all.
    attested_caps = entry.get("capabilities")
    if attested_caps is not None:
        attested_set = set(attested_caps)
        observed_caps = ev.get("capabilities") or []
        if isinstance(observed_caps, str):
            observed_caps = [observed_caps]
        # Deduplicate deterministically so a token observed twice in one event is
        # one finding per distinct out-of-envelope capability, not one per mention.
        for cap in sorted(set(observed_caps)):
            if cap in MODELED_CAPABILITIES and cap not in attested_set:
                out.append(_mk(
                    "DRF-008", name,
                    f"exercised capability '{cap}' outside its attested envelope "
                    f"{sorted(attested_set)} - the running server did something the "
                    "reviewed design never authorized",
                    event_no,
                ))
    return out


def detect_drift(policy: dict, events: list[dict]) -> list[Finding]:
    servers: dict[str, dict] = policy.get("servers", {})
    findings: list[Finding] = []
    for i, ev in enumerate(events, 1):
        findings.extend(_per_event(servers, ev, i))
    findings.extend(_budget_drift(policy, events))
    findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return findings


class DriftMonitor:
    """Continuous, stateful drift detection: feed it one runtime event at a time
    (a live mcp-guard telemetry pipe, or a tailed log) and it returns only the
    NEW drift that event triggers. This is what turns point-in-time drift into a
    running sidecar - the same review, checked at every invocation.

    Stateful across the stream so budgets and rug-pulls fire once at the moment
    they cross, not on every subsequent event:
      * DRF-006 - a consecutive run of the identical call reaching the loop
        budget fires once for that run.
      * DRF-007 - a server crossing its call-volume budget fires once.
      * DRF-005 - a rug-pull fires each time the served manifest changes to a
        new value, so a served-schema flip is caught the moment it happens.
    """

    def __init__(self, policy: dict) -> None:
        self.servers: dict[str, dict] = policy.get("servers", {})
        budgets = policy.get("budgets") or {}
        self._loop_threshold = _int_budget(budgets.get("loop_repeat_threshold"), 1)
        self._max_calls = _int_budget(budgets.get("max_calls_per_server"), 0)
        self._event_no = 0
        # DRF-006 consecutive-run state
        self._run_sig: str | None = None
        self._run_count = 0
        self._run_emitted = False
        # DRF-007 volume state
        self._counts: dict[str, int] = {}
        self._over_emitted: set[str] = set()
        # DRF-005 last-seen manifest per server
        self._manifest_seen: dict[str, str] = {}

    def observe(self, ev: dict) -> list[Finding]:
        """Return the new drift findings this single event triggers."""
        self._event_no += 1
        i = self._event_no
        # Streaming DRF-005 is change-detected below (fire once per new manifest),
        # so drop the per-event one and re-derive with throttling.
        out = [f for f in _per_event(self.servers, ev, i) if f.rule_id != "DRF-005"]

        name = str(ev.get("server", ""))
        entry = self.servers.get(name)
        allowed = bool(entry and entry.get("allow", False))

        # DRF-005: a rug-pull fires the moment the served manifest changes to a
        # value that differs from the attested pin (and from the last one seen).
        attested = entry.get("manifest_sha256") if entry else None
        if allowed and attested:
            observed = _observed_manifest(ev)
            if observed and observed != attested and self._manifest_seen.get(name) != observed:
                self._manifest_seen[name] = observed
                out.append(_mk(
                    "DRF-005", name,
                    f"observed manifest {observed[:16]}… != attested {attested[:16]}… "
                    "- the tool surface changed after review",
                    i,
                ))

        # DRF-006: identical call repeated consecutively past the loop budget.
        if self._loop_threshold:
            sig = _call_signature(ev)
            if sig == self._run_sig:
                self._run_count += 1
            else:
                self._run_sig, self._run_count, self._run_emitted = sig, 1, False
            if self._run_count >= self._loop_threshold and not self._run_emitted:
                self._run_emitted = True
                out.append(_mk(
                    "DRF-006", name,
                    f"tool '{ev.get('tool', '')}' called {self._run_count} times in a row "
                    f"with identical arguments (threshold {self._loop_threshold}) - runaway loop",
                    i,
                ))

        # DRF-007: per-server call volume crossing the budget, once.
        if self._max_calls is not None and allowed:
            self._counts[name] = self._counts.get(name, 0) + 1
            if self._counts[name] > self._max_calls and name not in self._over_emitted:
                self._over_emitted.add(name)
                out.append(_mk(
                    "DRF-007", name,
                    f"{self._counts[name]} calls exceed the attested budget of "
                    f"{self._max_calls} for this server",
                    i,
                ))

        out.sort(key=lambda f: f.severity.rank, reverse=True)
        return out


def _call_signature(ev: dict) -> str:
    """Stable key for one tool call (server + tool + args), so repeats of the
    identical call - a runaway loop - collapse to the same signature."""
    args = json.dumps(ev.get("args", []), sort_keys=True, default=str)
    return f"{ev.get('server', '')}\x00{ev.get('tool', '')}\x00{args}"


def _int_budget(val, minimum: int):
    """Coerce a budget value to an int >= minimum, else None (check disabled).
    Fails CLOSED on garbage - a hand-edited non-numeric budget disables that
    one check rather than crashing the whole drift run."""
    try:
        n = int(val)
    except (TypeError, ValueError):
        return None
    return n if n >= minimum else None


def _consecutive(events: list[dict], keyfn):
    """Yield (first_event, run_length, distinct_signatures, first_index) for each
    maximal run of CONSECUTIVE events sharing keyfn(event). Only adjacency counts,
    so benign identical calls spaced across the session don't accumulate."""
    runs = []
    key = None
    count = 0
    sigs: set = set()
    first = None
    start = 0
    for i, ev in enumerate(events, 1):
        k = keyfn(ev)
        if k == key:
            count += 1
            sigs.add(_call_signature(ev))
        else:
            if count:
                runs.append((first, count, len(sigs), start))
            key, count, sigs, first, start = k, 1, {_call_signature(ev)}, ev, i
    if count:
        runs.append((first, count, len(sigs), start))
    return runs


def _budget_drift(policy: dict, events: list[dict]) -> list[Finding]:
    """Resource-drain / DoS checks (R7): runaway loops (DRF-006) and per-server
    call-volume overruns (DRF-007), enforced against the policy's budgets block.
    Aggregate over the whole event stream, so they run once, not per event."""
    budgets = policy.get("budgets") or {}
    loop_threshold = _int_budget(budgets.get("loop_repeat_threshold"), 1)
    max_calls = _int_budget(budgets.get("max_calls_per_server"), 0)
    out: list[Finding] = []

    # DRF-006 - a runaway loop is a CONSECUTIVE run: identical (server,tool,args)
    # past loop_threshold, OR the same (server,tool) with VARYING arguments
    # (e.g. page=1,2,3...) past 2x the threshold so that stays low-noise.
    if loop_threshold:
        for ev, count, _sigs, idx in _consecutive(events, _call_signature):
            if count >= loop_threshold:
                out.append(_mk(
                    "DRF-006", str(ev.get("server", "")),
                    f"tool '{ev.get('tool', '')}' called {count} times in a row with "
                    f"identical arguments (threshold {loop_threshold}) - runaway loop",
                    idx,
                ))
        for ev, count, distinct, idx in _consecutive(
            events, lambda e: (str(e.get("server", "")), str(e.get("tool", "")))
        ):
            if distinct > 1 and count >= 2 * loop_threshold:
                out.append(_mk(
                    "DRF-006", str(ev.get("server", "")),
                    f"tool '{ev.get('tool', '')}' called {count} times in a row with "
                    f"varying arguments (threshold {2 * loop_threshold}) - runaway loop",
                    idx,
                ))

    # DRF-007 - per-server call volume over budget, only for attested & allowed
    # servers (unattested/denied servers are DRF-001/002's job, not a budget
    # overrun). max_calls == 0 means deny-all and is enforced, not ignored.
    if max_calls is not None:
        servers = policy.get("servers", {})
        per_server: dict[str, int] = {}
        for ev in events:
            name = str(ev.get("server", ""))
            entry = servers.get(name)
            if entry is None or not entry.get("allow", False):
                continue
            per_server[name] = per_server.get(name, 0) + 1
        for server, count in sorted(per_server.items()):
            if count > max_calls:
                out.append(_mk(
                    "DRF-007", server,
                    f"{count} calls exceed the attested budget of {max_calls} for this server",
                    0,
                ))
    return out


def load_events(path: str | Path) -> list[dict]:
    events = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events
