"""Design-runtime drift detection.

Reads a JSONL stream of tool-call events (mcp-guard telemetry format:
one object per line with at least `server`, `tool`, and optionally
`args`, `url`, `ts`, `capabilities`, and the SEP-2567 handle fields
`handle` + `handle_op`) and diffs each event against the compiled
policy derived from the attested design.

Fail-closed philosophy carries through: an event that references a server
absent from the attested model is CRITICAL drift - the deployed system has
grown beyond what was reviewed.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from attestral.manifest import manifest_hash, normalize_tools
from attestral.model import (CAPABILITY_CLASSES, Finding, Severity,
                             capabilities_outside_envelope)

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
    "DRF-009": ("Portable handle replayed by a different principal", Severity.CRITICAL),
    "DRF-010": ("Portable handle spent with unknown provenance", Severity.HIGH),
    "DRF-011": ("Credential-brokered server reached without the broker (bypass)", Severity.CRITICAL),
    "DRF-012": ("Standing credential still present in the server's runtime environment", Severity.HIGH),
}

# The concrete fix for the handle findings (DRF-009/010). MCP SEP-2567/2575
# ("stateless core") makes servers mint portable task/resource handles that
# travel in conversation text, so a handle IS a bearer credential: any
# principal that sees it can spend it.
_HANDLE_FIX = (
    "Revoke the handle and rotate any session transcript that carried it, then "
    "bind handle spends to the minting principal at the guard so a leaked "
    "handle is inert (MCP SEP-2567 handles are bearer credentials)."
)


def _mk(rule: str, server: str, detail: str, event_no: int,
        recommendation: str | None = None) -> Finding:
    title, sev = DRIFT_RULES[rule]
    return Finding(
        rule_id=rule,
        title=title,
        severity=sev,
        component_id=f"mcp_server.{server}",
        description=(f"Event #{event_no}: {detail}" if event_no else detail),
        recommendation=recommendation or (
            "Either revert the runtime change, or update the design, re-run the "
            "review, and re-compile the policy so deployment and review match."
        ),
        source="runtime-telemetry",
        origin="deterministic",
    )


def _handle_display(handle: str) -> str:
    """Truncate a handle for display: a finding must never re-publish a
    spendable bearer credential in full."""
    return handle if len(handle) <= 12 else handle[:12] + "…"


def _handle_replay(minted: dict, ev: dict, event_no: int) -> list[Finding]:
    """Stateful handle-provenance check for one event, updating `minted`
    (handle -> (minter server, mint event #)). Shared by the batch detector
    and the streaming monitor.

    MCP SEP-2567/2575 ("stateless core") mints portable task/resource handles
    that travel in conversation text; a handle in text is a bearer credential
    any principal that sees it can spend. Two drift classes:
      * DRF-009 - a spend whose principal (the event's `server` identity, the
        same field every other drift check keys on) differs from the handle's
        minter: a replay/confused-deputy in progress.
      * DRF-010 - a spend of a handle never seen minted in this log: unknown
        provenance, possibly replayed from another session's transcript.

    Fail-closed, in the DRF-008 style (only a positively-observed, well-formed
    signal counts):
      * only a non-empty string `handle` with `handle_op` exactly "mint" or
        "spend" participates; anything absent, malformed, or unrecognized is
        ignored - no crash, no spurious finding - so legacy handle-free logs
        behave byte-identically to before these checks existed.
      * first mint wins: a re-mint of a known handle never rewrites its
        provenance, so a thief can't launder a stolen handle by re-minting it
        under their own identity.
      * deliberately policy-independent: provenance is a property of the event
        stream itself, so a replay by an unattested server is still flagged
        (DRF-001 fires separately for the server).

    Double-spend of a single-use handle is deliberately out of scope: neither
    the event schema nor the compiled policy carries a single-use marker, and
    inventing one would be speculative until the SEP lands.
    """
    handle = ev.get("handle")
    op = ev.get("handle_op")
    if not isinstance(handle, str) or not handle or op not in ("mint", "spend"):
        return []
    principal = str(ev.get("server", ""))
    if op == "mint":
        minted.setdefault(handle, (principal, event_no))
        return []
    origin = minted.get(handle)
    if origin is None:
        return [_mk(
            "DRF-010", principal,
            f"handle '{_handle_display(handle)}' spent with no mint observed in "
            "this log - unknown provenance, possibly replayed from another "
            "session's transcript (MCP SEP-2567)",
            event_no, recommendation=_HANDLE_FIX,
        )]
    minter, mint_no = origin
    if minter != principal:
        return [_mk(
            "DRF-009", principal,
            f"handle '{_handle_display(handle)}' minted by '{minter}' (event "
            f"#{mint_no}) was spent by '{principal}' - a portable handle in "
            "conversation text is a bearer credential and this spend crossed "
            "principals (MCP SEP-2567)",
            event_no, recommendation=_HANDLE_FIX,
        )]
    return []


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
        # One finding per distinct out-of-envelope capability. The comparison
        # (str->list normalization, dedup, fail-closed on unknown/malformed) is the
        # shared helper posture's runtime verification also uses, so the two never
        # disagree on the same telemetry.
        for cap in capabilities_outside_envelope(ev.get("capabilities"), attested_caps):
            out.append(_mk(
                "DRF-008", name,
                f"exercised capability '{cap}' outside its attested envelope "
                f"{sorted(set(attested_caps))} - the running server did something the "
                "reviewed design never authorized",
                event_no,
            ))

    # DRF-011 - the runtime half of CB4A TM-11 (broker bypass). The attested
    # design routes this server through a credential broker (compile marked it
    # `broker_required`), but this invocation reports it reached the server
    # WITHOUT the broker, so it used a credential directly and skipped the
    # broker's policy, scoping, and audit. Fail-closed in the DRF-008 style: only
    # an explicit `brokered: false` fires; an ABSENT `brokered` key is unknown
    # telemetry and never fires, exactly as an absent `capabilities` key does.
    if entry.get("broker_required") and ev.get("brokered") is False:
        out.append(_mk(
            "DRF-011", name,
            f"server '{name}' is attested behind a credential broker, but this "
            "call reached it directly (brokered=false) - the broker's auth, "
            "scoping, and audit were bypassed",
            event_no,
        ))

    # DRF-012 - the standing key never actually left (CB4A TM-2's tail risk).
    # The attested design says this server's environment must be credential-free
    # (`broker_required`: the broker carries the traffic; or the
    # `forbid_env_secrets` constraint: the proxy strips at spawn), yet the
    # runtime positively reports standing credential names still present in the
    # server's process env. A broker in front of a still-present raw key is a
    # bypass waiting to happen - ATL-221 sees the static half; this is the
    # runtime half. Fail-closed in the DRF-008 style: only a well-formed,
    # non-empty `env_secrets` list of names fires; an absent key is unknown
    # telemetry, and an empty list is a positively-observed clean environment.
    expects_clean_env = (
        entry.get("broker_required")
        or constraints.get("forbid_env_secrets")
    )
    observed_secrets = ev.get("env_secrets")
    if (expects_clean_env and isinstance(observed_secrets, list)
            and observed_secrets
            and all(isinstance(k, str) for k in observed_secrets)):
        names = ", ".join(sorted(set(observed_secrets)))
        why = ("the broker carries its traffic" if entry.get("broker_required")
               else "the policy strips env secrets at the proxy")
        out.append(_mk(
            "DRF-012", name,
            f"server '{name}' still holds standing credential(s) {names} in its "
            f"runtime environment although {why} - the raw key is pure blast "
            "radius and its theft would never touch the broker's audit",
            event_no,
        ))
    return out


def evaluate_event(policy: dict, event: dict, event_no: int = 1) -> list[Finding]:
    """The stateless per-event verdict for one telemetry event against a policy.

    Public entry to the same `_per_event` checks (DRF-001..005, DRF-008,
    DRF-011/012) the batch detector runs, so an enforcement point (`attestral
    guard`) blocks EXACTLY what the detector would later flag: detection and
    enforcement share one decision function and can never diverge. It omits the
    cross-event checks (handle replay DRF-009/010, budgets DRF-006/007), which
    are only meaningful over a stream, not a single call.
    """
    return _per_event(policy.get("servers", {}), event, event_no)


def detect_drift(policy: dict, events: list[dict]) -> list[Finding]:
    servers: dict[str, dict] = policy.get("servers", {})
    findings: list[Finding] = []
    minted: dict[str, tuple[str, int]] = {}
    for i, ev in enumerate(events, 1):
        findings.extend(_per_event(servers, ev, i))
        findings.extend(_handle_replay(minted, ev, i))
    findings.extend(_budget_drift(policy, events))
    findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return findings


# --- closed-loop remediation: propose the minimal policy-tightening delta -------
#
# Drift means the runtime diverged from the REVIEWED design. Remediation closes
# the loop by synthesizing the narrowing that would have prevented each finding -
# but it PROPOSES, it never auto-applies, and it only ever tightens toward denial.
# Widening the design to match the drift would rubber-stamp the very attack drift
# caught, so a compromised runtime must never be able to drive its own policy.
#
# The load-bearing move is QUARANTINE: set the offending server's allow to false,
# carrying the DRF id as the reason. Constraints, capabilities and the manifest pin
# are KEPT intact - a denied server never reads them (DRF-002 early-returns), so
# keeping them is free and, critically, keeps the verdict a narrowing. Popping them
# (compile.py's deny path does this) reads as "dropped a constraint" = EXPANSION.

# Per-DRF advisory note surfaced to the human alongside the proposed op.
_DRF_NOTES = {
    "DRF-001": "needs re-review to admit the server into the design",
    "DRF-005": "if this was a legitimate upgrade, re-attest the new surface under human review",
    "DRF-006": "blocked, but the alarm persists - a clean clear needs a human budget decision",
    "DRF-009": "revoke the replayed handle and rotate the session that leaked it before re-allowing",
    "DRF-010": "confirm log coverage from session start before trusting handle provenance",
    "DRF-012": "rotate and delete the reported keys - the brokered/stripped path already "
               "carries the traffic, so the standing key is pure blast radius",
}


def _quarantine_reason(rule_id: str, detail: str) -> str:
    return f"quarantine: {rule_id} - {detail}"


def _tighten_for(rule_id: str, name: str, servers: dict, finding: Finding) -> dict | None:
    """Synthesize one per-server tightening op for a single drift finding, mutating
    `servers` (a copy of the policy's server map). Returns the typed op dict, or
    None for a terminal state that needs no change. Default action is QUARANTINE:
    deny the offending server and keep its constraints/capabilities intact."""
    detail = finding.description
    reason = _quarantine_reason(rule_id, detail)
    note = _DRF_NOTES.get(rule_id, "")

    if rule_id == "DRF-002":
        # Already denied - the terminal state every quarantine flips into. Never
        # widen it back to allowed.
        return None

    if rule_id == "DRF-001":
        # The server is absent from the design. Propose a deny-only quarantine
        # entry. A deny-only add grants zero ambient capability, so classify's
        # deny-only-add refinement scores it a narrowing; admitting the server is
        # a human design decision the tool must never take.
        before_allow = None
        servers[name] = {
            "allow": False,
            "reason": reason,
            "capabilities": [],
            "attested_source": "unattested-runtime",
        }
    else:
        entry = servers.get(name)
        if entry is None:
            # A budget/capability finding against a server the policy never
            # carried: quarantine it the same deny-only way as DRF-001.
            before_allow = None
            servers[name] = {"allow": False, "reason": reason, "capabilities": []}
        else:
            before_allow = bool(entry.get("allow", False))
            entry["allow"] = False
            entry["reason"] = reason  # KEEP constraints/capabilities/manifest pin

    return {
        "server": name,
        "drf_id": rule_id,
        "action": "quarantine",
        "before_allow": before_allow,
        "after_allow": False,
        "reason": reason,
        "note": note,
    }


def remediate_drift(policy: dict, findings: list[Finding]) -> tuple[dict, list[dict]]:
    """Given a compiled policy and its drift findings, synthesize the minimal
    policy-tightening delta that would have prevented each finding.

    Returns `(tightened, delta)`: a deep copy of the policy with the offending
    servers quarantined, and the list of typed per-server ops. The original is
    never mutated. Fail-closed: if the synthesized delta ever classifies as an
    EXPANSION of the original, it is refused (raised), so every widening shortcut
    (re-pin a rug-pull, widen a root, admit an unattested server) is rejected by
    the same gate. The result is a PROPOSAL; a human approves and re-compiles.
    """
    from attestral.narrowing import classify

    tightened = copy.deepcopy(policy)
    servers = tightened.setdefault("servers", {})
    delta: list[dict] = []
    for f in findings:
        name = f.component_id.removeprefix("mcp_server.")
        op = _tighten_for(f.rule_id, name, servers, f)
        if op:
            delta.append(op)

    if delta:
        # Provenance: any added metadata key changes policy_digest (which blanks
        # only generated_at), so a re-attest over the tightened policy shows a new
        # hash - correct, the reviewed surface changed.
        tightened.setdefault("metadata", {})["remediation"] = [op["reason"] for op in delta]

    if classify(policy, tightened).is_expansion:
        raise RuntimeError("refusing to emit: synthesized delta widens the policy")
    return tightened, delta


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
        # DRF-009/010 handle provenance ledger (handle -> (minter, event #))
        self._minted: dict[str, tuple[str, int]] = {}

    def observe(self, ev: dict) -> list[Finding]:
        """Return the new drift findings this single event triggers."""
        self._event_no += 1
        i = self._event_no
        # Streaming DRF-005 is change-detected below (fire once per new manifest),
        # so drop the per-event one and re-derive with throttling.
        out = [f for f in _per_event(self.servers, ev, i) if f.rule_id != "DRF-005"]
        # DRF-009/010 are edge-triggered per bad spend, so the batch helper's
        # semantics carry over unchanged - just persist the mint ledger.
        out.extend(_handle_replay(self._minted, ev, i))

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


# --- incident forensics: replay a recorded stream into a reconstruction ----------
#
# `attestral drift --replay` answers the two questions a responder asks after the
# fact: WHEN did the runtime diverge from the attested design, and what contained
# it. It feeds the recorded stream through a fresh DriftMonitor so every finding
# lands at the exact event ordinal (and timestamp, when the telemetry carries one)
# where it crossed, then merges the hash-chained containment journal into the same
# timeline. Forensics is fail-closed REPORTING: a malformed event line, a garbage
# timestamp, or a tampered journal is counted and surfaced as a headline of the
# reconstruction - never raised, never silently dropped.

@dataclass
class Replay:
    """The reconstructed incident: a chronological ``timeline`` of moments (each
    drift finding at the event where it crossed, each containment journal entry
    where it landed) plus honest ``summary`` stats. ``as_dict`` is the JSON
    incident record ``drift --replay -o`` writes."""
    timeline: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"timeline": self.timeline, "summary": self.summary}


def _parse_ts(val) -> datetime | None:
    """Best-effort ISO-8601 parse of an event/journal ``ts``. Returns an aware
    datetime (a naive value is assumed UTC so comparisons never raise), or None
    for absent/garbage input - a bad timestamp degrades the moment to ordinal
    ordering, it never crashes the replay."""
    if not isinstance(val, str) or not val.strip():
        return None
    try:
        dt = datetime.fromisoformat(val.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _journal_verdict(entries: list, malformed_lines: int) -> str:
    """Re-verify the containment journal's hash chain over already-parsed
    entries - the same tamper-evidence contract as ``lockdown.verify_journal``,
    carried into the replay so a doctored journal becomes a HEADLINE of the
    reconstruction rather than an exception. Returns "intact" or
    "TAMPERED: <reason>". Any unparseable line fails closed, exactly as the
    path-based verifier does."""
    from attestral.lockdown import _entry_sha

    if malformed_lines:
        return f"TAMPERED: {malformed_lines} unparseable journal line(s)"
    prev = ""
    for i, e in enumerate(entries, 1):
        if not isinstance(e, dict):
            return f"TAMPERED: entry {i} is not an object"
        if e.get("seq") != i:
            return f"TAMPERED: entry {i}: sequence break (got {e.get('seq')!r})"
        if e.get("prev_sha") != prev:
            return f"TAMPERED: entry {i}: prev_sha mismatch"
        try:
            expected = _entry_sha(e)
        except Exception:
            return f"TAMPERED: entry {i}: unhashable entry"
        if e.get("entry_sha") != expected:
            return f"TAMPERED: entry {i}: entry_sha mismatch"
        prev = e["entry_sha"]
    return "intact"


def replay_drift(policy: dict, events: list, journal_entries: list | None = None, *,
                 malformed_events: int = 0, malformed_journal_lines: int = 0) -> Replay:
    """Reconstruct the incident from a recorded stream (and, optionally, the
    containment journal `--lockdown --enforce` wrote while it happened).

    Every event runs through a fresh :class:`DriftMonitor`, so each finding is
    pinned to the 1-based event ordinal - and the event's ``ts``, when it parses -
    at which it actually crossed (a rug-pull at the manifest flip, a budget at the
    crossing call). Journal entries are matched into the timeline by their ``ts``,
    or appended in seq order after the last event when a timestamp comparison is
    not possible. The journal chain is verified FIRST and the verdict carried in
    the summary: a tampered journal earns no containment credit (the final state
    stays DRIFTED and the gap stats are withheld), but its claimed entries still
    appear in the timeline so the responder sees what the journal asserts."""
    monitor = DriftMonitor(policy)
    drift_moments: list[tuple[int, int, dict]] = []   # (position, emit order, moment)
    event_ts: list[datetime | None] = []              # parsed ts per fed event
    fed = 0
    for ev in events:
        if not isinstance(ev, dict):
            malformed_events += 1
            continue
        fed += 1
        parsed = _parse_ts(ev.get("ts"))
        event_ts.append(parsed)
        ts_str = str(ev["ts"]) if parsed else None
        try:
            new = monitor.observe(ev)
        except Exception:
            # A single hostile event must never kill the reconstruction.
            malformed_events += 1
            continue
        for f in new:
            drift_moments.append((fed, len(drift_moments), {
                "kind": "drift",
                "ordinal": fed,
                "ts": ts_str,
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "server": f.component_id.removeprefix("mcp_server."),
                "title": f.title,
                "detail": f.description.removeprefix(f"Event #{fed}: "),
            }))

    entries = list(journal_entries) if journal_entries is not None else []
    if journal_entries is None and not malformed_journal_lines:
        verdict = "no journal"
    else:
        verdict = _journal_verdict(entries, malformed_journal_lines)
    intact = verdict == "intact"

    contain_moments: list[tuple[int, int, dict]] = []
    have_ts = any(t is not None for t in event_ts)
    for idx, e in enumerate(entries, 1):
        if not isinstance(e, dict):
            continue  # already condemned by the chain verdict
        ets = _parse_ts(e.get("ts"))
        if ets is not None and have_ts:
            pos = 0  # after the last event at-or-before the entry's timestamp
            for i, t in enumerate(event_ts, 1):
                if t is not None and t <= ets:
                    pos = i
        else:
            pos = fed  # no comparable ts: append after the last event, seq order
        action = e.get("action")
        q = e.get("quarantined")
        contain_moments.append((pos, idx, {
            "kind": "containment",
            "ordinal": pos or None,
            "ts": str(e["ts"]) if ets else None,
            "seq": e.get("seq") if isinstance(e.get("seq"), int) else idx,
            "action": action if action in ("push", "refused") else "unknown",
            "quarantined": [str(s) for s in q] if isinstance(q, list) else [],
            "narrowing": str(e.get("narrowing", "")),
        }))

    # Chronological merge: a containment entry sorts AFTER the drift moment(s) of
    # the event it lands on - the push follows the drift that triggered it.
    merged = sorted(
        [(pos, 0, sub, m) for pos, sub, m in drift_moments]
        + [(pos, 1, sub, m) for pos, sub, m in contain_moments],
        key=lambda t: t[:3],
    )
    timeline = [m for _, _, _, m in merged]

    by_rule: dict[str, int] = {}
    for _, _, m in drift_moments:
        by_rule[m["rule_id"]] = by_rule.get(m["rule_id"], 0) + 1
    first_drift = None
    if drift_moments:
        m = drift_moments[0][2]
        first_drift = {"ordinal": m["ordinal"], "ts": m["ts"], "rule_id": m["rule_id"]}
    pushes = [(pos, m) for pos, _, m in contain_moments if m["action"] == "push"]
    refusals = sum(1 for _, _, m in contain_moments if m["action"] == "refused")

    # Containment credit requires an INTACT chain: a journal that fails
    # verification attests nothing, so the gap stats are withheld and the final
    # state stays DRIFTED. Fail-closed, like every other verdict in the pipeline.
    first_push = None
    gap = None
    if intact and pushes:
        pos, m = pushes[0]
        first_push = {"seq": m["seq"], "ts": m["ts"], "after_event": pos}
        if first_drift:
            d_ts, p_ts = _parse_ts(first_drift["ts"]), _parse_ts(m["ts"])
            if d_ts and p_ts:
                gap = {"seconds": (p_ts - d_ts).total_seconds()}
            else:
                gap = {"events": max(pos - first_drift["ordinal"], 0)}
    if not drift_moments:
        final_state = "CONFORM"
    elif intact and pushes:
        final_state = "CONTAINED"
    else:
        final_state = "DRIFTED"

    return Replay(timeline=timeline, summary={
        "events": fed,
        "malformed_event_lines": malformed_events,
        "findings": len(drift_moments),
        "by_rule": dict(sorted(by_rule.items())),
        "first_drift": first_drift,
        "pushes": len(pushes),
        "refusals": refusals,
        "first_push": first_push,
        "drift_to_containment": gap,
        "journal_entries": len(entries),
        "malformed_journal_lines": malformed_journal_lines,
        "journal_verdict": verdict,
        "final_state": final_state,
    })


def load_jsonl(path: str | Path) -> tuple[list[dict], int]:
    """Tolerant JSONL reader for forensics: returns ``(object lines, malformed
    line count)``. Unlike :func:`load_events`, the drop is COUNTED - a replay
    must report how many lines it could not read, never silently discard them."""
    objs: list[dict] = []
    bad = 0
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            bad += 1
            continue
        if isinstance(obj, dict):
            objs.append(obj)
        else:
            bad += 1
    return objs, bad


_SEV_CODES = {"critical": "1;31", "high": "31", "medium": "33", "low": "2", "info": "2"}


def _clock(ts: str | None) -> str:
    dt = _parse_ts(ts)
    return dt.strftime("%H:%M:%S") if dt else "--:--:--"


def _fmt_secs(x: float) -> str:
    return f"{x:.0f}s" if float(x).is_integer() else f"{x:.2f}s"


def render_replay(replay: Replay, *, color: bool | None = None) -> str:
    """Terminal timeline, chronological, one line per moment, then the summary
    block a responder reads first: first drift, drift-to-containment gap, the
    journal-chain verdict, and the final state."""
    from attestral.report_terminal import _bold, _dim, _paint, supports_color

    if color is None:
        color = supports_color()
    s = replay.summary
    chain_ok = s["journal_verdict"] == "intact"
    # A broken chain means every containment line is only a CLAIM.
    caveat = "" if chain_ok else _dim("  [claimed - chain broken]", color)
    lines = [_bold(f"REPLAY - incident reconstruction: {s['events']} event(s) "
                   "against the attested design", color), ""]

    if not replay.timeline:
        lines.append(_paint("  no drift and no containment - the runtime matched "
                            "the attested design", "32", color))
    for m in replay.timeline:
        num = f"#{m['ordinal']}" if m.get("ordinal") else "#-"
        stamp = f"  {num:>4} {_dim(_clock(m.get('ts')), color)}"
        if m["kind"] == "drift":
            rid = _paint(f"{m['rule_id']:<8}", _SEV_CODES.get(m["severity"], "31"), color)
            lines.append(f"{stamp}  {rid} {m['server']}: {m['detail']}")
        elif m["action"] == "push":
            lines.append(f"{stamp}  {_paint('LOCKDOWN pushed', '32', color)}  "
                         f"quarantined: {', '.join(m['quarantined']) or '-'}{caveat}")
        elif m["action"] == "refused":
            lines.append(f"{stamp}  {_paint('LOCKDOWN REFUSED', '1;31', color)}  "
                         "narrowing proof failed - nothing pushed "
                         f"(sought: {', '.join(m['quarantined']) or '-'}){caveat}")
        else:
            lines.append(f"{stamp}  {_dim('journal entry (unrecognized action)', color)}")

    lines += ["", _bold("  incident summary", color)]

    def row(label: str, value: str) -> None:
        lines.append(f"  {label:<18} {value}")

    events_cell = str(s["events"])
    if s["malformed_event_lines"]:
        events_cell += f" ({s['malformed_event_lines']} malformed line(s) skipped)"
    row("events", events_cell)
    counts = ", ".join(f"{k} x{v}" for k, v in s["by_rule"].items())
    row("drift findings", f"{s['findings']} ({counts})" if counts else "0")
    fd = s["first_drift"]
    if fd:
        at = _clock(fd["ts"]) if fd["ts"] else f"event #{fd['ordinal']}"
        row("first drift", f"#{fd['ordinal']} at {at} ({fd['rule_id']})")

    verdict = s["journal_verdict"]
    fp = s["first_push"]
    gap = s["drift_to_containment"]
    if verdict == "no journal":
        row("containment", "no journal provided (--journal merges the containment trail)")
    elif not chain_ok:
        row("containment", "unverifiable - the journal chain does not hold")
    elif not (s["pushes"] or s["refusals"]):
        row("containment", "none recorded in the journal")
    else:
        parts = []
        if fp:
            when = _clock(fp["ts"]) if fp["ts"] else f"after event #{fp['after_event']}"
            tail = ""
            if gap and "seconds" in gap:
                tail = f" - {_fmt_secs(gap['seconds'])} after first drift"
            elif gap and "events" in gap:
                tail = f" - {gap['events']} event(s) after first drift"
            parts.append(f"pushed at {when}{tail}")
        if s["refusals"]:
            parts.append(f"{s['refusals']} refusal(s)")
        row("containment", "; ".join(parts))

    if verdict == "no journal":
        row("journal chain", "none provided")
    elif chain_ok:
        n = s["journal_entries"]
        row("journal chain", _paint(
            f"intact ({n} {'entry' if n == 1 else 'entries'})", "32", color))
    else:
        row("journal chain", _paint(verdict, "1;31", color))

    state = s["final_state"]
    code = {"CONFORM": "32", "CONTAINED": "32"}.get(state, "1;31")
    row("final state", _paint(state, code, color))
    return "\n".join(lines)
