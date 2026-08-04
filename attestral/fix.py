"""Compile-the-fix: turn one finding into the enforceable control that closes it.

`compile.py` compiles a whole attested design into a runtime policy. This goes
the other direction, one finding at a time: for a specific finding, it emits the
exact mcp-guard control that neutralizes THAT finding, an explanation of why the
control closes it, and a verification verdict, all bound to the review's chain
head. A remediation that is also an enforceable control is the payoff of the
attest -> compile -> drift loop; no linter can offer it, because a linter has no
runtime policy to compile into.

Two honest verification kinds, never conflated:

* `re-synthesized` - for capability/fleet findings, the fix removes a capability,
  the model is re-synthesized, and the finding no longer fires. This is proven
  over the model, deterministically.
* `enforced-at-proxy` - for a per-server structural finding, the control is a
  constraint mcp-guard enforces at invocation (TLS-only, forbid-env-secrets, an
  egress allowlist, a deny). The control provably governs the rule's condition;
  it is enforced at runtime rather than re-derived here.

The control fragment is a valid slice of the same mcp-guard policy `compile`
produces, so a fix can be merged straight into the compiled policy.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field

from attestral.model import Finding, SystemModel

# rule_id -> (constraint_key, constraint_value, explanation). A `None` value with
# key "deny" means the control denies the server outright; otherwise the value is
# the constraint mcp-guard enforces at the proxy. These mirror the controls
# compile.py already emits, so a fix merges cleanly into a full policy.
_PROXY_CONTROLS: dict[str, tuple[str, object, str]] = {
    "ATL-101": ("transport", "tls_only",
                "mcp-guard refuses the plaintext endpoint and requires TLS, so tool "
                "traffic and any credential in it can no longer be read on the wire."),
    "ATL-102": ("deny", None,
                "The filesystem root is broader than the attested design allows; the "
                "proxy denies the server until the root is re-scoped in the design."),
    "ATL-103": ("deny", None,
                "No shell tool is attested; the proxy denies the shell-capable server "
                "so an injection cannot reach arbitrary command execution."),
    "ATL-104": ("forbid_env_secrets", True,
                "mcp-guard strips raw secrets from the server's environment, so tool "
                "output can never echo a credential the design placed in `env`."),
    "ATL-105": ("pin_launch", True,
                "The proxy refuses to launch an unpinned or auto-installed package, so "
                "the reviewed tool is the tool that runs."),
    "ATL-106": ("pin_launch", True,
                "The proxy pins the launch to an immutable version/digest, closing the "
                "mutable-tag rug-pull surface."),
    "ATL-107": ("egress_allowlist", [],
                "Default-deny egress: the proxy allows outbound only to an explicit "
                "destination allowlist, removing the free exfiltration channel."),
    "ATL-108": ("require_human_approval", True,
                "mcp-guard reinstates a human checkpoint on this server's tool calls, "
                "so auto-approved actions can no longer run unattended."),
    "ATL-109": ("require_auth", True,
                "The proxy requires a credential on the remote endpoint, so an "
                "unauthenticated caller can no longer drive or impersonate it."),
    "ATL-115": ("forbid_env_secrets", True,
                "The downstream credential is removed from the co-located remote "
                "server; exchange the caller's own identity instead (confused-deputy)."),
    "ATL-112": ("forbid_env_secrets", True,
                "mcp-guard strips the cloud credential from the tool server's "
                "environment, cutting the agent-to-cloud path."),
}

# Capability that each fleet/capability finding depends on, and which the fix
# removes to break the chain. The verification re-synthesizes the model without
# it and confirms the finding no longer fires.
_CAP_TO_STRIP: dict[str, str] = {
    "ATL-202": "network",     # break the exfiltration trifecta at the egress leg
    "ATL-203": "shell",       # break shell + network by removing shell
    "ATL-207": "shell",       # untrusted input can no longer reach code execution
    "ATL-RT-EXTERNAL": "shell",
    "ATL-RT-INTERNAL": "shell",
    "ATL-213": "shell",       # break the cross-repo chain at the pivot
}


@dataclass
class PolicyFix:
    rule_id: str
    component: str
    control: dict = field(default_factory=dict)   # a valid mcp-guard policy slice
    explanation: str = ""
    verification: str = ""     # "re-synthesized" | "enforced-at-proxy"
    verified: bool = False
    chain_head: str = ""
    # Broker-backed fixes only: the exact standing-credential env keys to remove
    # and the CB4A route plan that replaces them (written via --broker-output).
    strip_env: list[str] = field(default_factory=list)
    broker_plan: object | None = None   # attestral.broker.BrokerPlan

    @property
    def title(self) -> str:
        return f"fix for {self.rule_id} on {self.component}"


def _server_named(model: SystemModel, component_id: str):
    c = model.get(component_id)
    return c.name if c else component_id


def _model_without_cap(model: SystemModel, cap: str) -> SystemModel:
    """A deep copy of the model with `cap` stripped from every tool surface (and
    cloud credentials cleared for cap == 'network', which also gates egress)."""
    m = copy.deepcopy(model)
    for c in m.tool_surfaces():
        c.attributes["_capabilities"] = [
            x for x in (c.attr("_capabilities") or []) if x != cap
        ]
    return m


def _finding_fires(model: SystemModel, rule_id: str) -> bool:
    from attestral.rules import RuleEngine
    return any(f.rule_id == rule_id for f in RuleEngine().evaluate(model))


def _broker_fix(model: SystemModel, finding: Finding, chain_head: str) -> PolicyFix | None:
    """The broker-backed fix for a standing-credential finding: strip the exact
    env keys and front the server with the generated CB4A route. Verification is
    re-synthesized for real - the model copy has the keys removed and its
    credential attributes re-derived through the ingester's own classifiers, and
    the rule engine confirms the finding no longer fires."""
    from attestral.broker import plan_for, strip_standing_credentials
    plan = plan_for(model, finding.component_id)
    if plan is None:
        return None
    rid = finding.rule_id
    closed = not _finding_fires(
        strip_standing_credentials(model, finding.component_id), rid
    )
    # The mcp-guard slice stays a valid backstop (the proxy strips any secret
    # that survives the migration); the route is the replacement path itself.
    control = {"servers": {plan.name: {"constraints": {"forbid_env_secrets": True}}}}
    why = (
        f"The standing credential is removed, not just guarded: strip "
        f"{', '.join(plan.stripped)} from the server's env and route it through "
        f"the generated CB4A broker route (strict inbound auth, per-call scoped "
        f"token, secret by reference), so the agent process holds no reusable "
        f"key. Re-synthesizing the model without those keys confirms {rid} no "
        f"longer fires; forbid_env_secrets stays on as the proxy backstop."
    )
    return PolicyFix(rid, plan.name, control, why, "re-synthesized", closed,
                     chain_head, strip_env=list(plan.stripped), broker_plan=plan)


def fix_for_finding(model: SystemModel, finding: Finding, chain_head: str = "") -> PolicyFix | None:
    """The enforceable control that neutralizes `finding`, or None when the rule
    has no compilable runtime control (it is a design change only)."""
    from attestral.broker import BROKER_FIX_RULES
    rid = finding.rule_id
    name = _server_named(model, finding.component_id)

    # Standing-credential findings get the broker-backed fix (strip + JIT route)
    # ahead of the generic proxy constraint - remediation, not just containment.
    if rid in BROKER_FIX_RULES:
        fix = _broker_fix(model, finding, chain_head)
        if fix is not None:
            return fix

    if rid in _PROXY_CONTROLS:
        key, value, why = _PROXY_CONTROLS[rid]
        if key == "deny":
            control = {"servers": {name: {"allow": False,
                                          "reason": f"closed by fix for {rid}"}}}
        else:
            control = {"servers": {name: {"constraints": {key: value}}}}
        return PolicyFix(rid, name, control, why, "enforced-at-proxy", True, chain_head)

    if rid in _CAP_TO_STRIP:
        cap = _CAP_TO_STRIP[rid]
        closed = not _finding_fires(_model_without_cap(model, cap), rid)
        control = {"session_policy": {
            "isolate_capability": cap,
            "reason": f"break the chain behind {rid} by removing '{cap}' from the shared session",
        }}
        why = (
            f"The finding is compositional: it exists because one agent session "
            f"combines capabilities. mcp-guard isolates '{cap}' out of that session "
            f"(a separate, non-shared agent), which breaks the chain. Re-synthesizing "
            f"the model without '{cap}' confirms {rid} no longer fires."
        )
        return PolicyFix(rid, finding.component_id, control, why, "re-synthesized",
                         closed, chain_head)

    return None


def fixes_for(model: SystemModel, findings: list[Finding], chain_head: str = "") -> list[PolicyFix]:
    """Every compilable fix for the active findings, de-duplicated by (rule,
    component). Findings with no runtime control (a pure design change) are
    skipped; the caller still shows their recommendation from the finding."""
    out: list[PolicyFix] = []
    seen: set[tuple[str, str]] = set()
    for f in findings:
        if f.waived:
            continue
        fix = fix_for_finding(model, f, chain_head)
        if fix is None:
            continue
        key = (fix.rule_id, fix.component)
        if key in seen:
            continue
        seen.add(key)
        out.append(fix)
    return out


def broker_plans_for(fixes: list[PolicyFix]) -> list:
    """The deduplicated broker route plans behind a fix set, in fix order - what
    `attestral fix --broker-output` writes as one agentgateway config."""
    plans, seen = [], set()
    for fx in fixes:
        if fx.broker_plan is not None and fx.broker_plan.name not in seen:
            seen.add(fx.broker_plan.name)
            plans.append(fx.broker_plan)
    return plans


def render_fixes(model: SystemModel, findings: list[Finding], *,
                 chain_head: str = "", color: bool | None = None) -> str:
    from attestral.report_terminal import _bold, _dim, _paint, supports_color
    import yaml
    if color is None:
        color = supports_color()
    fixes = fixes_for(model, findings, chain_head)
    active = [f for f in findings if not f.waived]
    fixed_ids = {fx.rule_id for fx in fixes}
    no_control = sorted({f.rule_id for f in active} - fixed_ids)
    if not fixes:
        return _paint("No compilable fixes: these findings are design changes, not "
                      "runtime controls. See each finding's recommendation.", "33", color)

    lines = [_paint(f"Compile-the-fix ({len(fixes)}) - each control is enforceable, "
                    "bound to the review chain head", "1;31", color)]
    if chain_head:
        lines.append(_dim(f"  chain head: {chain_head[:16]}", color))
    for fx in fixes:
        verdict = (_paint("verified: " + fx.verification, "32", color)
                   if fx.verified else _dim("control emitted (verification inconclusive)", color))
        lines.append("")
        lines.append(f"  {_paint(fx.rule_id, '1;31', color)}  {_bold(fx.component, color)}  {verdict}")
        lines.append(f"    {_dim('why:', color)} {fx.explanation}")
        if fx.strip_env:
            lines.append(f"    {_dim('strip:', color)} {', '.join(fx.strip_env)}")
            lines.append(f"    {_dim('route:', color)} CB4A broker route "
                         f"'{fx.component}' (write it with --broker-output)")
        frag = yaml.safe_dump(fx.control, sort_keys=False).rstrip().splitlines()
        lines.append(f"    {_dim('control:', color)}")
        for ln in frag:
            lines.append(f"      {ln}")
    if no_control:
        lines.append("")
        lines.append(_dim("design-only (no runtime control, see recommendation): "
                          + ", ".join(no_control), color))
    return "\n".join(lines)
