"""Deterministic rule engine: structured matchers over the system model.

No eval(), no string execution - every matcher is a named, typed check.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from attestral.model import Component, Finding, Severity, SystemModel

_CORE = Path(__file__).parent / "core_rules.yaml"

# Cross-server reference matching only considers tool names that are
# structurally identifiers (send_message, list-issues, createIssue), never
# plain English words: a server legitimately named "search" would otherwise
# flag every description containing that word.
_MIN_TOOL_REF_LEN = 4


def _identifier_like(name: str) -> bool:
    if len(name) < _MIN_TOOL_REF_LEN:
        return False
    if "_" in name or "-" in name:
        return True
    return any(a.islower() and b.isupper() for a, b in zip(name, name[1:]))


def _references(surface: str, name: str) -> bool:
    """Case-insensitive, word-boundary occurrence of `name` in `surface`."""
    pattern = r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])"
    return re.search(pattern, surface, re.IGNORECASE) is not None


def _distinct_servers(model: SystemModel) -> list[Component]:
    """mcp_server components de-duplicated by (id, source), so a config file
    that happens to match two discovery globs never counts as two servers."""
    seen: set[tuple[str, str]] = set()
    out: list[Component] = []
    for c in model.by_type("mcp_server"):
        key = (c.id, c.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def _matches(component: Component, match: dict[str, Any]) -> bool:
    for kind, spec in match.items():
        if kind == "attr_equals":
            if not all(component.attr(k) == v for k, v in spec.items()):
                return False
        elif kind == "attr_in":
            if not all(component.attr(k) in v for k, v in spec.items()):
                return False
        elif kind == "attr_missing":
            keys = spec if isinstance(spec, list) else [spec]
            if not all(component.attr(k) is None for k in keys):
                return False
        elif kind == "attr_starts_with":
            if not all(str(component.attr(k, "")).startswith(v) for k, v in spec.items()):
                return False
        elif kind == "attr_contains":
            if not all(v in str(component.attr(k, "")) for k, v in spec.items()):
                return False
        elif kind == "attr_list_contains":
            if not all(v in (component.attr(k) or []) for k, v in spec.items()):
                return False
        elif kind == "attr_list_any_of":
            # Match when a value equals a list item (exact token, e.g. a capability
            # name) or an item is a path *under* a value root (v + "/"). We do NOT
            # do bare substring matching: a root of "/" must not match every arg that
            # merely contains a slash (docker refs, URLs, a Windows "/c" flag).
            ok = False
            for k, values in spec.items():
                items = [str(x) for x in (component.attr(k) or [])]
                if any(any(v == i or i.startswith(v + "/") for i in items) for v in values):
                    ok = True
            if not ok:
                return False
        elif kind == "attr_any_contains":
            ok = False
            for k, values in spec.items():
                hay = component.attr(k)
                hay = " ".join(str(x) for x in hay) if isinstance(hay, list) else str(hay or "")
                if any(v in hay for v in values):
                    ok = True
            if not ok:
                return False
        else:
            return False  # unknown matcher: fail closed
    return True


class RuleEngine:
    def __init__(self, rule_paths: list[str | Path] | None = None):
        paths = [_CORE] + [Path(p) for p in (rule_paths or [])]
        self.rules: list[dict] = []
        for p in paths:
            data = yaml.safe_load(Path(p).read_text()) or {}
            self.rules.extend(data.get("rules", []))

    def evaluate(self, model: SystemModel) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            target = rule.get("target", "")
            match = rule.get("match", {})
            if target == "model":
                findings.extend(self._evaluate_model_rule(rule, match, model))
                continue
            for c in model.by_type(target):
                if _matches(c, match):
                    findings.append(self._finding(rule, c.id, c.source))
        findings.sort(key=lambda f: f.severity.rank, reverse=True)
        return findings

    def _evaluate_model_rule(self, rule: dict, match: dict, model: SystemModel) -> list[Finding]:
        if "model_has_both" in match:
            a, b = match["model_has_both"]
            if model.by_type(a) and model.by_type(b):
                return [self._finding(rule, "model", "system model")]
        elif "model_capability_combo" in match:
            # Fires when every capability group is covered by SOME server in
            # the fleet - the servers may differ; the combination is the risk.
            groups = match["model_capability_combo"]
            if not (isinstance(groups, list) and groups
                    and all(isinstance(g, list) and g for g in groups)):
                return []  # malformed spec: fail closed
            fleet: set[str] = set()
            for c in model.by_type("mcp_server"):
                fleet.update(c.attr("_capabilities") or [])
            if all(fleet & set(g) for g in groups):
                return [self._finding(rule, "model", "system model")]
        elif "model_tool_name_collision" in match:
            # Two servers claiming one tool name: the client's routing decides
            # which implementation answers, so a lower-trust server can shadow
            # the trusted one. One finding per colliding name.
            if match["model_tool_name_collision"] is not True:
                return []  # malformed spec: fail closed
            owners: dict[str, list[Component]] = {}
            for c in _distinct_servers(model):
                for t in dict.fromkeys(str(x) for x in (c.attr("_tool_names") or [])):
                    owners.setdefault(t, []).append(c)
            findings = []
            for tool, servers in sorted(owners.items()):
                if len(servers) < 2:
                    continue
                names = ", ".join(sorted({s.name for s in servers}))
                sources = "; ".join(sorted({s.source for s in servers}))
                findings.append(self._finding(
                    rule, f"model:tool:{tool}", sources,
                    detail=f"Tool '{tool}' is exposed by {len(servers)} servers: {names}.",
                ))
            return findings
        elif "model_cross_server_tool_reference" in match:
            # The shadowing pattern itself: one server's tool metadata talks
            # about a tool that belongs to a different server. Matching is
            # purely structural (identifier cross-reference against the fleet
            # inventory) - the injection *language* is the ML layer's job.
            if match["model_cross_server_tool_reference"] is not True:
                return []  # malformed spec: fail closed
            servers = _distinct_servers(model)
            findings = []
            for a in servers:
                descs = a.attr("_tool_descriptions") or []
                surface = " ".join(
                    [str(a.attr("description") or "")]
                    + [str(d.get("description", "")) for d in descs]
                ).strip()
                if not surface:
                    continue
                own = {str(t) for t in (a.attr("_tool_names") or [])}
                for b in servers:
                    if a is b or a.name == b.name:
                        continue  # same server (or same identity twice: ATL-206's job)
                    for t in dict.fromkeys(str(x) for x in (b.attr("_tool_names") or [])):
                        if t in own or not _identifier_like(t):
                            continue
                        if _references(surface, t):
                            findings.append(self._finding(
                                rule, a.id, a.source,
                                detail=f"'{a.name}' describes behavior for tool "
                                       f"'{t}', which belongs to server '{b.name}'.",
                            ))
            return findings
        elif "model_server_name_conflict" in match:
            # One server name, several launch targets: which code answers to
            # that identity depends on config precedence. Identical mirrored
            # definitions are fine; only differing definitions fire.
            if match["model_server_name_conflict"] is not True:
                return []  # malformed spec: fail closed
            by_name: dict[str, list[Component]] = {}
            for c in _distinct_servers(model):
                by_name.setdefault(c.name, []).append(c)
            findings = []
            for name, comps in sorted(by_name.items()):
                signatures = {
                    (str(c.attr("command") or ""),
                     tuple(str(x) for x in (c.attr("args") or [])),
                     str(c.attr("url") or ""))
                    for c in comps
                }
                if len(comps) >= 2 and len(signatures) >= 2:
                    sources = sorted({c.source for c in comps})
                    findings.append(self._finding(
                        rule, f"model:server:{name}", "; ".join(sources),
                        detail=(
                            f"Server name '{name}' resolves to {len(signatures)} "
                            f"different launch targets across: {', '.join(sources)}."
                        ),
                    ))
            return findings
        return []

    @staticmethod
    def _finding(rule: dict, component_id: str, source: str, detail: str = "") -> Finding:
        description = rule.get("description", "")
        if detail:
            description = f"{description} {detail}" if description else detail
        return Finding(
            rule_id=rule["id"],
            title=rule["title"],
            severity=Severity(rule["severity"]),
            component_id=component_id,
            description=description,
            recommendation=rule.get("recommendation", ""),
            source=source,
            framework_refs=rule.get("frameworks", []),
            origin="deterministic",
        )
