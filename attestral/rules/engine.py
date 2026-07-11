"""Deterministic rule engine: structured matchers over the system model.

No eval(), no string execution - every matcher is a named, typed check.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from attestral.model import Component, Finding, Severity, SystemModel

_CORE = Path(__file__).parent / "core_rules.yaml"


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
            ok = False
            for k, values in spec.items():
                items = [str(x) for x in (component.attr(k) or [])]
                if any(any(v == i or i.startswith(v + "/") or v in i for i in items) for v in values):
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
        return []

    @staticmethod
    def _finding(rule: dict, component_id: str, source: str) -> Finding:
        return Finding(
            rule_id=rule["id"],
            title=rule["title"],
            severity=Severity(rule["severity"]),
            component_id=component_id,
            description=rule.get("description", ""),
            recommendation=rule.get("recommendation", ""),
            source=source,
            framework_refs=rule.get("frameworks", []),
            origin="deterministic",
        )
