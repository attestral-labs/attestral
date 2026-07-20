"""Shared test helpers: the build-model / evaluate / collect-ids idiom that most
rule-coverage tests repeat. Import these instead of re-defining a local `_ids`.

    from _helpers import ids_for        # ids_for("examples/aws-pack") -> {"ATL-027", ...}
    from _helpers import rule_ids       # rule_ids(model) for an already-built model
    from _helpers import findings_for   # findings_for(fixture) -> list[Finding]

pytest's default (prepend) import mode puts tests/ on sys.path, so the bare
`from _helpers import ...` resolves without a tests package. Not a test module -
it has no `test_` prefix, so pytest never collects it.
"""
from __future__ import annotations

from attestral.ingest import build_model
from attestral.model import Finding, SystemModel
from attestral.rules import RuleEngine


def model_for(fixture) -> SystemModel:
    """Build the system model for an examples/ fixture (a path str or Path)."""
    return build_model(str(fixture))


def evaluate(model: SystemModel) -> list[Finding]:
    """Run the deterministic rule engine over an already-built model."""
    return RuleEngine().evaluate(model)


def rule_ids(model: SystemModel) -> set[str]:
    """The set of rule ids the engine fires on an already-built model."""
    return {f.rule_id for f in evaluate(model)}


def findings_for(fixture) -> list[Finding]:
    """Findings for a fixture path (build + evaluate)."""
    return evaluate(model_for(fixture))


def ids_for(fixture) -> set[str]:
    """The set of rule ids fired for a fixture path (build + evaluate + collect)."""
    return rule_ids(model_for(fixture))
