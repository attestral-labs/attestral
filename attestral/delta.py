"""Security-impact delta between two revisions of an agent design.

The highest-leverage place to review an agent design is the pull request that
changes it. A rule scan answers "what is wrong now"; this answers "what did this
change make worse" - the question a reviewer actually asks. It builds the system
model on the base and the head revision and diffs them: the capabilities each
surface gained, the findings that appeared or were resolved, the attack paths
that opened or closed, and the shift in worst-case blast radius. The model diff
IS the review - only an assembled system model can say "this change gives a
secrets-reading server an outbound channel" or "this change opens a reachable
path from untrusted input to code execution".

Rendered as a short, severity-ranked markdown comment for a PR bot. Short is the
point: a noisy bot gets muted, so a change with no new risk says exactly that in
one line, and improvements (paths closed, findings resolved) are reported after
the regressions, never ahead of them.

Deterministic, zero-dependency. Both revisions must be scannable; the delta is
over declared design, inheriting every rule's static scope.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from attestral.blast_radius import blast_radius
from attestral.model import Finding, Severity, SystemModel
from attestral.paths import all_attack_paths
from attestral.rules import RuleEngine

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


@dataclass
class ComponentDelta:
    """How one surface's capability envelope changed between revisions."""
    name: str
    type: str
    status: str                       # added | removed | changed
    caps_gained: list[str] = field(default_factory=list)
    caps_lost: list[str] = field(default_factory=list)
    cloud_gained: bool = False
    cloud_lost: bool = False


@dataclass
class ModelDelta:
    """The security-relevant difference between a base and a head design."""
    added: list[ComponentDelta] = field(default_factory=list)
    removed: list[ComponentDelta] = field(default_factory=list)
    changed: list[ComponentDelta] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)
    new_paths: list[str] = field(default_factory=list)
    closed_paths: list[str] = field(default_factory=list)
    blast_before: float = 0.0
    blast_after: float = 0.0
    blast_top: str = ""

    @property
    def is_empty(self) -> bool:
        """No security-relevant change of any kind between the revisions."""
        return not (self.added or self.removed or self.changed or self.new_findings
                    or self.resolved_findings or self.new_paths or self.closed_paths)

    @property
    def has_regression(self) -> bool:
        """The change increases risk: a new finding, a newly reachable path, a
        capability or cloud crossing gained."""
        return bool(
            self.new_findings or self.new_paths
            or any(c.caps_gained or c.cloud_gained for c in self.added + self.changed)
        )

    def worst_new_severity(self) -> Severity | None:
        """The most severe newly-introduced finding, or None if none."""
        if not self.new_findings:
            return None
        return max((f.severity for f in self.new_findings), key=lambda s: s.rank)


def _caps_by_name(model: SystemModel) -> dict[str, dict]:
    """name -> {caps, cloud, type} for every tool-granting surface."""
    out: dict[str, dict] = {}
    for c in model.tool_surfaces():
        out[c.name] = {
            "caps": set(c.attr("_capabilities") or []),
            "cloud": bool(c.attr("_has_cloud_credentials")),
            "type": c.type,
        }
    return out


def _key(f: Finding) -> tuple[str, str]:
    return (f.rule_id, f.component_id)


def _top_blast(model: SystemModel) -> tuple[float, str]:
    rows = blast_radius(model)
    return (rows[0].score, rows[0].name) if rows else (0.0, "")


def diff_models(base: SystemModel, head: SystemModel) -> ModelDelta:
    """Diff two assembled models into a security-impact delta. Findings are
    evaluated with the deterministic rule engine on each side, so the diff is
    reproducible and needs no API key."""
    delta = ModelDelta()

    base_caps, head_caps = _caps_by_name(base), _caps_by_name(head)
    for name in sorted(set(base_caps) | set(head_caps)):
        b, h = base_caps.get(name), head_caps.get(name)
        if b is None and h is not None:
            delta.added.append(ComponentDelta(
                name, h["type"], "added", sorted(h["caps"]), [], h["cloud"], False))
        elif h is None and b is not None:
            delta.removed.append(ComponentDelta(
                name, b["type"], "removed", [], sorted(b["caps"]), False, b["cloud"]))
        else:
            gained = sorted(h["caps"] - b["caps"])
            lost = sorted(b["caps"] - h["caps"])
            cloud_gained = h["cloud"] and not b["cloud"]
            cloud_lost = b["cloud"] and not h["cloud"]
            if gained or lost or cloud_gained or cloud_lost:
                delta.changed.append(ComponentDelta(
                    name, h["type"], "changed", gained, lost, cloud_gained, cloud_lost))

    base_f = RuleEngine().evaluate(base)
    head_f = RuleEngine().evaluate(head)
    base_keys = {_key(f) for f in base_f}
    head_keys = {_key(f) for f in head_f}
    delta.new_findings = _rank([f for f in head_f if _key(f) not in base_keys])
    delta.resolved_findings = _rank([f for f in base_f if _key(f) not in head_keys])

    base_paths = {p.describe() for p in all_attack_paths(base)}
    head_paths = {p.describe() for p in all_attack_paths(head)}
    delta.new_paths = sorted(head_paths - base_paths)
    delta.closed_paths = sorted(base_paths - head_paths)

    delta.blast_before, _ = _top_blast(base)
    delta.blast_after, delta.blast_top = _top_blast(head)
    return delta


def _rank(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity.rank, f.rule_id, f.component_id))


def _short_component(f: Finding) -> str:
    cid = f.component_id
    return cid.split(".", 1)[1] if "." in cid and not cid.startswith("model") else cid


def render_delta_markdown(delta: ModelDelta) -> str:
    """The delta as a short, severity-ranked markdown comment. Regressions lead;
    improvements follow; a no-risk change says so in one line."""
    lines = ["## Attestral security-impact delta"]

    if delta.is_empty:
        lines.append("")
        lines.append("No change to the agent design surface.")
        return "\n".join(lines)

    if not delta.has_regression:
        lines.append("")
        lines.append("**No new risk introduced by this change.**")

    if delta.new_paths:
        lines.append("")
        lines.append(f"### New reachable attack path ({len(delta.new_paths)})")
        for p in delta.new_paths:
            lines.append(f"- {p}")

    if delta.new_findings:
        lines.append("")
        lines.append(f"### New findings ({len(delta.new_findings)})")
        for f in delta.new_findings:
            lines.append(
                f"- **{f.severity.value.upper()}** `{f.rule_id}` "
                f"on `{_short_component(f)}` - {f.title}")

    gained = [c for c in delta.added + delta.changed if c.caps_gained or c.cloud_gained]
    if gained:
        lines.append("")
        lines.append("### Capabilities gained")
        for c in gained:
            what = list(c.caps_gained) + (["cloud credentials"] if c.cloud_gained else [])
            verb = "new server" if c.status == "added" else "gained"
            lines.append(f"- `{c.name}` ({c.type}) {verb}: {', '.join(what)}")

    if delta.blast_after > delta.blast_before:
        lines.append("")
        lines.append(
            f"**Worst if-compromised reach:** {delta.blast_before:.1f} -> "
            f"{delta.blast_after:.1f}/10 (`{delta.blast_top}`)")

    improvements = []
    if delta.closed_paths:
        improvements.append(f"{len(delta.closed_paths)} attack path(s) closed")
    if delta.resolved_findings:
        improvements.append(f"{len(delta.resolved_findings)} finding(s) resolved")
    if improvements:
        lines.append("")
        lines.append("### Improvements")
        lines.append("- " + "; ".join(improvements))

    lines.append("")
    lines.append(
        "<sub>Delta over the declared design (base vs head). A newly reachable "
        "path is necessary, not sufficient, for exploitation.</sub>")
    return "\n".join(lines)
