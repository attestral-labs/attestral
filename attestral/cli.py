"""Attestral CLI: scan a project, emit an audit-ready design review."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from attestral import __version__
from attestral.evidence import audit_chain, render_markdown, verify_chain
from attestral.ingest import build_model
from attestral.rules import RuleEngine


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Attestral - continuous, audit-ready security design review."""


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("-o", "--output", default="attestral-report", help="Output file stem.")
@click.option("--format", "fmt", type=click.Choice(["md", "json", "both", "sarif"]), default="both",
              help="md/json report, both (default), or sarif for GitHub Code Scanning.")
@click.option("--llm", is_flag=True, help="Add LLM threat elicitation (needs ANTHROPIC_API_KEY).")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default=None,
              help="Exit non-zero if findings at/above this severity exist (CI gate).")
@click.option("--waivers", "waivers_path", type=click.Path(exists=True), default=None,
              help="YAML of documented waivers (auto-discovered as attestral-waivers.yaml).")
@click.option("--judge", is_flag=True, help="Verify findings with an LLM judge (needs an API key).")
@click.option("--judge-model", default="claude-sonnet-4-6", help="Model for the judge layer.")
@click.option("--judge-panel", type=int, default=1, help="Judges per finding; majority vote.")
@click.option("--judge-suppress", is_flag=True,
              help="Auto-waive high-confidence false positives (kept on the record).")
def scan(path: str, output: str, fmt: str, llm: bool, fail_on: str | None,
         waivers_path: str | None, judge: bool, judge_model: str, judge_panel: int,
         judge_suppress: bool) -> None:
    """Scan PATH (Terraform, MCP configs) and generate a design review."""
    model = build_model(path)
    findings = RuleEngine().evaluate(model)
    if llm:
        from attestral.llm import elicit
        findings += elicit(model)

    from attestral.waivers import apply_waivers, discover_waivers, load_waivers
    wpath = waivers_path or discover_waivers(path)
    if wpath:
        for note in apply_waivers(findings, load_waivers(wpath)):
            click.echo(f"  ! {note}", err=True)

    if judge:
        from attestral.judge import JudgeConfig, judge_findings
        cfg = JudgeConfig(model=judge_model, panel=judge_panel, suppress=judge_suppress)
        for note in judge_findings(model, findings, cfg):
            click.echo(f"  ! {note}", err=True)

    active = [f for f in findings if not f.waived]
    waived = [f for f in findings if f.waived]

    if fmt in ("md", "both"):
        Path(f"{output}.md").write_text(render_markdown(model, findings, path))
        click.echo(f"wrote {output}.md")
    if fmt in ("json", "both"):
        Path(f"{output}.json").write_text(
            json.dumps({"target": path, "chain": audit_chain(findings)}, indent=2)
        )
        click.echo(f"wrote {output}.json")
    if fmt == "sarif":
        from attestral.sarif import render_sarif
        Path(f"{output}.sarif").write_text(render_sarif(model, findings, path))
        click.echo(f"wrote {output}.sarif")

    for f in findings:
        if f.waived:
            tag = "  (waived)"
        elif f.judge_verdict:
            tag = f"  (judge: {f.judge_verdict} {f.judge_confidence})"
        else:
            tag = ""
        click.echo(f"  [{f.severity.value.upper():8}] {f.rule_id}  {f.title}  ({f.component_id}){tag}")
    summary = f"{len(model.components)} components · {len(active)} findings"
    if waived:
        summary += f" · {len(waived)} waived"
    click.echo(summary)

    if fail_on:
        from attestral.model import Severity
        threshold = Severity(fail_on).rank
        if any(f.severity.rank >= threshold for f in active):
            click.echo(f"FAIL-CLOSED: findings at or above '{fail_on}'", err=True)
            sys.exit(1)


@main.command()
@click.argument("report", type=click.Path(exists=True))
def verify(report: str) -> None:
    """Verify the tamper-evident audit chain in a JSON report."""
    data = json.loads(Path(report).read_text())
    ok = verify_chain(data.get("chain", []))
    click.echo("chain VALID ✅" if ok else "chain INVALID - report has been altered ❌")
    sys.exit(0 if ok else 1)


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("-o", "--output", default="mcp-guard-policy.yaml", help="Policy output file.")
def compile(path: str, output: str) -> None:
    """Compile PATH's attested design into an mcp-guard runtime policy."""
    from attestral.compile import compile_policy, render_policy_yaml
    model = build_model(path)
    findings = RuleEngine().evaluate(model)
    chain = audit_chain(findings)
    head = chain[-1]["hash"] if chain else ""
    policy = compile_policy(model, findings, chain_head=head)
    Path(output).write_text(render_policy_yaml(policy))
    allowed = sum(1 for s in policy["servers"].values() if s["allow"])
    denied = len(policy["servers"]) - allowed
    click.echo(f"wrote {output}  ·  default deny  ·  {allowed} allowed, {denied} denied")
    for name, s in policy["servers"].items():
        mark = "ALLOW" if s["allow"] else "DENY "
        why = "" if s["allow"] else f"  ({s.get('reason','')})"
        click.echo(f"  [{mark}] {name}{why}")


@main.command()
@click.argument("policy_file", type=click.Path(exists=True))
@click.argument("events_file", type=click.Path(exists=True))
@click.option("--fail-on-drift", is_flag=True, help="Exit non-zero on any drift (CI/cron gate).")
def drift(policy_file: str, events_file: str, fail_on_drift: bool) -> None:
    """Diff runtime EVENTS_FILE (JSONL) against a compiled POLICY_FILE."""
    import yaml as _yaml
    from attestral.drift import detect_drift, load_events
    policy = _yaml.safe_load(Path(policy_file).read_text())
    events = load_events(events_file)
    findings = detect_drift(policy, events)
    for f in findings:
        click.echo(f"  [{f.severity.value.upper():8}] {f.rule_id}  {f.title}  ({f.component_id})")
    click.echo(f"{len(events)} events · {len(findings)} drift findings")
    if findings and fail_on_drift:
        click.echo("DRIFT: deployment no longer matches the attested design", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
