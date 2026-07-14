"""Attestral CLI: scan a project, emit an audit-ready design review."""
from __future__ import annotations

import json
import os
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
@click.argument("path", type=click.Path(exists=True), required=False)
@click.option("--local", is_flag=True,
              help="Scan the MCP configs already installed on this machine "
                   "(Claude Desktop, Cursor, VS Code, Windsurf) instead of a PATH.")
@click.option("-o", "--output", default="attestral-report",
              help="Write report files to this stem (implies writing files).")
@click.option("--format", "fmt",
              type=click.Choice(["md", "json", "both", "sarif", "aibom"]), default="both",
              help="Report file format when writing: md/json/both/sarif, or "
                   "aibom for a CycloneDX 1.6 AI-BOM of the agent stack. "
                   "Passing this (or -o) writes files; otherwise results only print.")
@click.option("--llm", is_flag=True, help="Add LLM threat elicitation (needs ANTHROPIC_API_KEY).")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default=None,
              help="Exit non-zero if findings at/above this severity exist (CI gate).")
@click.option("--waivers", "waivers_path", type=click.Path(exists=True), default=None,
              help="YAML of documented waivers (auto-discovered as attestral-waivers.yaml).")
@click.option("--judge", is_flag=True, help="Verify findings with an LLM judge (needs an API key).")
@click.option("--judge-model", default="claude-opus-4-8", help="Model for the judge layer.")
@click.option("--judge-panel", type=int, default=1, help="Judges per finding; majority vote.")
@click.option("--judge-effort", type=click.Choice(["low", "medium", "high", "xhigh", "max"]),
              default="medium", help="Judge reasoning effort. Higher is more rigorous and costs more.")
@click.option("--judge-suppress", is_flag=True,
              help="Auto-waive high-confidence false positives (kept on the record).")
@click.option("--ml", is_flag=True,
              help="Force the model-grade ML tier (onnx/deberta if installed). The zero-dep "
                   "heuristic already runs by default; use --ml-engine to pick a specific tier.")
@click.option("--no-ml", is_flag=True,
              help="Skip the prompt-injection classifier (it runs by default, heuristic tier).")
@click.option("--ml-engine", type=click.Choice(["auto", "heuristic", "onnx", "deberta"]), default=None,
              help="ML tier: heuristic (zero-dep), onnx (attestral[onnx]), deberta (attestral[ml]), "
                   "or auto (default; onnx -> deberta -> heuristic). Also ATTESTRAL_ML_ENGINE.")
@click.option("--ml-model", default=None, help="Override the ML classifier model id.")
@click.option("--ml-revision", default=None, help="Pin the classifier to a model revision.")
@click.option("--ml-threshold", type=float, default=0.5,
              help="Min injection probability (0-1) to report. Default 0.5.")
@click.option("--aivss", is_flag=True,
              help="Rank agentic findings by an OWASP AIVSS Agentic AI Risk Score (AARS).")
@click.option("-q", "--quiet", is_flag=True,
              help="Suppress the per-finding detail; print only the summary and gate.")
@click.pass_context
def scan(ctx: click.Context, path: str | None, local: bool, output: str, fmt: str, llm: bool,
         fail_on: str | None, waivers_path: str | None, judge: bool, judge_model: str,
         judge_panel: int, judge_effort: str, judge_suppress: bool, ml: bool, no_ml: bool,
         ml_engine: str | None, ml_model: str | None, ml_revision: str | None, ml_threshold: float,
         aivss: bool, quiet: bool) -> None:
    """Scan PATH (Terraform, Kubernetes, MCP configs) and review its security design.

    Results print to the terminal. Report files are written only when you ask
    for them - pass -o/--output to set a file stem, or --format to pick a
    format. With neither, nothing is written to disk.

    With --local, discover and scan the MCP configs already installed on this
    machine instead of a PATH.
    """
    if local:
        from attestral.ingest.local_config import build_local_model
        model, sources = build_local_model()
        click.echo("Local MCP config discovery:", err=True)
        for s in sources:
            mark = "found " if s.found else "absent"
            count = f"  ({s.servers} server{'' if s.servers == 1 else 's'})" if s.found else ""
            click.echo(f"  [{mark}] {s.tool}: {s.path}{count}", err=True)
        found = [s for s in sources if s.found]
        if not found:
            click.echo("No installed MCP configs found. Nothing to scan.", err=True)
            return
        path = "local"  # report/target label; no repo path exists for --local
    else:
        if not path:
            raise click.UsageError("Provide a PATH to scan, or pass --local to "
                                   "scan the MCP configs installed on this machine.")
        model = build_model(path)
    findings = RuleEngine().evaluate(model)
    if llm:
        if not quiet:
            click.echo("scanning agentic surfaces with LLM elicitation…", err=True)
        from attestral.llm import elicit
        findings += elicit(model)
    if not no_ml:
        if not quiet:
            click.echo("scanning agentic surfaces for prompt injection…", err=True)
        from attestral.ml import MLConfig, scan as ml_scan
        # The zero-dep heuristic tier runs by default so every scan looks at the
        # language surfaces no matcher can (deterministic, offline). --ml or
        # --ml-engine (or ATTESTRAL_ML_ENGINE) opts into the model-grade tiers.
        engine = ml_engine or os.environ.get("ATTESTRAL_ML_ENGINE") or ("auto" if ml else "heuristic")
        cfg = MLConfig.from_env(model=ml_model, revision=ml_revision, engine=engine)
        cfg.threshold = ml_threshold
        ml_findings, ml_notes = ml_scan(model, cfg)
        findings += ml_findings
        for note in ml_notes:
            click.echo(f"  ! {note}", err=True)

    from attestral.waivers import apply_waivers, discover_waivers, load_waivers
    wpath = waivers_path or discover_waivers(path)
    if wpath:
        for note in apply_waivers(findings, load_waivers(wpath)):
            click.echo(f"  ! {note}", err=True)

    if judge:
        if not quiet:
            click.echo("cross-examining findings with the judge…", err=True)
        from attestral.judge import JudgeConfig, judge_findings
        cfg = JudgeConfig(model=judge_model, panel=judge_panel, effort=judge_effort,
                          suppress=judge_suppress)
        for note in judge_findings(model, findings, cfg):
            click.echo(f"  ! {note}", err=True)

    active = [f for f in findings if not f.waived]

    # Terminal-first: only touch the disk when the user explicitly asks for a
    # report, i.e. passes -o/--output or --format. Otherwise print and stop.
    write_files = (
        ctx.get_parameter_source("output").name != "DEFAULT"
        or ctx.get_parameter_source("fmt").name != "DEFAULT"
    )

    from attestral.report_terminal import gate_line, render_fleet, render_scan
    if local and not quiet:
        # A machine audit must show the surface it reviewed - "clean" with no
        # visible inventory is unverifiable, and the inventory IS the answer
        # to the question --local asks: what can my agents already reach?
        fleet = render_fleet(model)
        if fleet:
            click.echo(fleet)
            click.echo("")
    body = render_scan(model, findings, path, quiet=quiet)
    if body:
        click.echo(body)

    if aivss and not quiet:
        from attestral.aivss import render_aivss
        block = render_aivss(model, findings)
        if block:
            click.echo("")
            click.echo(block)

    if write_files:
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
        if fmt == "aibom":
            from attestral.aibom import render_aibom
            Path(f"{output}.cdx.json").write_text(render_aibom(model, path))
            click.echo(f"wrote {output}.cdx.json")
    elif not quiet:
        click.echo("(no files written - add -o to save a report)")

    if fail_on:
        from attestral.model import Severity
        threshold = Severity(fail_on).rank
        if any(f.severity.rank >= threshold for f in active):
            click.echo(gate_line(fail_on, True), err=True)
            sys.exit(1)
        if not quiet:
            click.echo(gate_line(fail_on, False))


_WORKFLOW_YAML = """\
name: attestral
on: [pull_request]
permissions:
  contents: read
  security-events: write        # to upload findings to the Security tab
jobs:
  design-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v6
        with: { python-version: "3.12" }
      - run: pip install "attestral[terraform]"
      - run: attestral scan . --format sarif -o attestral
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: attestral.sarif }
      - run: attestral scan . --fail-on high      # hard gate (auto-uses attestral-waivers.yaml)
"""

_PRE_COMMIT_YAML = """\
# .pre-commit-config.yaml - run attestral on every commit.
# Setup:  pip install pre-commit  &&  pre-commit install
repos:
  - repo: https://github.com/attestral-labs/attestral
    rev: v{version}   # pin to a released tag
    hooks:
      - id: attestral          # gate the infra/agent config committed in this repo
      # - id: attestral-local  # optional: also audit installed MCP servers
"""

_WAIVERS_YAML = """\
# attestral-waivers.yaml - documented, expiring exceptions (auto-discovered at
# the scan root). A waived finding stays in the evidence chain with its
# justification and becomes a SARIF suppression - suppressed from the gate, but
# never hidden. A waiver with no `reason` is ignored, and an expired waiver
# stops suppressing.
#
# waivers:
#   - rule: ATL-005
#     component: aws_db_instance.app     # or "*" for every component
#     reason: Encryption enforced at the storage layer; tracked in SEC-1234.
#     expires: 2026-12-31                # optional
waivers: []
"""


@main.command()
def init() -> None:
    """Scaffold attestral onboarding files into the current directory.

    Writes a GitHub Actions workflow, a pre-commit config, and a starter
    waivers file. Existing files are never overwritten - they are skipped and
    reported.
    """
    scaffold = {
        Path(".github/workflows/attestral.yml"): _WORKFLOW_YAML,
        Path(".pre-commit-config.yaml"): _PRE_COMMIT_YAML.format(version=__version__),
        Path("attestral-waivers.yaml"): _WAIVERS_YAML,
    }
    created: list[Path] = []
    skipped: list[Path] = []
    for target, content in scaffold.items():
        if target.exists():
            skipped.append(target)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        created.append(target)

    for p in created:
        click.echo(f"created {p}")
    for p in skipped:
        click.echo(f"skipped {p} (already exists)")

    click.echo("")
    if created:
        click.echo("Next steps:")
        click.echo("  1. attestral scan .                 # review this project now")
        click.echo("  2. pip install pre-commit && pre-commit install   # gate every commit")
        click.echo("  3. commit .github/workflows/attestral.yml         # gate every PR in CI")
    else:
        click.echo("Nothing to do - all onboarding files already exist.")


@main.command()
@click.argument("rule_id")
def explain(rule_id: str) -> None:
    """Explain a rule: title, severity, description, recommendation, frameworks.

    RULE_ID is matched case-insensitively (e.g. atl-103 or ATL-103).
    """
    engine = RuleEngine()
    rid = rule_id.strip().upper()
    rule = next((r for r in engine.rules if str(r.get("id", "")).upper() == rid), None)

    if rule is None:
        from attestral.report_terminal import supports_color
        color = supports_color(sys.stderr)
        red = "\033[31m" if color else ""
        reset = "\033[0m" if color else ""
        click.echo(f"{red}Unknown rule id: {rule_id!r}{reset}", err=True)
        ids = [str(r.get("id", "")) for r in engine.rules]
        click.echo(f"Attestral ships {len(ids)} rules. Available ids:", err=True)
        line = "  "
        for i in ids:
            if len(line) + len(i) + 2 > 76:
                click.echo(line.rstrip(), err=True)
                line = "  "
            line += i + "  "
        if line.strip():
            click.echo(line.rstrip(), err=True)
        sys.exit(1)

    from attestral.report_terminal import supports_color
    color = supports_color()
    sev = str(rule.get("severity", "")).lower()
    sev_code = {"critical": "1;31", "high": "31", "medium": "33",
                "low": "36", "info": "90"}.get(sev, "0")
    rid_disp = str(rule["id"])
    header_id = f"\033[{sev_code}m{rid_disp}\033[0m" if color else rid_disp
    sev_disp = f"\033[{sev_code}m{sev}\033[0m" if color else sev
    title = str(rule.get("title", ""))
    title_disp = f"\033[1m{title}\033[0m" if color else title

    click.echo(f"{header_id}  ·  {sev_disp}")
    click.echo(title_disp)
    if rule.get("description"):
        click.echo("")
        click.echo(str(rule["description"]))
    if rule.get("recommendation"):
        click.echo("")
        click.echo("Recommendation")
        click.echo(f"  {rule['recommendation']}")
    frameworks = rule.get("frameworks") or []
    if frameworks:
        click.echo("")
        click.echo("Frameworks")
        click.echo("  " + " · ".join(str(f) for f in frameworks))
    target = rule.get("target", "")
    matcher = ", ".join((rule.get("match") or {}).keys())
    click.echo("")
    click.echo(f"Applies to: {target}" + (f"   (matcher: {matcher})" if matcher else ""))


@main.command()
@click.argument("report", type=click.Path(exists=True))
def verify(report: str) -> None:
    """Verify the tamper-evident audit chain in a JSON report."""
    data = json.loads(Path(report).read_text())
    ok = verify_chain(data.get("chain", []))
    click.echo("chain VALID" if ok else "chain INVALID - report has been altered")
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


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("-o", "--output", default=None,
              help="Write the proof report (<stem>.md) and evidence chain (<stem>.json).")
@click.option("--fail-on-proof", is_flag=True,
              help="Exit non-zero if any exploit path is proven traversable (CI gate).")
def validate(path: str, output: str | None, fail_on_proof: bool) -> None:
    """Prove whether the attack paths in PATH's attested design actually hold.

    Symbolic tier: walks each assembled attack path over the model's own edges,
    with no execution and no network, and commits each proven path to the
    evidence chain as an attestable proof. The generative and executed tiers
    build on the same proof (research/adversarial-validation-spike.md).
    """
    from attestral.redteam import build_proofs
    from attestral.report_terminal import render_proofs
    model = build_model(path)
    proofs = build_proofs(model)
    click.echo(render_proofs(proofs))
    if output:
        findings = [p.to_finding() for p in proofs]
        Path(f"{output}.md").write_text(render_markdown(model, findings, path))
        Path(f"{output}.json").write_text(
            json.dumps({"target": path, "chain": audit_chain(findings)}, indent=2)
        )
        click.echo(f"wrote {output}.md · {output}.json")
    if fail_on_proof and proofs:
        click.echo("PROVEN: at least one exploit path is traversable in the "
                   "attested design", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
