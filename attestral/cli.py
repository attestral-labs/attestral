"""Attestral CLI: scan a project, emit an audit-ready design review."""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys
from pathlib import Path

import click

from attestral import __version__
from attestral.compile import COMPILE_TARGETS, TARGETS
from attestral.evidence import audit_chain, render_markdown, verify_chain
from attestral.ingest import build_model
from attestral.rules import RuleEngine


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Attestral - continuous, audit-ready security design review."""


def _report_path(output: str, ext: str) -> Path:
    """Resolve a report file path from the -o stem and a format extension.

    -o is a stem, so the extension is appended (`attestral-report` -> `.sarif`).
    But if the stem already ends with that extension - the user passed a full
    filename like `-o out.sarif` - use it verbatim instead of double-appending
    (`out.sarif.sarif`). The check is on the extension the format actually writes,
    so `-o out.cdx.json` for aibom and `-o out.summary.md` for md-summary are
    honoured too."""
    ext = ext if ext.startswith(".") else "." + ext
    return Path(output) if Path(output).name.endswith(ext) else Path(output + ext)


@main.command()
@click.argument("path", type=click.Path(exists=True), required=False)
@click.option("--local", is_flag=True,
              help="Scan the MCP configs already installed on this machine "
                   "(Claude Desktop, Cursor, VS Code, Windsurf) instead of a PATH.")
@click.option("-o", "--output", default="attestral-report",
              help="Write report files to this stem (implies writing files).")
@click.option("--format", "fmt",
              type=click.Choice(["md", "json", "both", "sarif", "aibom", "md-summary", "html"]),
              default="both",
              help="Report file format when writing: md/json/both/sarif, "
                   "aibom for a CycloneDX 1.6 AI-BOM of the agent stack, "
                   "md-summary for a compact PR/job-summary markdown, or "
                   "html for an interactive blast-radius threat topography. "
                   "Passing this (or -o) writes files; otherwise results only print.")
@click.option("--llm", is_flag=True, help="Add LLM threat elicitation (needs ANTHROPIC_API_KEY).")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default=None,
              help="Exit non-zero if findings at/above this severity exist (CI gate).")
@click.option("--min-confidence", type=click.Choice(["high", "medium", "low"]), default=None,
              help="Drop findings below this confidence. --min-confidence high keeps "
                   "only the structural, 0-FP-on-benign findings (the CI-safe set); it "
                   "filters the probabilistic ML tier and low-confidence advisories.")
@click.option("--waivers", "waivers_path", type=click.Path(exists=True), default=None,
              help="YAML of documented waivers (auto-discovered as attestral-waivers.yaml).")
@click.option("--judge", is_flag=True, help="Verify findings with an LLM judge (needs an API key).")
@click.option("--judge-model", default="claude-opus-4-8", help="Model for the judge layer.")
@click.option("--judge-panel", type=int, default=1, help="Judges per finding; majority vote.")
@click.option("--judge-effort", type=click.Choice(["low", "medium", "high", "xhigh", "max"]),
              default="medium", help="Judge reasoning effort. Higher is more rigorous and costs more.")
@click.option("--judge-suppress", is_flag=True,
              help="Auto-waive high-confidence false positives (kept on the record).")
@click.option("--judge-all", is_flag=True,
              help="Judge every finding, not just the FP-prone / high-severity ones "
                   "(by default the judge is spent only where it changes the answer).")
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
@click.option("--baseline", "baseline_path", type=click.Path(), default=None,
              help="Diff-aware mode. If the file exists, report only findings NOT in it "
                   "(net-new); if it does not, record the current findings as the baseline. "
                   "Lets you adopt on a brownfield repo and gate CI on what a PR adds.")
@click.option("--update-baseline", is_flag=True,
              help="Rewrite the --baseline file from the current scan (re-record).")
@click.option("--card", is_flag=True,
              help="Print a compact, screenshot-ready self-audit card instead of the "
                   "full report: does this fleet assemble the lethal trifecta, yes or no. "
                   "Pairs with --local to audit and share what your own machine runs.")
@click.option("-q", "--quiet", is_flag=True,
              help="Suppress the per-finding detail; print only the summary and gate.")
@click.pass_context
def scan(ctx: click.Context, path: str | None, local: bool, output: str, fmt: str, llm: bool,
         fail_on: str | None, min_confidence: str | None,
         waivers_path: str | None, judge: bool, judge_model: str,
         judge_panel: int, judge_effort: str, judge_suppress: bool, judge_all: bool,
         ml: bool, no_ml: bool,
         ml_engine: str | None, ml_model: str | None, ml_revision: str | None, ml_threshold: float,
         baseline_path: str | None, update_baseline: bool, aivss: bool, card: bool,
         quiet: bool) -> None:
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

    # Reachability-based severity: when a finding's component sits on an attack
    # chain the symbolic walk shows reachable, attach the chain to the finding
    # and raise it one band (capped at the chain's severity) - the raised rating
    # ships with the entry -> pivot -> impact path that justifies it.
    from attestral.reachability import annotate_reachability
    for note in annotate_reachability(model, findings):
        if not quiet:
            click.echo(f"  {note}", err=True)

    # Injection-reachability fusion: an ML-flagged injectable surface is only a
    # real primitive when it can reach an actionable sink. Escalate the ones that
    # reach an egress channel, a cloud crossing, code execution, or private data
    # (attaching the reachable chain); leave injectable dead-ends at their ML
    # severity. Runs after reachability so a finding already on a walked chain
    # keeps that stronger annotation.
    from attestral.injection_reach import annotate_injection_reach
    for note in annotate_injection_reach(model, findings):
        if not quiet:
            click.echo(f"  {note}", err=True)

    # Trust-asymmetry: a tool-name collision between a trusted server and a
    # lower-trust one (mutable @latest pin, remote-unauthed, known-CVE) is the
    # shadowing attack, not a config typo. Raise the collision one band and name
    # the lower-trust shadower.
    from attestral.trust_asymmetry import annotate_trust_asymmetry
    for note in annotate_trust_asymmetry(model, findings):
        if not quiet:
            click.echo(f"  {note}", err=True)

    # False-positive budget: drop findings below the confidence floor. Applied
    # after reachability (which can raise severity) but before waivers and the
    # gate, so a filtered finding neither prints nor trips --fail-on.
    if min_confidence:
        kept = [f for f in findings if f.meets_confidence(min_confidence)]
        dropped = len(findings) - len(kept)
        if dropped and not quiet:
            click.echo(f"  --min-confidence {min_confidence}: {dropped} lower-confidence "
                       "finding(s) filtered", err=True)
        findings = kept

    from attestral.waivers import apply_waivers, discover_waivers, load_waivers
    wpath = waivers_path or discover_waivers(path)
    if wpath:
        for note in apply_waivers(findings, load_waivers(wpath)):
            click.echo(f"  ! {note}", err=True)

    # Inline suppression: a `// attestral:ignore ATL-xxx` marker in the config
    # that produced a finding waives it in place (kept in the chain, not deleted).
    # Runs after the waiver file so both suppression paths compose.
    from attestral.inline_suppress import apply_inline_suppressions
    for note in apply_inline_suppressions(findings):
        if not quiet:
            click.echo(f"  {note}", err=True)

    if judge:
        if not quiet:
            click.echo("cross-examining findings with the judge…", err=True)
        from attestral.judge import JudgeConfig, judge_findings
        cfg = JudgeConfig(model=judge_model, panel=judge_panel, effort=judge_effort,
                          suppress=judge_suppress, gate=not judge_all)
        for note in judge_findings(model, findings, cfg):
            click.echo(f"  ! {note}", err=True)

    # Diff-aware baseline: on an existing file, drop pre-existing findings and
    # report only the net-new ones (so the report and the CI gate reflect what a
    # change added); on a missing file (or --update-baseline), record the current
    # set and report normally so the user sees what got baselined.
    net_new = False
    if baseline_path:
        from attestral.baseline import load_baseline, split_new, write_baseline
        bpath = Path(baseline_path)
        if bpath.exists() and not update_baseline:
            new, known = split_new(findings, load_baseline(bpath))
            if not quiet:
                click.echo(
                    f"  baseline: {len(known)} pre-existing finding(s) hidden; "
                    f"showing {len(new)} net-new", err=True)
            findings = new
            net_new = True
        else:
            n = write_baseline(bpath, findings)
            click.echo(f"  baseline recorded: {n} finding(s) -> {bpath} "
                       f"(future --baseline runs show only net-new)", err=True)

    active = [f for f in findings if not f.waived]

    # Terminal-first: only touch the disk when the user explicitly asks for a
    # report, i.e. passes -o/--output or --format. Otherwise print and stop.
    write_files = (
        ctx.get_parameter_source("output").name != "DEFAULT"
        or ctx.get_parameter_source("fmt").name != "DEFAULT"
    )

    from attestral.report_terminal import gate_line, render_card, render_fleet, render_scan
    if card:
        # The compact, shareable artifact: one screen, one answer, honest about a
        # thin or clean surface. Stands in for the full report, not alongside it.
        subject = "on this machine" if local else f"in {path}"
        click.echo(render_card(model, findings, subject))
    else:
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

    if aivss and not quiet and not card:
        from attestral.aivss import render_aivss
        block = render_aivss(model, findings)
        if block:
            click.echo("")
            click.echo(block)

    if write_files:
        if fmt in ("md", "both"):
            out = _report_path(output, ".md")
            out.write_text(render_markdown(model, findings, path))
            click.echo(f"wrote {out}")
        if fmt in ("json", "both"):
            from attestral.aivss import as_json as aivss_json
            out = _report_path(output, ".json")
            out.write_text(
                json.dumps(
                    {
                        "target": path,
                        "chain": audit_chain(findings),
                        "aivss": aivss_json(model, findings),
                    },
                    indent=2,
                )
            )
            click.echo(f"wrote {out}")
        if fmt == "sarif":
            from attestral.sarif import render_sarif
            out = _report_path(output, ".sarif")
            out.write_text(render_sarif(model, findings, path))
            click.echo(f"wrote {out}")
        if fmt == "aibom":
            from attestral.aibom import render_aibom
            out = _report_path(output, ".cdx.json")
            out.write_text(render_aibom(model, path))
            click.echo(f"wrote {out}")
        if fmt == "md-summary":
            from attestral.evidence import render_pr_summary
            out = _report_path(output, ".summary.md")
            out.write_text(render_pr_summary(model, findings, path, net_new=net_new))
            click.echo(f"wrote {out}")
        if fmt == "html":
            from attestral.topography import render_topography
            out = _report_path(output, ".html")
            out.write_text(render_topography(model, findings, path))
            click.echo(f"wrote {out} - interactive threat topography (open in a browser)")
    elif not quiet and not card:
        click.echo("(no files written - add -o to save a report)")

    if fail_on:
        from attestral.model import Severity
        threshold = Severity(fail_on).rank
        if any(f.severity.rank >= threshold for f in active):
            click.echo(gate_line(fail_on, True), err=True)
            sys.exit(1)
        if not quiet:
            click.echo(gate_line(fail_on, False))


@main.command()
@click.argument("paths", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default=None,
              help="Exit non-zero if findings at/above this severity exist (CI gate).")
@click.option("-o", "--output", default=None,
              help="Write the fleet report (<stem>.md and <stem>.json).")
@click.option("-q", "--quiet", is_flag=True, help="Print only the summary and gate.")
def fleet(paths: tuple[str, ...], fail_on: str | None, output: str | None, quiet: bool) -> None:
    """Model several repos as ONE agent fleet and find flows that span them.

    Give it two or more repo paths. Attestral merges them into a single system
    model - tagging each component with its repo - and runs the full review over
    the union, so a toxic flow whose entry lives in one repo and whose exfil
    sink lives in another is surfaced (ATL-213). That cross-repo flow is the
    thing no per-repo scanner can see: each repo looks fine on its own.
    """
    from attestral.fleet import build_fleet_model, render_fleet_overview
    from attestral.ml import MLConfig
    from attestral.ml import scan as ml_scan
    from attestral.reachability import annotate_reachability
    from attestral.report_terminal import gate_line, render_scan

    model, labels = build_fleet_model(list(paths))
    findings = RuleEngine().evaluate(model)   # includes ATL-213 on a fleet model
    ml_findings, _ = ml_scan(model, MLConfig(engine="heuristic"))
    findings += ml_findings
    for note in annotate_reachability(model, findings):
        if not quiet:
            click.echo(f"  {note}", err=True)

    target = " + ".join(labels)
    if not quiet:
        click.echo(render_fleet_overview(model, labels))
        click.echo("")
    body = render_scan(model, findings, target, quiet=quiet)
    if body:
        click.echo(body)

    if output:
        Path(f"{output}.md").write_text(render_markdown(model, findings, target))
        Path(f"{output}.json").write_text(
            json.dumps({"target": target, "repos": labels,
                        "chain": audit_chain(findings)}, indent=2))
        click.echo(f"wrote {output}.md · {output}.json")

    if fail_on:
        from attestral.model import Severity
        threshold = Severity(fail_on).rank
        active = [f for f in findings if not f.waived]
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

      # Inline annotations on the exact offending line, via GitHub code scanning.
      - run: attestral scan . --format sarif -o attestral
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: attestral.sarif }

      # A clean job summary rendering the reachable attack paths and the
      # findings this PR introduced. Commit attestral-baseline.json so the
      # summary and the gate below see only net-new findings, not day-one debt.
      - run: attestral scan . --baseline attestral-baseline.json --format md-summary -o attestral
      - run: cat attestral.summary.md >> "$GITHUB_STEP_SUMMARY"

      # Hard gate: fail only on net-new high/critical, and only on high-confidence
      # (structural, zero-false-positive-on-benign) findings, so a probabilistic
      # ML hit never breaks the build. Auto-uses attestral-waivers.yaml.
      - run: attestral scan . --baseline attestral-baseline.json --min-confidence high --fail-on high --quiet
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
# Prefer `attestral accept <path> <rule> <component> -r "why"` over hand-editing:
# it appends the entry with provenance (who accepted, when) and a content pin -
# if the finding's severity or attack chain later changes, the acceptance goes
# stale and the finding comes back.
#
# waivers:
#   - rule: ATL-005
#     component: aws_db_instance.app     # or "*" for every component
#     reason: Encryption enforced at the storage layer; tracked in SEC-1234.
#     expires: 2026-12-31                # optional
waivers: []
"""

# The Claude Code skill scaffolded into a project so Attestral is discoverable
# where agents are built: a developer editing an MCP config or agent prompt in
# Claude Code gets a review reflex without leaving the editor. This is the same
# content shipped as the installable plugin's skill (plugin/skills/attestral-
# review/SKILL.md); tests/test_init.py gates that they stay byte-identical.
_CLAUDE_SKILL_MD = '''\
---
name: attestral-review
description: Security design review for AI agents, MCP servers, and the cloud they can reach. Use when adding or editing an MCP server, agent config, subagent, system prompt, or tool definition, or when the user asks whether an agent setup is safe or has prompt-injection, tool-poisoning, excessive-agency, or lethal-trifecta risk. Runs `attestral scan` and explains the findings.
---

# Attestral security review

Attestral is a security design-review scanner for agentic systems. It reads the
declared surface (MCP configs, agent wiring, system prompts, tool descriptions,
and Terraform / Kubernetes) and reasons over a single system model to find the
risks that matter for agents: prompt injection, tool poisoning, excessive
agency, and the toxic flows that only exist across tools. A shell tool and an
egress tool are one injected sentence apart, and neither looks dangerous alone.

It is a design review, not a SAST tool. It reads the declared configuration; it
does not read the inside of a tool's implementation or run anything against a
live agent.

## When to use this skill

Reach for it whenever the agent's attack surface changes, or the user asks about
safety:

- A new or edited `.mcp.json` / MCP server, subagent, A2A card, or `@tool` function.
- A new or edited system prompt or agent-instruction file.
- The user asks "is this agent config safe", "could this be prompt-injected",
  "review this before I ship", or names tool poisoning, excessive agency, or a
  lethal trifecta.

## Install (once)

Attestral is a Python CLI with two core dependencies.

```bash
pipx install attestral        # isolated, recommended
# or: pip install attestral
```

The prompt-injection ML tier runs with no extra install (a zero-dependency
heuristic). `pip install "attestral[ml]"` upgrades it to a local DeBERTa
classifier; `[terraform]` adds HCL parsing.

## Core moves

Run these from the repo root and read the grouped, severity-ordered output.

```bash
attestral scan .                      # review this project (auto-discovers configs)
attestral scan . --ml                 # add prompt-injection scoring on language surfaces
attestral scan --local                # audit the MCP servers installed on THIS machine
attestral explain ATL-107             # what one finding means and how to fix it
```

To gate a change so only structural, zero-false-positive findings fail:

```bash
attestral scan . --min-confidence high --fail-on high
```

## Reading the output

- Findings are grouped by severity and tagged by origin: `deterministic` (a
  typed rule), `ml` (prompt-injection scoring), or `llm` (the optional judge).
- A finding on a walked attack chain carries a `path:` line naming
  entry -> pivot -> impact, and its severity is raised one band. That path is
  the story to surface, not just the rule title.
- The headline findings are the cross-tool ones (lethal trifecta, toxic flow):
  they exist because two capabilities co-occur, so look at the flow, not one
  tool.
- `confidence` (high / medium / low) tags how false-positive-prone a finding is.
  Deterministic rules are high; the ML tier tracks its probability.

## Handling a finding

1. Run `attestral explain <ID>` for the concrete fix and the framework citation
   (OWASP Agentic / LLM Top 10, MITRE ATLAS, NIST, CIS).
2. Apply the remediation: narrow a tool's scope, add a human-approval gate,
   allowlist egress, drop a secret from env.
3. If a finding is a deliberate accepted risk, do not silence it silently.
   Either a one-line `// attestral:ignore ATL-xxx reason: ...` marker in the
   config, or `attestral accept <path> <rule> <component> -r "why"` for a
   provenance-pinned waiver. Both keep the finding in the evidence chain.

## Gate it in CI

`attestral init` scaffolds a GitHub Action (SARIF into the Security tab, a
net-new baseline gate, a job summary with the reachable path) and a pre-commit
hook. Suggest it once a project scans clean or its findings are triaged.

Do not overstate results. A reachable path is necessary for exploitation, not
sufficient, and a clean scan means the declared surface looks sound, not that
the implementation is proven safe.
'''


@main.command()
def init() -> None:
    """Scaffold attestral onboarding files into the current directory.

    Writes a GitHub Actions workflow, a pre-commit config, a starter waivers
    file, and a Claude Code skill so Attestral is discoverable where agents are
    built. Existing files are never overwritten - they are skipped and reported.
    """
    scaffold = {
        Path(".github/workflows/attestral.yml"): _WORKFLOW_YAML,
        Path(".pre-commit-config.yaml"): _PRE_COMMIT_YAML.format(version=__version__),
        Path("attestral-waivers.yaml"): _WAIVERS_YAML,
        Path(".claude/skills/attestral-review/SKILL.md"): _CLAUDE_SKILL_MD,
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
        click.echo("  The .claude/ skill makes Attestral a review reflex in Claude Code;")
        click.echo("  or install the plugin: /plugin marketplace add attestral-labs/attestral")
    else:
        click.echo("Nothing to do - all onboarding files already exist.")


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.argument("rule_id")
@click.argument("component_id")
@click.option("-r", "--reason", required=True,
              help="Why this risk is acceptable. Goes on the record; an empty reason is refused.")
@click.option("--expires", default=None, metavar="YYYY-MM-DD",
              help="ISO date the acceptance lapses (the finding then comes back).")
@click.option("--by", "accepted_by", default=None,
              help="Identity to record. Defaults to git `user.name <user.email>`, else $USER.")
@click.option("--waivers", "waivers_path", type=click.Path(), default=None,
              help="Waivers file to append to (default: the discovered file, "
                   "else attestral-waivers.yaml at PATH).")
def accept(path: str, rule_id: str, component_id: str, reason: str, expires: str | None,
           accepted_by: str | None, waivers_path: str | None) -> None:
    """Accept RULE_ID on COMPONENT_ID as documented risk - itself an audit record.

    Scans PATH with the default layers, finds the matching live finding, and
    appends a provenance-carrying waiver to the waivers file: who accepted,
    when, why, and a content pin of the finding as accepted (rule, component,
    severity, reachable chain). If the risk later changes - a rule wave
    re-rates it, or a new tool completes an attack chain through the component
    - the pin stops matching, the acceptance goes stale, and the finding comes
    back. Suppressed is never hidden: the accepted finding stays in the
    evidence chain carrying who accepted it and on what basis.
    """
    from attestral.ml import MLConfig
    from attestral.ml import scan as ml_scan
    from attestral.reachability import annotate_reachability
    from attestral.waivers import discover_waivers, record_acceptance

    # The same default layers as a plain scan, so the pinned finding is exactly
    # the one the scan reports (deterministic heuristic ML tier included).
    model = build_model(path)
    findings = RuleEngine().evaluate(model)
    ml_findings, _ = ml_scan(model, MLConfig(engine="heuristic"))
    findings += ml_findings
    annotate_reachability(model, findings)

    rid = rule_id.strip().upper()
    target = next(
        (f for f in findings if f.rule_id == rid and f.component_id == component_id), None
    )
    if target is None:
        click.echo(f"no live finding {rid} on {component_id!r} in {path}", err=True)
        components = sorted({f.component_id for f in findings if f.rule_id == rid})
        if components:
            click.echo(f"{rid} currently fires on: {', '.join(components)}", err=True)
        else:
            click.echo(f"{rid} does not fire on this design - nothing to accept.", err=True)
        sys.exit(1)

    head = audit_chain(findings)[-1]["hash"]
    wpath = Path(waivers_path) if waivers_path else (
        discover_waivers(path)
        or (Path(path) if Path(path).is_dir() else Path(path).parent) / "attestral-waivers.yaml"
    )
    try:
        w = record_acceptance(wpath, target, reason, expires=expires,
                              by=accepted_by or "", chain_head=head)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc

    pinned = f"severity {target.severity.value}"
    if target.reachability:
        pinned += ", on a reachable attack chain"
    click.echo(f"accepted {rid} on {component_id}  ->  {wpath}")
    click.echo(f"  by:      {w.accepted_by}")
    click.echo(f"  at:      {w.accepted_at}")
    click.echo(f"  reason:  {w.reason}")
    if w.expires:
        click.echo(f"  expires: {w.expires}")
    click.echo(f"  pinned:  {w.finding_sha256[:16]}  ({pinned})")
    click.echo("the finding stays in the evidence chain as accepted risk; if its "
               "severity or chain changes, the acceptance goes stale and it comes back")


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


@main.command(name="blast-radius")
@click.argument("path", type=click.Path(exists=True))
@click.option("--limit", type=int, default=15,
              help="Show at most this many surfaces (default: 15).")
def blast_radius_cmd(path: str, limit: int) -> None:
    """Rank every agent surface by its if-compromised reach (blast radius).

    For each tool-granting surface, compute the weighted set of sensitive
    capabilities and the cloud crossing reachable from it over the modeled
    design, and print the surfaces worst-first - the lethal-trifecta host and
    the credential-holding server rise to the top on their own. Reach is over
    declared capability: a prioritisation signal, not proof of exploitability.
    """
    from attestral.blast_radius import render_blast_radius
    model = build_model(path)
    block = render_blast_radius(model, limit=limit)
    if not block:
        click.echo("No tool-granting surface found - nothing that can carry an injection.")
        return
    click.echo(block)


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("-o", "--output", default=None,
              help="Write the reach report JSON here. Terminal-first: nothing is written without -o.")
def reach(path: str, output: str | None) -> None:
    """Show which named cloud/Kubernetes resources each agent surface can reach.

    Every per-server scanner stops at 'this MCP server holds a cloud credential.'
    Attestral ingests the Terraform/Kubernetes resources into the SAME model, so
    it answers the question that decides the blast radius: from an agent surface -
    especially an injectable one that holds no credential of its own - WHICH named
    infrastructure resource is reachable, directly or laundered through a
    co-resident deputy, and by what path. The named resource lives in the cloud
    model, not in any MCP server, so no per-file scanner can name it. This is the
    evidence behind ATL-222. Reach is over the modeled edges: a prioritisation
    signal, not proof an injection would succeed.
    """
    from attestral.cloudreach import reach_report, render_reach
    model = build_model(path)
    click.echo(render_reach(model))
    if output:
        Path(output).write_text(json.dumps(reach_report(model), indent=2))
        click.echo(f"\nwrote {output}")


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--remove", "remove", default=None, metavar="NAME",
              help="Counterfactual: remove the component named NAME.")
@click.option("--deny", "deny", default=None, metavar="NAME:CAPABILITY",
              help="Counterfactual: scope CAPABILITY off the component named NAME "
                   "(e.g. web:network).")
def whatif(path: str, remove: str | None, deny: str | None) -> None:
    """Show the security delta of a design change BEFORE you make it.

    Applies one hypothetical change to the model of PATH - remove a server, or
    scope a capability away - and reports what it would fix: findings resolved,
    attack paths closed, and the drop in worst-case blast radius. It runs the
    tool's own rules, reachability, and blast-radius against the counterfactual,
    so a designer can compare fixes without editing anything. The change is never
    written; only a copy of the model is mutated.
    """
    from attestral.delta import render_delta_markdown
    from attestral.whatif import whatif as run_whatif

    deny_pair = None
    if deny:
        if ":" not in deny:
            raise click.UsageError("--deny expects NAME:CAPABILITY (e.g. web:network)")
        name, cap = deny.split(":", 1)
        deny_pair = (name.strip(), cap.strip())

    model = build_model(path)
    delta, note = run_whatif(model, remove=remove, deny=deny_pair)
    if delta is None:
        raise click.UsageError(note)

    change = f"remove '{remove}'" if remove else f"deny {deny_pair[0]}:{deny_pair[1]}"
    click.echo(f"what-if: {change}\n")
    if delta.is_empty:
        click.echo("No security change: this would resolve nothing and open nothing.")
        return
    click.echo(render_delta_markdown(delta))
    click.echo(f"\nblast radius: {delta.blast_before:.1f} -> {delta.blast_after:.1f}"
               + (f"  ({delta.blast_top})" if delta.blast_top else ""))


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--add", "add_path", required=True, metavar="CONFIG", type=click.Path(exists=True),
              help="An MCP config (or project) describing the server(s) you propose to add.")
@click.option("--fail-on-deny", is_flag=True,
              help="Exit non-zero when the verdict is DENY (a PR-time / install-time gate).")
@click.option("-o", "--output", default=None,
              help="Write the admission verdict JSON here. Terminal-first: nothing is written without -o.")
def admit(path: str, add_path: str, fail_on_deny: bool, output: str | None) -> None:
    """Decide whether an agent may load a proposed tool, and prove why.

    Admission control for the agent loadout: before you add an MCP server, this
    builds your current design, builds it WITH the proposed server added
    (re-deriving the credential-reach and taint edges so the new tool's
    interactions with the existing fleet appear), diffs the two, and returns
    ALLOW or DENY with the evidence. The risk of a new tool is almost never in
    the tool itself: a read-only fetcher is harmless alone, but dropped into a
    runtime that already holds a cloud credential it becomes the injectable entry
    of a confused-deputy path into named infrastructure. The verdict is the
    security DELTA of admitting it - new findings, new attack paths, new
    cross-boundary reach, the blast-radius shift - with the deny reasons named, so
    the gate proves itself. Deterministic and offline.
    """
    from attestral.admit import admit as run_admit
    from attestral.admit import admit_report, render_admit
    verdict = run_admit(path, add_path)
    click.echo(render_admit(verdict))
    if output:
        Path(output).write_text(json.dumps(admit_report(verdict), indent=2))
        click.echo(f"\nwrote {output}")
    if fail_on_deny and not verdict.allowed:
        sys.exit(1)


@main.command()
@click.argument("base", type=click.Path(exists=True))
@click.argument("head", type=click.Path(exists=True))
@click.option("-o", "--output", default=None, metavar="FILE",
              help="Write the markdown delta to FILE (for a PR comment).")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]),
              default=None,
              help="Exit non-zero if the change introduces a NEW finding at or "
                   "above this severity (CI gate).")
def diff(base: str, head: str, output: str | None, fail_on: str | None) -> None:
    """Post the security-impact delta between two revisions of a design.

    Builds the system model on BASE and HEAD, diffs them, and renders a short,
    severity-ranked markdown comment: capabilities gained, findings and attack
    paths opened or closed, and the shift in worst-case blast radius. This is
    the engine behind the PR-review bot (examples/github-actions/security-delta.yml).
    """
    from attestral.delta import diff_models, render_delta_markdown
    from attestral.model import Severity

    delta = diff_models(build_model(base), build_model(head))
    markdown = render_delta_markdown(delta)
    if output:
        Path(output).write_text(markdown + "\n")
        click.echo(f"wrote {output}")
    else:
        click.echo(markdown)

    if fail_on:
        worst = delta.worst_new_severity()
        floor = Severity(fail_on).rank
        if worst is not None and worst.rank >= floor:
            click.echo(
                f"\nGate: this change introduces a new {worst.value} finding "
                f"(>= {fail_on}).", err=True)
            sys.exit(1)


@main.command(name="design-diff")
@click.argument("old_path", type=click.Path(exists=True))
@click.argument("new_path", type=click.Path(exists=True))
@click.option("--fail-on-widen", is_flag=True,
              help="Exit 3 when the change widens the agent's reach "
                   "(verdict WIDENED or MIXED) - the CI gate for PRs.")
@click.option("-o", "--output", default=None, metavar="FILE",
              help="Write the diff as JSON to FILE (nothing is written without it).")
def design_diff(old_path: str, new_path: str, fail_on_widen: bool,
                output: str | None) -> None:
    """Diff the capability envelope of two design revisions (the PR widen-gate).

    Builds the system model on OLD_PATH and NEW_PATH, runs the deterministic
    rule pass on both, and reports what the change did to the agent's reach:
    components added or removed, capabilities and standing credentials gained
    or dropped, cross-boundary edges opened or closed, and the rules that
    started or stopped firing - classified WIDENED / NARROWED / MIXED /
    UNCHANGED. Offline and deterministic (no ML, no LLM), so the gate is fast
    and reproducible. With --fail-on-widen, any widening exits 3: "this PR
    quietly widened what the agent can reach" becomes a red build.
    """
    from attestral.designdiff import GATE_VERDICTS, diff_designs, render_design_diff

    old_model, new_model = build_model(old_path), build_model(new_path)
    diff = diff_designs(old_model, new_model,
                        RuleEngine().evaluate(old_model),
                        RuleEngine().evaluate(new_model))
    click.echo(render_design_diff(diff))
    if output:
        Path(output).write_text(diff.to_json() + "\n")
        click.echo(f"wrote {output}")
    if fail_on_widen and diff.verdict in GATE_VERDICTS:
        click.echo(f"Gate: the change widens the agent's reach "
                   f"(verdict: {diff.verdict}).", err=True)
        sys.exit(3)


@main.command()
@click.argument("report", type=click.Path(exists=True))
@click.option("--public-key", type=click.Path(exists=True), default=None,
              help="Ed25519 public key (PEM) to check the report's signature against.")
def verify(report: str, public_key: str | None) -> None:
    """Verify a report's evidence chain: integrity always, authenticity if signed.

    The hash chain is checked with zero dependencies (integrity: no past entry
    was altered). If the report carries a signature and a --public-key is given,
    the signature is also verified (authenticity: this is the chain that signer
    sealed, not a recomputed forgery).
    """
    data = json.loads(Path(report).read_text())
    chain = data.get("chain", [])
    ok = verify_chain(chain)
    click.echo("chain VALID" if ok else "chain INVALID - report has been altered")
    if not ok:
        sys.exit(1)

    envelope = data.get("signature")
    if envelope and public_key:
        from attestral.evidence import GENESIS
        from attestral.signing import envelope_head, verify_envelope
        pub = Path(public_key).read_text()
        head = chain[-1]["hash"] if chain else GENESIS
        sig_ok = verify_envelope(envelope, pub)
        bound = envelope_head(envelope) == head
        if sig_ok and bound:
            click.echo("signature VALID - authentic, sealed by the key holder")
        elif sig_ok and not bound:
            click.echo("signature INVALID - signed a different chain head "
                       "(report altered after signing)", err=True)
            sys.exit(1)
        else:
            click.echo("signature INVALID - not signed by this key", err=True)
            sys.exit(1)
    elif envelope and not public_key:
        click.echo("(report is signed; pass --public-key to verify authenticity)")
    sys.exit(0)


@main.command()
@click.argument("report", type=click.Path(exists=True), required=False)
@click.option("--key", "key_path", type=click.Path(exists=True), default=None,
              help="Ed25519 private key (PEM) to sign with.")
@click.option("--gen-key", "gen_key", default=None, metavar="STEM",
              help="Generate a keypair to STEM.key + STEM.pub and exit.")
@click.option("--signer", default="", help="Identity to record in the signature.")
@click.option("-o", "--output", default=None, help="Write the signed report here (default: in place).")
@click.option("--rekor", "rekor_flag", is_flag=True,
              help="Anchor the signed head in Sigstore Rekor (a public transparency log "
                   "outside your control) and write the receipt to <output>.rekor.json. "
                   "Opt-in and online.")
@click.option("--rekor-url", default=None,
              help="Rekor instance to anchor to (default: https://rekor.sigstore.dev).")
def sign(report: str | None, key_path: str | None, gen_key: str | None,
         signer: str, output: str | None, rekor_flag: bool, rekor_url: str | None) -> None:
    """Sign a report's evidence-chain head (tamper-evident -> authentic).

    Wraps the chain head in a DSSE envelope signed with your Ed25519 key, so a
    tampered chain can no longer be re-sealed without the private key. Generate a
    keypair with --gen-key; verify a signed report with `attestral verify
    --public-key`.
    """
    from attestral.signing import generate_keypair, sign_head
    if gen_key:
        priv, pub = generate_keypair()
        Path(f"{gen_key}.key").write_text(priv)
        Path(f"{gen_key}.pub").write_text(pub)
        click.echo(f"wrote {gen_key}.key (private, keep secret) and {gen_key}.pub (public)")
        return
    if not report:
        raise click.UsageError("provide a REPORT.json to sign, or --gen-key to make a keypair.")
    if not key_path:
        raise click.UsageError("pass --key <private.pem> to sign (or --gen-key first).")
    from attestral.evidence import GENESIS
    data = json.loads(Path(report).read_text())
    chain = data.get("chain", [])
    if not verify_chain(chain):
        click.echo("refusing to sign: chain INVALID - report has been altered", err=True)
        sys.exit(1)
    head = chain[-1]["hash"] if chain else GENESIS
    data["signature"] = sign_head(head, len(chain), str(data.get("target", "")),
                                  Path(key_path).read_text(), signer=signer)
    out = output or report
    Path(out).write_text(json.dumps(data, indent=2))
    click.echo(f"signed {out}  ·  head {head[:16]}  ·  signer {signer or '(unnamed)'}")

    if rekor_flag:
        from attestral.rekor import DEFAULT_REKOR, anchor, receipt_line
        from attestral.signing import public_key_of
        try:
            receipt = anchor(data["signature"], public_key_of(Path(key_path).read_text()),
                             rekor_url=rekor_url or DEFAULT_REKOR)
        except Exception as exc:  # noqa: BLE001 - the network is the failure surface
            click.echo(f"Rekor anchoring FAILED - {exc}", err=True)
            sys.exit(1)
        Path(f"{out}.rekor.json").write_text(json.dumps(receipt, indent=2))
        click.echo(f"  {receipt_line(receipt)}")


@main.group()
def memory() -> None:
    """Signed memory provenance: bind a memory entry's trust label to its content.

    A trusted label an attacker can flip is no defense against memory poisoning.
    `memory sign` makes an entry's label part of an Ed25519-signed record; `memory
    verify` audits a store against a keyring of trusted writers, so a relabelled
    or tampered entry is caught cryptographically, not by hoping the label held.
    """


@memory.command("sign")
@click.option("--content", required=True, help="The memory entry's content.")
@click.option("--label", "trust_label", default="trusted", show_default=True,
              help="Trust label to bind to the content (trusted | system | untrusted).")
@click.option("--writer", required=True, help="The writer identity (a key in the keyring).")
@click.option("--key", "key_path", type=click.Path(exists=True), required=True,
              help="Ed25519 private key (PEM) to sign with.")
@click.option("--id", "entry_id", default="", help="Optional stable id for the entry.")
@click.option("-o", "--output", type=click.Path(), default=None,
              help="Append the signed entry (JSONL) here; default prints to stdout.")
def memory_sign(content: str, trust_label: str, writer: str, key_path: str,
                entry_id: str, output: str | None) -> None:
    """Sign one memory entry, binding its trust label to its content."""
    from attestral.memory import sign_entry
    entry = sign_entry(content, trust_label, writer, Path(key_path).read_text(), entry_id=entry_id)
    line = json.dumps(entry)
    if output:
        with open(output, "a") as fh:
            fh.write(line + "\n")
        click.echo(f"appended signed entry ({trust_label}, writer {writer}) to {output}")
    else:
        click.echo(line)


@memory.command("verify")
@click.argument("store", type=click.Path(exists=True))
@click.option("--keyring", "keyring_path", type=click.Path(exists=True), required=True,
              help="YAML of trusted writers -> public key (PEM or .pub path).")
@click.option("--fail-on-untrusted", is_flag=True,
              help="Exit non-zero if any entry fails its trust claim (CI/cron gate).")
def memory_verify(store: str, keyring_path: str, fail_on_untrusted: bool) -> None:
    """Audit a memory STORE (JSONL) against a keyring of trusted writers.

    Every entry that claims a trusted label must verify against its writer's key.
    A relabelled entry (MEM-001), an unknown writer (MEM-002), or a trust claim
    with no signature (MEM-003) is reported; untrusted entries are the safe
    default and pass silently.
    """
    from attestral.memory import audit_store, load_keyring, load_store
    entries = load_store(store)
    findings = audit_store(entries, load_keyring(keyring_path))
    for f in sorted(findings, key=lambda x: -x.severity.rank):
        click.echo(f"  [{f.severity.value.upper():8}] {f.rule_id}  {f.title}  ({f.component_id})")
        click.echo(f"           {f.description}")
    click.echo(f"{len(entries)} entries · {len(findings)} failed their trust claim")
    if findings and fail_on_untrusted:
        click.echo("MEMORY: an entry's trust label is not backed by a valid signature", err=True)
        sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--rule", "rule_id", default=None,
              help="Only show the remediation for this rule id (e.g. ATL-101).")
def remediate(path: str, rule_id: str | None) -> None:
    """Show the concrete source edit that clears each finding.

    For every finding, read the rule's matcher and the component's actual value
    and print the exact change to make in the source: a boolean flag to flip, a
    control to add, a bad value to replace, tied to the file it lives in. This
    is the source-side twin of `attestral fix`: `remediate` is the change to
    make in your config, `fix` is the runtime control that enforces it.
    """
    from attestral.reachability import annotate_reachability
    from attestral.remediate import render_remediations
    engine = RuleEngine()
    model = build_model(path)
    findings = engine.evaluate(model)
    annotate_reachability(model, findings)
    if rule_id:
        rid = rule_id.strip().upper()
        findings = [f for f in findings if f.rule_id == rid]
        if not findings:
            click.echo(f"{rid} does not fire on this design - nothing to remediate.", err=True)
            sys.exit(1)
    click.echo(render_remediations(model, findings, engine.rules))


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--rule", "rule_id", default=None,
              help="Only compile the fix for this rule id (e.g. ATL-103).")
@click.option("-o", "--output", default=None,
              help="Write the merged fix controls to this mcp-guard policy file.")
@click.option("--broker-output", "broker_output", default=None,
              help="Write the CB4A broker routes that replace the stripped "
                   "standing credentials to this agentgateway config file.")
def fix(path: str, rule_id: str | None, output: str | None,
        broker_output: str | None) -> None:
    """Compile the enforceable control that neutralizes each finding.

    For every active finding, emit the exact mcp-guard control that closes it,
    an explanation, and a verification verdict (re-synthesized over the model,
    or enforced at the proxy), bound to the review's evidence-chain head. A
    remediation that is also an enforceable runtime control is the payoff of the
    attest-compile-drift loop. Standing-credential findings compile to a
    broker-backed fix: the exact env keys to strip plus the CB4A route that
    replaces them (`--broker-output` writes the routes as one agentgateway
    config). `--rule` narrows to one rule; `-o` writes the merged controls as a
    policy slice you can hand to mcp-guard.
    """
    from attestral.fix import broker_plans_for, fixes_for, render_fixes
    from attestral.reachability import annotate_reachability
    model = build_model(path)
    findings = RuleEngine().evaluate(model)
    annotate_reachability(model, findings)
    if rule_id:
        rid = rule_id.strip().upper()
        findings = [f for f in findings if f.rule_id == rid]
        if not findings:
            click.echo(f"{rid} does not fire on this design - nothing to fix.", err=True)
            sys.exit(1)
    chain = audit_chain(findings)
    head = chain[-1]["hash"] if chain else ""
    click.echo(render_fixes(model, findings, chain_head=head))
    if broker_output:
        from attestral.broker import render_broker_config
        plans = broker_plans_for(fixes_for(model, findings, head))
        if plans:
            Path(broker_output).write_text(render_broker_config(plans))
            click.echo(f"\nwrote {broker_output} - agentgateway broker route(s) "
                       f"replacing the stripped credentials ({len(plans)} route(s))")
        else:
            click.echo("\nno standing-credential fixes here - no broker config "
                       "to write.")
    if output:
        import yaml as _yaml
        fixes = fixes_for(model, findings, head)
        merged: dict = {"version": 1, "compiled_from": {"target": path, "chain_head": head},
                        "servers": {}, "session_policy": {}}
        for fx in fixes:
            for name, entry in fx.control.get("servers", {}).items():
                merged["servers"].setdefault(name, {}).update(entry)
            if "session_policy" in fx.control:
                merged["session_policy"].setdefault(fx.rule_id, fx.control["session_policy"])
        Path(output).write_text(_yaml.safe_dump(merged, sort_keys=False))
        click.echo(f"wrote {output}  ·  {len(fixes)} enforceable fix control(s)")


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("-o", "--output", default=None,
              help="Policy output file (defaults to the target's own filename).")
@click.option("--target", type=click.Choice(COMPILE_TARGETS), default="mcp-guard",
              help="Output format: mcp-guard (default, drift-enforced), cedar (an AWS "
                   "Cedar authorization policy), agentgateway (a CB4A broker config), or "
                   "claude-managed (Claude Code enterprise-managed MCP config: managed-mcp.json "
                   "+ managed-settings.json, deployed via MDM), or copilot-registry (a GitHub "
                   "Copilot internal MCP registry v0.1 catalog for 'Registry only' mode). Cedar, "
                   "claude-managed, and copilot-registry are lossy and one-way: not a valid "
                   "--against prior and attestral drift cannot read them.")
@click.option("--against", "prior", type=click.Path(exists=True), default=None,
              help="A prior policy to verify this re-attestation narrows. Exits "
                   "non-zero on an expansion (a widening the review must approve). "
                   "Requires an mcp-guard YAML prior; a .cedar file is not parseable back.")
@click.option("--verify", "verify", is_flag=True,
              help="Prove security properties over the compiled policy (no secret "
                   "exfiltration, no code-exec egress, default-deny, TLS-only), with "
                   "a counterexample for any that fail.")
@click.option("--fail-on-violation", "fail_on_violation", is_flag=True,
              help="Implies --verify: exit non-zero if any security property is "
                   "violated (CI gate).")
def compile(path: str, output: str | None, target: str, prior: str | None,
            verify: bool, fail_on_violation: bool) -> None:
    """Compile PATH's attested design into a runtime policy (mcp-guard or Cedar)."""
    from attestral.compile import compile_policy
    from attestral.reachability import annotate_reachability
    model = build_model(path)
    findings = RuleEngine().evaluate(model)
    # The policy must see the same severities a scan reports: a finding raised
    # to critical by a reachable chain denies its server here too.
    annotate_reachability(model, findings)
    chain = audit_chain(findings)
    head = chain[-1]["hash"] if chain else ""
    policy = compile_policy(model, findings, chain_head=head)
    allowed = sum(1 for s in policy["servers"].values() if s["allow"])
    denied = len(policy["servers"]) - allowed
    if target == "claude-managed":
        from attestral.compile import CLAUDE_MANAGED_PATHS, compile_claude_managed
        files = compile_claude_managed(model, policy)
        outdir = Path(output) if output else Path.cwd()
        outdir.mkdir(parents=True, exist_ok=True)
        for fname, text in files.items():
            (outdir / fname).write_text(text)
        click.echo(f"wrote {outdir}/managed-mcp.json + {outdir}/managed-settings.json  ·  "
                   f"target claude-managed  ·  default deny  ·  {allowed} allowed, {denied} denied")
        click.echo("  managed-mcp.json is the enforcing file (Claude Code loads ONLY these "
                   "servers, and refuses `claude mcp add`); managed-settings.json adds the "
                   "allowlist keyed on serverUrl/serverCommand plus disableSideloadFlags.")
        click.echo("  deploy via MDM to " + CLAUDE_MANAGED_PATHS["macOS"] + " (macOS), "
                   + CLAUDE_MANAGED_PATHS["Linux"] + " (Linux), or "
                   + CLAUDE_MANAGED_PATHS["Windows"] + " (Windows).")
    elif target == "copilot-registry":
        from attestral.compile import compile_copilot_registry
        out = output or "copilot-mcp-registry.json"
        Path(out).write_text(compile_copilot_registry(model, policy))
        click.echo(f"wrote {out}  ·  target copilot-registry  ·  default deny  ·  "
                   f"{allowed} allowed, {denied} denied")
        click.echo("  serve this as GET /v0.1/servers, set your Copilot 'MCP Registry URL' to the "
                   "host (Copilot appends /v0.1 itself), and choose enforcement 'Registry only'.")
        click.echo("  the host must send CORS (Access-Control-Allow-Origin: *) and answer the same "
                   "wrapped entry at /v0.1/servers/{name}/versions/latest. Copilot enforces by "
                   "server name (exact match); denied servers are simply absent.")
    else:
        renderer, default_out = TARGETS[target]
        out = output or default_out
        Path(out).write_text(renderer(policy))
        click.echo(f"wrote {out}  ·  target {target}  ·  default deny  ·  "
                   f"{allowed} allowed, {denied} denied")
    for name, s in policy["servers"].items():
        mark = "ALLOW" if s["allow"] else "DENY "
        why = "" if s["allow"] else f"  ({s.get('reason','')})"
        click.echo(f"  [{mark}] {name}{why}")

    if prior:
        import yaml as _yaml

        from attestral.narrowing import classify
        result = classify(_yaml.safe_load(Path(prior).read_text()) or {}, policy)
        label = {"narrowing": "NARROWING", "equal": "UNCHANGED",
                 "expansion": "EXPANSION"}[result.overall]
        click.echo(f"\nre-attestation vs {prior}: {label}", err=result.is_expansion)
        if result.is_expansion:
            click.echo("  this design grants more ambient capability than the "
                       "reviewed one; a human must approve it before it runs:", err=True)
            for e in result.expansions:
                click.echo(f"    + {e}", err=True)
            sys.exit(1)
        for v in result.servers:
            if v.narrowings:
                click.echo(f"  - {v.name}: {'; '.join(v.narrowings)}")

    if verify or fail_on_violation:
        from attestral.policy_verify import render_verification, verify_policy
        results = verify_policy(policy)
        click.echo("")
        click.echo(render_verification(results))
        if fail_on_violation and any(not r.holds for r in results):
            violated = ", ".join(r.name for r in results if not r.holds)
            click.echo(f"\nGate: security propert(ies) violated: {violated}", err=True)
            sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("-o", "--output", default=None,
              help="Write the generated agentgateway credential-broker config to "
                   "this file. Without it, the plan prints only.")
def broker(path: str, output: str | None) -> None:
    """Strip standing credentials and generate a per-call credential broker for PATH.

    For every MCP server that holds a secret in its environment, prints the exact
    keys to remove and the CB4A Model A broker route (a strict-auth, per-call,
    provider-scoped token) that replaces them, so the agent process holds no
    reusable key. With -o, writes the generated agentgateway broker config.
    Terminal-first: nothing is written without -o.
    """
    from attestral.broker import broker_plans, render_broker_config, render_broker_plan
    model = build_model(path)
    click.echo(render_broker_plan(model))
    if output:
        plans = broker_plans(model)
        if plans:
            Path(output).write_text(render_broker_config(plans))
            click.echo(f"\nwrote {output} - agentgateway credential-broker config "
                       f"({len(plans)} route(s), default-deny)")


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("-o", "--output", default=None,
              help="Write the chaos report JSON here. Terminal-first: nothing is written without -o.")
@click.option("--fail-on-miss", is_flag=True,
              help="Exit non-zero if any DETERMINISTIC poisoning attack slips through (CI robustness gate). "
                   "Generated attacks never gate here - use --fail-on-generated-miss for those.")
@click.option("--generate", is_flag=True,
              help="Add an LLM-authored attack tier: propose novel poisoning payloads against this "
                   "design's own surfaces and run them through the same loop. Opt-in, needs ANTHROPIC_API_KEY.")
@click.option("--generate-count", default=5, show_default=True,
              help="How many payloads the --generate tier authors.")
@click.option("--fail-on-generated-miss", is_flag=True,
              help="Also gate on LLM-generated misses (off by default - generated attacks are exploratory, "
                   "not a stable CI floor).")
def chaos(path: str, output: str | None, fail_on_miss: bool, generate: bool,
          generate_count: int, fail_on_generated_miss: bool) -> None:
    """Simulate poisoning attacks against PATH's design and report what the review catches.

    Chaos engineering for agents: applies a deterministic library of poisoning
    mutations (smuggle a shell tool, inject a prompt-injection tool description,
    poison a schema with an external $ref, flip a pin to @latest, add a
    secret-holding server) to a copy of the attested model, re-runs Attestral's
    own rules and ML injection tier over each mutant, and reports CAUGHT vs
    slipped-through. Offline and deterministic - no API key, no eval.

    `--generate` layers on an optional LLM tier that authors NOVEL payloads
    against this design's own tool/server surfaces (opt-in, needs
    ANTHROPIC_API_KEY); each generated payload is recorded verbatim so a
    slip-through is reproducible. The deterministic library stays the CI-stable
    floor: generated misses do not fail the gate unless --fail-on-generated-miss.
    """
    from attestral.chaos import chaos_report, generate_attacks, render_chaos, run_chaos
    model = build_model(path)
    extra = generate_attacks(model, generate_count) if generate else []
    if generate and not extra:
        click.echo("Generator tier produced no payloads: set ANTHROPIC_API_KEY and install "
                   "the anthropic extra (`pip install attestral[llm]`).", err=True)
    results = run_chaos(model, extra_attacks=extra)
    click.echo(render_chaos(results))
    if output:
        Path(output).write_text(json.dumps(chaos_report(results), indent=2))
        click.echo(f"\nwrote {output}")
    gated = [r for r in results if not r.caught
             and (not r.attack.generated or fail_on_generated_miss)]
    if fail_on_miss and gated:
        missed = ", ".join(r.attack.id for r in gated)
        click.echo(f"\nGate: simulated attack(s) slipped through: {missed}", err=True)
        sys.exit(1)


@main.command()
@click.argument("policy_file", type=click.Path(exists=True))
@click.argument("events_file", type=click.Path(exists=True), required=False)
@click.option("--fail-on-drift", is_flag=True, help="Exit non-zero on any drift (CI/cron gate).")
@click.option("--stdin", "use_stdin", is_flag=True,
              help="Run as a continuous sidecar: read JSONL events from stdin (a live "
                   "mcp-guard telemetry pipe) and stream drift as it happens.")
@click.option("--watch", is_flag=True,
              help="Run as a continuous sidecar: tail EVENTS_FILE and stream drift as new "
                   "events are appended. Runs until interrupted.")
@click.option("--remediate", is_flag=True,
              help="PROPOSE the minimal policy-tightening delta that would have prevented "
                   "each drift finding (quarantine the offending server), for both compiled "
                   "targets. Proposed only - a human reviews and re-compiles; it never widens.")
@click.option("--lockdown", "lockdown_flag", is_flag=True,
              help="ACT: emit an instant containment - the enforcement policy with every "
                   "drifted server quarantined - plus a machine-consumable lockdown record. "
                   "Carries a narrowing proof (only removes capability), so a responder can "
                   "auto-apply it. Exits 2 when a lockdown is emitted (the responder signal).")
@click.option("--enforce", "enforce_path", type=click.Path(), default=None,
              help="The LIVE enforcement policy file - the path a running mcp-guard reads. "
                   "With --lockdown, every narrowing-verified lockdown is pushed here "
                   "atomically (temp file + rename) and journaled to a hash-chained "
                   "<ENFORCE>.journal.jsonl. A lockdown that would widen is refused and "
                   "never written.")
@click.option("--reload-cmd", default=None,
              help="Command run after each successful push to --enforce (e.g. a container "
                   "HUP so the guard re-reads its policy). Run without a shell; a non-zero "
                   "exit or failed spawn is a warning line, never fatal to the monitor.")
@click.option("--replay", "replay_flag", is_flag=True,
              help="Post-incident forensics: reconstruct WHEN the runtime diverged - each "
                   "finding pinned to the event ordinal and timestamp where it crossed - "
                   "and what contained it, as a chronological timeline plus honest summary "
                   "stats (first drift, drift-to-containment gap, final state).")
@click.option("--journal", "journal_file", type=click.Path(exists=True), default=None,
              help="With --replay: the hash-chained containment journal "
                   "(<ENFORCE>.journal.jsonl) to merge into the timeline. The chain is "
                   "verified first; a tampered journal is a headline of the "
                   "reconstruction and earns no containment credit, never trusted.")
@click.option("-o", "--output", default=None,
              help="With --remediate: write the re-emitted mcp-guard policy here plus a "
                   "sibling .cedar. With --lockdown: write <stem>.lockdown.yaml (the policy "
                   "to apply) and <stem>.lockdown.json (the record); streaming without "
                   "--enforce keeps the journal at <stem>.lockdown.journal.jsonl. With "
                   "--replay: write the JSON incident record here. Nothing is written "
                   "without -o or --enforce.")
def drift(policy_file: str, events_file: str | None, fail_on_drift: bool,
          use_stdin: bool, watch: bool, remediate: bool, lockdown_flag: bool,
          enforce_path: str | None, reload_cmd: str | None, replay_flag: bool,
          journal_file: str | None, output: str | None) -> None:
    """Diff runtime events against a compiled POLICY_FILE.

    Batch (default): diff every event in EVENTS_FILE at once. Continuous:
    `--stdin` reads a live telemetry pipe and `--watch` tails EVENTS_FILE, both
    streaming drift the moment it happens - the review, checked at every
    invocation. Rug-pulls (a served tool schema that no longer matches the
    attested manifest) and budget overruns fire once, when they cross.

    `--remediate` closes the loop: a drift finding means the runtime diverged from
    the reviewed design, so it PROPOSES the minimal tightening that would have
    prevented each finding (quarantine the offending server toward denial) and
    re-emits it to both mcp-guard and Cedar. It only ever narrows the policy; it
    never widens the design to match the drift, so a compromised runtime cannot
    drive its own policy. Proposed only - a human approves and re-compiles.

    `--lockdown --enforce` closes it LIVE: in streaming mode, each time the
    quarantine set grows, the narrowing-verified lockdown is pushed atomically to
    the enforcement policy the guard reads, journaled to a hash-chained
    <ENFORCE>.journal.jsonl, and `--reload-cmd` (if given) is run so the guard
    picks it up. Detection never moves: every event is still evaluated against
    the ORIGINAL attested POLICY_FILE, so drift is always measured against the
    reviewed design while enforcement only ever narrows the runtime. A lockdown
    that fails the narrowing proof is REFUSED and journaled, never pushed, and
    the monitor keeps running.

    `--replay` looks BACKWARD: incident forensics over a recorded stream. Every
    event replays through a fresh monitor so each finding lands at the exact
    ordinal (and timestamp) where it crossed, the containment journal
    (`--journal`) merges into the same timeline with its hash chain verified
    first, and the summary answers the responder's questions: when did it
    diverge, how long until containment, does the journal hold, and did the run
    end CONFORM, DRIFTED, or CONTAINED. Terminal-first; `-o` writes the JSON
    incident record.
    """
    import yaml as _yaml
    from attestral.drift import (DriftMonitor, detect_drift, load_events,
                                 load_jsonl, render_replay, replay_drift)
    if enforce_path and not lockdown_flag:
        raise click.UsageError("--enforce only acts on lockdowns; pass --lockdown as well.")
    if reload_cmd and not enforce_path:
        raise click.UsageError("--reload-cmd fires after a push to --enforce; pass --enforce.")
    if replay_flag and (use_stdin or watch or remediate or lockdown_flag):
        raise click.UsageError("--replay is post-incident forensics over a recorded "
                               "stream; it cannot combine with --watch, --stdin, "
                               "--remediate, or --lockdown.")
    if journal_file and not replay_flag:
        raise click.UsageError("--journal merges the containment trail into --replay; "
                               "pass --replay as well.")
    policy = _yaml.safe_load(Path(policy_file).read_text())

    if replay_flag:
        if not events_file:
            raise click.UsageError("--replay needs EVENTS_FILE - the recorded stream "
                                   "to reconstruct.")
        events, bad_events = load_jsonl(events_file)
        journal_entries, bad_journal = (load_jsonl(journal_file)
                                        if journal_file else (None, 0))
        replay = replay_drift(policy, events, journal_entries,
                              malformed_events=bad_events,
                              malformed_journal_lines=bad_journal)
        click.echo(render_replay(replay))
        if output:
            Path(output).write_text(json.dumps(replay.as_dict(), indent=2))
            click.echo(f"\nwrote {output} - JSON incident record")
        if fail_on_drift and replay.summary["findings"]:
            click.echo("DRIFT: deployment no longer matches the attested design", err=True)
            sys.exit(1)
        return

    def _emit(f) -> None:
        click.echo(f"  [{f.severity.value.upper():8}] {f.rule_id}  {f.title}  ({f.component_id})")

    def _run_reload() -> None:
        """Run the --reload-cmd hook after a successful push. Never fatal: a
        non-zero exit or a failed spawn is a warning line and the monitor
        continues - containment must not die on a flaky hook."""
        if not reload_cmd:
            return
        import shlex
        import subprocess
        try:
            proc = subprocess.run(shlex.split(reload_cmd), check=False)
            if proc.returncode != 0:
                click.echo(f"  warning: --reload-cmd exited {proc.returncode} "
                           "(monitor continues)", err=True)
        except (OSError, ValueError) as exc:
            click.echo(f"  warning: --reload-cmd failed to start: {exc} "
                       "(monitor continues)", err=True)

    if use_stdin or watch:
        monitor = DriftMonitor(policy)
        seen = drifts = 0
        stream_findings: list = []      # every drift finding seen so far, accumulated
        last_pushed: set[str] | None = None
        last_refused: set[str] | None = None
        pushed_any = False
        gate_tripped = False

        journal_path = None
        if lockdown_flag:
            if enforce_path:
                journal_path = Path(f"{enforce_path}.journal.jsonl")
            elif output:
                journal_path = Path(f"{output}.lockdown.journal.jsonl")
            # neither --enforce nor -o: terminal-first, nothing is written.

        def _contain(new_findings) -> None:
            """Rebuild the lockdown from every finding seen so far and act only
            when the quarantine set changed. Drift is still measured against the
            ORIGINAL attested policy (the monitor never re-reads the enforcement
            file); enforcement only ever narrows the runtime."""
            nonlocal last_pushed, last_refused, pushed_any
            from attestral.lockdown import (build_lockdown, journal_append,
                                            lockdown_journal_entry, push_lockdown)
            stream_findings.extend(new_findings)
            lock = build_lockdown(policy, stream_findings)
            if not lock.triggered:
                return
            qset = set(lock.quarantined)
            names = ", ".join(lock.quarantined)
            if not lock.safe_to_apply:
                # Fail-closed: never widen, never die. Journal the refusal and
                # keep monitoring.
                if qset != last_refused:
                    last_refused = qset
                    click.echo(f"  REFUSED lockdown of {names}: the tightening would "
                               "widen the policy - not pushed, monitoring continues")
                    if journal_path:
                        journal_append(journal_path,
                                       lockdown_journal_entry(policy, lock, "refused"))
                return
            if qset == last_pushed:
                return  # idempotent: the same offenders re-drifting is one push
            last_pushed = qset
            pushed_any = True
            if enforce_path:
                push_lockdown(lock, enforce_path)
                click.echo(f"  LOCKDOWN pushed: quarantined {names} -> {enforce_path}")
            else:
                click.echo(f"  LOCKDOWN pushed: quarantined {names} "
                           "(no --enforce target - responder signal only)")
            if journal_path:
                journal_append(journal_path, lockdown_journal_entry(policy, lock, "push"))
            if enforce_path:
                _run_reload()

        def _feed(lines):
            nonlocal seen, drifts, gate_tripped
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                seen += 1
                new = monitor.observe(ev)
                for f in new:
                    drifts += 1
                    _emit(f)
                if not new:
                    continue
                if lockdown_flag:
                    _contain(new)
                if fail_on_drift:
                    if lockdown_flag:
                        # The sidecar's job is containment: note the gate, keep
                        # monitoring, settle the exit code at stream end.
                        gate_tripped = True
                    else:
                        click.echo("DRIFT: deployment no longer matches the attested design", err=True)
                        sys.exit(1)

        if use_stdin:
            _feed(sys.stdin)
            click.echo(f"{seen} events · {drifts} drift findings (stream ended)", err=True)
            if pushed_any:
                sys.exit(2)  # the responder signal, same as batch --lockdown
            if gate_tripped:
                click.echo("DRIFT: deployment no longer matches the attested design", err=True)
                sys.exit(1)
        else:
            import time
            click.echo(f"watching {events_file} for drift (Ctrl-C to stop)…", err=True)
            with open(events_file) as fh:
                fh.seek(0, 2)  # tail: start at end, only new appends
                while True:
                    line = fh.readline()
                    if line:
                        _feed([line])
                    else:
                        time.sleep(0.5)
        return

    if not events_file:
        raise click.UsageError("provide EVENTS_FILE, or use --stdin for a live pipe.")
    events = load_events(events_file)
    findings = detect_drift(policy, events)
    for f in findings:
        _emit(f)
    click.echo(f"{len(events)} events · {len(findings)} drift findings")

    if remediate:
        from attestral.compile import render_cedar, render_policy_yaml
        from attestral.drift import remediate_drift
        from attestral.narrowing import classify
        tightened, delta = remediate_drift(policy, findings)
        result = classify(policy, tightened)
        click.echo(
            "\nPROPOSED tightening - a human reviews and re-compiles. A drift finding "
            "means the runtime diverged from the reviewed design, so this only ever "
            "narrows the policy toward denial (quarantine the offending server); it "
            "never widens the design to match the drift. A compromised runtime cannot "
            "drive its own policy."
        )
        for op in delta:
            before = "absent" if op["before_allow"] is None else str(op["before_allow"])
            click.echo(f"  PROPOSE {op['drf_id']}  {op['server']}: "
                       f"allow {before}->{op['after_allow']}  ({op['reason']})")
            if op["note"]:
                click.echo(f"    note: {op['note']}")
        if not delta:
            click.echo("  no drift to remediate - the policy is unchanged")
        click.echo(f"  narrowing check: {result.overall}")
        if result.is_expansion:
            click.echo("REFUSING: proposal would widen the policy", err=True)
            sys.exit(1)
        if output:
            Path(output).write_text(render_policy_yaml(tightened))
            cedar_out = Path(output).with_suffix(".cedar")
            cedar_out.write_text(render_cedar(tightened))
            click.echo(f"  wrote {output}  ·  {cedar_out}")

    if lockdown_flag:
        from attestral.compile import render_policy_yaml
        from attestral.lockdown import (build_lockdown, journal_append,
                                        lockdown_journal_entry, lockdown_record,
                                        push_lockdown, render_lockdown)
        lock = build_lockdown(policy, findings)
        click.echo("")
        click.echo(render_lockdown(lock))
        journal_path = Path(f"{enforce_path}.journal.jsonl") if enforce_path else None
        if lock.triggered and not lock.safe_to_apply:
            # Fail-closed: a lockdown that would widen the policy is never emitted.
            if journal_path:
                journal_append(journal_path, lockdown_journal_entry(policy, lock, "refused"))
            sys.exit(1)
        if output and lock.triggered:
            enforce = Path(f"{output}.lockdown.yaml")
            enforce.write_text(render_policy_yaml(lock.policy))
            record = Path(f"{output}.lockdown.json")
            record.write_text(json.dumps(lockdown_record(policy, lock), indent=2))
            click.echo(f"  wrote {enforce}  ·  {record}")
        if enforce_path and lock.triggered:
            push_lockdown(lock, enforce_path)
            click.echo(f"  LOCKDOWN pushed: quarantined {', '.join(lock.quarantined)} "
                       f"-> {enforce_path}")
            journal_append(journal_path, lockdown_journal_entry(policy, lock, "push"))
            _run_reload()
        if lock.triggered:
            # The lockdown signal a responder / CI acts on (distinct from the
            # generic drift gate exit 1), so an orchestrator can apply the policy.
            sys.exit(2)

    if findings and fail_on_drift:
        click.echo("DRIFT: deployment no longer matches the attested design", err=True)
        sys.exit(1)


@main.command(context_settings={"ignore_unknown_options": True})
@click.argument("policy_file", type=click.Path(exists=True))
@click.option("--server", "server", required=True,
              help="Which attested server this proxy fronts (the key in the compiled "
                   "policy). A server absent from the design, or one the review denied, "
                   "never launches.")
@click.option("--telemetry", "telemetry", type=click.Path(), default=None,
              help="Append the decision journal here as JSONL (default: "
                   "<POLICY_FILE>.telemetry.jsonl). This is the event stream "
                   "`attestral drift`, `lockdown`, and `incident` consume.")
@click.option("--observe", "observe", is_flag=True,
              help="Dry-run: record the verdict every call WOULD get, but forward it "
                   "anyway. Run this first to see what enforcement would block before "
                   "you switch it on.")
@click.option("--print-config", "print_config", is_flag=True,
              help="Do not run. Print the `.mcp.json` server stanza that reroutes this "
                   "server through the guard, so installing enforcement is a one-line "
                   "config rewrite the MCP client already understands.")
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
def guard(policy_file: str, server: str, telemetry: str | None, observe: bool,
          print_config: bool, command: tuple) -> None:
    """Enforce a compiled POLICY_FILE as a stdio MCP proxy in front of COMMAND.

    The enforcement point the loop was missing. `compile` writes the default-deny
    policy and `drift` reads runtime events back against it; `guard` sits in the
    live path between an MCP client and the server it wraps and makes the verdict
    bite. A server the review DENIED (or one absent from the attested design)
    never starts. Every `tools/call` is judged - by the SAME function `drift`
    uses, so the guard blocks exactly what drift would flag - and a call that
    escapes the attested filesystem roots or downgrades a TLS-only transport is
    refused with a JSON-RPC error before it reaches the server. Every decision,
    plus the live tool surface seen on `tools/list`, is appended to the telemetry
    JSONL, so the guard is also the runtime loop's first real event source.

    Put it in front of a server by wrapping its launch command:

        attestral guard policy.yaml --server files -- npx @modelcontextprotocol/server-filesystem /srv

    or let `--print-config` write the wrapped `.mcp.json` stanza for you. Standard
    library only; no new dependency. Exit code: 3 if the server was refused at
    load, 2 if the session ran but at least one call was blocked, else the wrapped
    server's own code.
    """
    from attestral.guard import (default_telemetry_path, load_policy, run_guard,
                                  wrapped_config_stanza)
    cmd = list(command)
    # Click leaves a leading `--` separator in COMMAND; drop it so the real
    # launch argv starts at the program name.
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    policy = load_policy(policy_file)

    if print_config:
        if not cmd:
            raise click.UsageError("--print-config needs the wrapped command after --.")
        stanza = wrapped_config_stanza(policy_file, server, cmd)
        click.echo(json.dumps({"mcpServers": stanza}, indent=2))
        return

    if not cmd:
        raise click.UsageError(
            "Give the server launch command after `--`, e.g. "
            "`attestral guard policy.yaml --server files -- npx server-filesystem /srv`.")
    tpath = telemetry or default_telemetry_path(policy_file)
    code = run_guard(policy, server, cmd, telemetry_path=tpath, enforce=not observe)
    sys.exit(code)


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("-o", "--output", default=None,
              help="Write the reachability report (<stem>.md) and evidence chain (<stem>.json).")
@click.option("--fail-on-reachable", "--fail-on-proof", "fail_on_proof", is_flag=True,
              help="Exit non-zero if any attack path is reachable in the modeled design (CI gate). "
                   "(--fail-on-proof is a deprecated alias.)")
@click.option("--remediate", is_flag=True,
              help="Show the minimal fix for each reachable path, each verified by re-synthesis.")
@click.option("--action-space", "action_space_flag", is_flag=True,
              help="Enumerate the tool-call sequences the fleet can be induced into.")
@click.option("--generate", is_flag=True,
              help="Tier 1: an LLM drafts the predicted exploit per path (needs an API key). Never executed.")
@click.option("--execute", is_flag=True,
              help="Tier 2: replay each reachable path through Attestral's sandbox harness with a planted canary. No live target.")
@click.option("--proof-of-exploit", "proof_of_exploit", is_flag=True,
              help="Ship a proof-of-exploit per reachable path: a narrated scenario "
                   "validated against the model (no hallucinated hops) plus a gated "
                   "test asserting the path exists. With -o, writes the tests.")
def validate(path: str, output: str | None, fail_on_proof: bool, remediate: bool,
             action_space_flag: bool, generate: bool, execute: bool,
             proof_of_exploit: bool) -> None:
    """Check which attack paths in PATH's attested design are reachable.

    Symbolic tier: walks each assembled attack path over the model's own edges,
    with no execution and no network, and commits each reachable path to the
    evidence chain. Reachability is computed over declared capability (a sound
    over-approximation) and is a necessary, not sufficient, condition for
    exploitation - the report states this assumption. --remediate shows the fix
    verified to close the path; --action-space enumerates the inducible
    sequences; --generate drafts the predicted (never executed) exploit.
    """
    from attestral import redteam
    from attestral.report_terminal import render_proofs
    model = build_model(path)
    proofs = redteam.build_proofs(model)
    click.echo(render_proofs(proofs))

    if action_space_flag:
        block = redteam.render_action_space(model)
        if block:
            click.echo("")
            click.echo(block)
    if remediate:
        block = redteam.render_remediations(model)
        if block:
            click.echo("")
            click.echo(block)
    if generate:
        click.echo("")
        click.echo("drafting predicted exploits (tier 1)…", err=True)
        click.echo(redteam.render_exploits(model))
    if execute:
        click.echo("")
        click.echo("replaying paths through the sandbox harness (tier 2)…", err=True)
        click.echo(redteam.render_execution(model))
    if proof_of_exploit:
        from attestral.selfplay import proofs_of_exploit, render_proofs_of_exploit
        poe = proofs_of_exploit(model, path)
        block = render_proofs_of_exploit(model, path, proofs=poe)
        if block:
            click.echo("")
            click.echo(block)
            if output:
                test_path = Path(f"{output}_proof.py")
                test_path.write_text("\n\n".join(p.test_source for p in poe))
                click.echo(f"  wrote {test_path}", err=True)
    if output:
        findings = [p.to_finding() for p in proofs]
        Path(f"{output}.md").write_text(render_markdown(model, findings, path))
        Path(f"{output}.json").write_text(
            json.dumps({"target": path, "chain": audit_chain(findings)}, indent=2)
        )
        click.echo(f"wrote {output}.md · {output}.json")
    if fail_on_proof and proofs:
        click.echo("REACHABLE: at least one exploit path is traversable in the "
                   "modeled design", err=True)
        sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--runtime", "runtime_events", type=click.Path(exists=True), default=None,
              help="A JSONL runtime event stream to bind (and re-run drift over on --verify).")
@click.option("--key", "key_path", type=click.Path(exists=True), default=None,
              help="Ed25519 private key (PEM) to sign the attestation with.")
@click.option("--gen-key", "gen_key", default=None, metavar="STEM",
              help="Generate a keypair to STEM.key + STEM.pub and sign with it.")
@click.option("--signer", default="", help="Identity to record in the attestation.")
@click.option("--verify", "do_verify", is_flag=True,
              help="Verify an existing attestation against PATH (recompute every digest offline).")
@click.option("--public-key", type=click.Path(exists=True), default=None,
              help="Ed25519 public key (PEM) to check the attestation's signature against (--verify).")
@click.option("-o", "--output", default="attestation.json",
              help="Attestation bundle file (default: attestation.json).")
@click.option("--log", "log_path", type=click.Path(), default=None, metavar="LOG",
              help="Append the attestation to an append-only transparency log at LOG "
                   "(with --verify: check the log's history and this bundle's inclusion).")
@click.option("--rekor", "rekor_flag", is_flag=True,
              help="Anchor a SIGNED attestation in Sigstore Rekor, a public transparency "
                   "log outside your control, and write the receipt to <output>.rekor.json. "
                   "Opt-in and online. With --verify: check the receipt binds this attestation.")
@click.option("--rekor-url", default=None,
              help="Rekor instance to anchor to (default: https://rekor.sigstore.dev).")
def attest(path: str, runtime_events: str | None, key_path: str | None, gen_key: str | None,
           signer: str, do_verify: bool, public_key: str | None, output: str,
           log_path: str | None, rekor_flag: bool, rekor_url: str | None) -> None:
    """Produce or verify a signed conformance attestation for PATH.

    An attestation binds, in one DSSE-signed in-toto Statement: the reviewed
    design (model hash), the review chain head, a digest and severity summary of
    the findings, the hash of BOTH compiled policies (mcp-guard + Cedar), and,
    with --runtime, a digest of the events plus the drift verdict. `--verify`
    recomputes every digest offline from the supplied design (and re-runs drift on
    the supplied events) and checks the signature, so any tamper - a changed
    design, a swapped policy, a doctored event stream - makes verification FAIL.

    This is a TAMPER-EVIDENT, SIGNATURE-BASED CONFORMANCE ATTESTATION, not a proof
    that the design is safe. It proves the runtime observed matches the design
    reviewed and the policies compiled from it, nothing more.
    """
    from attestral.attest import build_bundle, verify_bundle
    from attestral.drift import load_events
    from attestral.signing import generate_keypair

    events = load_events(runtime_events) if runtime_events else None

    if do_verify:
        bundle = json.loads(Path(output).read_text())
        pub = Path(public_key).read_text() if public_key else None
        ok, failures = verify_bundle(bundle, path, events=events, public_pem=pub)
        pred = (bundle.get("statement") or {}).get("predicate") or {}
        runtime = pred.get("runtime") or {}
        if ok:
            click.echo("attestation CONFORMING - the supplied design, policies, and "
                       "runtime match what was attested")
            if runtime:
                rules = ", ".join(runtime.get("driftRules", [])) or "-"
                click.echo(f"  runtime verdict: {runtime.get('verdict', '-')} "
                           f"({'drift ' + rules if runtime.get('driftRules') else 'no drift'})")
            if public_key is None:
                click.echo("  (signature not checked; pass --public-key to verify authenticity)")
            if log_path:
                from attestral.translog import (
                    bundle_digest, find_entry, inclusion_proof, read_log,
                    verify_inclusion, verify_log,
                )
                try:
                    entries = read_log(log_path)
                    lok, lfail = verify_log(entries)
                except ValueError as exc:
                    lok, lfail = False, [str(exc)]
                if not lok:
                    click.echo(f"transparency log FAILED - {lfail[0]}", err=True)
                    sys.exit(1)
                entry = find_entry(entries, bundle_digest(bundle))
                if entry is None:
                    click.echo("transparency log FAILED - this attestation is not in "
                               f"{log_path}", err=True)
                    sys.exit(1)
                proof = inclusion_proof(entries, entry["index"])
                if not verify_inclusion(entry["bundle_sha256"], proof):
                    click.echo("transparency log FAILED - inclusion proof does not verify",
                               err=True)
                    sys.exit(1)
                click.echo(f"  transparency log: entry #{entry['index']} of {len(entries)} "
                           f"· history CONSISTENT · inclusion VERIFIED · "
                           f"root {proof['root'][:16]}…")
            if rekor_flag:
                from attestral.rekor import verify_receipt
                receipt_path = Path(f"{output}.rekor.json")
                if not receipt_path.exists():
                    click.echo(f"Rekor receipt FAILED - {receipt_path} not found", err=True)
                    sys.exit(1)
                receipt = json.loads(receipt_path.read_text())
                rok, rnotes = verify_receipt(receipt, bundle.get("envelope") or {})
                if not rok:
                    click.echo(f"Rekor receipt FAILED - {rnotes[0]}", err=True)
                    sys.exit(1)
                click.echo(f"  Rekor receipt: {rnotes[-1]}")
            sys.exit(0)
        click.echo(f"attestation FAILED - first failing step: {failures[0]}", err=True)
        click.echo(f"  all failing steps: {', '.join(failures)}", err=True)
        sys.exit(1)

    private_pem = None
    if gen_key:
        priv, pub = generate_keypair()
        Path(f"{gen_key}.key").write_text(priv)
        Path(f"{gen_key}.pub").write_text(pub)
        click.echo(f"wrote {gen_key}.key (private, keep secret) and {gen_key}.pub (public)")
        private_pem = priv
    elif key_path:
        private_pem = Path(key_path).read_text()

    now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    bundle = build_bundle(path, events=events, private_pem=private_pem,
                          signer=signer, generated_at=now)
    Path(output).write_text(json.dumps(bundle, indent=2))

    if log_path:
        from attestral.translog import append_bundle
        try:
            entry = append_bundle(log_path, bundle, logged_at=now)
        except ValueError as exc:
            click.echo(f"transparency log FAILED - {exc}", err=True)
            sys.exit(1)
        click.echo(f"logged: entry #{entry['index']} · log size {entry['size']} · "
                   f"root {entry['root'][:16]}…")
        click.echo("  the log proves append-only history, not distributed witness: "
                   "publish the head root somewhere you do not control (a commit, "
                   "Sigstore Rekor) so a rewrite has an external copy to contradict.")

    if rekor_flag:
        if not bundle.get("envelope"):
            click.echo("Rekor anchoring FAILED - needs a signed attestation "
                       "(pass --key or --gen-key)", err=True)
            sys.exit(1)
        from attestral.rekor import DEFAULT_REKOR, anchor, receipt_line
        from attestral.signing import public_key_of
        try:
            receipt = anchor(bundle["envelope"], public_key_of(private_pem),
                             rekor_url=rekor_url or DEFAULT_REKOR)
        except Exception as exc:  # noqa: BLE001 - the network is the failure surface
            click.echo(f"Rekor anchoring FAILED - {exc}", err=True)
            sys.exit(1)
        Path(f"{output}.rekor.json").write_text(json.dumps(receipt, indent=2))
        click.echo(f"  {receipt_line(receipt)}")
        click.echo(f"  receipt written to {output}.rekor.json - a public witness "
                   "a rewrite cannot contradict")

    pred = bundle["statement"]["predicate"]
    subject_digest = bundle["statement"]["subject"][0]["digest"]["sha256"]
    signed = "signed" if bundle["envelope"] else "unsigned"
    click.echo(f"wrote {output}  ·  {signed}  ·  model {subject_digest[:16]}…")
    click.echo(f"  signer: {signer or '-'}")
    runtime = pred.get("runtime")
    if runtime:
        rules = ", ".join(runtime["driftRules"]) or "-"
        click.echo(f"  runtime verdict: {runtime['verdict']} "
                   f"({'drift ' + rules if runtime['driftRules'] else 'no drift'}) "
                   f"over {runtime['events']['count']} events")
    click.echo("  tamper-evident conformance, not a proof the design is safe: it binds "
               "the runtime observed to the design reviewed.")


@main.command()
@click.argument("policy_file", type=click.Path(exists=True))
@click.argument("events_file", type=click.Path(exists=True))
@click.option("--journal", "journal_file", type=click.Path(exists=True), default=None,
              help="The hash-chained containment journal (<ENFORCE>.journal.jsonl) to bind. "
                   "Its verdict and chain head become part of the attestation; a tampered "
                   "journal is attested AS tampered, never laundered into containment credit.")
@click.option("--key", "key_path", type=click.Path(exists=True), default=None,
              help="Ed25519 private key (PEM) to sign the incident attestation with.")
@click.option("--gen-key", "gen_key", default=None, metavar="STEM",
              help="Generate a keypair to STEM.key + STEM.pub and sign with it.")
@click.option("--signer", default="", help="Identity to record in the attestation.")
@click.option("--verify", "do_verify", is_flag=True,
              help="Verify an existing incident bundle against the supplied policy, events, "
                   "and journal (recompute the whole reconstruction offline).")
@click.option("--public-key", type=click.Path(exists=True), default=None,
              help="Ed25519 public key (PEM) to check the bundle's signature against (--verify).")
@click.option("-o", "--output", default="incident.json",
              help="Incident bundle file (default: incident.json).")
@click.option("--rekor", "rekor_flag", is_flag=True,
              help="Anchor a SIGNED incident attestation in Sigstore Rekor and write the "
                   "receipt to <output>.rekor.json. Opt-in and online. With --verify: check "
                   "the receipt binds this bundle.")
@click.option("--rekor-url", default=None,
              help="Rekor instance to anchor to (default: https://rekor.sigstore.dev).")
def incident(policy_file: str, events_file: str, journal_file: str | None,
             key_path: str | None, gen_key: str | None, signer: str, do_verify: bool,
             public_key: str | None, output: str, rekor_flag: bool,
             rekor_url: str | None) -> None:
    """Produce or verify a signed incident attestation from a drift replay.

    Reconstructs the incident exactly as `drift --replay` does - every event
    through a fresh monitor, the containment journal's hash chain verified
    first - then binds the reconstruction into a DSSE-signable in-toto
    Statement: the policy digest the stream was judged against, the event
    stream's digest, the journal verdict and chain head, and a digest of the
    full timeline. `--verify` recomputes everything from the supplied inputs,
    so a doctored event line, a rewritten journal, or an edited verdict makes
    verification FAIL.

    This closes the runtime loop: the attested design became the runtime
    policy (`compile`), the runtime was policed against it (`drift`), and now
    the incident record itself carries the same tamper-evidence as the design
    review it descends from.
    """
    import yaml as _yaml

    from attestral.drift import load_jsonl
    from attestral.incident import (
        build_incident_bundle, render_incident, verify_incident_bundle,
    )
    from attestral.signing import generate_keypair

    policy = _yaml.safe_load(Path(policy_file).read_text())
    if not isinstance(policy, dict):
        raise click.UsageError(f"{policy_file} is not a policy mapping")
    events, malformed_events = load_jsonl(events_file)
    journal_entries: list | None = None
    malformed_journal = 0
    if journal_file:
        journal_entries, malformed_journal = load_jsonl(journal_file)

    if do_verify:
        bundle = json.loads(Path(output).read_text())
        pub = Path(public_key).read_text() if public_key else None
        ok, failures = verify_incident_bundle(
            bundle, policy, events, journal_entries,
            malformed_events=malformed_events,
            malformed_journal_lines=malformed_journal,
            public_pem=pub,
        )
        if ok:
            click.echo("incident attestation VERIFIED - the supplied policy, events, and "
                       "journal reproduce exactly this reconstruction")
            click.echo(render_incident(bundle))
            if public_key is None:
                click.echo("  (signature not checked; pass --public-key to verify "
                           "authenticity)")
            if rekor_flag:
                from attestral.rekor import verify_receipt
                receipt_path = Path(f"{output}.rekor.json")
                if not receipt_path.exists():
                    click.echo(f"Rekor receipt FAILED - {receipt_path} not found", err=True)
                    sys.exit(1)
                receipt = json.loads(receipt_path.read_text())
                rok, rnotes = verify_receipt(receipt, bundle.get("envelope") or {})
                if not rok:
                    click.echo(f"Rekor receipt FAILED - {rnotes[0]}", err=True)
                    sys.exit(1)
                click.echo(f"  Rekor receipt: {rnotes[-1]}")
            sys.exit(0)
        click.echo(f"incident attestation FAILED - first failing step: {failures[0]}",
                   err=True)
        click.echo(f"  all failing steps: {', '.join(failures)}", err=True)
        sys.exit(1)

    private_pem = None
    if gen_key:
        priv, pub_pem = generate_keypair()
        Path(f"{gen_key}.key").write_text(priv)
        Path(f"{gen_key}.pub").write_text(pub_pem)
        click.echo(f"wrote {gen_key}.key (private, keep secret) and {gen_key}.pub (public)")
        private_pem = priv
    elif key_path:
        private_pem = Path(key_path).read_text()

    now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    bundle = build_incident_bundle(
        policy, Path(events_file).name, events, journal_entries,
        malformed_events=malformed_events,
        malformed_journal_lines=malformed_journal,
        private_pem=private_pem, signer=signer, generated_at=now,
    )
    Path(output).write_text(json.dumps(bundle, indent=2))

    if rekor_flag:
        if not bundle.get("envelope"):
            click.echo("Rekor anchoring FAILED - needs a signed incident attestation "
                       "(pass --key or --gen-key)", err=True)
            sys.exit(1)
        from attestral.rekor import DEFAULT_REKOR, anchor, receipt_line
        from attestral.signing import public_key_of
        try:
            receipt = anchor(bundle["envelope"], public_key_of(private_pem),
                             rekor_url=rekor_url or DEFAULT_REKOR)
        except Exception as exc:  # noqa: BLE001 - the network is the failure surface
            click.echo(f"Rekor anchoring FAILED - {exc}", err=True)
            sys.exit(1)
        Path(f"{output}.rekor.json").write_text(json.dumps(receipt, indent=2))
        click.echo(f"  {receipt_line(receipt)}")
        click.echo(f"  receipt written to {output}.rekor.json - a public witness "
                   "a rewrite cannot contradict")

    click.echo(f"wrote {output}")
    click.echo(render_incident(bundle))


if __name__ == "__main__":
    main()
