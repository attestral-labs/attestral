"""GitHub Actions ingester: the CI confused-deputy signals (CVE-2026-54316).

One `ci_workflow` component per workflow job, stamped with the four fail-closed
halves of the chain: untrusted trigger -> AI agent -> secrets in scope ->
shell under the agent.
"""
from attestral.ingest import build_model
from attestral.ingest.github_actions import ingest_github_actions
from attestral.model import SystemModel

FIXTURE = "examples/ci-agent-confused-deputy"


def _job(model, component_id):
    c = model.get(component_id)
    assert c is not None, f"missing component {component_id}"
    return c


def test_triage_job_lights_up_all_four_signals():
    model = build_model(FIXTURE)
    c = _job(model, "ci_workflow.triage.triage")
    assert c.type == "ci_workflow"
    assert c.trust_boundary == "ci"
    assert c.source.endswith(".github/workflows/triage.yml")
    # The four halves of the confused deputy, plus their evidence lists.
    assert c.attr("_untrusted_trigger") is True
    assert c.attr("_untrusted_triggers") == ["issues", "issue_comment"]
    assert c.attr("_invokes_ai_agent") is True
    assert c.attr("_ai_agent") == "anthropics/claude-code-action"
    assert c.attr("_secrets_in_scope") is True
    assert c.attr("_secret_refs") == ["SOME_API_KEY", "permissions:contents:write"]
    assert c.attr("_agent_step_has_shell") is True


def test_benign_ci_job_has_all_four_signals_false():
    model = build_model(FIXTURE)
    c = _job(model, "ci_workflow.ci.test")
    assert c.attr("_untrusted_trigger") is False
    assert c.attr("_untrusted_triggers") == []
    assert c.attr("_invokes_ai_agent") is False
    assert c.attr("_ai_agent") is None  # omitted, so attr_missing keeps meaning
    assert c.attr("_secrets_in_scope") is False
    assert c.attr("_secret_refs") == []
    # ci.yml has plain `run:` steps, but no agent -> no agent shell exposure.
    assert c.attr("_agent_step_has_shell") is False


def test_ci_boundary_is_seeded():
    model = build_model(FIXTURE)
    assert "ci" in {b.id for b in model.boundaries}


def test_malformed_workflow_is_skipped_without_raising(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "broken.yml").write_text("on: [issues\njobs: {::not yaml")
    (wf / "ok.yml").write_text(
        "on: push\njobs:\n  build:\n    steps:\n      - run: make\n"
    )
    model = ingest_github_actions(tmp_path, SystemModel())
    ids = {c.id for c in model.by_type("ci_workflow")}
    assert ids == {"ci_workflow.ok.build"}


def test_non_workflow_yaml_is_ignored(tmp_path):
    # A jobs-less YAML in the workflows dir, and a workflow-shaped YAML outside
    # .github/workflows, both contribute nothing (fail closed).
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "config.yml").write_text("retention: 30\n")
    (tmp_path / "pipeline.yml").write_text(
        "on: issues\njobs:\n  j:\n    steps:\n      - run: claude -p hi\n"
    )
    model = ingest_github_actions(tmp_path, SystemModel())
    assert model.by_type("ci_workflow") == []


def test_run_step_cli_match_is_command_position_only(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "agents.yml").write_text(
        "on: [issue_comment]\n"
        "jobs:\n"
        "  fix:\n"
        "    steps:\n"
        "      - run: npx claude-code --allowedTools Bash -p 'fix it'\n"
        "  build:\n"
        "    steps:\n"
        "      - run: pytest tests/test_codex.py  # substring must not match\n"
    )
    model = ingest_github_actions(tmp_path, SystemModel())
    fix = model.get("ci_workflow.agents.fix")
    build = model.get("ci_workflow.agents.build")
    # A `run:` invocation of an agent CLI is inherently shell-capable.
    assert fix.attr("_invokes_ai_agent") is True
    assert fix.attr("_ai_agent") == "claude-code"
    assert fix.attr("_agent_step_has_shell") is True
    # `codex` inside a path argument is not a command-position match.
    assert build.attr("_invokes_ai_agent") is False
    assert build.attr("_agent_step_has_shell") is False


def test_agent_action_without_shell_config_stays_shell_false(tmp_path):
    # An agent action with no tool/bash configuration: agent yes, shell no
    # (conservative - only clearly shell-capable flips the signal).
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "review.yml").write_text(
        "on:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  review:\n"
        "    steps:\n"
        "      - uses: openai/codex-action@v2\n"
        "        with:\n"
        "          prompt: review the diff\n"
    )
    model = ingest_github_actions(tmp_path, SystemModel())
    c = model.get("ci_workflow.review.review")
    assert c.attr("_untrusted_triggers") == ["pull_request_target"]
    assert c.attr("_invokes_ai_agent") is True
    assert c.attr("_agent_step_has_shell") is False


def test_plain_pull_request_is_not_an_untrusted_trigger(tmp_path):
    # A fork `pull_request` runs with a read-only token and no secrets, so it
    # lacks the privileged half of the deputy - deliberately not counted.
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "pr.yml").write_text(
        "on: [pull_request]\njobs:\n  lint:\n    steps:\n      - run: ruff .\n"
    )
    model = ingest_github_actions(tmp_path, SystemModel())
    c = model.get("ci_workflow.pr.lint")
    assert c.attr("_untrusted_trigger") is False
    assert c.attr("triggers") == ["pull_request"]


def test_job_permissions_override_workflow_permissions(tmp_path):
    # GitHub semantics: a job-level `permissions:` replaces the workflow block
    # entirely, so a read-only job under a write-all workflow is clean.
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "perms.yml").write_text(
        "on: issues\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  narrow:\n"
        "    permissions:\n"
        "      contents: read\n"
        "    steps:\n"
        "      - run: make\n"
        "  broad:\n"
        "    steps:\n"
        "      - run: make\n"
    )
    model = ingest_github_actions(tmp_path, SystemModel())
    assert model.get("ci_workflow.perms.narrow").attr("_secrets_in_scope") is False
    broad = model.get("ci_workflow.perms.broad")
    assert broad.attr("_secrets_in_scope") is True
    assert broad.attr("_secret_refs") == ["permissions:write-all"]
