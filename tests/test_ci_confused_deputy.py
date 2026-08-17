"""ATL-223: an AI coding agent in a CI job reachable by untrusted input with
secrets in scope (CVE-2026-54316). The rule matches the four-bool conjunction the
github_actions ingester derives on `ci_workflow` components."""
from attestral.ingest import build_model
from attestral.ingest.github_actions import ingest_github_actions
from attestral.model import SystemModel
from attestral.rules import RuleEngine

FIXTURE = "examples/ci-agent-confused-deputy"


def _findings():
    return RuleEngine().evaluate(build_model(FIXTURE))


def _model_from_yaml(tmp_path, yaml_text: str) -> SystemModel:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "w.yml").write_text(yaml_text)
    return ingest_github_actions(str(tmp_path), SystemModel())


def test_read_only_comment_bot_is_not_flagged(tmp_path):
    # The judge's confirmed FP: a read-only summarization bot with no Bash tool,
    # whose only secret lives in a SIBLING step the agent cannot read. Must stay
    # silent - the shell word appears only in the prompt, and the secret is not
    # agent-reachable.
    m = _model_from_yaml(tmp_path, """
on: issue_comment
permissions: { contents: read }
jobs:
  triage:
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_tools: "Read,Grep"
          claude_args: "-p 'Summarize the issue and flag unsafe bash usage'"
      - run: curl -d @- "$WEBHOOK"
        env:
          WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
""")
    c = m.get("ci_workflow.w.triage")
    assert c.attr("_agent_step_has_shell") is False   # "bash" only in prompt prose
    assert c.attr("_secrets_in_scope") is False        # secret is in a sibling step
    assert [f for f in RuleEngine().evaluate(m) if f.rule_id == "ATL-223"] == []


def test_triage_job_fires_atl223():
    hits = [f for f in _findings() if f.rule_id == "ATL-223"]
    assert [f.component_id for f in hits] == ["ci_workflow.triage.triage"]
    assert hits[0].severity.value == "critical"


def test_benign_ci_job_does_not_fire():
    hits = [f for f in _findings()
            if f.rule_id == "ATL-223" and f.component_id == "ci_workflow.ci.test"]
    assert hits == []


def test_rule_needs_the_full_conjunction():
    # Remove any one of the four halves and the rule must NOT fire - it is the
    # conjunction, not any single signal, that is the confused deputy.
    model = build_model(FIXTURE)
    triage = model.get("ci_workflow.triage.triage")
    for attr in ("_untrusted_trigger", "_invokes_ai_agent",
                 "_secrets_in_scope", "_agent_step_has_shell"):
        assert triage.attr(attr) is True     # fixture lights all four
        saved = triage.attributes.pop(attr)
        hits = [f for f in RuleEngine().evaluate(model) if f.rule_id == "ATL-223"]
        assert hits == [], f"ATL-223 fired without {attr}"
        triage.attributes[attr] = saved
