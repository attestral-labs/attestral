"""Property verification over the compiled policy (issue #75)."""
from pathlib import Path

from click.testing import CliRunner

from attestral.cli import main
from attestral.compile import compile_policy
from attestral.ingest import build_model
from attestral.policy_verify import verify_policy
from attestral.rules import RuleEngine

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _policy(fixture: str) -> dict:
    model = build_model(str(EXAMPLES / fixture))
    return compile_policy(model, RuleEngine().evaluate(model))


def test_a_design_with_no_servers_proves_every_property():
    results = verify_policy(_policy("aws-pack"))
    assert results and all(r.holds for r in results)


def test_secret_exfiltration_is_caught_with_its_counterexample():
    # delta-head: db-reader holds a secret, fetcher has an outbound channel; the
    # secret can route out through the shared agent.
    by_name = {r.name: r for r in verify_policy(_policy("delta-head"))}
    exfil = by_name["no-secret-exfiltration"]
    assert not exfil.holds
    assert "db-reader" in exfil.counterexample
    assert "fetcher" in exfil.counterexample


def test_denying_the_shell_server_proves_no_command_and_control():
    # runner (shell, ATL-103 critical) is denied, so the allowed set has no
    # code-execution surface - the C2 property is proved, and the compile
    # denial is now a proved property, not just a claim.
    by_name = {r.name: r for r in verify_policy(_policy("delta-head"))}
    assert by_name["no-code-exec-egress"].holds
    assert by_name["default-deny"].holds
    assert by_name["remote-allows-are-tls"].holds


def test_every_result_labels_its_method_structural():
    for r in verify_policy(_policy("delta-head")):
        assert r.method == "structural"


def test_compile_fail_on_violation_gates_ci():
    runner = CliRunner()
    with runner.isolated_filesystem():
        bad = runner.invoke(main, [
            "compile", str(EXAMPLES / "delta-head"), "-o", "p.yaml", "--fail-on-violation"])
        assert bad.exit_code == 1 and "violated" in bad.output.lower()

        clean = runner.invoke(main, [
            "compile", str(EXAMPLES / "aws-pack"), "-o", "q.yaml", "--fail-on-violation"])
        assert clean.exit_code == 0
