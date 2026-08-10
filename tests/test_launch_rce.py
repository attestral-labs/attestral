"""ATL-171: an MCP server whose launch command fetches and executes remote code.

The config-injection RCE class (TrustFall / poisoned `.mcp.json`): loading the
config runs attacker-changeable remote code before the model reasons. Distinct
from ATL-105 (package auto-install) and ATL-155 (fetch-exec in an instruction
file). Recall on the malicious launches, precision on a properly pinned server.
"""
from _helpers import findings_for, ids_for

from attestral.ingest import build_model

FIXTURE = "examples/mcp-launch-rce"


def test_atl171_fires_on_curl_pipe_shell_and_powershell_iex():
    hits = {f.component_id for f in findings_for(FIXTURE) if f.rule_id == "ATL-171"}
    assert hits == {"mcp_server.setup-helper", "mcp_server.win-agent"}


def test_atl171_is_critical():
    (some,) = [f for f in findings_for(FIXTURE)
               if f.rule_id == "ATL-171" and f.component_id == "mcp_server.setup-helper"]
    assert some.severity.value == "critical"


def test_pinned_server_does_not_fire():
    model = build_model(FIXTURE)
    pinned = next(c for c in model.by_type("mcp_server") if c.name == "pinned-server")
    assert pinned.attr("_launch_fetch_exec") is False
    assert "ATL-171" not in {
        f.rule_id for f in findings_for(FIXTURE)
        if f.component_id == "mcp_server.pinned-server"
    }


def test_derivation_flags_both_fetch_exec_forms():
    model = build_model(FIXTURE)
    flags = {c.name: c.attr("_launch_fetch_exec") for c in model.by_type("mcp_server")}
    assert flags["setup-helper"] is True    # curl … | sh
    assert flags["win-agent"] is True        # iex(iwr …)
    assert flags["pinned-server"] is False


def test_pinned_npx_server_is_not_confused_with_fetch_exec():
    # ATL-105 (npx -y auto-install) and ATL-171 are different rules; a plain
    # `npx pkg@version` fetches nothing into a shell and must not trip ATL-171.
    assert "ATL-171" not in ids_for("examples/guard-runtime")  # npx server-filesystem
