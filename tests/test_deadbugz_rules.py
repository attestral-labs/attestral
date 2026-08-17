"""Deadbugz MCP rug-pull pair (Pillar Security, 2026-08-12): ATL-172 disposable
tunnel-hosted endpoint + ATL-173 hidden nested dot-cache launch path."""
from attestral.ingest import build_model
from attestral.ingest.mcp import _disposable_host, _hidden_launch_path
from attestral.rules import RuleEngine

FIXTURE = "examples/deadbugz-rugpull"


def _findings():
    return RuleEngine().evaluate(build_model(FIXTURE))


def test_disposable_tunnel_endpoint_fires_atl172():
    hits = [f for f in _findings() if f.rule_id == "ATL-172"]
    assert [f.component_id for f in hits] == ["mcp_server.productivity-suite"]


def test_hidden_cache_launch_fires_atl173():
    # The real campaign IOC: ~/.config/.cache/.sys/.deadbug-mcp.py
    hits = [f for f in _findings() if f.rule_id == "ATL-173"]
    assert [f.component_id for f in hits] == ["mcp_server.sys-helper"]


def test_benign_server_fires_neither():
    model = build_model(FIXTURE)
    benign = model.get("mcp_server.docs-tools")
    assert benign.attr("_disposable_host") is None
    assert benign.attr("_hidden_launch_path") is None
    benign_hits = {
        f.rule_id for f in RuleEngine().evaluate(model)
        if f.component_id == "mcp_server.docs-tools"
    }
    assert not benign_hits & {"ATL-172", "ATL-173"}


def test_disposable_host_is_suffix_match_not_substring():
    # Registrable-suffix match on genuine ephemeral tunnels only.
    assert _disposable_host("https://x.trycloudflare.com/mcp") is True
    assert _disposable_host("https://productivity-suite-mcp.trycloudflare.com/mcp") is True
    # A lookalike apex/subdomain of the tunnel host must NOT match (fail closed).
    assert _disposable_host("https://trycloudflare.com.evil.org/mcp") is False
    assert _disposable_host("https://ngrok.io.evil.org/mcp") is False


def test_disposable_host_excludes_durable_paid_paas():
    # The precision fix: paid PaaS hosts are legitimate canonical MCP endpoints,
    # so firing on the host alone would be a false positive on real small vendors.
    for url in ("https://acme-mcp.onrender.com/mcp",   # paid Render service
                "https://api.render.com/v1",           # Render's own infra
                "https://my-app.repl.co/mcp",
                "https://my-app.glitch.me/mcp"):
        assert _disposable_host(url) is False, url


def test_disposable_host_fails_closed_on_empty_and_loopback():
    assert _disposable_host("") is False
    assert _disposable_host("http://localhost:8080/mcp") is False
    assert _disposable_host("not a url") is False


def test_hidden_launch_path_ignores_ordinary_dotfiles():
    # One hidden segment is everyday hygiene, never a finding (fail closed).
    assert _hidden_launch_path("python3", ["~/.config/app/server.py"]) is False
    assert _hidden_launch_path(".venv/bin/python", ["server.py"]) is False
    assert _hidden_launch_path("npx", ["-y", "@scope/pkg@1.2.3"]) is False
    assert _hidden_launch_path("", []) is False


def test_hidden_launch_path_ignores_nested_venv_and_tool_dirs():
    # The confirmed false positives: a venv nested inside a dotfiles repo or an
    # editor config dir is two hidden segments but everyday developer layout.
    assert _hidden_launch_path("python3", ["~/.dotfiles/.venv/bin/s.py"]) is False
    assert _hidden_launch_path("python3", ["~/.config/.venv/bin/server.py"]) is False
    assert _hidden_launch_path("python3", ["~/.vscode/.venv/bin/x"]) is False


def test_hidden_launch_path_catches_nested_and_cache_dropper():
    # The Deadbugz IOC (three nested hidden dirs + a dot-prefixed script).
    assert _hidden_launch_path("python3", ["~/.config/.cache/.sys/.deadbug-mcp.py"]) is True
    # Two consecutive hidden directory segments alone are enough.
    assert _hidden_launch_path("node", ["/home/u/.config/.cache/run.js"]) is True
    # A dot-prefixed script directly under a hidden cache dir.
    assert _hidden_launch_path("python3", ["~/.cache/.helper.py"]) is True
