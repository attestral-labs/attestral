"""ATL-147 precision: bind-to-all-interfaces is matched on the exact host, so a
specific private bind never false-positives, IPv6 (::) is covered, and a
host/bind config field counts as well as a launch flag.

ATL-147 used to substring-match "0.0.0.0" in the launch args, which flagged a
deliberate bind to a specific private address whose text merely contains it
(10.0.0.0) and missed the IPv6 all-interfaces form entirely.
"""
from attestral.ingest.mcp import _binds_all_interfaces, ingest_mcp
from attestral.model import SystemModel
from attestral.rules import RuleEngine


def _fires(cfg_json: str) -> bool:
    import tempfile
    from pathlib import Path

    d = Path(tempfile.mkdtemp())
    (d / "mcp.json").write_text(cfg_json)
    model = ingest_mcp(d / "mcp.json", SystemModel())
    return "ATL-147" in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_exact_host_match_ipv4_and_ipv6():
    assert _binds_all_interfaces(["--host", "0.0.0.0"], {}) is True
    assert _binds_all_interfaces(["--host", "::"], {}) is True
    assert _binds_all_interfaces(["--bind", "[::]:8080"], {}) is True
    assert _binds_all_interfaces(["--inspect=0.0.0.0:9229"], {}) is True
    assert _binds_all_interfaces([], {"host": "0.0.0.0"}) is True


def test_specific_private_bind_does_not_false_positive():
    # The old substring matcher flagged these because their text contains
    # "0.0.0.0"; the exact host match must not.
    assert _binds_all_interfaces(["--host", "10.0.0.0"], {}) is False
    assert _binds_all_interfaces(["--host", "100.0.0.0"], {}) is False
    assert _binds_all_interfaces(["--host", "192.168.0.0"], {}) is False
    assert _binds_all_interfaces(["--host", "127.0.0.1"], {}) is False


def test_ipv6_all_interfaces_now_fires_end_to_end():
    assert _fires('{"mcpServers": {"api": {"command": "node", '
                  '"args": ["s.js", "--host", "::", "--port", "8080"]}}}')


def test_config_host_field_fires():
    assert _fires('{"mcpServers": {"api": {"command": "node", '
                  '"args": ["s.js"], "host": "0.0.0.0"}}}')


def test_specific_private_ip_is_silent_end_to_end():
    assert not _fires('{"mcpServers": {"api": {"command": "node", '
                      '"args": ["s.js", "--host", "10.0.0.0"]}}}')
