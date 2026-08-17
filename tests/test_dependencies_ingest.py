"""Dependency-manifest ingester: known-vulnerable pins -> ATL-145."""
from attestral.ingest import build_model
from attestral.ingest.dependencies import _dep_cve, ingest_dependencies
from attestral.model import SystemModel
from attestral.rules import RuleEngine


def test_fixture_flags_known_vulnerable_deps():
    model = build_model("examples/vulnerable-deps")
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-145" in ids
    deps = {c.attr("_known_cve") for c in model.by_type("dependency")}
    assert {"CVE-2025-68664", "CVE-2025-67644",
            "CVE-2025-1793", "CVE-2026-26030"} <= deps


def test_agent_framework_cve_ranges_are_branch_precise():
    # The 2026 sweep additions: each is checked at an affected pin and at its fix.
    # langgraph-checkpoint has two CVEs partitioned across the 2.x / 3.x windows.
    assert _dep_cve("langgraph-checkpoint", "2.1.0") == "CVE-2025-64439"
    assert _dep_cve("langgraph-checkpoint", "3.5.0") == "CVE-2026-27794"
    assert _dep_cve("langgraph-checkpoint", "4.0.0") is None          # patched
    # llama-index-core: the critical SQLi owns <=0.12.28, the file-read the window above.
    assert _dep_cve("llama-index-core", "0.12.20") == "CVE-2025-1793"
    assert _dep_cve("llama-index-core", "0.12.35") == "CVE-2025-6209"
    assert _dep_cve("llama-index-core", "0.12.41") is None            # patched
    # vLLM: the torch.load RCE (62164) owns 0.10.2-0.11.0 as first-match; the wider
    # multimodal-video RCE (22778, CVSS 9.8) covers 0.8.3-<0.14.1 around it.
    assert _dep_cve("vllm", "0.11.0") == "CVE-2025-62164"             # first-match in overlap
    assert _dep_cve("vllm", "0.11.1") == "CVE-2026-22778"            # above 62164, still <0.14.1
    assert _dep_cve("vllm", "0.9.0") == "CVE-2026-22778"            # in 22778's wider floor
    assert _dep_cve("vllm", "0.14.0") == "CVE-2026-22778"
    assert _dep_cve("vllm", "0.14.1") is None                        # 22778 patched
    assert _dep_cve("vllm", "0.8.0") is None                         # below 22778's 0.8.3 floor
    # semantic-kernel eval() RCE and pydantic-ai SSRF.
    assert _dep_cve("semantic-kernel", "1.39.3") == "CVE-2026-26030"
    assert _dep_cve("semantic-kernel", "1.39.4") is None              # patched
    assert _dep_cve("pydantic-ai", "1.55.0") == "CVE-2026-25580"
    assert _dep_cve("pydantic-ai", "1.56.0") is None                 # patched
    # smolagents XPath injection; the MCP Python SDK DNS-rebind SSRF.
    assert _dep_cve("smolagents", "1.20.0") == "CVE-2025-11844"
    assert _dep_cve("mcp", "1.22.0") == "CVE-2025-66416"
    assert _dep_cve("mcp", "1.23.0") is None                          # patched
    # Langflow: three CISA-KEV unauth-RCEs partitioned first-match. 3248 owns
    # <1.3.0; 0770 the 1.3.0-1.9.1 window; 9198 (auto_login superuser token +
    # validate/code exec, affected 1.0.0-1.10.0) the 1.9.2-1.10.0 window above.
    # The IDOR KEV 55255 (<1.9.2) sits entirely inside the RCE windows, so
    # first-match always reports the RCEs; its row documents the advisory.
    assert _dep_cve("langflow", "1.2.0") == "CVE-2025-3248"
    assert _dep_cve("langflow", "1.3.0") == "CVE-2026-0770"          # safe from 3248, hit by 0770
    assert _dep_cve("langflow", "1.9.1") == "CVE-2026-0770"          # 55255 shadowed by the RCE KEV
    assert _dep_cve("langflow", "1.9.2") == "CVE-2026-9198"          # safe from 0770, hit by 9198
    assert _dep_cve("langflow", "1.10.0") == "CVE-2026-9198"
    assert _dep_cve("langflow", "1.10.1") is None                     # all patched
    # The MCP TS SDK id-collision CVE sits just above the ReDoS ceiling (1.25.1).
    assert _dep_cve("@modelcontextprotocol/sdk", "1.25.2") == "CVE-2026-25536"


def test_safe_pin_is_not_flagged(tmp_path):
    # 1.2.22 is fixed for BOTH langchain-core CVEs (68664 fixed 1.2.5, 34070
    # fixed 1.2.22); anything below 1.2.22 is still vulnerable to one of them.
    (tmp_path / "requirements.txt").write_text(
        "langchain-core==1.2.22\nrequests==2.31.0\n"
    )
    model = build_model(str(tmp_path))
    assert not model.by_type("dependency")
    assert "ATL-145" not in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_open_range_is_not_flagged(tmp_path):
    # Only an exact pin is comparable; an open range must not flag (fail closed).
    (tmp_path / "requirements.txt").write_text("langchain-core>=0.1\n")
    model = build_model(str(tmp_path))
    assert not model.by_type("dependency")


def test_version_ranges_are_branch_precise():
    # 68664 is fixed on two branches (0.3.81 and 1.2.5); a version fixed on one
    # branch must not be flagged for it.
    assert _dep_cve("langchain-core", "1.2.4") == "CVE-2025-68664"
    assert _dep_cve("langchain-core", "0.3.80") == "CVE-2025-68664"
    assert _dep_cve("langchain-core", "0.3.81") is None      # fixed on the 0.x branch
    # 1.2.5 fixes LangGrinch but is still vulnerable to the path-traversal CVE:
    assert _dep_cve("langchain-core", "1.2.5") == "CVE-2026-34070"
    assert _dep_cve("langchain-core", "1.2.21") == "CVE-2026-34070"
    assert _dep_cve("langchain-core", "1.2.22") is None       # both fixed


def test_langgraph_chain_and_mcp_sdk_cves():
    # msgpack RCE in langgraph (chains with the SQLite-checkpointer SQLi).
    assert _dep_cve("langgraph", "1.0.5") == "CVE-2026-28277"
    assert _dep_cve("langgraph", "1.0.10") is None                  # patched
    # RediSearch injection in the Redis checkpointer (scoped npm name).
    assert _dep_cve("@langchain/langgraph-checkpoint-redis", "1.0.0") == "CVE-2026-27022"
    assert _dep_cve("@langchain/langgraph-checkpoint-redis", "1.0.1") is None
    # ReDoS in the MCP TypeScript SDK's UriTemplate parser, floored at 1.3.0.
    assert _dep_cve("@modelcontextprotocol/sdk", "1.20.0") == "CVE-2026-0621"
    # 1.25.2 fixes the ReDoS but is affected by the id-collision CVE below it;
    # 1.26.0 fixes both.
    assert _dep_cve("@modelcontextprotocol/sdk", "1.25.2") == "CVE-2026-25536"
    assert _dep_cve("@modelcontextprotocol/sdk", "1.26.0") is None  # both patched
    assert _dep_cve("@modelcontextprotocol/sdk", "1.2.0") is None   # below the affected floor


def test_2026_08_radar_rows_are_branch_precise():
    # Flowise 3.1.3 fix wave: the critical sandbox-escape RCE (69253) fronts the
    # cluster (69251 TypeORM RCE / 69258 unauth overrideConfig injection fixed in
    # the same release); flowise-components carries its own advisory id.
    assert _dep_cve("flowise", "3.1.2") == "CVE-2026-69253"
    assert _dep_cve("flowise", "3.1.3") is None                       # patched
    assert _dep_cve("flowise-components", "3.1.2") == "CVE-2026-73601"
    assert _dep_cve("flowise-components", "3.1.3") is None            # patched
    # mcp-grafana credentialed SSRF, patched 1.1.0.
    assert _dep_cve("mcp-grafana", "1.0.9") == "CVE-2026-19516"
    assert _dep_cve("mcp-grafana", "1.1.0") is None                   # patched
    # n8n MCP-client SSRF allowlist bypass, patched 2.32.1.
    assert _dep_cve("n8n", "2.32.0") == "CVE-2026-72768"
    assert _dep_cve("n8n", "2.32.1") is None                          # patched
    # vLLM incomplete-fix bypass of the 62164 torch.load RCE: >=0.21.0 <0.26.0,
    # the window above 22778's 0.14.0 ceiling (0.14.1-0.20.x stays clean).
    assert _dep_cve("vllm", "0.21.0") == "CVE-2026-73557"
    assert _dep_cve("vllm", "0.25.9") == "CVE-2026-73557"
    assert _dep_cve("vllm", "0.20.0") is None                         # below the bypass floor
    assert _dep_cve("vllm", "0.26.0") is None                         # patched


def test_litellm_mcp_config_command_injection_cve():
    # CVE-2026-30623: authenticated command injection via LiteLLM's MCP server
    # creation (arbitrary stdio command/args). Patched in 1.83.7.
    assert _dep_cve("litellm", "1.83.6") == "CVE-2026-30623"
    assert _dep_cve("litellm", "1.80.0") == "CVE-2026-30623"
    assert _dep_cve("litellm", "1.83.7") is None                    # patched


def test_mcp_wave_cve_rows_are_branch_precise():
    # 2026 MCP-server dependency CVE wave: each is checked at an affected pin and
    # at its fix (aws-mcp has no fix, so only the affected pin is asserted).
    # CVE-2026-61459: mcp-server-kubernetes argument injection (npm), <3.9.0;
    # supersedes the older 47250 / 53355 command-injection advisories.
    assert _dep_cve("mcp-server-kubernetes", "3.8.9") == "CVE-2026-61459"
    assert _dep_cve("mcp-server-kubernetes", "2.4.9") == "CVE-2026-61459"
    assert _dep_cve("mcp-server-kubernetes", "3.9.0") is None            # patched
    # CVE-2026-45672: open-webui code-exec gate bypass, <=0.8.11.
    assert _dep_cve("open-webui", "0.8.11") == "CVE-2026-45672"
    assert _dep_cve("open-webui", "0.8.12") is None                      # patched
    # CVE-2026-40576: excel-mcp-server unauth path traversal, <=0.1.7.
    assert _dep_cve("excel-mcp-server", "0.1.7") == "CVE-2026-40576"
    assert _dep_cve("excel-mcp-server", "0.1.8") is None                 # patched
    # CVE-2026-5059: aws-mcp unauth command-injection RCE, <=1.7.0, no fix.
    assert _dep_cve("aws-mcp", "1.7.0") == "CVE-2026-5059"
    assert _dep_cve("aws-mcp", "0.1.0") == "CVE-2026-5059"


def test_mcp_wave_fixture_flags_all_four():
    model = build_model("examples/vuln-deps-mcp-wave")
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-174" not in ids  # a manifest fixture, not an MCP config
    assert "ATL-145" in ids
    cves = {c.attr("_known_cve") for c in model.by_type("dependency")}
    assert {"CVE-2026-61459", "CVE-2026-45672",
            "CVE-2026-40576", "CVE-2026-5059"} <= cves


def test_name_normalization():
    # PEP 503: langchain_core / LangChain-Core normalize to the same package.
    assert _dep_cve("LangChain_Core", "1.2.4") == "CVE-2025-68664"


def test_pyproject_and_package_json_pins(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        'dependencies = ["langchain-core==1.2.4", "httpx==0.27.0"]\n'
    )
    model = ingest_dependencies(str(tmp_path), SystemModel())
    assert {c.attr("_known_cve") for c in model.by_type("dependency")} == {"CVE-2025-68664"}
