"""Launch-based capability classification (_CAPABILITY_HINTS).

A tool server is classified by what its launch command + name reach. The bank
covers the npx/uvx forms AND the docker-image (`mcp/<name>`) and
`mcp-server-<name>` package forms of the canonical reference servers, because a
server packaged as a docker image reaches exactly what its npx form does -
missing the docker form silently under-classified real corpora and made the
lethal-trifecta rule under-fire. Tokens stay specific: never a bare `git`.
"""
from attestral.ingest.mcp import ingest_mcp
from attestral.model import SystemModel


def _caps(cfg_json: str, tmp_path) -> dict[str, list]:
    p = tmp_path / "mcp.json"
    p.write_text(cfg_json)
    m = ingest_mcp(p, SystemModel())
    return {c.name: sorted(c.attr("_capabilities") or []) for c in m.by_type("mcp_server")}


def test_docker_image_launch_classifies_like_the_npx_form(tmp_path):
    caps = _caps(
        '{"mcpServers": {'
        '"memory": {"command": "docker", "args": ["run", "-i", "--rm", "mcp/memory"]},'
        '"memory-npx": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]}'
        '}}', tmp_path)
    assert "memory" in caps["memory"]           # docker mcp/memory now classifies
    assert "memory" in caps["memory-npx"]       # and the npx form still does


def test_git_server_is_filesystem(tmp_path):
    caps = _caps(
        '{"mcpServers": {'
        '"git": {"command": "uvx", "args": ["mcp-server-git"]},'
        '"git-docker": {"command": "docker", "args": ["run", "--rm", "mcp/git"]}'
        '}}', tmp_path)
    assert caps["git"] == ["filesystem"]
    assert caps["git-docker"] == ["filesystem"]


def test_bare_git_reference_does_not_classify_filesystem(tmp_path):
    # A github URL or a repo path must NOT be read as the git server: the token is
    # `server-git` / `mcp-server-git` / `mcp/git`, never a bare `git`.
    caps = _caps(
        '{"mcpServers": {"gh": {"command": "npx", "args": ['
        '"some-tool", "--repo", "https://github.com/acme/widgets.git"]}}}', tmp_path)
    assert "filesystem" not in caps["gh"]
    # github IS a saas_data source, so that leg is (correctly) present
    assert "saas_data" in caps["gh"]


def test_canonical_npx_forms_still_classify(tmp_path):
    caps = _caps(
        '{"mcpServers": {'
        '"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},'
        '"fs": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/data"]},'
        '"sqlite-docker": {"command": "docker", "args": ["run", "mcp/sqlite"]}'
        '}}', tmp_path)
    assert "network" in caps["fetch"]
    assert "filesystem" in caps["fs"]
    assert "database" in caps["sqlite-docker"]   # docker sqlite matches via "sqlite"
