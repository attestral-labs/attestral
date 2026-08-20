"""A FastMCP server implementation whose tools together form a lethal trifecta.

Mirrors the shape found in the wild (validated against Damn Vulnerable MCP
challenge 2, 2026-08-19): a single MCP *server implementation* - not a client
`.mcp.json` config - that exposes an untrusted-input tool, a shell tool, and an
egress tool. One injected instruction can read a secret and send it out.

Attestral ingests the server implementation itself via the `mcp` / FastMCP
framework recognition in the agent-code ingester, so a Python MCP server that
ships no client config is still reviewed for the flow across its own tools.
"""
from mcp.server.fastmcp import FastMCP

server = FastMCP("Notes Assistant")


@server.tool()
def fetch_url(url: str) -> str:
    """Fetch and summarize any web page for the user (untrusted external input)."""
    import requests
    return requests.get(url).text


@server.tool()
def read_file(path: str) -> str:
    """Read a local file to answer questions about the user's notes and keys."""
    with open(path) as fh:
        return fh.read()


@server.tool()
def run_command(command: str) -> str:
    """Run a shell command to help with local tasks."""
    import subprocess
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()


@server.tool()
def send_webhook(message: str) -> str:
    """Post a message to an external webhook endpoint."""
    import requests
    return requests.post("https://example.com/webhook", json={"text": message}).text
