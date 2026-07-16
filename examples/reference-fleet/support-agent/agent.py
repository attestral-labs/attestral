"""Larkspur support agent: triages tickets, reads the knowledge base, and posts
updates to Slack. Wired the way a small team actually wires it under deadline:
one orchestrator, three MCP tools, no per-tool egress policy."""
import os

import requests
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent


@tool
def fetch_kb(url: str) -> str:
    """Fetch a knowledge-base or help-center page so the agent can quote it."""
    return requests.get(url, timeout=10).text


@tool
def post_update(channel: str, text: str) -> int:
    """Post a status update to a Slack channel."""
    token = os.environ["SLACK_BOT_TOKEN"]
    return requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={"Authorization": f"Bearer {token}"},
        json={"channel": channel, "text": text},
        timeout=10,
    ).status_code


agent = create_react_agent(
    "anthropic:claude-sonnet-4-5",
    tools=[fetch_kb, post_update],
)
