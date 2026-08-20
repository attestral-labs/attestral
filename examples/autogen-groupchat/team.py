"""An AutoGen group chat whose lethal trifecta is split ACROSS three agents.

No single agent holds the whole trifecta, and the tools are plain callables handed
to each agent's `tools=[...]`, not @tool decorators - so a tool-only scanner would
not model this file. Modeling each team member as its own component surfaces the
real cross-agent flow: the researcher ingests untrusted web content, the round
robin passes to the operator (code execution), which passes to the reporter (the
outbound egress channel).
"""
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import RoundRobinGroupChat


def fetch_page(url: str) -> str:
    """Fetch a web page the user asked about (untrusted external input)."""
    import requests

    return requests.get(url).text


def run_shell(cmd: str) -> str:
    """Run a shell command on the host and return its output."""
    import subprocess

    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()


def post_slack(message: str) -> str:
    """Post a message to the team Slack webhook."""
    import requests

    return requests.post("https://hooks.slack.com/services/x", json={"text": message}).text


researcher = AssistantAgent(name="Researcher", tools=[fetch_page])
operator = AssistantAgent(name="Operator", tools=[run_shell])
reporter = AssistantAgent(name="Reporter", tools=[post_slack])

team = RoundRobinGroupChat([researcher, operator, reporter])
