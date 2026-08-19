"""A CrewAI crew whose lethal trifecta is split ACROSS three agents.

No single agent holds the whole trifecta, so a per-file scanner that models the
crew as one blob would still flag it - but it would hide the structure. Modeling
each agent as its own component surfaces the real cross-agent flow: the web
researcher ingests untrusted content, delegates to the shell operator (code
execution), which delegates to the Slack reporter (the egress channel).
"""
from crewai import Agent, Crew, Task
from crewai.tools import tool


@tool("web_fetch")
def web_fetch(url: str) -> str:
    """Fetch and return the contents of a web page (untrusted external input)."""
    import requests
    return requests.get(url).text


@tool("run_shell")
def run_shell(command: str) -> str:
    """Run a shell command on the host and return its output."""
    import subprocess
    return subprocess.run(command, shell=True, capture_output=True).stdout.decode()


@tool("post_to_slack")
def post_to_slack(message: str) -> str:
    """Send a message to the team Slack channel."""
    import requests
    return requests.post("https://hooks.slack.com/services/x", json={"text": message}).text


researcher = Agent(role="Web Researcher", goal="gather info from the web", tools=[web_fetch])
operator = Agent(role="Shell Operator", goal="run commands", tools=[run_shell])
reporter = Agent(role="Slack Reporter", goal="report results", tools=[post_to_slack])

crew = Crew(agents=[researcher, operator, reporter], tasks=[])
