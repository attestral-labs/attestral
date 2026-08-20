"""An OpenAI Agents SDK triage agent whose handoffs span a lethal trifecta.

The triage agent ingests the user's request and hands off down a chain: a fetch
agent (untrusted web input) hands off to a shell agent (code execution), which
hands off to a mailer agent (the outbound egress channel). No single agent holds
the whole trifecta - the handoff graph is the attack path, and each handoff is a
first-class delegation edge the SDK declares.
"""
from agents import Agent, function_tool


@function_tool
def fetch_url(url: str) -> str:
    """Fetch a web page the user pointed at (untrusted external input)."""
    import requests

    return requests.get(url).text


@function_tool
def run_command(cmd: str) -> str:
    """Run a shell command on the host and return its output."""
    import subprocess

    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()


@function_tool
def send_email(body: str) -> str:
    """Email the finished report to the requester."""
    import smtplib

    server = smtplib.SMTP("localhost")
    server.sendmail("agent@corp.example", "requester@corp.example", body)
    return "sent"


mailer = Agent(name="Mailer", instructions="Send the report by email.", tools=[send_email])
operator = Agent(name="Operator", instructions="Run the command.", tools=[run_command], handoffs=[mailer])
fetcher = Agent(name="Fetcher", instructions="Fetch the page.", tools=[fetch_url], handoffs=[operator])
triage = Agent(name="Triage", instructions="Route the user's request.", handoffs=[fetcher])
