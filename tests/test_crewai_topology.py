"""CrewAI multi-agent topology ingestion.

A crew is modeled as one `code_agent` component PER AGENT (not one blob per file),
each with only its own tools' capabilities, plus `invokes` delegation edges. The
payoff is that a toxic flow split across agents (untrusted-input agent -> shell
agent -> egress agent) becomes a real cross-agent attack path the fleet synthesis
surfaces. A single-agent crew still models as one component.
"""
from __future__ import annotations

from attestral.ingest import build_model
from attestral.ingest.agent_code import ingest_agent_code
from attestral.model import SystemModel
from attestral.paths import all_attack_paths

_MULTI = '''\
from crewai import Agent, Crew
from crewai.tools import tool

@tool("web_fetch")
def web_fetch(url):
    """Fetch a web page."""
    import requests
    return requests.get(url).text

@tool("run_shell")
def run_shell(cmd):
    """Run a shell command."""
    import subprocess
    return subprocess.run(cmd, shell=True).stdout

@tool("post")
def post(msg):
    """Post to Slack."""
    import requests
    return requests.post("https://hooks.slack.com/x", json={"text": msg})

a = Agent(role="Web Researcher", tools=[web_fetch])
b = Agent(role="Shell Operator", tools=[run_shell])
c = Agent(role="Slack Reporter", tools=[post])
crew = Crew(agents=[a, b, c])
'''

_SINGLE = '''\
from crewai import Agent, Crew
from crewai.tools import tool

@tool("run_shell")
def run_shell(cmd):
    """Run a shell command and fetch a page."""
    import subprocess, requests
    requests.get("http://x")
    return subprocess.run(cmd, shell=True).stdout

only = Agent(role="Solo", tools=[run_shell])
crew = Crew(agents=[only])
'''


def _model_from(src: str, tmp_path) -> SystemModel:
    (tmp_path / "crew.py").write_text(src)
    m = SystemModel()
    ingest_agent_code(tmp_path, m)
    return m


def test_crew_splits_into_one_component_per_agent(tmp_path):
    m = _model_from(_MULTI, tmp_path)
    agents = {c.name: set(c.attr("_capabilities") or []) for c in m.by_type("code_agent")}
    assert set(agents) == {"Web Researcher", "Shell Operator", "Slack Reporter"}
    assert "network" in agents["Web Researcher"]
    assert "shell" in agents["Shell Operator"]
    assert agents["Slack Reporter"] & {"network", "messaging"}
    # delegation edges connect the crew's agents
    assert sum(1 for e in m.edges if e.kind == "invokes") >= 2


def test_cross_agent_attack_path_spans_distinct_agents(tmp_path):
    m = _model_from(_MULTI, tmp_path)
    paths = all_attack_paths(m)
    assert paths, "the split crew should assemble a cross-agent path"
    p = paths[0]
    # the pivot (shell) is a DIFFERENT agent than the entry/impact - a real
    # cross-agent flow, not a single-component trifecta.
    assert "Shell Operator" in p.pivot.components
    assert "Shell Operator" not in p.entry.components


def test_single_agent_crew_stays_one_component(tmp_path):
    m = _model_from(_SINGLE, tmp_path)
    agents = m.by_type("code_agent")
    assert len(agents) == 1  # no split when only one agent


def test_shipped_fixture_models_three_agents():
    m = build_model("examples/crewai-crossagent")
    assert len([c for c in m.by_type("code_agent")]) == 3
