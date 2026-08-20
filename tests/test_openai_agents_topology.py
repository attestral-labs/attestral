"""OpenAI Agents SDK multi-agent topology ingestion.

An `Agent(name=..., tools=[...], handoffs=[...])` network is modeled as one
`code_agent` component PER AGENT, with an `invokes` edge per handoff (the SDK's
first-class delegation primitive). A trifecta spread across handoff targets
becomes a real cross-agent path. The SDK's `Agent` constructor is disambiguated
from CrewAI's `Agent(role=...)` by carrying `name=` and no `role=`, so a file
that uses one framework never triggers the other's split.
"""
from __future__ import annotations

from attestral.ingest import build_model
from attestral.ingest.agent_code import ingest_agent_code
from attestral.model import SystemModel
from attestral.paths import all_attack_paths

# A triage router hands off down a chain that spreads the trifecta across agents.
_MULTI = '''\
from agents import Agent, function_tool

@function_tool
def fetch(url):
    """Fetch a page."""
    import requests
    return requests.get(url).text

@function_tool
def run(cmd):
    """Run a shell command."""
    import subprocess
    return subprocess.run(cmd, shell=True).stdout

@function_tool
def mail(body):
    """Email a report."""
    import smtplib
    smtplib.SMTP("localhost").sendmail("a@b.c", "d@e.f", body)

mailer = Agent(name="Mailer", tools=[mail])
operator = Agent(name="Operator", tools=[run], handoffs=[mailer])
fetcher = Agent(name="Fetcher", tools=[fetch], handoffs=[operator])
triage = Agent(name="Triage", handoffs=[fetcher])
'''

# One SDK agent: not a topology; the single-surface path models it as one blob
# because it still carries a @function_tool.
_SINGLE = '''\
from agents import Agent, function_tool

@function_tool
def do_all(x):
    """Run a shell command and fetch a page."""
    import subprocess, requests
    requests.get("http://x")
    return subprocess.run(x, shell=True).stdout

solo = Agent(name="Solo", tools=[do_all])
'''

# A CrewAI Agent(role=...) in the same import space must NOT be split by the SDK
# path - the role=/name= disambiguation.
_CREW_NOT_SDK = '''\
from crewai import Agent, Crew
from crewai.tools import tool

@tool("run_shell")
def run_shell(cmd):
    """Run a shell command."""
    import subprocess
    return subprocess.run(cmd, shell=True).stdout

@tool("fetch")
def fetch(url):
    """Fetch a page."""
    import requests
    return requests.get(url).text

a = Agent(role="Operator", tools=[run_shell])
b = Agent(role="Researcher", tools=[fetch])
crew = Crew(agents=[a, b])
'''


# The SDK's idiomatic typed-agent form: Agent[Context](name=..., handoffs=[...]).
# The constructor callee is a Subscript, which a bare dotted-name read misses.
_TYPED = '''\
from agents import Agent, function_tool

@function_tool
def fetch(url):
    """Fetch a page."""
    import requests
    return requests.get(url).text

@function_tool
def run(cmd):
    """Run a shell command."""
    import subprocess
    return subprocess.run(cmd, shell=True).stdout

fetcher = Agent[MyCtx](name="Fetcher", tools=[fetch])
operator = Agent[MyCtx](name="Operator", tools=[run])
triage = Agent[MyCtx](name="Triage", handoffs=[fetcher, operator])
'''


def _model_from(src: str, tmp_path) -> SystemModel:
    (tmp_path / "agents.py").write_text(src)
    m = SystemModel()
    ingest_agent_code(tmp_path, m)
    return m


def test_agents_split_into_one_component_per_agent(tmp_path):
    m = _model_from(_MULTI, tmp_path)
    agents = {c.name: set(c.attr("_capabilities") or []) for c in m.by_type("code_agent")}
    assert set(agents) == {"Triage", "Fetcher", "Operator", "Mailer"}
    assert "network" in agents["Fetcher"]
    assert "shell" in agents["Operator"]
    assert agents["Mailer"] & {"network", "messaging"}
    assert all(c.attr("_sdk_agent") for c in m.by_type("code_agent"))


def test_handoffs_become_invokes_edges(tmp_path):
    m = _model_from(_MULTI, tmp_path)
    ids = {c.name: c.id for c in m.by_type("code_agent")}
    invokes = {(e.source_id, e.target_id) for e in m.edges if e.kind == "invokes"}
    assert (ids["Triage"], ids["Fetcher"]) in invokes
    assert (ids["Fetcher"], ids["Operator"]) in invokes
    assert (ids["Operator"], ids["Mailer"]) in invokes


def test_cross_agent_attack_path_spans_distinct_agents(tmp_path):
    m = _model_from(_MULTI, tmp_path)
    paths = all_attack_paths(m)
    assert paths, "the handoff network should assemble a cross-agent path"
    p = paths[0]
    assert "Operator" in p.pivot.components
    assert "Operator" not in p.entry.components


def test_single_agent_stays_one_component(tmp_path):
    m = _model_from(_SINGLE, tmp_path)
    assert len(m.by_type("code_agent")) == 1


def test_crewai_agent_not_split_by_sdk_path(tmp_path):
    # role= => CrewAI; the SDK split must not fire, and the crew split still owns it
    m = _model_from(_CREW_NOT_SDK, tmp_path)
    assert all(not c.attr("_sdk_agent") for c in m.by_type("code_agent"))
    assert any(c.attr("_crew_agent") for c in m.by_type("code_agent"))


def test_typed_agent_subscript_constructor_is_recognized(tmp_path):
    # Agent[Context](...) - the callee is a Subscript; the split must still fire.
    m = _model_from(_TYPED, tmp_path)
    agents = {c.name for c in m.by_type("code_agent")}
    assert agents == {"Fetcher", "Operator", "Triage"}
    ids = {c.name: c.id for c in m.by_type("code_agent")}
    invokes = {(e.source_id, e.target_id) for e in m.edges if e.kind == "invokes"}
    assert (ids["Triage"], ids["Fetcher"]) in invokes
    assert (ids["Triage"], ids["Operator"]) in invokes


def test_shipped_fixture_models_four_agents():
    m = build_model("examples/openai-agents-handoff")
    assert len(m.by_type("code_agent")) == 4
