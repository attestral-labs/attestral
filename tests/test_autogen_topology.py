"""AutoGen multi-agent topology ingestion.

A team container (GroupChat / RoundRobinGroupChat / Swarm / ...) is modeled as one
`code_agent` component PER MEMBER, chained with `invokes` edges in the team's agent
order. Each AssistantAgent's capabilities are read from its `tools=[...]` (plain
callables, not @tool-decorated), so this also models teams that carry a full
trifecta with no @tool in the file. A trifecta split across the team becomes a real
cross-agent path the fleet synthesis surfaces.
"""
from __future__ import annotations

from attestral.ingest import build_model
from attestral.ingest.agent_code import ingest_agent_code
from attestral.model import SystemModel
from attestral.paths import all_attack_paths

# Three AssistantAgents wired into a round robin; the trifecta is split across them.
_MULTI = '''\
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import RoundRobinGroupChat

def fetch(url):
    """Fetch a page."""
    import requests
    return requests.get(url).text

def run(cmd):
    """Run a shell command."""
    import subprocess
    return subprocess.run(cmd, shell=True).stdout

def post(msg):
    """Post to Slack."""
    import requests
    return requests.post("https://hooks.slack.com/x", json={"text": msg})

researcher = AssistantAgent(name="Researcher", tools=[fetch])
operator = AssistantAgent(name="Operator", tools=[run])
reporter = AssistantAgent(name="Reporter", tools=[post])
team = RoundRobinGroupChat([researcher, operator, reporter])
'''

# One agent, no team of >= 2: not a topology. It carries no @tool either, so it is
# simply not modeled (precision over recall) - assert it did not split.
_SINGLE = '''\
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import RoundRobinGroupChat

def run(cmd):
    """Run a shell command."""
    import subprocess
    return subprocess.run(cmd, shell=True).stdout

solo = AssistantAgent(name="Solo", tools=[run])
team = RoundRobinGroupChat([solo])
'''


def _model_from(src: str, tmp_path) -> SystemModel:
    (tmp_path / "team.py").write_text(src)
    m = SystemModel()
    ingest_agent_code(tmp_path, m)
    return m


def test_team_splits_into_one_component_per_member(tmp_path):
    m = _model_from(_MULTI, tmp_path)
    agents = {c.name: set(c.attr("_capabilities") or []) for c in m.by_type("code_agent")}
    assert set(agents) == {"Researcher", "Operator", "Reporter"}
    assert "network" in agents["Researcher"]
    assert "shell" in agents["Operator"]
    assert agents["Reporter"] & {"network", "messaging"}
    assert all(c.attr("_autogen_agent") for c in m.by_type("code_agent"))


def test_team_members_chained_in_order(tmp_path):
    m = _model_from(_MULTI, tmp_path)
    ids = {c.name: c.id for c in m.by_type("code_agent")}
    invokes = {(e.source_id, e.target_id) for e in m.edges if e.kind == "invokes"}
    assert (ids["Researcher"], ids["Operator"]) in invokes
    assert (ids["Operator"], ids["Reporter"]) in invokes


def test_cross_agent_attack_path_spans_distinct_agents(tmp_path):
    m = _model_from(_MULTI, tmp_path)
    paths = all_attack_paths(m)
    assert paths, "the split team should assemble a cross-agent path"
    p = paths[0]
    assert "Operator" in p.pivot.components
    assert "Operator" not in p.entry.components


def test_single_member_team_does_not_split(tmp_path):
    m = _model_from(_SINGLE, tmp_path)
    assert len(m.by_type("code_agent")) <= 1


def test_shipped_fixture_models_three_agents():
    m = build_model("examples/autogen-groupchat")
    assert len(m.by_type("code_agent")) == 3
