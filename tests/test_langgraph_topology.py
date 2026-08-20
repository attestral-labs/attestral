"""LangGraph multi-node topology ingestion.

A StateGraph is modeled as one `code_agent` component PER NODE (not one blob per
file), each with only its own node function's capabilities, plus `invokes` edges
read from add_edge / add_conditional_edges. The payoff mirrors the CrewAI split: a
toxic flow spread across nodes (untrusted-input node -> shell node -> egress node)
becomes a real cross-node attack path the fleet synthesis surfaces. Because node
functions are plain callables (not @tool-decorated), this also models graphs that
carry a full trifecta with no @tool in the file at all - which the tool gate,
checked after topology, would otherwise drop entirely.
"""
from __future__ import annotations

from attestral.ingest import build_model
from attestral.ingest.agent_code import ingest_agent_code
from attestral.model import SystemModel
from attestral.paths import all_attack_paths

# No @tool anywhere: three plain node functions carry the split trifecta, wired
# with a conditional edge (intake -> executor) and a plain edge (executor -> notifier).
_MULTI = '''\
from langgraph.graph import START, END, StateGraph

def intake(state):
    """Fetch the page the user asked about."""
    import requests
    return {"content": requests.get(state["url"]).text}

def executor(state):
    """Run a shell command."""
    import subprocess
    return {"out": subprocess.run(state["cmd"], shell=True).stdout}

def notifier(state):
    """Post the result to Slack."""
    import requests
    requests.post("https://hooks.slack.com/x", json={"text": state["out"]})
    return state

g = StateGraph(dict)
g.add_node("intake", intake)
g.add_node("executor", executor)
g.add_node("notifier", notifier)
g.add_edge(START, "intake")
g.add_conditional_edges("intake", lambda s: "executor", {"run": "executor"})
g.add_edge("executor", "notifier")
g.add_edge("notifier", END)
graph = g.compile()
'''

# One node: not a topology. It carries a @tool so the single-surface path still
# models it as exactly one component (the >= 2 gate is not met).
_SINGLE = '''\
from langgraph.graph import StateGraph
from langchain_core.tools import tool

@tool
def do_everything(x):
    """Run a shell command and fetch a page."""
    import subprocess, requests
    requests.get("http://x")
    return subprocess.run(x, shell=True).stdout

def step(state):
    return {"out": do_everything(state["x"])}

g = StateGraph(dict)
g.add_node("only", step)
graph = g.compile()
'''


def _model_from(src: str, tmp_path) -> SystemModel:
    (tmp_path / "graph.py").write_text(src)
    m = SystemModel()
    ingest_agent_code(tmp_path, m)
    return m


def test_graph_splits_into_one_component_per_node(tmp_path):
    m = _model_from(_MULTI, tmp_path)
    nodes = {c.name: set(c.attr("_capabilities") or []) for c in m.by_type("code_agent")}
    assert set(nodes) == {"intake", "executor", "notifier"}
    assert "network" in nodes["intake"]
    assert "shell" in nodes["executor"]
    assert nodes["notifier"] & {"network", "messaging"}
    # every split node is flagged as a graph node
    assert all(c.attr("_graph_node") for c in m.by_type("code_agent"))
    # add_edge + add_conditional_edges both contribute invokes edges
    assert sum(1 for e in m.edges if e.kind == "invokes") >= 2


def test_conditional_edge_connects_nodes(tmp_path):
    m = _model_from(_MULTI, tmp_path)
    ids = {c.name: c.id for c in m.by_type("code_agent")}
    invokes = {(e.source_id, e.target_id) for e in m.edges if e.kind == "invokes"}
    # the conditional edge intake -> executor and the plain edge executor -> notifier
    assert (ids["intake"], ids["executor"]) in invokes
    assert (ids["executor"], ids["notifier"]) in invokes


def test_cross_node_attack_path_spans_distinct_nodes(tmp_path):
    m = _model_from(_MULTI, tmp_path)
    paths = all_attack_paths(m)
    assert paths, "the split graph should assemble a cross-node path"
    p = paths[0]
    # the pivot (shell) is a DIFFERENT node than the entry - a real cross-node
    # flow, not a single-component trifecta.
    assert "executor" in p.pivot.components
    assert "executor" not in p.entry.components


def test_single_node_graph_stays_one_component(tmp_path):
    m = _model_from(_SINGLE, tmp_path)
    assert len(m.by_type("code_agent")) == 1  # no split when only one node


def test_shipped_fixture_models_three_nodes():
    m = build_model("examples/langgraph-crossagent")
    assert len(m.by_type("code_agent")) == 3
