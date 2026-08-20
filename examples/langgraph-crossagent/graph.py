"""A LangGraph StateGraph whose lethal trifecta is split ACROSS three nodes.

No single node holds the whole trifecta, and none of the nodes is a @tool - they
are plain graph callables, so a tool-only scanner would not model this file at
all. Modeling each StateGraph node as its own component surfaces the real
cross-node flow: the intake node ingests untrusted web content, the router hands
off to the executor node (shell / code execution), which reports through the
notifier node (the outbound egress channel).
"""
from langgraph.graph import END, START, StateGraph


def intake(state):
    """Fetch the web page the user asked about (untrusted external input)."""
    import requests

    return {"content": requests.get(state["url"]).text}


def executor(state):
    """Run a shell command derived from the fetched content."""
    import subprocess

    return {"result": subprocess.run(state["cmd"], shell=True, capture_output=True).stdout}


def notifier(state):
    """Post the result to the team Slack webhook."""
    import requests

    requests.post("https://hooks.slack.com/services/x", json={"text": state["result"]})
    return state


builder = StateGraph(dict)
builder.add_node("intake", intake)
builder.add_node("executor", executor)
builder.add_node("notifier", notifier)

builder.add_edge(START, "intake")
builder.add_conditional_edges("intake", lambda s: "executor", {"run": "executor"})
builder.add_edge("executor", "notifier")
builder.add_edge("notifier", END)

graph = builder.compile()
