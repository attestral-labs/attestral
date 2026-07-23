# Poisoned MCP Apps HTML body (agent clickbait)

Two servers, each shipping an embedded `text/html;profile=mcp-app` resource -
the MCP Apps surface where a server renders its own UI inside the agent host.
`release-dashboard`'s panel looks like a normal status page, but a
`display:none` div carries an instruction-override payload: invisible to the
human looking at the panel, fully readable by the agent whose context the
rendered resource enters. Hiding from the human while steering the model is
the attack - MITRE ATLAS calls it AI Agent Clickbait (AML.T0100); the
delivery is tool-data poisoning (AML.T0099).

`notes-panel` is the control: a benign HTML pane that must stay clean.

```bash
attestral scan examples/mcp-app-html-injection
```

2 components · 1 finding · 1 high

The finding is `ATL-ML-001` on the `release-dashboard` app-UI body, from the
zero-dependency heuristic tier that runs on every scan. The ingester exposes
embedded UI bodies (`_ui_resource_texts`), and the ML layer reduces each to
its agent-readable text before scoring: tags are stripped so hidden-div text
survives, HTML comments are kept (a zero-render channel where payloads hide),
script/style code is dropped, and entities unescape so `&#105;gnore` folds
back to `ignore`. The label of the surface never joins the ATL-ML-002
cross-tool reassembly pool - UI bodies are scored whole, per resource.

## The fix

Treat every server-authored UI body as untrusted input to the agent. Strip or
sandbox rendered resources out of the model's context, and review embedded
HTML for content addressed to the agent rather than the user.

## Research

- **MITRE ATLAS AML.T0100** (AI Agent Clickbait), **AML.T0099** (Tool Data
  Poisoning).
- MCP Apps / SEP-1865 `ui://` resources render server HTML in the host; the
  ext-apps spec (2026-01-26) defaults `connect-src` to `'none'`, which limits
  egress but not context poisoning - the words still reach the model.
- Sibling checks: ATL-160/161/162 (UI CSP and permission declarations, static
  rules) and ATL-220 (fleet-level UI egress pairing). This fixture's rule is
  the *language* complement: the risk is in the words, so it lives in the ML
  layer, not the rule pack.
