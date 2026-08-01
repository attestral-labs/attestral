"""Interactive threat topography: a self-contained HTML blast-radius map.

A terminal report tells you a finding exists; this renders what it can *reach*.
`attestral scan PATH --format html -o topo.html` emits one self-contained,
offline HTML file (no external requests, theme-aware) that draws every modeled
component as a node sized by its blast radius, grouped into its trust-boundary
zone (agent runtime, cloud, cluster), with the modeled edges between them - the
agent-to-cloud reachability picture a per-file scanner cannot draw. Clicking a
surface animates the if-compromised wavefront to the capability classes it can
drive; clicking a walked attack path lights up the entry -> pivot -> impact
chain the symbolic walk proved reachable, crossing zone borders. The picture is
the tool's own reasoning (same model, blast radius, and red-team walk), not a
redraw.

Design invariant: the scanner stays terminal-first. This writes a file only when
the user opts in with `--format html` (and `-o`), exactly like `sarif`/`aibom`.
"""
from __future__ import annotations

import html
import json

from attestral.blast_radius import blast_radius
from attestral.model import Finding, SystemModel
from attestral.redteam import build_proofs

# Impact vocabulary for each capability class a blast radius can reach: the rail
# label, its one-line "what breaks", and the verb phrase used in the narrative.
# A class not listed still renders with a sensible fallback, so a new capability
# never crashes the view.
_IMPACT = {
    "cloud":      ("cloud",      "cloud account / infra",      "take over the connected <b>cloud account</b>"),
    "shell":      ("shell",      "arbitrary host commands",    "run <b>arbitrary commands</b> on the host"),
    "filesystem": ("filesystem", "read / write the disk",      "read and write the <b>host filesystem</b>"),
    "network":    ("network",    "outbound exfil channel",     "open an <b>outbound exfiltration</b> channel"),
    "memory":     ("memory",     "poison agent memory",        "<b>poison the agent's long-term memory</b>"),
    "database":   ("database",   "read / write databases",     "read and write connected <b>databases</b>"),
    "messaging":  ("messaging",  "send as the agent",          "send <b>messages as the agent</b>"),
    "saas_data":  ("saas_data",  "SaaS data access",           "reach connected <b>SaaS data</b>"),
    "ui_egress":  ("ui_egress",  "embedded UI egress",         "exfiltrate through an <b>embedded UI</b>"),
}
# The order capability sinks appear in the impact rail (known first, then any new
# class in stable order so the layout is deterministic).
_SINK_ORDER = ("cloud", "shell", "filesystem", "network", "memory",
               "database", "messaging", "saas_data", "ui_egress")

# Trust-boundary zones render in this order (only when non-empty); any boundary
# outside the seeded three follows in sorted order, so the layout stays
# deterministic for a fixed model.
_ZONE_ORDER = ("agent_runtime", "cloud", "cluster")
# Surfaces drawn per zone; past the cap the zone collapses the rest into a
# "+N more" marker so a large fleet never becomes an unreadable hairball.
_ZONE_CAP = 18


def _sink_meta(cls: str) -> dict:
    label, desc, _ = _IMPACT.get(cls, (cls, "reachable capability", None))
    return {"k": cls, "t": label, "d": desc}


def build_topography(model: SystemModel, findings: list[Finding]) -> dict:
    """The structured data the view renders: surfaces grouped into
    trust-boundary zones (each with blast score + the capability classes it
    reaches), the modeled edges between rendered surfaces, the walked attack
    paths, the impact sinks present, and the findings grouped into
    per-component and fleet-level (model-scoped) sets."""
    blast = {b.component_id: b for b in blast_radius(model)}
    by_zone: dict[str, list[dict]] = {}
    for c in model.components:
        b = blast.get(c.id)
        zone = c.trust_boundary or "agent_runtime"
        by_zone.setdefault(zone, []).append({
            "id": c.id, "name": c.name, "type": c.type,
            "boundary": zone,
            "caps": list(c.attr("_capabilities") or []),
            "secrets": bool(c.attr("_env_has_secrets")),
            "score": round(b.score, 1) if b else 0.0,
            "reached": dict(b.reached) if b else {},
        })
    # Zones in fixed order, only when present; inside a zone the highest blast
    # radius renders first, so the cap always keeps the most dangerous surfaces.
    zone_keys = [k for k in _ZONE_ORDER if k in by_zone]
    zone_keys += sorted(k for k in by_zone if k not in _ZONE_ORDER)
    comps: list[dict] = []
    zones: list[dict] = []
    for k in zone_keys:
        rows = sorted(by_zone[k], key=lambda r: (-r["score"], r["id"]))
        zones.append({"k": k, "more": max(0, len(rows) - _ZONE_CAP)})
        comps.extend(rows[:_ZONE_CAP])

    # Modeled edges whose both endpoints render as nodes. Taint/boundary
    # sentinels (`taint:*`, `boundary:cloud`) have no node, so they drop out
    # here; cross marks an edge whose endpoints sit in different boundaries.
    boundary_of = {c["id"]: c["boundary"] for c in comps}
    seen: set[tuple[str, str]] = set()
    edges: list[dict] = []
    for e in model.edges:
        sb, tb = boundary_of.get(e.source_id), boundary_of.get(e.target_id)
        if sb is None or tb is None or e.source_id == e.target_id:
            continue
        key = (e.source_id, e.target_id)
        if key in seen:
            continue
        seen.add(key)
        edges.append({"s": e.source_id, "t": e.target_id, "cross": sb != tb})
    edges.sort(key=lambda e: (e["s"], e["t"]))

    # The walked attack paths, as chains of rendered node ids. Proof steps name
    # components; map names back to ids and skip any step whose component is
    # not a rendered node, so the overlay never points at a missing position.
    name_to_id: dict[str, str] = {}
    for c in comps:
        name_to_id.setdefault(c["name"], c["id"])
    paths: list[dict] = []
    for p in build_proofs(model):
        steps = [{"id": name_to_id[s.component], "role": s.role}
                 for s in p.steps if s.component in name_to_id]
        if steps:
            paths.append({"kind": p.kind, "sev": p.severity.value, "steps": steps})

    # Which capability classes any rendered surface reaches -> the impact rail.
    reached_classes = {k for c in comps for k in c["reached"]}
    sinks = [_sink_meta(k) for k in _SINK_ORDER if k in reached_classes]
    sinks += [_sink_meta(k) for k in sorted(reached_classes) if k not in _SINK_ORDER]

    per_comp, fleet = [], []
    comp_ids = {c["id"] for c in comps}
    for f in findings:
        row = {"rule": f.rule_id, "sev": f.severity.name.lower(),
               "comp": f.component_id, "title": f.title}
        (per_comp if f.component_id in comp_ids else fleet).append(row)
    return {"components": comps, "zones": zones, "edges": edges, "paths": paths,
            "sinks": sinks, "findings": per_comp, "fleet": fleet}


def render_topography(model: SystemModel, findings: list[Finding], target: str) -> str:
    """A complete, self-contained HTML document (no external requests) for the
    interactive blast-radius topography of `target`."""
    data = build_topography(model, findings)
    data["fixture"] = target
    n_comp = len(model.components)
    n_find = len(findings)
    # Escape the HTML-significant characters so a component name or finding title
    # drawn from a (possibly poisoned) scanned config can never break out of the
    # <script> literal. < etc. are valid JSON and render back as < in JS.
    payload = (json.dumps(data, separators=(",", ":"))
               .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))
    subtitle = html.escape(
        f"live scan · {target} · {n_comp} surfaces · {n_find} findings"
    )
    return _TEMPLATE.replace("__DATA__", payload).replace("__SUB__", subtitle)


# The view. Static CSS/JS; only __DATA__ and __SUB__ are substituted. Kept in one
# string so the output is a single portable file. Mirrors the site design tokens
# (seal red, verify green) so it reads as the same product.
_TEMPLATE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attestral Threat Topography</title>
<style>
  :root{
    --bg:#0B0F0D;--panel:#141A16;--card:#182019;--ink:#E9ECE4;--muted:#8B968C;
    --hair:#28322B;--seal:#E0555F;--wave:#E0555F;--node:#1E2721;
    --crit:#E0555F;--high:#E0A33C;--med:#CBA14B;--none:#5A6B60;
    --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
    --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  }
  @media (prefers-color-scheme:light){:root{
    --bg:#F3F4F1;--panel:#FBFBF9;--card:#FFF;--ink:#171F1C;--muted:#5D6660;
    --hair:#DADED7;--seal:#96222E;--wave:#96222E;--node:#EEF0EC;
    --crit:#96222E;--high:#9A6712;--med:#7D6320;--none:#9BA79C;}}
  :root[data-theme="dark"]{
    --bg:#0B0F0D;--panel:#141A16;--card:#182019;--ink:#E9ECE4;--muted:#8B968C;
    --hair:#28322B;--seal:#E0555F;--wave:#E0555F;--node:#1E2721;
    --crit:#E0555F;--high:#E0A33C;--med:#CBA14B;--none:#5A6B60;}
  :root[data-theme="light"]{
    --bg:#F3F4F1;--panel:#FBFBF9;--card:#FFF;--ink:#171F1C;--muted:#5D6660;
    --hair:#DADED7;--seal:#96222E;--wave:#96222E;--node:#EEF0EC;
    --crit:#96222E;--high:#9A6712;--med:#7D6320;--none:#9BA79C;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
    line-height:1.5;-webkit-font-smoothing:antialiased}
  .wrap{max-width:1220px;margin:0 auto;padding:24px 20px 64px}
  .top{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;
    border-bottom:1px solid var(--hair);padding-bottom:18px;margin-bottom:22px}
  .mark{display:flex;align-items:center;gap:12px}
  .plate{width:34px;height:34px;border-radius:3px;background:var(--seal);color:#fff;
    display:grid;place-items:center;font-family:var(--mono);font-weight:700;font-size:19px;flex:0 0 auto}
  h1{font-size:20px;margin:0;letter-spacing:-.01em;font-weight:640}
  .sub{color:var(--muted);font-size:12.5px;margin-top:3px;font-family:var(--mono)}
  .toggle{background:var(--card);border:1px solid var(--hair);color:var(--muted);
    border-radius:3px;padding:7px 10px;cursor:pointer;font-family:var(--mono);font-size:12px}
  .toggle:hover{color:var(--ink)}
  .lede{color:var(--muted);font-size:14.5px;max-width:72ch;margin:0 0 20px}
  .lede b{color:var(--ink);font-weight:600}
  .grid{display:grid;grid-template-columns:1.55fr 1fr;gap:18px;align-items:start}
  @media (max-width:880px){.grid{grid-template-columns:1fr}}
  .stage{background:var(--panel);border:1px solid var(--hair);border-radius:6px;padding:8px;overflow-x:auto}
  svg{width:100%;height:auto;display:block;min-width:560px}
  .zone-label,.rail-label{font-family:var(--mono);font-size:10.5px;letter-spacing:.14em;
    text-transform:uppercase;fill:var(--muted)}
  .nlabel{font-family:var(--mono);font-size:11px;fill:var(--ink)}
  .nmeta{font-family:var(--mono);font-size:9px;fill:var(--muted)}
  .snode{cursor:pointer}.snode:focus{outline:none}
  .mesh{stroke:var(--hair);stroke-width:1;fill:none;opacity:.75}
  .mesh.cross{stroke:var(--seal);opacity:.5;stroke-dasharray:3 4}
  .edge{stroke:var(--wave);fill:none;opacity:0;transition:opacity .25s}
  .edge.live{opacity:.85}
  .hop{font-family:var(--mono);font-size:9px;fill:var(--wave);opacity:0}.hop.live{opacity:.9}
  .pseg{stroke:var(--wave);stroke-width:2.4;fill:none;stroke-dasharray:7 5;opacity:.95;
    animation:march 1.1s linear infinite}
  @keyframes march{to{stroke-dashoffset:-24}}
  .role{font-family:var(--mono);font-size:9px;fill:var(--wave);letter-spacing:.08em;text-transform:uppercase}
  .sink{fill:var(--card);stroke:var(--hair)}.sink.hit{stroke:var(--wave)}
  .sink-t{font-family:var(--mono);font-size:11px;fill:var(--ink)}
  .sink-d{font-family:var(--sans);font-size:10px;fill:var(--muted)}
  .dim{opacity:.22;transition:opacity .25s}
  .panel{background:var(--panel);border:1px solid var(--hair);border-radius:6px;padding:18px;position:sticky;top:16px}
  .pk{font-family:var(--mono);font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
  .pname{font-family:var(--mono);font-size:17px;font-weight:600;margin:2px 0 0}
  .score{display:flex;align-items:baseline;gap:8px;margin:14px 0 4px}
  .score b{font-family:var(--mono);font-size:34px;font-weight:680;line-height:1;letter-spacing:-.02em}
  .score span{color:var(--muted);font-size:12px;font-family:var(--mono)}
  .bar{height:6px;border-radius:3px;background:var(--hair);overflow:hidden;margin:8px 0 16px}
  .bar>i{display:block;height:100%;background:var(--wave)}
  .h{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:16px 0 8px;font-family:var(--mono)}
  .chips{display:flex;flex-wrap:wrap;gap:6px}
  .chip{font-family:var(--mono);font-size:11px;padding:4px 8px;border-radius:3px;
    background:var(--card);border:1px solid var(--hair);color:var(--ink)}
  .chip.hop0{border-color:var(--wave);color:var(--wave)}
  .impact{color:var(--muted);font-size:13px;margin:4px 0 0}.impact b{color:var(--ink)}
  .flist{list-style:none;margin:6px 0 0;padding:0;display:flex;flex-direction:column;gap:7px}
  .fitem{display:grid;grid-template-columns:auto 1fr;gap:9px;align-items:start;
    padding:8px 10px;background:var(--card);border:1px solid var(--hair);border-radius:4px}
  .pitem{cursor:pointer}.pitem:hover{border-color:var(--seal)}.pitem.on{border-color:var(--seal)}
  .sev{width:8px;height:8px;border-radius:2px;margin-top:5px}
  .frule{font-family:var(--mono);font-size:11px;color:var(--muted)}
  .ftitle{font-size:12.5px}
  .empty{color:var(--muted);font-size:12.5px;font-style:italic}
  .legend{display:flex;flex-wrap:wrap;gap:14px;margin-top:14px;font-family:var(--mono);font-size:11px;color:var(--muted);align-items:center}
  .legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:middle}
  .tri{margin-top:16px;background:var(--panel);border:1px solid color-mix(in srgb,var(--seal) 40%,var(--hair));border-radius:6px;padding:14px 16px}
  .tri .pk{color:var(--seal)}.tri p{margin:6px 0 0;font-size:13px;color:var(--ink)}
  .foot{margin-top:26px;color:var(--muted);font-size:12px;font-family:var(--mono);border-top:1px solid var(--hair);padding-top:14px}
  .foot code{color:var(--ink)}
  @media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style></head><body>
<div class="wrap">
  <div class="top">
    <div class="mark"><div class="plate">A</div>
      <div><h1>Threat Topography</h1><div class="sub">__SUB__</div></div></div>
    <button class="toggle" id="tt">theme</button>
  </div>
  <p class="lede">A report tells you a finding exists. This tells you what it can <b>reach</b>.
  Every node is a modeled component, grouped into its <b>trust boundary</b>; its size is its
  <b>blast radius</b> - the if-compromised reach over the modeled design. Faint lines are modeled
  edges; dashed red ones cross a boundary. <b>Click a surface</b> to simulate its compromise, or
  <b>click an attack path</b> in the panel to light up a walked entry -> pivot -> impact chain.
  Esc or the background clears the overlay.</p>
  <div class="grid">
    <div class="stage">
      <svg id="svg" role="img" aria-label="Interactive agent threat topography">
        <g id="zones"></g><g id="mesh"></g><g id="edges"></g><g id="sinks"></g><g id="nodes"></g></svg>
      <div class="legend">
        <span><i style="background:var(--crit)"></i>critical</span>
        <span><i style="background:var(--high)"></i>high</span>
        <span><i style="background:var(--med)"></i>medium</span>
        <span><i style="background:var(--none)"></i>no direct finding</span>
        <span><i style="background:var(--seal);height:2px;width:14px;border-radius:0"></i>crosses a boundary</span>
        <span>&#9671; holds secrets</span><span>size = blast radius</span>
      </div>
      <div class="tri" id="tri" hidden><div class="pk" id="tri-k"></div><p id="tri-p"></p></div>
    </div>
    <div class="panel" id="panel">
      <div class="pk">Blast-radius simulation</div>
      <div class="pname" id="p-name">select a surface</div>
      <div class="score"><b id="p-score">-</b><span id="p-rank"></span></div>
      <div class="bar"><i id="p-fill" style="width:0"></i></div>
      <div class="h">If compromised, reaches</div>
      <div class="chips" id="p-reach"></div>
      <p class="impact" id="p-impact"></p>
      <div class="h">Findings on this surface</div>
      <ul class="flist" id="p-findings"></ul>
      <div class="h" id="p-paths-h">Attack paths - walked over the model</div>
      <ul class="flist" id="p-paths"></ul>
    </div>
  </div>
  <div class="foot">Live data from <code id="foot-fx"></code> ·
    <code>attestral scan --format html</code>. Reach is over declared capability in the modeled
    design - a prioritisation signal, not proof of exploitability.</div>
</div>
<script>
const DATA=__DATA__;
const IMPACT={cloud:"take over the connected <b>cloud account</b>",shell:"run <b>arbitrary commands</b> on the host",filesystem:"read and write the <b>host filesystem</b>",network:"open an <b>outbound exfiltration</b> channel",memory:"<b>poison the agent's long-term memory</b>",database:"read and write connected <b>databases</b>",messaging:"send <b>messages as the agent</b>",saas_data:"reach connected <b>SaaS data</b>",ui_egress:"exfiltrate through an <b>embedded UI</b>"};
const SEV={critical:"var(--crit)",high:"var(--high)",medium:"var(--med)",low:"var(--none)",info:"var(--none)"};
const SRANK={critical:4,high:3,medium:2,low:1,info:0};
const ZLABEL={agent_runtime:"agent runtime",cloud:"cloud",cluster:"cluster"};
const NS="http://www.w3.org/2000/svg";
const el=(n,a={})=>{const e=document.createElementNS(NS,n);for(const k in a)e.setAttribute(k,a[k]);return e;};
const byComp={};DATA.findings.forEach(f=>{(byComp[f.comp]=byComp[f.comp]||[]).push(f);});
const worst=id=>{let s=null,r=0;(byComp[id]||[]).forEach(f=>{if(SRANK[f.sev]>r){r=SRANK[f.sev];s=f.sev;}});return s;};
const comps=DATA.components, sinks=DATA.sinks, zones=DATA.zones||[],
      meshEdges=DATA.edges||[], paths=DATA.paths||[];
const cols=3,ZX=36,ZY0=64,cw=190,rh=126,ZGAP=26;
const ZW=cw*cols+52,RX=ZX+ZW+56,RW=248;
const byZone={};comps.forEach(c=>{(byZone[c.boundary]=byZone[c.boundary]||[]).push(c);});
// One dashed zone per trust boundary present, stacked; each keeps the grid math.
const pos={};const zoneGeo=[];let zy=ZY0;
zones.forEach(z=>{const zc=byZone[z.k]||[];const slots=zc.length+(z.more?1:0);
  const rows=Math.max(1,Math.ceil(slots/cols));
  const h=Math.max(160,rows*rh+52);
  zc.forEach((c,i)=>{const col=i%cols,row=(i-col)/cols;
    pos[c.id]={x:ZX+28+col*cw+cw/2-14,y:zy+58+row*rh};});
  zoneGeo.push({k:z.k,y:zy,h:h,more:z.more,slot:zc.length});
  zy+=h+ZGAP;});
const stageBottom=zones.length?zy-ZGAP:ZY0+150;
const VW=RX+RW+20, VH=Math.max(stageBottom+30, ZY0+sinks.length*100+40);
document.getElementById("svg").setAttribute("viewBox",`0 0 ${VW} ${VH}`);
const sinkPos={};sinks.forEach((s,i)=>{sinkPos[s.k]={x:RX+16,y:ZY0+34+i*100,w:RW-32,h:66};});
const scoreVals=comps.map(c=>c.score),SMAX=Math.max(1,...scoreVals),SMIN=Math.min(...scoreVals);
const rankOrder=comps.slice().sort((a,b)=>b.score-a.score).map(c=>c.id);
const gZ=document.getElementById("zones"),gM=document.getElementById("mesh"),
      gE=document.getElementById("edges"),gS=document.getElementById("sinks"),
      gN=document.getElementById("nodes");
zoneGeo.forEach(z=>{
  gZ.appendChild(el("rect",{x:ZX,y:z.y,width:ZW,height:z.h,rx:10,fill:"none",stroke:"var(--hair)","stroke-dasharray":"3 5"}));
  const t=el("text",{x:ZX+14,y:z.y+22,class:"zone-label"});
  t.textContent=(ZLABEL[z.k]||z.k.replace(/_/g," "))+" · trust boundary";gZ.appendChild(t);
  if(z.more){const col=z.slot%cols,row=(z.slot-col)/cols;
    const m=el("text",{x:ZX+28+col*cw+cw/2-14,y:z.y+58+row*rh+4,"text-anchor":"middle",class:"nmeta"});
    m.textContent="+ "+z.more+" more surfaces";gZ.appendChild(m);}});
if(sinks.length){const t=el("text",{x:RX+16,y:ZY0+22,class:"rail-label"});t.textContent="impact · what breaks";gZ.appendChild(t);}
sinks.forEach(s=>{const p=sinkPos[s.k];
  gS.appendChild(el("rect",{x:p.x,y:p.y,width:p.w,height:p.h,rx:5,class:"sink",id:"sink-"+s.k}));
  let a=el("text",{x:p.x+14,y:p.y+27,class:"sink-t"});a.textContent=s.t;gS.appendChild(a);
  let b=el("text",{x:p.x+14,y:p.y+46,class:"sink-d"});b.textContent=s.d;gS.appendChild(b);});
// Modeled edges between rendered nodes: always-visible hairlines under the
// nodes; a cross-boundary edge is the agent-to-cloud crossing, dashed seal.
meshEdges.forEach(e=>{const a=pos[e.s],b=pos[e.t];if(!a||!b)return;
  const mx=(a.x+b.x)/2,my=(a.y+b.y)/2-18;
  gM.appendChild(el("path",{class:"mesh"+(e.cross?" cross":""),d:`M${a.x},${a.y} Q${mx},${my} ${b.x},${b.y}`}));});
const nodeEls={};
comps.forEach(c=>{const p=pos[c.id],r=10+18*((c.score-SMIN)/(SMAX-SMIN||1));
  const g=el("g",{class:"snode",tabindex:"0",role:"button","aria-label":c.name+" surface"});
  const sv=worst(c.id),fill=sv?SEV[sv]:"var(--none)";
  if(c.secrets)g.appendChild(el("circle",{cx:p.x,cy:p.y,r:r+5,fill:"none",stroke:fill,"stroke-width":1,"stroke-dasharray":"2 3",opacity:.8}));
  g.appendChild(el("circle",{cx:p.x,cy:p.y,r:r,fill:"var(--node)",stroke:fill,"stroke-width":2.4}));
  g.appendChild(el("circle",{cx:p.x,cy:p.y,r:Math.max(3,r*.34),fill:fill,opacity:.9}));
  let lb=el("text",{x:p.x,y:p.y+r+15,"text-anchor":"middle",class:"nlabel"});lb.textContent=c.name;g.appendChild(lb);
  const cap=c.caps[0]||c.type.replace("mcp_server","tool").replace("agent_instruction","skill").replace(/_/g," ");
  let mt=el("text",{x:p.x,y:p.y+r+27,"text-anchor":"middle",class:"nmeta"});mt.textContent=cap;g.appendChild(mt);
  g.addEventListener("click",()=>select(c.id));
  g.addEventListener("keydown",e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();select(c.id);}});
  gN.appendChild(g);nodeEls[c.id]={g,p,r};});
let activePath=-1;
function markPaths(){document.querySelectorAll("#p-paths .pitem").forEach((n,j)=>n.classList.toggle("on",j===activePath));}
function select(id){const c=comps.find(x=>x.id===id);if(!c)return;
  activePath=-1;markPaths();
  gE.innerHTML="";
  comps.forEach(x=>nodeEls[x.id].g.classList.toggle("dim",x.id!==id));
  sinks.forEach(s=>document.getElementById("sink-"+s.k).classList.remove("hit"));
  const p=nodeEls[id].p;
  Object.entries(c.reached).forEach(([k,hop])=>{const sp=sinkPos[k];if(!sp)return;
    document.getElementById("sink-"+k).classList.add("hit");
    const x1=p.x,y1=p.y,x2=sp.x,y2=sp.y+sp.h/2,mx=(x1+x2)/2;
    gE.appendChild(el("path",{class:"edge live",d:`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`,
      "stroke-width":hop===0?2.6:1.6,"stroke-dasharray":hop===0?"none":"4 4"}));
    let hl=el("text",{x:mx,y:(y1+y2)/2-4,"text-anchor":"middle",class:"hop live"});
    hl.textContent=hop===0?"is this":hop+" hop";gE.appendChild(hl);});
  renderPanel(c);}
// The attack-path overlay: dim everything off the chain, march the wavefront
// along the walked steps in order, and label each rung with its role.
function selectPath(i){const p=paths[i];if(!p)return;
  activePath=i;markPaths();
  gE.innerHTML="";
  const onChain=new Set(p.steps.map(s=>s.id));
  comps.forEach(x=>nodeEls[x.id].g.classList.toggle("dim",!onChain.has(x.id)));
  sinks.forEach(s=>document.getElementById("sink-"+s.k).classList.remove("hit"));
  for(let k=0;k+1<p.steps.length;k++){const a=pos[p.steps[k].id],b=pos[p.steps[k+1].id];
    if(!a||!b||(a.x===b.x&&a.y===b.y))continue;
    const mx=(a.x+b.x)/2,my=(a.y+b.y)/2-24;
    const seg=el("path",{class:"pseg",d:`M${a.x},${a.y} Q${mx},${my} ${b.x},${b.y}`});
    seg.style.animationDelay=(k*0.12)+"s";gE.appendChild(seg);}
  const roles={};p.steps.forEach(s=>{const r=roles[s.id]=roles[s.id]||[];if(!r.includes(s.role))r.push(s.role);});
  Object.keys(roles).forEach(id=>{const q=pos[id],n=nodeEls[id];if(!q||!n)return;
    const t=el("text",{x:q.x,y:q.y+n.r+40,"text-anchor":"middle",class:"role"});
    t.textContent=roles[id].join("+");gE.appendChild(t);});}
function clearOverlay(){activePath=-1;markPaths();
  if(rankOrder.length)select(rankOrder[0]);
  else{gE.innerHTML="";comps.forEach(x=>nodeEls[x.id].g.classList.remove("dim"));}}
document.addEventListener("keydown",e=>{if(e.key==="Escape")clearOverlay();});
document.getElementById("svg").addEventListener("click",e=>{if(e.target.closest(".snode"))return;clearOverlay();});
function renderPanel(c){
  document.getElementById("p-name").textContent=c.name;
  document.getElementById("p-score").textContent=c.score.toFixed(1);
  document.getElementById("p-rank").textContent=`reach · rank ${rankOrder.indexOf(c.id)+1} of ${rankOrder.length}`;
  document.getElementById("p-fill").style.width=Math.round(100*c.score/SMAX)+"%";
  const reach=document.getElementById("p-reach");reach.innerHTML="";
  const order=Object.entries(c.reached).sort((a,b)=>a[1]-b[1]);
  order.forEach(([k,hop])=>{const s=document.createElement("span");
    s.className="chip"+(hop===0?" hop0":"");s.textContent=k+(hop===0?" · direct":" · "+hop+"h");reach.appendChild(s);});
  const imp=document.getElementById("p-impact");
  imp.innerHTML=order.length?`Hijacking <b>${c.name}</b> lets an attacker `+
    order.map(([k])=>IMPACT[k]||("reach <b>"+k+"</b>")).slice(0,3).join(", ")+
    (order.length>3?`, and ${order.length-3} more`:"")+`.`:
    `<b>${c.name}</b> reaches no capability sink in the modeled design.`;
  const fl=document.getElementById("p-findings");fl.innerHTML="";
  const fs=(byComp[c.id]||[]).slice().sort((a,b)=>SRANK[b.sev]-SRANK[a.sev]);
  if(!fs.length){const li=document.createElement("li");li.className="empty";
    li.textContent="No direct finding - yet its blast radius is "+c.score.toFixed(1)+". Reach is a risk even where a rule does not fire.";fl.appendChild(li);}
  fs.forEach(f=>{const li=document.createElement("li");li.className="fitem";
    li.innerHTML=`<span class="sev" style="background:${SEV[f.sev]}"></span>`+
      `<span><span class="frule">${f.rule} · ${f.sev}</span><br><span class="ftitle">${escape_(f.title)}</span></span>`;fl.appendChild(li);});}
function escape_(s){const d=document.createElement("div");d.textContent=s;return d.innerHTML;}
// The walked-chain list is model-level, so it is populated once and persists
// while surface selection changes.
const nameOf=id=>{const c=comps.find(x=>x.id===id);return c?c.name:id;};
const pl=document.getElementById("p-paths");
if(!paths.length){document.getElementById("p-paths-h").hidden=true;pl.hidden=true;}
paths.forEach((p,i)=>{const li=document.createElement("li");li.className="fitem pitem";li.tabIndex=0;
  const chain=[];p.steps.forEach(s=>{const n=nameOf(s.id);if(chain[chain.length-1]!==n)chain.push(n);});
  li.innerHTML=`<span class="sev" style="background:${SEV[p.sev]}"></span>`+
    `<span><span class="frule">${p.kind} chain · ${p.sev}</span><br><span class="ftitle">${escape_(chain.join(" -> "))}</span></span>`;
  li.addEventListener("click",()=>selectPath(i));
  li.addEventListener("keydown",e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();selectPath(i);}});
  pl.appendChild(li);});
const trifecta=DATA.fleet.find(f=>f.rule==="ATL-202");
if(trifecta){const tri=document.getElementById("tri");tri.hidden=false;
  document.getElementById("tri-k").textContent="Fleet finding · ATL-202 · "+trifecta.sev;
  document.getElementById("tri-p").innerHTML="<b>Lethal trifecta.</b> No single surface is the whole risk - the fleet is. "+
    "Filesystem, standing secrets, and an outbound channel co-exist in one runtime, so untrusted input can be read, "+
    "joined to a credential, and exfiltrated. Only the system model sees this; a per-file linter never does.";}
document.getElementById("foot-fx").textContent=DATA.fixture;
if(rankOrder.length)select(rankOrder[0]);
document.getElementById("tt").addEventListener("click",()=>{
  const cur=document.documentElement.getAttribute("data-theme");
  const now=cur==="light"?"dark":cur==="dark"?"light":
    (matchMedia("(prefers-color-scheme: dark)").matches?"light":"dark");
  document.documentElement.setAttribute("data-theme",now);});
</script></body></html>"""
