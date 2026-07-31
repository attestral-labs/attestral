"""Interactive threat topography: a self-contained HTML blast-radius map.

A terminal report tells you a finding exists; this renders what it can *reach*.
`attestral scan PATH --format html -o topo.html` emits one self-contained,
offline HTML file (no external requests, theme-aware) that draws every agent
tool surface as a node sized by its blast radius and, on click, animates the
if-compromised wavefront to the capability classes it can drive. It is the
visual counterpart to `attestral blast-radius`, built from the same system
model, reachability, and rule findings, so the picture is the tool's own
reasoning, not a redraw.

Design invariant: the scanner stays terminal-first. This writes a file only when
the user opts in with `--format html` (and `-o`), exactly like `sarif`/`aibom`.
"""
from __future__ import annotations

import html
import json

from attestral.blast_radius import blast_radius
from attestral.model import Finding, SystemModel

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


def _sink_meta(cls: str) -> dict:
    label, desc, _ = _IMPACT.get(cls, (cls, "reachable capability", None))
    return {"k": cls, "t": label, "d": desc}


def build_topography(model: SystemModel, findings: list[Finding]) -> dict:
    """The structured data the view renders: surfaces (with blast score + the
    capability classes each reaches), the impact sinks present, and the findings
    grouped into per-component and fleet-level (model-scoped) sets."""
    blast = {b.component_id: b for b in blast_radius(model)}
    comps = []
    for c in model.components:
        b = blast.get(c.id)
        comps.append({
            "id": c.id, "name": c.name, "type": c.type,
            "boundary": c.trust_boundary or "agent_runtime",
            "caps": list(c.attr("_capabilities") or []),
            "secrets": bool(c.attr("_env_has_secrets")),
            "score": round(b.score, 1) if b else 0.0,
            "reached": dict(b.reached) if b else {},
        })
    # Which capability classes any surface reaches -> the impact rail.
    reached_classes = {k for c in comps for k in c["reached"]}
    sinks = [_sink_meta(k) for k in _SINK_ORDER if k in reached_classes]
    sinks += [_sink_meta(k) for k in sorted(reached_classes) if k not in _SINK_ORDER]

    per_comp, fleet = [], []
    comp_ids = {c["id"] for c in comps}
    for f in findings:
        row = {"rule": f.rule_id, "sev": f.severity.name.lower(),
               "comp": f.component_id, "title": f.title}
        (per_comp if f.component_id in comp_ids else fleet).append(row)
    return {"components": comps, "sinks": sinks,
            "findings": per_comp, "fleet": fleet}


def render_topography(model: SystemModel, findings: list[Finding], target: str) -> str:
    """A complete, self-contained HTML document (no external requests) for the
    interactive blast-radius topography of `target`."""
    data = build_topography(model, findings)
    data["fixture"] = target
    n_comp = len(data["components"])
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
  .edge{stroke:var(--wave);fill:none;opacity:0;transition:opacity .25s}
  .edge.live{opacity:.85}
  .hop{font-family:var(--mono);font-size:9px;fill:var(--wave);opacity:0}.hop.live{opacity:.9}
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
  @media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style></head><body>
<div class="wrap">
  <div class="top">
    <div class="mark"><div class="plate">A</div>
      <div><h1>Threat Topography</h1><div class="sub">__SUB__</div></div></div>
    <button class="toggle" id="tt">theme</button>
  </div>
  <p class="lede">A report tells you a finding exists. This tells you what it can <b>reach</b>.
  Every node is a tool surface from this scan; its size is its <b>blast radius</b> - the if-compromised
  reach over the modeled design. <b>Click any surface</b> to simulate its compromise and watch the
  wavefront hit the capabilities it can drive.</p>
  <div class="grid">
    <div class="stage">
      <svg id="svg" role="img" aria-label="Interactive agent threat topography">
        <g id="zones"></g><g id="edges"></g><g id="sinks"></g><g id="nodes"></g></svg>
      <div class="legend">
        <span><i style="background:var(--crit)"></i>critical</span>
        <span><i style="background:var(--high)"></i>high</span>
        <span><i style="background:var(--med)"></i>medium</span>
        <span><i style="background:var(--none)"></i>no direct finding</span>
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
const NS="http://www.w3.org/2000/svg";
const el=(n,a={})=>{const e=document.createElementNS(NS,n);for(const k in a)e.setAttribute(k,a[k]);return e;};
const byComp={};DATA.findings.forEach(f=>{(byComp[f.comp]=byComp[f.comp]||[]).push(f);});
const worst=id=>{let s=null,r=0;(byComp[id]||[]).forEach(f=>{if(SRANK[f.sev]>r){r=SRANK[f.sev];s=f.sev;}});return s;};
const comps=DATA.components, sinks=DATA.sinks;
const cols=3, rows=Math.ceil(comps.length/cols);
const ZX=36,ZY=64,cw=190,rh=126;
const ZW=cw*cols+52, ZH=Math.max(160,rows*rh+30), RX=ZX+ZW+56, RW=248;
const VW=RX+RW+20, VH=Math.max(ZY+ZH+30, ZY+sinks.length*100+40);
document.getElementById("svg").setAttribute("viewBox",`0 0 ${VW} ${VH}`);
const pos={};comps.forEach((c,i)=>{const col=i%cols,row=(i-col)/cols;
  pos[c.id]={x:ZX+28+col*cw+cw/2-14,y:ZY+42+row*rh};});
const sinkPos={};sinks.forEach((s,i)=>{sinkPos[s.k]={x:RX+16,y:ZY+34+i*100,w:RW-32,h:66};});
const scoreVals=comps.map(c=>c.score),SMAX=Math.max(1,...scoreVals),SMIN=Math.min(...scoreVals);
const rankOrder=comps.slice().sort((a,b)=>b.score-a.score).map(c=>c.id);
const gZ=document.getElementById("zones"),gE=document.getElementById("edges"),
      gS=document.getElementById("sinks"),gN=document.getElementById("nodes");
gZ.appendChild(el("rect",{x:ZX,y:ZY,width:ZW,height:ZH,rx:10,fill:"none",stroke:"var(--hair)","stroke-dasharray":"3 5"}));
let t=el("text",{x:ZX+14,y:ZY+22,class:"zone-label"});t.textContent="agent surfaces · trust boundary";gZ.appendChild(t);
if(sinks.length){t=el("text",{x:RX+16,y:ZY+22,class:"rail-label"});t.textContent="impact · what breaks";gZ.appendChild(t);}
sinks.forEach(s=>{const p=sinkPos[s.k];
  gS.appendChild(el("rect",{x:p.x,y:p.y,width:p.w,height:p.h,rx:5,class:"sink",id:"sink-"+s.k}));
  let a=el("text",{x:p.x+14,y:p.y+27,class:"sink-t"});a.textContent=s.t;gS.appendChild(a);
  let b=el("text",{x:p.x+14,y:p.y+46,class:"sink-d"});b.textContent=s.d;gS.appendChild(b);});
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
  gN.appendChild(g);nodeEls[c.id]={g,p};});
function select(id){const c=comps.find(x=>x.id===id);if(!c)return;
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
