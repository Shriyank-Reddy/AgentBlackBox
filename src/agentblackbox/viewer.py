"""Turn a trace into ONE self-contained HTML file (inline CSS + JS, no network, no CDN).

Safety note: trace contents are attacker-influenced (tool arguments can contain HTML).
The page therefore never uses innerHTML; the JSON is embedded in an inert
``<script type="application/json">`` block with ``<``, ``>`` and ``&`` escaped, and the
script builds the DOM with ``textContent`` only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .recorder import DEFAULT_HEAD_KEY, verify_trace


def _read_lenient(path: Path) -> list[dict[str, Any]]:
    """Parse as many events as possible; a tampered file must still be viewable."""
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events


def build_view_data(trace_path: str | Path, key: bytes = DEFAULT_HEAD_KEY) -> dict[str, Any]:
    path = Path(trace_path)
    check = verify_trace(path, key=key)
    events = _read_lenient(path)
    results = {e.get("ref_seq"): e for e in events if e.get("kind") == "result"}
    steps = [
        {"call": e, "result": results.get(e.get("seq"))} for e in events if e.get("kind") == "call"
    ]
    counts = {
        d: sum(1 for s in steps if s["call"].get("decision") == d)
        for d in ("allow", "flag", "deny")
    }
    return {
        "name": path.name,
        "session_id": events[0].get("session_id", "") if events else "",
        "integrity": {
            "ok": check.ok,
            "count": check.count,
            "errors": [{"seq": e.seq, "reason": e.reason} for e in check.errors],
        },
        "counts": counts,
        "steps": steps,
    }


def render_html(data: dict[str, Any]) -> str:
    payload = json.dumps(data, sort_keys=True)
    # Keep the JSON inert inside <script>: no "</script>", no "<!--".
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return _TEMPLATE.replace("__DATA__", payload)


def render_report(trace_path: str | Path, key: bytes = DEFAULT_HEAD_KEY) -> str:
    return render_html(build_view_data(trace_path, key))


_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentBlackBox trace</title>
<style>
:root{
  --bg:#f6f7f9; --surface:#fff; --text:#1c2128; --muted:#59636e; --border:#d0d7de;
  --allow:#1a7f37; --allow-bg:#dafbe1; --deny:#b4232c; --deny-bg:#ffebe9;
  --flag:#8a5a00; --flag-bg:#fff3c4; --priv:#6f3fb5; --priv-bg:#f0e6ff;
  --untr:#a24a00; --untr-bg:#ffe8d1; --rule-bg:#e8eef5; --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --bg:#0d1117; --surface:#161b22; --text:#e6edf3; --muted:#9aa4af; --border:#30363d;
    --allow:#56d364; --allow-bg:#0f2d1a; --deny:#ff7b72; --deny-bg:#3a1517;
    --flag:#e3b341; --flag-bg:#33280a; --priv:#d2a8ff; --priv-bg:#2a1f45;
    --untr:#ffa657; --untr-bg:#3b2410; --rule-bg:#1f2933;
  }
}
:root[data-theme="dark"]{
  --bg:#0d1117; --surface:#161b22; --text:#e6edf3; --muted:#9aa4af; --border:#30363d;
  --allow:#56d364; --allow-bg:#0f2d1a; --deny:#ff7b72; --deny-bg:#3a1517;
  --flag:#e3b341; --flag-bg:#33280a; --priv:#d2a8ff; --priv-bg:#2a1f45;
  --untr:#ffa657; --untr-bg:#3b2410; --rule-bg:#1f2933;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:860px;margin:0 auto;padding:20px 16px 60px}
h1{font-size:22px;margin:0 0 4px}
.sub{color:var(--muted);margin:0 0 16px}
.banner{border-radius:8px;padding:12px 14px;margin:0 0 16px;border:1px solid;font-weight:600}
.banner.ok{background:var(--allow-bg);color:var(--allow);border-color:var(--allow)}
.banner.bad{background:var(--deny-bg);color:var(--deny);border-color:var(--deny)}
.banner small{display:block;font-weight:400;color:var(--text);margin-top:4px}
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 18px}
.bar button{font:inherit;padding:4px 12px;border-radius:999px;border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer}
.bar button[aria-pressed="true"]{border-color:var(--text);font-weight:600}
ol{list-style:none;margin:0;padding:0 0 0 22px;border-left:2px solid var(--border)}
li.step{position:relative;margin:0 0 14px;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:10px 12px}
li.step::before{content:"";position:absolute;left:-30px;top:16px;width:12px;height:12px;border-radius:50%;background:var(--muted);border:2px solid var(--bg)}
li.step.allow::before{background:var(--allow)} li.step.deny::before{background:var(--deny)} li.step.flag::before{background:var(--flag)}
li.step.deny{border-color:var(--deny)}
li.step[hidden]{display:none}
.head{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.seq{color:var(--muted);font-family:var(--mono);font-size:13px}
.tool{font-family:var(--mono);font-weight:700}
.badge{padding:1px 9px;border-radius:999px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.03em}
.badge.allow{background:var(--allow-bg);color:var(--allow)} .badge.deny{background:var(--deny-bg);color:var(--deny)} .badge.flag{background:var(--flag-bg);color:var(--flag)}
.chip{padding:1px 8px;border-radius:6px;font-size:12px;font-family:var(--mono)}
.chip.rule{background:var(--rule-bg)} .chip.private_data{background:var(--priv-bg);color:var(--priv)} .chip.untrusted_content{background:var(--untr-bg);color:var(--untr)}
.row{margin:6px 0 0;display:flex;flex-wrap:wrap;gap:6px;align-items:baseline}
.label{color:var(--muted);font-size:12px;min-width:64px}
.args{font-family:var(--mono);font-size:13px;margin:6px 0 0;white-space:pre-wrap;word-break:break-word;background:var(--bg);border-radius:6px;padding:6px 8px}
.args .k{color:var(--muted)}
mark.redacted{background:var(--deny-bg);color:var(--deny);border-radius:4px;padding:0 3px;border:1px dashed var(--deny)}
ul.reasons{margin:6px 0 0;padding-left:18px;color:var(--muted);font-size:13px}
.result{margin:8px 0 0;font-size:13px;color:var(--muted)}
.hash{font-family:var(--mono);font-size:11px;color:var(--muted);margin-left:auto}
@media (max-width:480px){main{padding:14px 12px 40px} ol{padding-left:16px} li.step::before{left:-24px}}
</style>
</head>
<body>
<main>
  <h1>AgentBlackBox trace</h1>
  <p class="sub" id="sub"></p>
  <div id="banner" class="banner" role="status"></div>
  <div class="bar" id="bar" aria-label="Filter by decision"></div>
  <ol id="timeline"></ol>
</main>
<script id="abb-data" type="application/json">__DATA__</script>
<script>
(function(){
"use strict";
var D = JSON.parse(document.getElementById("abb-data").textContent);
function el(tag, cls, text){var e=document.createElement(tag); if(cls) e.className=cls; if(text!==undefined) e.textContent=text; return e;}
function withRedactions(parent, text){
  var re=/\[REDACTED:([a-z_]+):([0-9a-f]{8})\]/g, last=0, m;
  while((m=re.exec(text))){
    if(m.index>last) parent.appendChild(document.createTextNode(text.slice(last,m.index)));
    var s=el("mark","redacted",m[0]); s.title="Redacted "+m[1]+" value (fingerprint "+m[2]+"). Equal fingerprints mean equal values.";
    parent.appendChild(s); last=m.index+m[0].length;
  }
  if(last<text.length) parent.appendChild(document.createTextNode(text.slice(last)));
}
function fmt(v){return typeof v==="string" ? v : JSON.stringify(v);}
document.getElementById("sub").textContent = D.name+" · session "+D.session_id+" · "+D.steps.length+" tool calls";

var b=document.getElementById("banner"), I=D.integrity;
if(I.ok){
  b.className="banner ok"; b.textContent="✓ Chain intact: "+I.count+" events verified (hash chain + signed head).";
}else{
  b.className="banner bad"; b.textContent="✗ Chain BROKEN at seq "+I.errors[0].seq+". Do not trust this trace.";
  var s=el("small",null,I.errors.map(function(e){return "seq "+e.seq+": "+e.reason;}).join(" | ")); b.appendChild(s);
}

var bar=document.getElementById("bar"), filt="all", tl=document.getElementById("timeline");
[["all","All "+D.steps.length],["deny","Denied "+D.counts.deny],["flag","Flagged "+D.counts.flag],["allow","Allowed "+D.counts.allow]].forEach(function(p){
  var btn=el("button",null,p[1]); btn.type="button"; btn.setAttribute("aria-pressed", p[0]==="all"?"true":"false");
  btn.addEventListener("click",function(){
    filt=p[0]; Array.prototype.forEach.call(bar.children,function(c){c.setAttribute("aria-pressed","false");}); btn.setAttribute("aria-pressed","true");
    Array.prototype.forEach.call(tl.children,function(li){li.hidden = filt!=="all" && li.dataset.decision!==filt;});
  });
  bar.appendChild(btn);
});

D.steps.forEach(function(st){
  var c=st.call, r=st.result, dec=c.decision||"allow";
  var li=el("li","step "+dec); li.dataset.decision=dec;
  var head=el("div","head");
  head.appendChild(el("span","seq","#"+c.seq));
  head.appendChild(el("span","tool",c.tool));
  head.appendChild(el("span","badge "+dec,dec));
  if(c.mode==="monitor" && dec==="deny") head.appendChild(el("span","chip rule","monitor: not blocked"));
  head.appendChild(el("span","seq",c.ts||""));
  head.appendChild(el("span","hash","hash "+String(c.hash||"").slice(0,12)));
  li.appendChild(head);

  var args=el("div","args"); var keys=Object.keys(c.args||{});
  if(!keys.length) args.textContent="(no arguments)";
  keys.forEach(function(k,i){
    if(i) args.appendChild(document.createTextNode("\n"));
    args.appendChild(el("span","k",k+": ")); withRedactions(args, fmt(c.args[k]));
  });
  li.appendChild(args);

  if((c.rule_ids||[]).length){
    var row=el("div","row"); row.appendChild(el("span","label","rules fired"));
    c.rule_ids.forEach(function(id){row.appendChild(el("span","chip rule",id));}); li.appendChild(row);
  }
  var T=c.taint||{}, ct=T.call||[], stt=T.session||[];
  if(ct.length||stt.length){
    var row2=el("div","row");
    if(stt.length){row2.appendChild(el("span","label","session taint")); stt.forEach(function(t){row2.appendChild(el("span","chip "+t,t));});}
    if(ct.length){row2.appendChild(el("span","label","arguments carry")); ct.forEach(function(t){row2.appendChild(el("span","chip "+t,t));});}
    li.appendChild(row2);
  }
  if((c.reasons||[]).length){
    var ul=el("ul","reasons"); c.reasons.forEach(function(x){var q=el("li"); withRedactions(q,x); ul.appendChild(q);}); li.appendChild(ul);
  }
  if((c.canary||[]).length){
    var row3=el("div","row"); row3.appendChild(el("span","label","canary hit"));
    c.canary.forEach(function(x){row3.appendChild(el("span","chip rule",x));}); li.appendChild(row3);
  }
  var res=el("div","result");
  if(r && r.result_summary){
    var S=r.result_summary;
    if(S.error){res.textContent="Tool error: "+S.error;}
    else{res.appendChild(document.createTextNode("Result: "+S.len+" chars, sha256 "+S.sha256+" — ")); withRedactions(res,S.preview||"");}
  }else if(c.blocked){res.textContent="Blocked: the tool did not run.";}
  else{res.textContent="No result recorded.";}
  li.appendChild(res);
  tl.appendChild(li);
});
})();
</script>
</body>
</html>
"""
