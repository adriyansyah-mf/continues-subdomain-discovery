"""Management console (static single-page app) served by the orchestrator.

A thin client over the existing REST API — it adds no backend logic and no new authority: every
data call it makes goes through the same API-key-authenticated endpoints as the CLI. The page
shell loads without a key; nothing is shown until the operator supplies one (kept in the browser's
localStorage only). Analytics stay in Kibana; this console only manages programs, scope, policies,
scans, jobs and schedules. The HTML is embedded as a string so it is always present in the
pip-installed package (no reliance on package-data).
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse

router = APIRouter()

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bug Bounty Platform — Console</title>
<style>
  :root{--bg:#0f1420;--panel:#171e2e;--panel2:#1f2838;--line:#2b3650;--fg:#e6ecf5;--mut:#8b9ab5;
        --accent:#4f8cff;--ok:#3ecf8e;--warn:#ffb454;--bad:#ff6b6b;--chip:#243049;}
  *{box-sizing:border-box}
  body{margin:0;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
  header{display:flex;gap:12px;align-items:center;padding:10px 16px;background:var(--panel);
         border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5;flex-wrap:wrap}
  header h1{font-size:15px;margin:0;font-weight:600;letter-spacing:.2px}
  header .grow{flex:1}
  input,select,textarea,button{font:inherit;color:var(--fg);background:var(--panel2);
        border:1px solid var(--line);border-radius:7px;padding:7px 9px}
  textarea{width:100%;min-height:72px;resize:vertical}
  button{background:var(--accent);border-color:var(--accent);color:#fff;cursor:pointer;font-weight:600}
  button.ghost{background:var(--panel2);border-color:var(--line);color:var(--fg);font-weight:500}
  button:hover{filter:brightness(1.08)} button:disabled{opacity:.5;cursor:default}
  a{color:var(--accent)}
  nav{display:flex;gap:4px;padding:8px 16px;background:var(--panel);border-bottom:1px solid var(--line);
      flex-wrap:wrap;position:sticky;top:52px;z-index:4}
  nav button{background:transparent;border:1px solid transparent;color:var(--mut);padding:6px 12px}
  nav button.active{color:var(--fg);border-color:var(--line);background:var(--panel2)}
  main{padding:16px;max-width:1100px;margin:0 auto}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}
  .card h2{margin:0 0 12px;font-size:14px;color:var(--mut);text-transform:uppercase;letter-spacing:.6px}
  .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px}
  .row>label{min-width:84px;color:var(--mut)}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--mut);font-weight:600;position:sticky}
  .chip{display:inline-block;padding:1px 8px;border-radius:20px;background:var(--chip);font-size:12px}
  .s-ok{color:var(--ok)} .s-bad{color:var(--bad)} .s-warn{color:var(--warn)} .mut{color:var(--mut)}
  .hidden{display:none}
  #toast{position:fixed;right:16px;bottom:16px;max-width:360px;z-index:20}
  .msg{background:var(--panel2);border:1px solid var(--line);border-left-width:4px;border-radius:8px;
       padding:10px 12px;margin-top:8px;box-shadow:0 6px 20px rgba(0,0,0,.4);white-space:pre-wrap}
  .msg.ok{border-left-color:var(--ok)} .msg.err{border-left-color:var(--bad)}
  code{background:var(--panel2);padding:1px 5px;border-radius:4px}
  .inline{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
  .checks label{display:inline-flex;gap:5px;align-items:center;margin-right:12px;color:var(--fg)}
</style></head>
<body>
<header>
  <h1>🛰️ Bug Bounty Platform</h1>
  <span class="chip" id="whoami">not connected</span>
  <span class="grow"></span>
  <input id="apiBase" placeholder="API base (blank = same origin)" style="width:220px">
  <input id="apiKey" type="password" placeholder="X-API-Key" style="width:190px">
  <button onclick="saveCreds()">Connect</button>
  <a id="kibanaLink" class="chip" href="#" target="_blank" style="text-decoration:none">📊 Kibana</a>
</header>
<nav id="tabs"></nav>
<main id="view"></main>
<div id="toast"></div>
<script>
const S={base:localStorage.getItem('bb_base')||'',key:localStorage.getItem('bb_key')||'',
         kibana:localStorage.getItem('bb_kibana')||'',tab:'watch',programs:[],policies:[]};
const $=(s,r=document)=>r.querySelector(s); const el=(h)=>{const d=document.createElement('div');d.innerHTML=h;return d.firstElementChild;};
const esc=(s)=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function toast(msg,ok=true){const t=el(`<div class="msg ${ok?'ok':'err'}">${esc(msg)}</div>`);$('#toast').appendChild(t);setTimeout(()=>t.remove(),ok?3500:7000);}
async function api(method,path,body){
  const h={'Content-Type':'application/json'}; if(S.key)h['X-API-Key']=S.key;
  const r=await fetch((S.base||'')+path,{method,headers:h,body:body?JSON.stringify(body):undefined});
  const txt=await r.text(); let data; try{data=txt?JSON.parse(txt):null}catch{data=txt}
  if(!r.ok)throw new Error((data&&data.detail)?(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail)):('HTTP '+r.status));
  return data;
}
function saveCreds(){
  S.base=$('#apiBase').value.trim().replace(/\\/$/,''); S.key=$('#apiKey').value.trim();
  localStorage.setItem('bb_base',S.base); localStorage.setItem('bb_key',S.key);
  refreshWho();
}
async function refreshWho(){
  try{const s=await api('GET','/stats');$('#whoami').textContent='connected · '+(s.assets?.total??0)+' assets';$('#whoami').className='chip s-ok';render();}
  catch(e){$('#whoami').textContent='auth failed';$('#whoami').className='chip s-bad';toast(e.message,false);}
}
const TABS=['watch','programs','scope','scan','jobs','policies','schedules','stats'];
function setTab(t){S.tab=t;[...$('#tabs').children].forEach(b=>b.classList.toggle('active',b.dataset.t===t));render();}
function renderTabs(){$('#tabs').innerHTML='';TABS.forEach(t=>{const b=el(`<button data-t="${t}">${t[0].toUpperCase()+t.slice(1)}</button>`);b.onclick=()=>setTab(t);$('#tabs').appendChild(b);});setTab(S.tab);}
async function loadProgramsPolicies(){try{S.programs=await api('GET','/programs');}catch{} try{S.policies=await api('GET','/policies');}catch{}}
function progOptions(sel){return S.programs.map(p=>`<option value="${esc(p.slug||p.id)}" ${sel===p.slug?'selected':''}>${esc(p.name)} (${esc(p.slug)})${p.active?'':' · inactive'}</option>`).join('');}

async function render(){
  const v=$('#view'); if(!S.key){v.innerHTML='<div class="card">Masukkan API key di kanan atas lalu klik <b>Connect</b>. Key = <code>BB_API_KEY</code>/<code>BB_BOOTSTRAP_ADMIN_KEY</code>.</div>';return;}
  await loadProgramsPolicies();
  if(S.tab==='watch')return viewWatch(v);
  if(S.tab==='programs')return viewPrograms(v);
  if(S.tab==='scope')return viewScope(v);
  if(S.tab==='scan')return viewScan(v);
  if(S.tab==='jobs')return viewJobs(v);
  if(S.tab==='policies')return viewPolicies(v);
  if(S.tab==='schedules')return viewSchedules(v);
  if(S.tab==='stats')return viewStats(v);
}
function viewWatch(v){
  v.innerHTML=`<div class="card"><h2>Watch a scope — full auto</h2>
    <p class="mut" style="margin-top:-6px">Masukkan scope, selesai. Platform otomatis: bikin program, pasang scope, temukan subdomain, lalu scan terus-menerus (dns, http, tls, crawl, nuclei). Asset baru auto-scan. Hasil di Kibana.</p>
    <div class="row"><input id="wv" placeholder="*.ezviz.com  /  example.com  /  1.2.3.0/24" style="width:320px;font-size:16px;padding:10px">
      <button style="font-size:16px;padding:10px 18px" onclick="runWatch()">▶ Watch</button></div>
    <div class="row"><label>Nama (opsional)</label><input id="wn" placeholder="(default: domain)" style="width:200px">
      <label>Interval</label><select id="wi"><option value="3600">tiap 1 jam</option><option value="21600" selected>tiap 6 jam</option><option value="86400">tiap 24 jam</option></select></div>
    <div id="wres"></div></div>
    <div class="card"><h2 class="mut" style="text-transform:none">⚠️ Penting</h2>
    Ini mengirim traffic nyata (termasuk vuln scan) ke semua host di bawah scope, berulang. Jalankan HANYA untuk program bug bounty yang kamu ikuti & dalam scope resminya. Platform menegakkan scope yang kamu masukkan, bukan otorisasi program aslinya.</div>`;
}
async function runWatch(){
  const value=$('#wv').value.trim(); if(!value)return toast('isi scope dulu',false);
  const body={value,interval_seconds:+$('#wi').value}; const n=$('#wn').value.trim(); if(n)body.name=n;
  $('#wres').innerHTML='<p class=mut>menyiapkan…</p>';
  try{const r=await api('POST','/watch',body);
    $('#wres').innerHTML=`<div class="msg ok" style="position:static">✅ Watch aktif untuk <b>${esc(r.program)}</b>${r.reused_program?' (program dipakai ulang)':''}.<br>
      Scope: ${esc((r.scope||[]).join(', '))}<br>Scanner: ${esc((r.scanners||[]).join(', '))}<br>
      Jadwal: <code>${esc(r.schedule||'-')}</code> (tiap ${Math.round((r.interval_seconds||0)/3600)} jam)<br>
      Scan awal: ${esc(JSON.stringify(r.initial_scan||{}))}</div>
      <p>Pantau di tab <b>Jobs</b>, hasil lengkap di <b>Kibana</b>.</p>`;
    toast('watch dibuat untuk '+r.program);
  }catch(e){$('#wres').innerHTML='';toast(e.message,false);}
}
function viewPrograms(v){
  v.innerHTML=`<div class="card"><h2>New program</h2>
    <div class="row"><label>Name</label><input id="pn" placeholder="EZVIZ"></div>
    <div class="row"><label>Slug</label><input id="ps" placeholder="ezviz"></div>
    <div class="row"><label>Platform</label><input id="pp" value="custom"></div>
    <div class="row"><label>Default policy</label><select id="pd"><option value="">(none → passive)</option>${S.policies.map(p=>`<option>${esc(p.name)}</option>`).join('')}</select></div>
    <div class="row"><button onclick="createProgram()">Create</button></div></div>
    <div class="card"><h2>Programs</h2><div id="plist">…</div></div>`;
  listPrograms();
}
async function listPrograms(){
  try{const ps=await api('GET','/programs');S.programs=ps;
    $('#plist').innerHTML=`<table><tr><th>Name</th><th>Slug</th><th>Platform</th><th>Active</th><th>Default policy</th></tr>${ps.map(p=>`<tr><td>${esc(p.name)}</td><td><code>${esc(p.slug)}</code></td><td>${esc(p.platform)}</td><td>${p.active?'<span class=s-ok>yes</span>':'<span class=mut>no</span>'}</td><td>${esc(p.default_scan_policy||'')}</td></tr>`).join('')}</table>`;
  }catch(e){$('#plist').innerHTML='<span class=s-bad>'+esc(e.message)+'</span>';}
}
async function createProgram(){
  const body={name:$('#pn').value.trim(),platform:$('#pp').value.trim()||'custom'};
  const slug=$('#ps').value.trim(); if(slug)body.slug=slug;
  const pol=$('#pd').value; if(pol)body.default_scan_policy=pol;
  if(!body.name)return toast('name wajib diisi',false);
  try{await api('POST','/programs',body);toast('program dibuat');listPrograms();}catch(e){toast(e.message,false);}
}
function viewScope(v){
  v.innerHTML=`<div class="card"><h2>Scope (CDB)</h2>
    <div class="row"><label>Program</label><select id="sp" onchange="listScope()">${progOptions()}</select></div>
    <div class="row"><label>Value</label><input id="sv" placeholder="*.ezviz.com" style="width:240px">
      <select id="st"><option value="">(auto type)</option>${['domain','wildcard','cidr','ipv4','ipv6','asn','url'].map(t=>`<option>${t}</option>`).join('')}</select>
      <select id="sm"><option>include</option><option>exclude</option></select>
      <button onclick="addScope()">Add</button></div>
    <div id="slist">…</div></div>`;
  listScope();
}
async function listScope(){
  const p=$('#sp').value; if(!p){$('#slist').innerHTML='<span class=mut>buat program dulu</span>';return;}
  try{const rows=await api('GET',`/programs/${encodeURIComponent(p)}/scope`);
    $('#slist').innerHTML=`<table><tr><th>Mode</th><th>Type</th><th>Value</th><th>Source</th><th></th></tr>${rows.map(r=>`<tr><td>${r.mode==='exclude'?'<span class=s-bad>exclude</span>':'<span class=s-ok>include</span>'}</td><td>${esc(r.type)}</td><td><code>${esc(r.value||r.normalized_value)}</code></td><td class=mut>${esc(r.source||'')}</td><td><button class=ghost onclick="delScope('${r.id}')">✕</button></td></tr>`).join('')}</table>`;
  }catch(e){$('#slist').innerHTML='<span class=s-bad>'+esc(e.message)+'</span>';}
}
async function addScope(){
  const p=$('#sp').value; const body={value:$('#sv').value.trim(),mode:$('#sm').value};
  const t=$('#st').value; if(t)body.type=t;
  if(!body.value)return toast('value wajib',false);
  try{await api('POST',`/programs/${encodeURIComponent(p)}/scope`,body);toast('scope ditambah');$('#sv').value='';listScope();}catch(e){toast(e.message,false);}
}
async function delScope(id){if(!confirm('Hapus entri scope ini?'))return;try{await api('DELETE','/scope/'+id);toast('dihapus');listScope();}catch(e){toast(e.message,false);}}
function viewScan(v){
  v.innerHTML=`<div class="card"><h2>Run scan</h2>
    <div class="row"><label>Program</label><select id="rp">${progOptions()}</select></div>
    <div class="row"><label>Policy</label><select id="rpol"><option value="">(program default)</option>${S.policies.map(p=>`<option>${esc(p.name)}</option>`).join('')}</select></div>
    <div class="row" style="align-items:flex-start"><label>Targets</label><textarea id="rt" placeholder="satu per baris, mis.&#10;www.ezviz.com&#10;api.ezviz.com"></textarea></div>
    <div class="row"><label>Scanners</label><span class="checks">${['dns','httpx','tlsx','katana','nuclei','bbot','uncover','mapcidr'].map(s=>`<label><input type=checkbox value="${s}" ${['dns','httpx','tlsx'].includes(s)?'checked':''}>${s}</label>`).join('')}</span></div>
    <div class="row"><label>Priority</label><input id="rpr" type="number" value="5" min="0" max="9" style="width:70px">
      <label style="min-width:auto"><input type=checkbox id="rf"> force (bypass dedup)</label>
      <button onclick="runScan()">Run</button></div>
    <div id="rres"></div></div>
    <div class="card"><h2 class="mut" style="text-transform:none">Catatan</h2>
    Scanner harus <b>dipilih di sini</b> <i>dan</i> <b>enabled di policy</b>. Policy <code>passive</code> cuma dns;
    pakai <code>discovery</code> (dns+httpx+tlsx) atau <code>recon</code> untuk lebih lengkap. Wildcard cocok subdomain saja, bukan apex.</div>`;
}
async function runScan(){
  const scanners=[...document.querySelectorAll('#view .checks input:checked')].map(c=>c.value);
  if(!scanners.length)return toast('pilih minimal satu scanner',false);
  const targets=$('#rt').value.split(/\\s+/).map(s=>s.trim()).filter(Boolean);
  if(!targets.length)return toast('isi minimal satu target',false);
  const body={program:$('#rp').value,scanners,targets,priority:+$('#rpr').value,force:$('#rf').checked};
  const pol=$('#rpol').value; if(pol)body.policy=pol;
  try{const r=await api('POST','/scans',body);
    const rows=r.jobs.map(j=>`<tr><td>${esc(j.scanner)}</td><td>${esc(j.target)}</td><td class="${j.status==='QUEUED'?'s-ok':(j.status==='BLOCKED'?'s-bad':'s-warn')}">${esc(j.status)}</td><td class=mut>${esc(j.block_reason||'')}</td></tr>`).join('');
    $('#rres').innerHTML=`<p>summary: ${esc(JSON.stringify(r.summary))}</p><table><tr><th>Scanner</th><th>Target</th><th>Status</th><th>Reason</th></tr>${rows}</table>`;
    toast('scan dikirim');
  }catch(e){toast(e.message,false);}
}
async function viewJobs(v){
  v.innerHTML=`<div class="card"><h2>Recent jobs <button class=ghost style="float:right" onclick="viewJobs(document.getElementById('view'))">⟳ refresh</button></h2><div id="jl">…</div></div>`;
  try{const js=await api('GET','/jobs?limit=50');
    $('#jl').innerHTML=`<table><tr><th>Scanner</th><th>Target</th><th>Status</th><th>Reason/Error</th><th>Findings</th></tr>${js.map(j=>`<tr><td>${esc(j.scanner)}</td><td>${esc(j.target||'')}</td><td class="${j.status==='SUCCESS'?'s-ok':(['BLOCKED','FAILED','OUT_OF_SCOPE'].includes(j.status)?'s-bad':'s-warn')}">${esc(j.status)}</td><td class=mut>${esc(j.block_reason||j.error||'')}</td><td>${esc((j.result_summary&&(j.result_summary.findings??j.result_summary.records))??'')}</td></tr>`).join('')}</table>`;
  }catch(e){$('#jl').innerHTML='<span class=s-bad>'+esc(e.message)+'</span>';}
}
function viewPolicies(v){
  v.innerHTML=`<div class="card"><h2>Policies</h2><table><tr><th>Name</th><th>Enabled scanners</th><th>Description</th></tr>${S.policies.map(p=>{const on=Object.entries(p.config||{}).filter(([,c])=>c&&c.enabled).map(([k])=>k).join(', ');return `<tr><td><code>${esc(p.name)}</code></td><td>${esc(on)}</td><td class=mut>${esc(p.description||'')}</td></tr>`;}).join('')}</table></div>`;
}
async function viewSchedules(v){
  v.innerHTML=`<div class="card"><h2>Schedules (continuous recon)</h2><div id="schl">…</div>
    <p class="mut">Aktifkan agar scanner jalan berkala otomatis. Hasil & perubahan muncul di Kibana.</p></div>`;
  try{const ss=await api('GET','/schedules');
    $('#schl').innerHTML=`<table><tr><th>Name</th><th>Scanner</th><th>Interval</th><th>Enabled</th><th>Next run</th><th></th></tr>${ss.map(s=>`<tr><td>${esc(s.name)}</td><td>${esc(s.scanner)}</td><td>${(s.interval_seconds/3600).toFixed(1)}h</td><td class="${s.enabled?'s-ok':'mut'}">${s.enabled}</td><td class=mut>${esc(s.next_run_at||'')}</td><td><button class=ghost onclick="toggleSched('${esc(s.name)}',${!s.enabled})">${s.enabled?'Disable':'Enable'}</button></td></tr>`).join('')}</table>`;
  }catch(e){$('#schl').innerHTML='<span class=s-bad>'+esc(e.message)+'</span>';}
}
async function toggleSched(name,on){try{await api('PATCH','/schedules/'+encodeURIComponent(name),{enabled:on});toast(name+(on?' enabled':' disabled'));viewSchedules($('#view'));}catch(e){toast(e.message,false);}}
async function viewStats(v){
  try{const s=await api('GET','/stats');const w=await api('GET','/workers').catch(()=>null);
    const by=s.assets?.by_type||{};
    v.innerHTML=`<div class="card"><h2>Overview</h2>
      <table><tr><th>Programs</th><td>${s.programs?.total??0} (${s.programs?.active??0} active)</td></tr>
      <tr><th>Scope entries</th><td>${s.scope_entries??0}</td></tr>
      <tr><th>Assets</th><td>${s.assets?.total??0} — ${esc(Object.entries(by).map(([k,n])=>k+':'+n).join(', '))}</td></tr>
      <tr><th>Relationships</th><td>${s.relationships??0}</td></tr>
      <tr><th>Scope blocked</th><td>${s.scope_blocked??0}</td></tr></table></div>
      ${w?`<div class="card"><h2>Worker pools</h2><table><tr><th>Queue</th><th>Pending</th><th>Workers</th><th>Busy</th><th>DLQ</th></tr>${Object.entries(w.pools).map(([q,p])=>`<tr><td>${esc(q)}</td><td>${p.pending}</td><td>${p.workers}</td><td>${p.busy_workers}</td><td class="${p.dlq?'s-bad':''}">${p.dlq}</td></tr>`).join('')}</table></div>`:''}
      <div class="card">Analitik lengkap (aset, sertifikat, teknologi, temuan, perubahan) ada di <a href="${esc(S.kibana||'#')}" target="_blank">Kibana</a>.</div>`;
  }catch(e){v.innerHTML='<div class="card s-bad">'+esc(e.message)+'</div>';}
}
// init
$('#apiBase').value=S.base; $('#apiKey').value=S.key;
$('#kibanaLink').onclick=(e)=>{if(!S.kibana){e.preventDefault();const u=prompt('URL Kibana (disimpan di browser):',location.protocol+'//'+location.hostname+':15601');if(u){S.kibana=u;localStorage.setItem('bb_kibana',u);$('#kibanaLink').href=u;window.open(u,'_blank');}}};
if(S.kibana)$('#kibanaLink').href=S.kibana;
renderTabs();
if(S.key)refreshWho(); else render();
</script></body></html>
"""


@router.get("/ui", include_in_schema=False, response_class=HTMLResponse)
def console() -> HTMLResponse:
    """Serve the management console. The page shell is public; all data calls it makes require a key."""
    return HTMLResponse(_PAGE)


@router.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/ui")
