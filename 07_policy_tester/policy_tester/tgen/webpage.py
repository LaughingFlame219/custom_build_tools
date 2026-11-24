PAGE = r'''<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Policy Tester</title>
<style>
:root{--ink:#2b3440;--mute:#6b7685;--line:#dfe3e8;--bg:#f2f4f7;--card:#fff;--blue:#3aa3e3;--blue2:#1d88c9;
--pass:#12b560;--drop:#f59e0b;--block:#f2623a;--err:#e03b3b;--oth:#b8bec6;--hd:#e9edf2}
*{box-sizing:border-box}html,body{height:100%}body{margin:0;background:var(--bg);color:var(--ink);font:13px/1.45 "Yu Gothic UI",Meiryo,"Segoe UI",sans-serif;display:flex;flex-direction:column;overflow:hidden}
#tb{height:44px;background:var(--card);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:4px;padding:0 12px;flex:none}
.tbtn{border:0;background:none;color:var(--ink);padding:6px 9px;border-radius:5px;cursor:pointer;font-size:12.5px;display:flex;align-items:center;gap:5px;white-space:nowrap}
.tbtn:hover{background:#eef1f5}.tbtn:disabled{opacity:.4;cursor:default}.tbtn.run{color:#12805a;font-weight:700}.tbtn.stop{color:var(--err);font-weight:700}
.sep{width:1px;height:20px;background:var(--line);margin:0 6px}.sp{flex:1}
.pill{display:flex;align-items:center;border-radius:999px;background:#eceff3;overflow:hidden;cursor:pointer;font-size:11.5px;margin-left:6px;border:2px solid transparent}
.pill.on{border-color:#27425e}.pill b{padding:3px 12px;color:#fff;font-weight:600}.pill i{font-style:normal;padding:3px 14px 3px 10px;min-width:56px;text-align:center;font-variant-numeric:tabular-nums}
#panel{display:none;background:var(--card);border-bottom:1px solid var(--line);padding:10px 16px;gap:14px;align-items:center;flex-wrap:wrap;font-size:12px;color:var(--mute)}
#panel input[type=number],#panel input[type=text]{border:1px solid var(--line);border-radius:5px;padding:4px 6px;width:70px;color:var(--ink)}#panel input[type=text]{width:210px}
#main{flex:1;display:flex;min-height:0}
#side{width:272px;flex:none;overflow:auto;padding:12px;display:flex;flex-direction:column;gap:12px;background:var(--bg)}
.card{background:var(--card);border-radius:8px;padding:12px 13px;box-shadow:0 1px 2px rgba(20,30,50,.06)}
.card h3{margin:0 0 8px;font-size:12px;display:flex;align-items:center;gap:6px;font-weight:700}
.card h3:before{content:"i";display:inline-flex;width:14px;height:14px;border-radius:50%;background:var(--blue);color:#fff;font-size:10px;align-items:center;justify-content:center;font-style:italic}
.ok{color:#14804f}.ng{color:var(--err)}.wn{color:#b7791f}.mu{color:var(--mute);font-size:12px}
.sb{display:block;width:100%;border:0;border-radius:4px;background:var(--blue);color:#fff;padding:7px;margin-top:6px;cursor:pointer;font-size:12.5px;text-align:center;text-decoration:none}
.sb:hover{background:var(--blue2)}.sb.o{background:#fff;border:1px solid var(--blue);color:var(--blue2)}.sb:disabled{opacity:.5}
.badge{display:inline-block;color:#fff;border-radius:999px;padding:1px 10px;font-size:11px;font-weight:700;margin-left:6px}
.kv{font-size:12px;margin:2px 0}.adv{color:var(--err);font-size:12px;margin-top:8px;white-space:pre-line}
#gw{flex:1;position:relative;overflow:auto;background:#fff;outline:0;min-width:0}
#sz{position:relative}
.hd{position:sticky;top:0;z-index:5;display:flex;background:var(--hd);height:26px;width:max-content}
.hc{flex:none;border-right:1px solid #cfd5dc;border-bottom:1px solid #cfd5dc;font-weight:700;font-size:12px;display:flex;align-items:center;justify-content:center;gap:4px;padding:0 4px;position:relative;white-space:nowrap}
.hc.num{position:sticky;left:0;z-index:6;background:var(--hd)}.hc u{color:var(--err);text-decoration:none}
.fi{width:15px;height:15px;border-radius:3px;background:#dbe9f6;color:#2a8fd6;font-size:9px;display:flex;align-items:center;justify-content:center;cursor:pointer;flex:none}.fi.on{background:var(--blue);color:#fff}
.r{position:absolute;left:0;display:flex;height:24px;width:max-content}
.c{flex:none;height:24px;border-right:1px solid #eceff2;border-bottom:1px solid #eceff2;padding:3px 6px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;font-size:12.5px;cursor:cell}
.c.num{position:sticky;left:0;z-index:2;background:#f3f5f8;color:var(--mute);text-align:center;padding:3px 0;cursor:pointer;border-right:1px solid #cfd5dc}
.c.ro{background:#fafbfc}.c.sel{outline:2px solid #2a8fd6;outline-offset:-2px;background:#fff;z-index:1}
.r.rs .c.num{background:#cfe5f7;color:#134a75;font-weight:700}
.r.err .c{background:#f8caca}.r.err .c.num{background:#f1a9a9}
.c.res-pass{background:var(--pass)!important;color:#fff;font-weight:700}.c.res-drop{background:#fcd9a0!important;font-weight:700}.c.res-block{background:#f9c0b0!important;font-weight:700}
.c.res-error{background:#f19797!important;font-weight:700}.c.mis{color:var(--err);font-weight:700}
.c input,.c select{width:100%;height:100%;border:0;outline:0;font:inherit;background:#fff;padding:0 2px;margin:-3px 0}
#tip{position:fixed;z-index:30;background:#fff;border:1px solid var(--line);border-radius:6px;padding:8px;box-shadow:0 4px 14px rgba(0,0,0,.15);display:none}
#tip input{border:1px solid var(--line);border-radius:4px;padding:4px 6px;width:170px}
#toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%);background:#27425e;color:#fff;padding:9px 18px;border-radius:7px;display:none;z-index:50;max-width:70vw;white-space:pre-line}
#bd{position:fixed;inset:0;background:rgba(20,30,50,.35);display:none;align-items:center;justify-content:center;z-index:40}
#md{background:#fff;border-radius:10px;width:min(620px,92vw);max-height:84vh;overflow:auto;padding:18px 20px}
#md h2{margin:0 0 10px;font-size:15px}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:8px 0}
.vd{border:1px solid var(--line);border-radius:6px;padding:7px 10px;margin:5px 0;display:flex;gap:8px;align-items:center}

#nav{position:fixed;left:0;top:44px;bottom:0;width:300px;background:#fff;border-right:1px solid var(--line);z-index:35;padding:10px 12px;display:none;flex-direction:column;gap:2px}
#nav a{display:flex;align-items:center;gap:10px;padding:11px 14px;border-radius:22px;cursor:pointer;color:#2a8fd6;font-size:13.5px}#nav a:hover{background:#eef6fc}#nav a.on{background:#e8f1f8;font-weight:700}
#nav small{color:#9aa4b2;padding:10px 14px 2px;font-size:11px}
.view{flex:1;overflow:auto;padding:26px 30px;display:none;background:#fff}.view h1{font-size:19px;margin:0 0 18px;font-weight:600}
.tbl{width:100%;border-collapse:collapse;font-size:13px}.tbl th{color:var(--mute);font-weight:600;text-align:left;padding:12px 10px;border-bottom:1px solid var(--line);background:#fafbfc}
.tbl td{padding:9px 10px;border-bottom:1px solid #eef0f3}.tbl tr.sub td:nth-child(2){padding-left:34px}.tbl a{color:#2a8fd6;text-decoration:underline;cursor:pointer}
.tbl select{border:1px solid var(--line);border-radius:5px;padding:5px 8px;min-width:130px;background:#fff}
.btn{border:1px solid var(--blue);background:#fff;color:var(--blue2);border-radius:5px;padding:6px 14px;cursor:pointer;font-size:12.5px}.btn:hover{background:#eef6fc}
.btn.p{background:var(--blue);color:#fff}.btn.p:hover{background:var(--blue2)}.btn.d{border-color:#e08a80;color:#c0392b}.btn.dd{background:#d94b3b;border-color:#d94b3b;color:#fff}
.btn:disabled{opacity:.45;cursor:default}
.fm{display:grid;grid-template-columns:190px 1fr;gap:12px 14px;align-items:center;margin:14px 0}.fm label{font-weight:600;font-size:12.5px}.fm label u{color:var(--err);text-decoration:none}
.fm input,.fm select,.fm textarea{border:1px solid #c9d1da;border-radius:6px;padding:7px 9px;font:inherit;width:100%}
.tabs{display:flex;border-bottom:1px solid var(--line);margin-bottom:12px}.tabs div{flex:1;text-align:center;padding:10px;cursor:pointer;color:var(--ink)}.tabs div.on{color:var(--blue2);border-bottom:2px solid var(--blue)}
.sec{background:#efefef;padding:6px 8px;font-weight:700;margin:14px 0 6px}
.rt{display:grid;grid-template-columns:130px 1.2fr 1fr 1.2fr 38px;gap:8px;align-items:center;margin:6px 0}.rt input,.rt select{border:1px solid #c9d1da;border-radius:6px;padding:7px 8px;font:inherit;width:100%}
.mini{width:32px;height:32px;border:1px solid var(--blue);border-radius:5px;background:#fff;color:var(--blue2);cursor:pointer;font-size:16px}
.tog{display:inline-block;width:38px;height:20px;border-radius:12px;background:#c9d1da;position:relative;cursor:pointer;vertical-align:middle}.tog:after{content:"";position:absolute;left:2px;top:2px;width:16px;height:16px;border-radius:50%;background:#fff;transition:.15s}.tog.on{background:var(--blue)}.tog.on:after{left:20px}
.vlist a{display:flex;gap:8px;padding:8px 10px;border-radius:5px;color:#2a8fd6;cursor:pointer}.vlist a.on{background:#eef1f5}
.apply.dirty{color:#e08a00;font-weight:700}.wlist{max-height:220px;overflow:auto;font-size:12.5px;margin:8px 0}.wlist div{padding:3px 0}
</style></head><body>
<div id="tb">
<button class="tbtn menu" title="メニュー">☰</button><span class="sep"></span>
<button class="tbtn" id="bLoad">📂 シナリオを読み込む</button><input type="file" id="fCsv" accept=".csv,.txt" hidden>
<button class="tbtn run" id="bRun">▶ 実行</button><button class="tbtn stop" id="bStop" style="display:none">■ 中止</button>
<button class="tbtn" id="bPath">▶ 疎通・経路確認</button>
<button class="tbtn" id="bCsv">💾 CSV</button><button class="tbtn" id="bEvi">💾 エビデンス保存</button>
<span class="sp"></span><div id="pills" style="display:flex"></div></div>
<div id="tb2" style="display:none;height:44px;background:var(--card);border-bottom:1px solid var(--line);align-items:center;gap:4px;padding:0 12px;flex:none">
<button class="tbtn menu">☰</button><span class="sep"></span>
<button class="tbtn" id="cLoad">📂 設定ファイルを読み込む</button><input type="file" id="fConf" accept=".toml,.txt" hidden>
<button class="tbtn apply" id="cApply">✔ 設定を適用</button><button class="tbtn" id="cSave">💾 設定ファイルを保存</button>
<button class="tbtn" id="cCheck">▤ テスト構成確認</button><span class="tog" id="cL2"></span><span id="cL2t" style="font-size:12.5px;margin-left:4px">L2モード：OFF</span></div>
<div id="nav"><a data-v="test">▣ ポリシーテスト</a><a data-v="if">⚙ インターフェース設定</a><a data-v="vr">⚙ 仮想ルーター設定</a><small>管理</small><a data-v="opt">⚙ 実行オプション</a></div>
<div id="panel">
<label>同時実行 <input type="number" id="oWorkers" value="64" min="1" max="500"></label>
<label>タイムアウト既定(秒) <input type="number" id="oTimeout" value="3" min="0.5" step="0.5"></label>
<label>最大実行回数既定 <input type="number" id="oTries" value="1" min="1" max="5"></label>
<label><input type="checkbox" id="oLenient"> expectがdrop/blockのときdrop≒blockとみなす</label>
<label><input type="checkbox" id="oSim"> 疑似FWで実行 (NIC不要・動作確認用)</label>
<label>FQDN→IP <input type="text" id="oHosts" placeholder="www.example.com=203.0.113.10,..."></label>
<label>pcap保存先 <input type="text" id="oPcap" placeholder="C:\temp\run.pcap"></label></div>
<div id="main">
<div id="side">
<div class="card" id="cEnv"></div>
<div class="card" id="cRes"></div>
<div class="card" id="cDesc"></div>
<div class="card"><button class="sb o" id="bToml">⚙ 仮想ルーター設定(TOML)を読み込む</button><input type="file" id="fToml" accept=".toml,.txt" hidden>
<a class="sb o" href="/api/sample.csv">⬇ シナリオのサンプルを取得する</a>
<button class="sb o" id="bReset">🗑 テーブル設定を初期化する</button></div>
<div class="card"><button class="sb" id="bGen">✎ シナリオを自動生成する</button></div>
</div>
<div id="gw" tabindex="0"><div id="sz"></div></div>
</div>
<div class="view" id="vIf"></div><div class="view" id="vVr"></div>
<div id="tip"></div><div id="toast"></div>
<div id="bd"><div id="md"></div></div>
<script>
const $=id=>document.getElementById(id);
const COLS=[
{k:'protocol',h:'プロトコル',req:1,w:84,sel:['','icmp','tcp','udp','dns','http','https','ftp','smtp','imap']},
{k:'src-ip',h:'送信元IP',req:1,w:116},{k:'src-port(option)',h:'送信元Port',w:84},{k:'src-nat-ip(option)',h:'送信元NAT IP',w:116},
{k:'is-receiver-physical(option)',h:'実機',w:64,sel:['','true']},
{k:'dst-nat-ip(option)',h:'宛先NATIP',w:116},{k:'dst-nat-port (option)',h:'宛先NATPort',w:92},
{k:'dst-ip',h:'宛先IP',req:1,w:116},{k:'dst-port',h:'宛先Port',w:76},{k:'url/domain(option)',h:'URL / ドメイン',w:140},
{k:'anti-virus(option)',h:'アンチウイルス',w:104,sel:['','eicar']},{k:'timeout(option)',h:'タイムアウト',w:84},{k:'try(option)',h:'最大実行回数',w:92},
{k:'expect',h:'期待値',req:1,w:80,sel:['','pass','drop','block']},
{k:'result',h:'結果',w:300,ro:1},{k:'ping-traceroute',h:'疎通・経路確認',w:140,ro:1},{k:'description',h:'説明',w:280},
{k:'_ts',h:'テスト実施時刻',w:150,ro:1},{k:'_name',h:'シナリオ名',w:140,ro:1},{k:'_svr',h:'送信元VR',w:110,ro:1},
{k:'_snh',h:'送信元ネクストホップ',w:150,ro:1},{k:'_dvr',h:'宛先VR',w:110,ro:1},{k:'_dnh',h:'宛先ネクストホップ',w:140,ro:1}];
const NW=COLS.filter(c=>c.k[0]!=='_').map(c=>c.k);
const RH=24,NUMW=46;let rows=[],sel={r:0,c:0},selRow=-1,ed=null,filt='all',colF={},toml='',cfg=null,env=null,since=0,running=false,vis=[],path=null,seq=0;
const blank=()=>{const o={res:null};COLS.forEach(c=>o[c.k]='');return o};
const has=r=>r&&r.protocol!=='';
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const pad=n=>String(n).padStart(2,'0');
function stamp(){const d=new Date();return `${d.getFullYear()}.${pad(d.getMonth()+1)}.${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`}
let tt;function toast(m){const t=$('toast');t.textContent=m;t.style.display='block';clearTimeout(tt);tt=setTimeout(()=>t.style.display='none',3800)}
try{const o=JSON.parse(localStorage.getItem('pt_opts')||'{}');for(const k in o){const e=$(k);if(e){e.type==='checkbox'?e.checked=o[k]:e.value=o[k]}}}catch(e){}
function saveOpts(){try{const o={};document.querySelectorAll('#panel input').forEach(e=>o[e.id]=e.type==='checkbox'?e.checked:e.value);localStorage.setItem('pt_opts',JSON.stringify(o))}catch(e){}}
document.querySelectorAll('#panel input').forEach(e=>e.onchange=saveOpts);

const opts=()=>({workers:$('oWorkers').value,timeout:$('oTimeout').value,tries:$('oTries').value,lenient:$('oLenient').checked,sim:$('oSim').checked,hosts:$('oHosts').value,pcap:$('oPcap').value});
const post=(u,b)=>fetch(u,{method:'POST',body:JSON.stringify(b)});
/* ---------- CSV ---------- */
function parseCSV(t){const out=[];let row=[],f='',q=false;t=t.replace(/^\ufeff/,'');for(let i=0;i<t.length;i++){const c=t[i];if(q){if(c==='"'){if(t[i+1]==='"'){f+='"';i++}else q=false}else f+=c}else if(c==='"')q=true;else if(c===','){row.push(f);f=''}else if(c==='\n'){row.push(f);out.push(row);row=[];f=''}else if(c!=='\r')f+=c}
if(f!==''||row.length){row.push(f);out.push(row)}return out}
function toCSV(list){const q=s=>/[",\n\r]/.test(s)?'"'+s.replace(/"/g,'""')+'"':s;return [NW.join(',')].concat(list.map(r=>NW.map(k=>q(String(r[k]==null?'':r[k]))).join(','))).join('\n')+'\n'}
async function readText(f){const b=await f.arrayBuffer();try{return new TextDecoder('utf-8',{fatal:true}).decode(b)}catch(e){return new TextDecoder('shift_jis').decode(b)}}
function loadRows(text){const t=parseCSV(text);if(!t.length)return 0;const h=t[0].map(x=>x.trim());const ix={};NW.forEach(k=>{let i=h.indexOf(k);if(i<0)i=h.indexOf(k.replace(' (','('));ix[k]=i});
const d=new Date(),day=`${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;rows=[];
t.slice(1).forEach(r=>{if(!r.some(x=>x.trim()))return;const o=blank();NW.forEach(k=>{o[k]=ix[k]>=0&&ix[k]<r.length?r[ix[k]].trim():''});o._name='nw-'+day+'-'+(rows.length+1);rows.push(o)});
selRow=-1;sel={r:0,c:0};filt='all';colF={};annotate();return rows.length}
/* ---------- grid ---------- */
const gw=$('gw');
function totalW(){return NUMW+COLS.reduce((a,c)=>a+c.w,0)}
function cellText(r,c){return r?(c.k==='result'&&r.res?r.res.result_text:r[c.k]):''}
function calcVis(){const out=[];for(let i=0;i<rows.length;i++){const r=rows[i];if(!has(r))continue;
if(filt!=='all'){const s=r.res&&r.res.status;if(filt==='others'){if(s&&['pass','drop','block','error'].includes(s))continue}else if(s!==filt)continue}
let ok=true;for(const k in colF){if(colF[k]&&!String(cellText(r,COLS.find(c=>c.k===k))||'').toLowerCase().includes(colF[k].toLowerCase())){ok=false;break}}
if(ok)out.push(i)}return out}
let raf=0;function render(){if(!raf)raf=requestAnimationFrame(()=>{raf=0;draw()})}
function draw(){const filtered=filt!=='all'||Object.values(colF).some(v=>v);vis=filtered?calcVis():null;
const n=filtered?vis.length:Math.max(rows.length+1,Math.ceil(gw.clientHeight/RH)+1);const H=n*RH+26;
const st=gw.scrollTop,first=Math.max(0,Math.floor((st-26)/RH)-4),last=Math.min(n-1,Math.ceil((st+gw.clientHeight)/RH)+4);
let h=`<div class="hd"><div class="hc num" style="width:${NUMW}px"></div>`+COLS.map(c=>`<div class="hc" style="width:${c.w}px">${esc(c.h)}${c.req?' <u>*</u>':''}<span class="fi ${colF[c.k]?'on':''}" data-f="${c.k}">▼</span></div>`).join('')+`</div>`;
for(let d=first;d<=last;d++){const ri=filtered?vis[d]:d,r=rows[ri];const e=r&&r.res&&r.res.status==='error';
h+=`<div class="r ${e?'err':''} ${ri===selRow?'rs':''}" style="top:${26+d*RH}px"><div class="c num" style="width:${NUMW}px" data-r="${ri}">${ri+1}</div>`;
COLS.forEach((c,ci)=>{const v=cellText(r,c);let cl='c'+(c.ro?' ro':'');const isSel=sel.r===ri&&sel.c===ci;if(isSel)cl+=' sel';
if(c.k==='result'&&r&&r.res)cl+=' res-'+r.res.status;
if(c.k==='expect'&&r&&r.res&&r.res.judge==='NG')cl+=' mis';
let inner;if(ed&&ed.r===ri&&ed.c===ci){inner=c.sel?`<select id="ed">${c.sel.map(o=>`<option ${o===v?'selected':''}>${esc(o)}</option>`).join('')}</select>`:`<input id="ed" value="${esc(ed.v)}">`}else inner=esc(v);
h+=`<div class="${cl}" style="width:${c.w}px" data-r="${ri}" data-c="${ci}" title="">${inner}</div>`});h+='</div>'}
const keep=gw.scrollLeft;$('sz').style.height=H+'px';$('sz').style.width=totalW()+'px';$('sz').innerHTML=h;
if(ed){const e=$('ed');if(e){e.focus();if(e.select&&e.tagName==='INPUT'){ed.sel!==false&&e.select()}bindEd(e)}}
pills();side()}
gw.addEventListener('scroll',()=>{if(!ed)render()});window.addEventListener('resize',render);
function ensureRow(i){while(rows.length<=i)rows.push(blank())}
function startEdit(r,c,init){const col=COLS[c];if(col.ro)return;ensureRow(r);ed={r,c,v:init!==undefined?init:rows[r][col.k],sel:init===undefined};render()}
function commit(move){if(!ed)return;const e=$('ed');const col=COLS[ed.c];const val=e?(e.value):ed.v;ensureRow(ed.r);const row=rows[ed.r];
if(row[col.k]!==val){row[col.k]=val;row.res=null;row.result='';if(col.k==='protocol'||col.k==='src-ip'||col.k==='dst-ip'||col.k==='dst-nat-ip(option)')annotate()}
const r=ed.r,c=ed.c;ed=null;if(move==='down')sel={r:r+1,c};else if(move==='right')sel={r,c:Math.min(COLS.length-1,c+1)};else sel={r,c};selRow=sel.r;render();gw.focus()}
function bindEd(e){e.onkeydown=ev=>{if(ev.key==='Enter'){ev.preventDefault();commit('down')}else if(ev.key==='Tab'){ev.preventDefault();commit('right')}else if(ev.key==='Escape'){ed=null;render();gw.focus()}ev.stopPropagation()};
e.onblur=()=>{if(ed)commit()};if(e.tagName==='SELECT')e.onchange=()=>commit()}
$('sz').addEventListener('mousedown',ev=>{const f=ev.target.closest('[data-f]');if(f){ev.preventDefault();ev.stopPropagation();openFilter(f);return}
const c=ev.target.closest('.c');if(!c||ev.target.id==='ed')return;if(ed)commit();const r=+c.dataset.r;if(c.classList.contains('num')){selRow=r;sel={r,c:sel.c}}else{sel={r,c:+c.dataset.c};selRow=r}render();setTimeout(()=>{if(!ed)gw.focus()},0)});
$('sz').addEventListener('dblclick',ev=>{const c=ev.target.closest('.c');if(c&&!c.classList.contains('num')&&ev.target.id!=='ed'){startEdit(+c.dataset.r,+c.dataset.c)}});
gw.addEventListener('keydown',ev=>{if(ed)return;const mv=(dr,dc)=>{ev.preventDefault();sel={r:Math.max(0,sel.r+dr),c:Math.max(0,Math.min(COLS.length-1,sel.c+dc))};selRow=sel.r;scrollTo(sel.r);render()};
if(ev.key==='ArrowDown')mv(1,0);else if(ev.key==='ArrowUp')mv(-1,0);else if(ev.key==='ArrowLeft')mv(0,-1);else if(ev.key==='ArrowRight')mv(0,1);else if(ev.key==='Tab'){mv(0,ev.shiftKey?-1:1)}
else if(ev.key==='Enter'||ev.key==='F2'){ev.preventDefault();startEdit(sel.r,sel.c)}
else if(ev.key==='Delete'||ev.key==='Backspace'){ev.preventDefault();const col=COLS[sel.c];if(!col.ro&&rows[sel.r]){rows[sel.r][col.k]='';rows[sel.r].res=null;render()}}
else if(ev.key.length===1&&!ev.ctrlKey&&!ev.metaKey&&!ev.altKey){const col=COLS[sel.c];if(!col.ro){ev.preventDefault();startEdit(sel.r,sel.c,col.sel?undefined:ev.key)}}
else if((ev.ctrlKey||ev.metaKey)&&ev.key==='c'){const r=rows[sel.r];if(r)navigator.clipboard&&navigator.clipboard.writeText(String(cellText(r,COLS[sel.c])||'')).catch(()=>{})}});
gw.addEventListener('paste',ev=>{if(ed)return;const t=(ev.clipboardData||window.clipboardData).getData('text');if(!t)return;ev.preventDefault();
const lines=t.replace(/\r/g,'').replace(/\n$/,'').split('\n');lines.forEach((ln,i)=>{const r=sel.r+i;ensureRow(r);ln.split('\t').forEach((v,j)=>{const c=COLS[sel.c+j];if(c&&!c.ro){rows[r][c.k]=v;rows[r].res=null}})});annotate();render();toast(lines.length+'行を貼り付けました')});
function scrollTo(r){const y=r*RH+26,h=gw.clientHeight;if(y<gw.scrollTop+26)gw.scrollTop=y-26;else if(y+RH>gw.scrollTop+h)gw.scrollTop=y+RH-h}
function openFilter(f){const k=f.dataset.f,t=$('tip'),b=f.getBoundingClientRect();t.style.left=Math.min(b.left,innerWidth-200)+'px';t.style.top=b.bottom+4+'px';t.style.display='block';t.innerHTML=`<input id="fi" placeholder="絞り込み (含む)" value="${esc(colF[k]||'')}">`;const i=$('fi');i.focus();i.oninput=()=>{colF[k]=i.value;render()};i.onkeydown=e=>{if(e.key==='Enter'||e.key==='Escape')t.style.display='none'}}
document.addEventListener('mousedown',e=>{if(!e.target.closest('#tip')&&!e.target.closest('[data-f]'))$('tip').style.display='none'});
/* ---------- pills / side ---------- */
function pills(){const ex={pass:0,drop:0,block:0},rc={pass:0,drop:0,block:0,error:0};let done=0,tot=0;rows.forEach(r=>{if(!has(r))return;tot++;if(ex[r.expect]!==undefined)ex[r.expect]++;if(r.res){done++;if(rc[r.res.status]!==undefined)rc[r.res.status]++}});
const oth=rows.filter(r=>has(r)&&!['pass','drop','block'].includes(r.expect)).length;
const P=(k,t,c,v)=>`<div class="pill ${filt===k?'on':''}" data-k="${k}"><b style="background:${c}">${t}</b><i>${v}</i></div>`;
$('pills').innerHTML=P('all','All','#2da3f5',`${done} / ${tot}`)+P('pass','Pass','var(--pass)',`${rc.pass} / ${ex.pass}`)+P('drop','Drop','var(--drop)',`${rc.drop} / ${ex.drop}`)+P('block','Block','var(--block)',`${rc.block} / ${ex.block}`)+P('error','Error','var(--err)',rc.error)+P('others','Others','var(--oth)',oth);
document.querySelectorAll('.pill').forEach(p=>p.onclick=()=>{filt=p.dataset.k;render()})}
function side(){let e='';
e+=env?(env.npcap?`<div class="ok">● Npcapを検出しました</div>`:`<div class="wn">▲ Npcap未検出 (疑似FWでのみ実行可)</div>`):'';
if(!cfg)e+=`<div class="wn">▲ 仮想ルーター設定が未読込です</div>`;
else if(!cfg.ok)e+=`<div class="ng">▲ ${esc(cfg.error)}</div>`;
else{e+=`<div class="ok">● 仮想ルーター ${cfg.vrs.length}台 / IF ${cfg.interfaces}</div>`;if(cfg.noos&&cfg.noos.length&&!$('oSim').checked)e+=`<div class="wn">▲ os_if未設定: ${esc(cfg.noos.join(', '))}</div>`}
e+=`<div style="margin-top:8px;border-top:1px solid var(--line);padding-top:6px" class="mu">L2モード：${cfg&&cfg.ok&&cfg.l2?'ON':'OFF'}</div>`;$('cEnv').innerHTML=e;
const r=rows[selRow];const n=selRow+1;let h='';
if(!has(r)){h=`<h3>テスト結果</h3><div class="mu">行を選択してください</div>`}
else{const x=r.res;h=`<h3>#${n} テスト結果${x?`<span class="badge" style="background:var(--${x.status==='pass'?'pass':x.status==='drop'?'drop':x.status==='block'?'block':'err'})">${x.status==='pass'?'Pass':x.status==='drop'?'Drop':x.status==='block'?'Block':'Error'}</span>`:''}</h3>`;
if(!x)h+=`<div class="mu">未実行</div>`;
else if(x.err){h+=`<div style="font-weight:700">${esc(x.err.title)}</div>`;if(x.err.fields.length)h+=`<div style="color:#b42318;margin:6px 0">⚠</div>`+x.err.fields.map(f=>`<div class="kv">${esc(f[0])}: ${esc(f[1])}</div>`).join('');if(x.err.advice)h+=`<div class="adv">${esc(x.err.advice)}</div>`}
else{h+=`<div class="kv">${esc(x.detail)}</div>`;if(x.observed_src)h+=`<div class="kv mu">受信側で観測: ${esc(x.observed_src)} → ${esc(x.observed_dst)}</div>`;if(x.cert_issuer)h+=`<div class="kv mu">証明書issuer: ${esc(x.cert_issuer)}${x.ssl_inspected?' <b class="ng">(SSL復号検出)</b>':''}</div>`;h+=`<div class="kv mu">${x.elapsed_ms} ms</div>`}
if(r['ping-traceroute'])h+=`<div class="kv mu" style="margin-top:6px">疎通・経路: ${esc(r['ping-traceroute'])}</div>`;
h+=`<button class="sb" id="bOne" ${running?'disabled':''}>このシナリオを個別にテストする</button><button class="sb" id="bPath2">疎通・経路確認</button>`}
$('cRes').innerHTML=h;
$('cDesc').innerHTML=`<h3>${has(r)?'#'+n+' ':''}説明</h3><div class="mu" style="white-space:pre-wrap;word-break:break-all">${esc(has(r)?r.description:'')}</div>`+(path?`<div style="margin-top:10px;border-top:1px solid var(--line);padding-top:6px"><b style="font-size:12px">疎通・経路確認</b>${path.map(p=>`<div class="kv ${p.ok?'ok':'ng'}">${p.ok?'●':'✕'} ${esc(p.vr)} → ${esc(p.ip)} (${esc(p.if)}) ${p.ok?esc(p.mac):'ARP応答なし'}</div>`).join('')}</div>`:'');
const b1=$('bOne');if(b1)b1.onclick=()=>runRows([selRow]);const b2=$('bPath2');if(b2)b2.onclick=()=>pathCheck(true)}

function arpModal(list){const ng=list.filter(p=>!p.ok);const card=p=>`<div style="border:1px solid var(--line);border-radius:6px;padding:8px 10px;margin:8px 0"><div style="background:#4fbdf0;color:#fff;font-weight:700;padding:5px 9px;border-radius:3px">VR: ${esc(p.vr)}</div><div style="display:flex;gap:50px;padding:12px 10px 6px"><div><b>Nexthop</b><div style="margin-top:6px">${esc(p.ip)}</div></div><div><b>destination</b><div style="margin-top:6px">${esc(p.dest||'')}</div></div><div><b>ARP送信元I/F</b><div style="margin-top:6px">${esc(p.if)}</div></div></div></div>`;
let h=`<h2>ARPリクエスト結果</h2>`;
if(!list.length)h+=`<div class="wn" style="font-weight:700;margin:12px 0">確認対象のexternalルート(ネクストホップ)がありません。</div>`;
else if(ng.length)h+=`<div style="font-weight:700;margin:14px 0 6px;color:var(--err)">ARPリプライがないネクストホップがありました。</div><div class="mu">仮想ルーターで指定したゲートウェイ(ネクストホップ)からARP応答がありません。ネクストホップIPアドレス、ケーブル・VLAN・ネットワーク構成を見直してください。</div><div class="wlist" style="max-height:300px">${ng.map(card).join('')}</div>`+(list.length>ng.length?`<div class="mu">応答あり: ${list.filter(p=>p.ok).map(p=>esc(p.vr)+' → '+esc(p.ip)).join(' / ')}</div>`:'');
else h+=`<div class="ok" style="font-weight:700;margin:14px 0 6px">すべてのネクストホップからARPリプライがありました。</div><div class="wlist">${list.map(p=>`<div class="ok">● ${esc(p.vr)} → ${esc(p.ip)} (${esc(p.if)}) ${esc(p.mac)}</div>`).join('')}</div>`;
modal(h+`<div class="row" style="justify-content:flex-end"><button class="btn p" onclick="closeM()">閉じる</button></div>`)}
/* ---------- 実行 ---------- */
async function annotate(){const idx=rows.map((r,i)=>has(r)?i:-1).filter(i=>i>=0);if(!toml||!idx.length){idx.forEach(i=>{['_svr','_snh','_dvr','_dnh'].forEach(k=>rows[i][k]='')});return}
const d=await (await post('/api/annotate',{toml,rows:idx.map(i=>({'src-ip':rows[i]['src-ip'],'dst-ip':rows[i]['dst-ip'],'dst-nat-ip(option)':rows[i]['dst-nat-ip(option)']}))})).json();
idx.forEach((i,j)=>{const a=d.rows[j]||{};rows[i]._svr=a.svr||'';rows[i]._snh=a.snh||'';rows[i]._dvr=a.dvr||'';rows[i]._dnh=a.dnh||''});render()}
const csvRow=r=>{const o={};NW.forEach(k=>o[k]=r[k]);return o};
async function runRows(list){if(running)return;if(dirty)toast('未適用の設定変更があります (適用済みの設定で実行します)');if(!toml.trim()){toast('先に仮想ルーター設定(TOML)を読み込んでください');return}
list=list.filter(i=>has(rows[i]));if(!list.length){toast('実行できるシナリオがありません');return}
list.forEach(i=>{rows[i].res=null;rows[i].result='';rows[i]._ts=''});since=0;render();
const r=await (await post('/api/run',{items:list.map(i=>({idx:i,row:csvRow(rows[i])})),toml,options:opts()})).json();if(!r.ok){toast(r.error);return}
running=true;ui();poll()}
function ui(){$('bRun').style.display=running?'none':'';$('bStop').style.display=running?'':'none';side()}
async function poll(){let d;try{d=await (await fetch('/api/status?since='+since)).json()}catch(e){setTimeout(poll,800);return}
since=d.next;d.events.forEach(ev=>{const r=rows[ev.idx];if(r){r.res=ev;r.result=ev.result_text;r._ts=stamp()}});render();
if(d.state==='running'){setTimeout(poll,300)}else{running=false;ui();if(d.error)toast(d.error);else toast((d.state==='stopped'?'中止しました':'完了しました')+`  ${d.done}/${d.total}件 ${d.elapsed}秒`+(d.warnings.length?'\n'+d.warnings.join('\n'):''))}}
$('bRun').onclick=()=>runRows(rows.map((r,i)=>has(r)?i:-1).filter(i=>i>=0));
$('bStop').onclick=()=>post('/api/stop',{});
async function pathCheck(sel1){if(!toml.trim()){toast('先に仮想ルーター設定(TOML)を読み込んでください');return}
let vrs=null;const r=rows[selRow];if(sel1&&has(r)){vrs=[r._svr,r._dvr].filter(Boolean)}
toast('疎通・経路確認中…');const d=await (await post('/api/pathcheck',{toml,rows:rows.filter(has).map(csvRow),vrs,options:opts()})).json();
if(!d.ok){toast(d.error);return}path=d.results;if(sel1&&has(r)){r['ping-traceroute']=d.results.map(p=>p.vr+':'+(p.ok?'OK':'NG')).join(' ')}
arpModal(d.results);render()}
$('bPath').onclick=()=>pathCheck(false);
/* ---------- 入出力 ---------- */
$('bLoad').onclick=()=>$('fCsv').click();
$('fCsv').onchange=async()=>{const f=$('fCsv').files[0];if(!f)return;const n=loadRows(await readText(f));$('fCsv').value='';toast(n+'件のシナリオを読み込みました');render()};
$('bToml').onclick=()=>$('fToml').click();
async function setToml(t){toml=t;cfg=await (await post('/api/config',{toml})).json();if(cfg.ok){conf=normConf(cfg.conf);dirty=false;vrSel=0}annotate();render();cfgRender()}
$('fToml').onchange=async()=>{const f=$('fToml').files[0];if(!f)return;await setToml((await readText(f)).replace(/^\ufeff/,''));$('fToml').value='';toast(cfg.ok?'仮想ルーター設定を読み込みました':cfg.error)};
function dl(name,blob){const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove()},500)}
const outRows=()=>rows.filter(has).map(r=>Object.assign(csvRow(r),{result:r.result||r.result_text||''}));
$('bCsv').onclick=()=>{if(!rows.some(has)){toast('シナリオがありません');return}dl('scenarios_result.csv',new Blob(['\ufeff'+toCSV(outRows())],{type:'text/csv'}))};
$('bEvi').onclick=async()=>{const done=rows.filter(r=>has(r)&&r.res);if(!done.length){toast('実行結果がありません。先にテストを実行してください');return}
const c={pass:0,drop:0,block:0,error:0,ok:0,ng:0};done.forEach(r=>{c[r.res.status]++;if(r.res.judge==='OK')c.ok++;if(r.res.judge==='NG')c.ng++});
const summary=`実施日時: ${stamp()}\n実行: ${done.length}/${rows.filter(has).length}件\nPass ${c.pass} / Drop ${c.drop} / Block ${c.block} / Error ${c.error}\n期待どおり ${c.ok} / 不一致 ${c.ng}\nモード: ${$('oSim').checked?'疑似FW':'実機'}\n`;
const details=rows.map((r,i)=>r.res?Object.assign({no:i+1,result:r.res.result_text},r.res):null).filter(Boolean);
const rs=await post('/api/evidence',{csv:toCSV(outRows()),toml,details,summary,options:opts()});dl(rs.headers.get('X-Filename')||'evidence.zip',await rs.blob());toast('エビデンスを保存しました (結果CSV + 仮想ルーター設定)')};
$('bReset').onclick=()=>{filt='all';colF={};render();toast('フィルタを初期化しました')};
/* ---------- 自動生成 ---------- */
function modal(h){$('md').innerHTML=h;$('bd').style.display='flex'}function closeM(){$('bd').style.display='none'}
$('bd').onmousedown=e=>{if(e.target===$('bd'))closeM()};
$('bGen').onclick=()=>{modal(`<h2>シナリオを自動生成する</h2><div class="mu">FortiGate / Palo Alto のコンフィグから、シナリオCSVと仮想ルーター設定(TOML)を生成して読み込みます。</div>
<div class="row"><input type="file" id="fCfg"><select id="gv"><option value="auto">自動判定</option><option value="fortigate">FortiGate</option><option value="palo">Palo Alto</option></select></div>
<div class="row mu">組合せ上限 <input id="gCombo" type="number" min="0" value="100" style="width:70px" title="1ポリシーの (送信元×宛先×サービス) がこれを超えたら、全ての値を1回ずつ使う形に間引く。0=全組合せ"> ポリシーあたり最大 <input id="gMax" type="number" min="0" value="0" style="width:70px" title="0=無制限"> <label><input type="checkbox" id="gNeg"> 境界の拒否テストも生成</label></div><div id="gr"></div>`);
$('fCfg').onchange=async()=>{const f=$('fCfg').files[0];if(!f)return;$('gr').innerHTML='<div class="mu">生成中… (ポリシーが多いと数十秒かかることがあります)</div>';const text=await readText(f);
const gopts={max_combo:$('gCombo').value,max_per_policy:$('gMax').value,negative:$('gNeg').checked};
const d=await (await post('/api/generate',{text,vendor:$('gv').value,opts:gopts})).json();if(!d.ok){$('gr').innerHTML=`<div class="ng">${esc(d.error)}</div>`;return}
window._gen=d;$('gr').innerHTML=`<div class="ok" style="margin:6px 0">${esc(d.vendor)}: ${d.vdoms.length} 件</div>`+d.vdoms.map((v,i)=>`<label class="vd"><input type="radio" name="vd" value="${i}" ${i===0?'checked':''}><b>${esc(v.name||'(vdomなし)')}</b><span class="mu">${v.count} シナリオ / 仮想ルーター ${v.toml?'あり':'なし'} / 警告 ${v.warnings.length}${v.warn_total>v.warnings.length?'+':''}</span></label>`).join('')+
(d.vdoms.some(v=>v.count>50000)?'<div class="wn" style="margin:6px 0">シナリオが5万件を超えています。表示・実行が重くなるので「組合せ上限」や「ポリシーあたり最大」を下げて作り直すことをおすすめします。</div>':'')+
`<details class="mu"><summary>警告の内容 (先頭30件)</summary><div class="wlist wn">${d.vdoms.map(v=>v.warnings.map(w=>`<div>▲ ${esc(w[0])} (×${w[1]})</div>`).join('')).join('')||'なし'}</div></details>`+
`<div class="row"><button class="sb" id="gl" style="width:auto;padding:7px 18px">読み込む</button><button class="sb o" id="gc" style="width:auto;padding:7px 18px">閉じる</button></div>`;
$('gc').onclick=closeM;$('gl').onclick=async()=>{const v=window._gen.vdoms[+document.querySelector('input[name=vd]:checked').value];const n=loadRows(v.csv);await setToml(v.toml);closeM();toast(`${n}件のシナリオと仮想ルーター設定を読み込みました`+(v.warnings.length?`\n警告 ${v.warnings.length}件 (詳細は scenario_gen の画面で確認)`:''));render()}}};

/* ================= 設定編集 (インターフェース / 仮想ルーター) ================= */
const newConf=()=>({version:'1902',l2_mode:false,interfaces:[1,2,3].map(n=>({name:'eth0/'+n,type:'physical',os_if:'',ip_aliases:[],ipaddress:''})),vRouters:[]});
function normConf(c){c=JSON.parse(JSON.stringify(c||{}));c.version=c.version||'1902';c.l2_mode=!!c.l2_mode;c.interfaces=(c.interfaces||[]).map(i=>{i.ip_aliases=(i.ip_aliases||[]).map(a=>typeof a==='string'?a:(a.ipaddress||a.ip||''));i.ipaddress=i.ipaddress||'';if(i.type==='vlan'){i.vlan_id=String(i.vlan_id||'');i.base_if=i.base_if||''}else{i.type='physical';i.os_if=i.os_if||''}return i});
c.vRouters=(c.vRouters||[]).map(v=>{v.if_names=v.if_names||[];const r=v.routes||{};v.routes={internal:(r.internal||[]).map(x=>({destination:x.destination,comment:x.comment||''})),external:(r.external||[]).map(x=>({destination:x.destination,next_hop:x.next_hop||'',comment:x.comment||''}))};return v});
if(!c.interfaces.length)c.interfaces=newConf().interfaces;return c}
let conf=newConf(),dirty=false,view='test',vrSel=0,navOpen=false,vm=null;
const netOf=c=>{const m=c.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/);if(!m)return c;const p=+m[5];let ip=((+m[1]<<24)|(+m[2]<<16)|(+m[3]<<8)|+m[4])>>>0;const mask=p===0?0:(0xFFFFFFFF<<(32-p))>>>0;ip=(ip&mask)>>>0;return [ip>>>24,(ip>>>16)&255,(ip>>>8)&255,ip&255].join('.')+'/'+p};
const vrOf=n=>{const v=conf.vRouters.find(v=>v.if_names.includes(n));return v?v.name:''};
const ifOpts=(sel,list)=>list.map(o=>`<option value="${esc(o)}" ${o===sel?'selected':''}>${esc(o)}</option>`).join('');
function setView(v){view=v;navOpen=false;const t=v==='test';$('tb').style.display=t?'flex':'none';$('tb2').style.display=t?'none':'flex';$('main').style.display=t?'flex':'none';
$('vIf').style.display=v==='if'?'block':'none';$('vVr').style.display=v==='vr'?'block':'none';cfgRender();navUI();if(t)render()}
function navUI(){$('nav').style.display=navOpen?'flex':'none';document.querySelectorAll('.menu').forEach(b=>b.textContent=navOpen?'✕':'☰');document.querySelectorAll('#nav a').forEach(a=>a.classList.toggle('on',a.dataset.v===view))}
document.querySelectorAll('.menu').forEach(b=>b.onclick=()=>{navOpen=!navOpen;navUI()});
document.querySelectorAll('#nav a').forEach(a=>a.onclick=()=>{const v=a.dataset.v;if(v==='opt'){const p=$('panel');p.style.display=p.style.display==='flex'?'none':'flex';navOpen=false;navUI();return}setView(v)});
function cfgRender(){const a=$('cApply');a.classList.toggle('dirty',dirty);a.textContent=dirty?'✔ 設定を適用':'✔ 設定を適用';$('cL2').classList.toggle('on',conf.l2_mode);$('cL2t').textContent='L2モード：'+(conf.l2_mode?'ON':'OFF');
if(view==='if')renderIf();else if(view==='vr')renderVr();side()}
const mark=()=>{dirty=true;cfgRender()};
$('cL2').onclick=()=>{conf.l2_mode=!conf.l2_mode;mark()};
/* ---- ツールバー ---- */
$('cLoad').onclick=()=>$('fConf').click();
$('fConf').onchange=async()=>{const f=$('fConf').files[0];if(!f)return;await setToml((await readText(f)).replace(/^﻿/,''));$('fConf').value='';toast(cfg.ok?'設定ファイルを読み込みました':cfg.error)};
async function validateConf(){return await (await post('/api/validate',{conf})).json()}
$('cApply').onclick=async()=>{const v=await validateConf();if(v.errors.length){modal(`<h2>設定にエラーがあります</h2><div class="wlist ng">${v.errors.map(e=>`<div>✕ ${esc(e)}</div>`).join('')}</div>${v.warnings.length?`<div class="wlist wn">${v.warnings.map(e=>`<div>▲ ${esc(e)}</div>`).join('')}</div>`:''}<div class="row"><button class="btn" onclick="closeM()">閉じる</button></div>`);return}
const g=await (await post('/api/tomlgen',{conf})).json();if(!g.ok){toast(g.error);return}await setToml(g.toml);
if(v.warnings.length)modal(`<h2>設定を適用しました</h2><div class="mu">次の点を確認してください。</div><div class="wlist wn">${v.warnings.map(e=>`<div>▲ ${esc(e)}</div>`).join('')}</div><div class="row"><button class="btn p" onclick="closeM()">OK</button></div>`);else toast('設定を適用しました')};
$('cSave').onclick=async()=>{const g=await (await post('/api/tomlgen',{conf})).json();if(!g.ok){toast(g.error);return}dl('vrouter_config.toml',new Blob([g.toml],{type:'text/plain'}));toast('設定ファイルを保存しました'+(dirty?' (未適用の変更を含みます)':''))};
$('cCheck').onclick=async()=>{if(dirty){toast('先に「設定を適用」してください');return}if(!toml.trim()){toast('仮想ルーター設定がありません');return}
toast('テスト構成を確認中…');const d=await (await post('/api/pathcheck',{toml,rows:rows.filter(has).map(csvRow),vrs:null,options:opts()})).json();if(!d.ok){toast(d.error);return}path=d.results;
arpModal(d.results)};
/* ---- インターフェース設定 ---- */
function renderIf(){const phys=conf.interfaces.filter(i=>i.type!=='vlan'),vl=conf.interfaces.filter(i=>i.type==='vlan');
const order=[];phys.forEach(p=>{order.push([p,false]);vl.filter(v=>v.base_if===p.name).forEach(v=>order.push([v,true]))});vl.filter(v=>!phys.some(p=>p.name===v.base_if)).forEach(v=>order.push([v,true]));
const vrs=['',...conf.vRouters.map(v=>v.name)];
$('vIf').innerHTML=`<h1>インターフェース設定</h1><div style="display:flex;align-items:center"><button class="btn p" id="ifNew">＋ 新規作成</button><span class="sp"></span><span class="mu">${conf.interfaces.length} / 50</span></div>
<table class="tbl" style="margin-top:14px"><thead><tr><th>Link</th><th>インターフェース名</th><th>タイプ</th><th>IPアドレス/CIDR</th><th>VLAN ID</th><th>OSインターフェース</th><th>MACアドレス</th><th>仮想ルーター</th><th></th><th>操作</th></tr></thead><tbody>`+
order.map(([i,sub])=>{const base=sub?conf.interfaces.find(p=>p.name===i.base_if):i;const noos=!base||!base.os_if;
return `<tr class="${sub?'sub':''}"><td title="${noos?'OSインターフェースが未設定です':'OK'}" class="${noos?'wn':'ok'}">${noos?'▲':'●'}</td><td><a data-e="${esc(i.name)}">${esc(i.name)}</a></td><td>${sub?'vlan':'physical'}</td><td>${esc(i.ipaddress)}${i.ip_aliases.length?` <span class="mu">(+${i.ip_aliases.length})</span>`:''}</td><td>${sub?esc(i.vlan_id):''}</td><td>${sub?'<span class="mu">'+esc(base&&base.os_if||'')+'</span>':esc(i.os_if)}</td><td class="mu">自動</td>
<td><select data-vr="${esc(i.name)}">${ifOpts(vrOf(i.name),vrs)}</select></td><td><a data-e="${esc(i.name)}" title="IPエイリアス等の詳細設定" style="text-decoration:none">⚙</a></td><td>${sub?`<button class="btn d" data-del="${esc(i.name)}">削除</button>`:'-'}</td></tr>`}).join('')+`</tbody></table>`;
$('ifNew').onclick=()=>ifModal(null);
document.querySelectorAll('#vIf [data-e]').forEach(a=>a.onclick=()=>ifModal(a.dataset.e));
document.querySelectorAll('#vIf [data-vr]').forEach(sl=>sl.onchange=()=>{const n=sl.dataset.vr;conf.vRouters.forEach(v=>v.if_names=v.if_names.filter(x=>x!==n));const t=conf.vRouters.find(v=>v.name===sl.value);if(t)t.if_names.push(n);mark()});
document.querySelectorAll('#vIf [data-del]').forEach(b=>b.onclick=()=>{const n=b.dataset.del;conf.interfaces=conf.interfaces.filter(i=>i.name!==n);conf.vRouters.forEach(v=>v.if_names=v.if_names.filter(x=>x!==n));mark()})}
function ifModal(name){const isNew=!name;const o=isNew?{type:'',name:'',base_if:'',vlan_id:'',ipaddress:'',ip_aliases:[],os_if:''}:JSON.parse(JSON.stringify(conf.interfaces.find(i=>i.name===name)));
const phys=conf.interfaces.filter(i=>i.type!=='vlan').map(i=>i.name);const devs=((env&&env.devices)||[]).map(d=>d.friendly||d.desc).filter(Boolean);
const draw=()=>{const t=o.type;modal(`<h2>インターフェース${isNew?'追加':'編集'}</h2><div class="fm">
<label>インターフェース名</label><input id="mName" value="${esc(o.name)}" placeholder="空白の場合は自動で生成します" ${!isNew&&t!=='vlan'?'disabled':''}>
<label>タイプ ${isNew?'<u>*</u>':''}</label>${isNew?`<select id="mType"><option value="">選択してください</option><option value="vlan" ${t==='vlan'?'selected':''}>VLAN</option></select>`:`<span>${t==='vlan'?'vlan':'physical'}</span>`}
${t==='vlan'?`<label>Baseインターフェース <u>*</u></label><select id="mBase"><option value=""></option>${ifOpts(o.base_if,phys)}</select><label>VLAN ID <u>*</u></label><input id="mVid" type="number" min="1" max="4094" value="${esc(o.vlan_id)}">`:''}
${t?`<label>IPアドレス/CIDR</label><input id="mIp" value="${esc(o.ipaddress)}" placeholder="例: 10.0.0.1/24">`:''}
${t==='physical'?`<label>OSインターフェース</label><div><input id="mOs" list="osl" value="${esc(o.os_if)}" placeholder="例: イーサネット"><datalist id="osl">${devs.map(d=>`<option value="${esc(d)}">`).join('')}</datalist></div>`:''}
${t?`<label>IPエイリアス<br><span class="mu" style="font-weight:400">1行に1つ (ip/prefix)</span></label><textarea id="mAl" rows="3">${esc(o.ip_aliases.join('\n'))}</textarea>`:''}</div>
<div class="row" style="justify-content:flex-end"><button class="btn p" id="mOk" ${t?'':'disabled'}>${isNew?'追加する':'更新する'}</button><button class="btn" onclick="closeM()">閉じる</button></div>`);
if(isNew)$('mType').onchange=()=>{keep();o.type=$('mType').value;draw()};
$('mOk').onclick=()=>{keep();const err=check();if(err){toast(err);return}save()}};
const keep=()=>{const g=id=>$(id)?$(id).value.trim():undefined;if(g('mName')!==undefined)o.name=g('mName');if(g('mBase')!==undefined)o.base_if=g('mBase');if(g('mVid')!==undefined)o.vlan_id=g('mVid');if(g('mIp')!==undefined)o.ipaddress=g('mIp');if(g('mOs')!==undefined)o.os_if=g('mOs');if($('mAl'))o.ip_aliases=$('mAl').value.split('\n').map(x=>x.trim()).filter(Boolean)};
const check=()=>{if(!o.type)return 'タイプを選択してください';if(o.type==='vlan'){if(!o.base_if)return 'Baseインターフェースを選択してください';const v=+o.vlan_id;if(!(v>=1&&v<=4094))return 'VLAN IDは 1〜4094 で指定してください'}
if(o.ipaddress&&!/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(o.ipaddress))return 'IPアドレスは ip/prefix 形式で入力してください (例: 10.0.0.1/24)';if(o.ip_aliases.some(a=>!/^\d+\.\d+\.\d+\.\d+\/\d+$/.test(a)))return 'IPエイリアスは ip/prefix 形式で入力してください';
if(isNew&&o.name&&conf.interfaces.some(i=>i.name===o.name))return 'インターフェース名が重複しています';if(!isNew&&o.type==='vlan'&&o.name!==name&&conf.interfaces.some(i=>i.name===o.name))return 'インターフェース名が重複しています';return ''};
const save=()=>{if(isNew){if(!o.name){o.name='vlan'+o.vlan_id;let k=2;while(conf.interfaces.some(i=>i.name===o.name))o.name='vlan'+o.vlan_id+'_'+k++}
const e={name:o.name,type:'vlan',ipaddress:o.ipaddress,vlan_id:String(o.vlan_id),base_if:o.base_if,ip_aliases:o.ip_aliases};const bi=conf.interfaces.findIndex(i=>i.name===o.base_if);let at=bi+1;while(at<conf.interfaces.length&&conf.interfaces[at].type==='vlan')at++;conf.interfaces.splice(at,0,e)}
else{const t=conf.interfaces.find(i=>i.name===name);if(o.type==='vlan'&&o.name&&o.name!==name){conf.vRouters.forEach(v=>v.if_names=v.if_names.map(x=>x===name?o.name:x));t.name=o.name}
t.ipaddress=o.ipaddress;t.ip_aliases=o.ip_aliases;if(o.type==='vlan'){t.base_if=o.base_if;t.vlan_id=String(o.vlan_id)}else t.os_if=o.os_if}
closeM();mark()};draw()}
/* ---- 仮想ルーター設定 ---- */
function renderVr(){const L=conf.vRouters;if(vrSel>=L.length)vrSel=L.length?0:-2;
const v=vrSel>=0?L[vrSel]:null;
let right='';
if(vrSel===-1){right=`<table class="tbl"><thead><tr><th>仮想ルーター</th><th>所属インターフェース</th><th>external</th><th>internal</th></tr></thead><tbody>`+L.map((x,i)=>`<tr><td><a data-s="${i}">${esc(x.name)}</a></td><td>${esc(x.if_names.join(', '))}</td><td>${x.routes.external.length}</td><td>${x.routes.internal.length}</td></tr>`).join('')+`</tbody></table>`}
else if(v){const conn=v.if_names.map(n=>conf.interfaces.find(i=>i.name===n)).filter(i=>i&&i.ipaddress).map(i=>['internal(connected)',{destination:netOf(i.ipaddress),comment:'added by NEEDLEWORK'}]);const rows=[...conn,...v.routes.external.map(r=>['external',r]),...v.routes.internal.map(r=>['internal',r])];
right=`<div style="display:flex;gap:10px;align-items:center;margin-bottom:18px"><span class="mu"><u>仮想ルーターとは？</u></span><span class="sp"></span><button class="btn" id="vEdit">編集</button><button class="btn dd" id="vDel">削除</button></div>
<div style="display:flex;gap:40px;margin-bottom:26px"><div><span class="mu">仮想ルーター名*</span>　<b style="font-weight:500;margin-left:20px">${esc(v.name)}</b></div><div><span class="mu">所属インターフェース</span>　<b style="font-weight:500;margin-left:20px">${esc(v.if_names.join(', '))}</b></div></div>
<div style="display:flex;align-items:center;gap:12px;color:var(--blue2);margin:26px 0 8px"><hr style="flex:1;border:0;border-top:1px solid var(--blue)">Routing Table<hr style="flex:1;border:0;border-top:1px solid var(--blue)"></div>
<table class="tbl"><thead><tr><th>タイプ</th><th>宛先ネットワーク</th><th>ネクストホップ</th><th>コメント</th></tr></thead><tbody>${rows.map(([t,r])=>`<tr><td>${t}</td><td>${esc(r.destination)}</td><td>${esc(r.next_hop||'')}</td><td>${esc(r.comment||'')}</td></tr>`).join('')||'<tr><td colspan="4" class="mu">ルートがありません</td></tr>'}</tbody></table>`}
else right='<div class="mu">仮想ルーターがありません。「仮想ルーターを追加」から作成してください。</div>';
$('vVr').innerHTML=`<div style="display:flex;gap:26px;align-items:flex-start;padding:0"><div class="card vlist" style="width:290px;flex:none;padding:18px"><div class="mu" style="margin-bottom:12px"><b style="color:var(--ink)">仮想ルーター</b>　${L.length} / 50</div><button class="btn p" id="vAdd" style="width:100%">＋ 仮想ルーターを追加</button><button class="btn" id="vList" style="width:100%;margin-top:10px">仮想ルーターリスト</button><hr style="border:0;border-top:1px solid var(--line);margin:16px 0 8px">${L.map((x,i)=>`<a data-s="${i}" class="${i===vrSel?'on':''}">▣ ${esc(x.name)}</a>`).join('')}</div>
<div style="flex:1;min-width:0"><h1 style="margin-bottom:10px">仮想ルーター設定</h1>${right}</div></div>`;
document.querySelectorAll('#vVr [data-s]').forEach(a=>a.onclick=()=>{vrSel=+a.dataset.s;renderVr()});
$('vAdd').onclick=()=>vrModal(null);$('vList').onclick=()=>{vrSel=-1;renderVr()};
if(v){$('vEdit').onclick=()=>vrModal(vrSel);$('vDel').onclick=()=>{conf.vRouters.splice(vrSel,1);vrSel=0;mark()}}}
function vrModal(idx){const v=idx==null?null:conf.vRouters[idx];
vm={tab:0,name:v?v.name:'',ifs:v?[...v.if_names]:[''],routes:v?[...v.routes.external.map(r=>({type:'external',destination:r.destination,next_hop:r.next_hop||'',comment:r.comment||''})),...v.routes.internal.map(r=>({type:'internal',destination:r.destination,next_hop:'',comment:r.comment||''}))]:[{type:'external',destination:'0.0.0.0/0',next_hop:'',comment:''}]};
const draw=()=>{const used=new Set();conf.vRouters.forEach((x,i)=>{if(i!==idx)x.if_names.forEach(n=>used.add(n))});const free=conf.interfaces.map(i=>i.name).filter(n=>!used.has(n));
modal(`<h2 style="margin-bottom:6px">仮想ルーターの設定を${v?'編集':'追加'}</h2><div class="tabs"><div data-t="0" class="${vm.tab===0?'on':''}">全般設定</div><div data-t="1" class="${vm.tab===1?'on':''}">ルート設定</div></div>`+
(vm.tab===0?`<div class="sec">基本設定</div><div class="fm"><label>仮想ルーター名<u>*</u></label><input id="vName" value="${esc(vm.name)}"></div><div class="sec">所属インターフェース</div><div style="font-weight:600;margin:10px 0 4px">インターフェース名</div><div class="mu" style="margin-bottom:8px">* 所属インターフェースのネットワークは設定適用時にルート（internal）に追加されます</div>`+
vm.ifs.map((x,i)=>`<div style="display:flex;gap:10px;margin:6px 0"><select data-i="${i}" style="flex:1;border:1px solid #c9d1da;border-radius:6px;padding:7px"><option value=""></option>${ifOpts(x,free.filter(n=>n===x||!vm.ifs.includes(n)))}</select><button class="mini" data-rm="${i}">−</button></div>`).join('')+`<button class="mini" id="vIfAdd">+</button>`
:`<div class="rt mu" style="font-weight:600"><span>タイプ</span><span>宛先ネットワーク</span><span>ネクストホップ</span><span>コメント</span><span></span></div>`+vm.routes.map((r,i)=>`<div class="rt"><select data-rt="${i}" data-f="type"><option ${r.type==='external'?'selected':''}>external</option><option ${r.type==='internal'?'selected':''}>internal</option></select><input data-rt="${i}" data-f="destination" value="${esc(r.destination)}" placeholder="Ex. 10.0.0.0/24"><input data-rt="${i}" data-f="next_hop" value="${esc(r.next_hop)}" placeholder="Ex. 192.168.1.254" ${r.type==='internal'?'disabled':''}><input data-rt="${i}" data-f="comment" value="${esc(r.comment)}"><button class="mini" data-rr="${i}">−</button></div>`).join('')+`<button class="mini" id="vRtAdd">+</button>`)+
`<div class="row" style="justify-content:flex-end;margin-top:22px"><button class="btn p" id="vOk">${v?'更新する':'追加する'}</button><button class="btn" onclick="closeM()">キャンセル</button></div>`);
document.querySelectorAll('#md .tabs div').forEach(t=>t.onclick=()=>{pull();vm.tab=+t.dataset.t;draw()});
document.querySelectorAll('#md [data-rm]').forEach(b=>b.onclick=()=>{pull();vm.ifs.splice(+b.dataset.rm,1);if(!vm.ifs.length)vm.ifs=[''];draw()});
if($('vIfAdd'))$('vIfAdd').onclick=()=>{pull();vm.ifs.push('');draw()};
document.querySelectorAll('#md [data-rr]').forEach(b=>b.onclick=()=>{pull();vm.routes.splice(+b.dataset.rr,1);draw()});
if($('vRtAdd'))$('vRtAdd').onclick=()=>{pull();vm.routes.push({type:'external',destination:'',next_hop:'',comment:''});draw()};
document.querySelectorAll('#md select[data-f=type]').forEach(s=>s.onchange=()=>{pull();draw()});
$('vOk').onclick=()=>{pull();const n=vm.name.trim();if(!n){toast('仮想ルーター名を入力してください');return}if(conf.vRouters.some((x,i)=>i!==idx&&x.name===n)){toast('仮想ルーター名が重複しています');return}
const nv={name:n,if_names:vm.ifs.filter(Boolean),routes:{internal:[],external:[]}};
for(const r of vm.routes){if(!r.destination.trim())continue;if(r.type==='external')nv.routes.external.push({destination:r.destination.trim(),next_hop:r.next_hop.trim(),comment:r.comment});else nv.routes.internal.push({destination:r.destination.trim(),comment:r.comment})}
if(idx==null){conf.vRouters.push(nv);vrSel=conf.vRouters.length-1}else conf.vRouters[idx]=nv;closeM();mark()}};
const pull=()=>{if($('vName'))vm.name=$('vName').value;document.querySelectorAll('#md select[data-i]').forEach(s=>vm.ifs[+s.dataset.i]=s.value);document.querySelectorAll('#md [data-rt]').forEach(e=>vm.routes[+e.dataset.rt][e.dataset.f]=e.value)};
draw()}

/* ---------- 起動 ---------- */
fetch('/api/env').then(r=>r.json()).then(d=>{env=d;side()});render();setView('test');
</script></body></html>'''
