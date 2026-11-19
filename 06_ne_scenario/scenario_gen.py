#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scenario_gen.py - FortiGate / Palo Alto コンフィグ -> NEEDLEWORKシナリオCSV

  python scenario_gen.py                      # ブラウザUIを起動 (http://127.0.0.1:8765)
  python scenario_gen.py config.conf -o out.csv [--vendor auto|fortigate|palo] [--negative]

必要なもの: Python 3.8+ (標準ライブラリのみ)。 同じフォルダに fg2scenario.py / palo2scenario.py
"""
from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import os
import re
import sys
import zipfile
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import fg2scenario as fg
import palo2scenario as palo
import vrouter_gen as vg

DEFAULTS = dict(max_addr=3, max_port=3, max_svc=6, max_per_policy=0, negative=False,
                deny_as="drop", any_src="192.0.2.1", any_dst="198.51.100.1",
                include_disabled=True, disabled_mode="actual")


def detect_vendor(text: str) -> str:
    if text.lstrip().startswith("<"):
        return "palo"
    if "config firewall policy" in text:
        return "fortigate"
    if "rulebase security rules" in text:
        return "palo"
    return ""


def parse_pairs(text: str, kind: str) -> dict:
    """UI/CLI用: 1行1件の 'キー=値' を辞書に。kind=map なら 'tcp/8080=http' を ((l4,port)->app) に"""
    out: dict = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"書式が不正です: {line}")
        k, v = (x.strip() for x in line.split("=", 1))
        if kind == "map":
            try:
                l4, port = k.split("/", 1)
                out[(l4.lower(), int(port))] = v.lower()
            except ValueError:
                raise ValueError(f"アプリ層指定の書式が不正です: {line} (例: tcp/8080=http)")
        else:
            out[k] = v
    return out


def make_args(opts: dict) -> SimpleNamespace:
    a = dict(DEFAULTS)
    for k, default in DEFAULTS.items():
        v = opts.get(k)
        if v in (None, ""):
            continue
        a[k] = type(default)(v) if not isinstance(default, bool) else bool(v)
    a["map"] = parse_pairs(opts.get("map", ""), "map")
    a["fqdn_map"] = parse_pairs(opts.get("fqdn_map", ""), "fqdn")
    return SimpleNamespace(**a)


def to_csv(cols: list, dicts: list) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, lineterminator="\r\n")
    w.writeheader()
    w.writerows(dicts)
    return buf.getvalue()


def safe_name(name: str) -> str:
    return re.sub(r"[^\w.\-]", "_", name)


def suffix(vdom: str) -> str:
    return f"_{safe_name(vdom)}" if vdom else ""


def run(text: str, opts: dict, vendor: str = "auto") -> dict:
    """vdomごとに、シナリオCSV・詳細CSV・仮想ルーター設定(.toml)を作る。
    vdomなしのコンフィグ (およびPalo) は、vdom名 "" の1件になる。"""
    if vendor in ("", "auto", None):
        vendor = detect_vendor(text)
    if vendor not in ("fortigate", "palo"):
        raise ValueError("ベンダーを判定できませんでした。FortiGate(config firewall policy…)か "
                         "Palo Alto(XMLまたはset形式)のコンフィグか確認してください。")
    args = make_args(opts)
    root = fg.parse_config(text) if vendor == "fortigate" else None
    names: list = (fg.vdom_names(root) if root is not None else []) or [None]
    want = [x.strip() for x in str(opts.get("vdoms") or "").replace(",", "\n").splitlines() if x.strip()]
    if want and names != [None]:
        names = [n for n in names if n in want]
        if not names:
            raise ValueError(f"指定したvdomが見つかりません: {', '.join(want)}")
    os_ifs = [x.strip() for x in str(opts.get("os_if") or "").split(",") if x.strip()] or None
    vdoms: list = []
    for vd in names:
        rs = fg.Resolver(root, args, vd) if vendor == "fortigate" else palo.PaloResolver(text, args)
        policies = rs.build_policies()
        rows = fg.generate(rs, policies, args)
        vr_toml, vr_warn = "", []
        if vendor == "fortigate":  # 仮想ルーター設定(.toml)。Paloは未対応
            vr_toml, w, _ = vg.build_fortigate(
                root, policies,
                if_map=parse_pairs(opts.get("tester_if", ""), "kv"),
                tester_ips=parse_pairs(opts.get("tester_ip", ""), "kv"),
                vr_names=parse_pairs(opts.get("vr_name", ""), "kv"), vdom=vd, os_ifs=os_ifs,
                any_src=args.any_src, any_dst=args.any_dst, with_internal=not opts.get("no_internal"))
            vr_warn = [("[仮想ルーター] " + m, n, w.pols.get(m, [])) for m, n in w.items()]
        vdoms.append({
            "name": vd or "",
            "policies": len(policies),
            "count": len(rows),
            "csv": to_csv(fg.NW_COLUMNS, [r["nw"] for r in rows]),
            "detail_csv": to_csv(fg.DETAIL_COLUMNS, [r["detail"] for r in rows]),
            "vrouter_toml": vr_toml,
            # (メッセージ, 件数, 該当ポリシー名のリスト)
            "warnings": [(m, n, rs.warn_pols.get(m, [])) for m, n in rs.warnings.items()]
                        + vr_warn,
            "skipped": [list(x) for x in rs.skipped],
            "preview": [r["nw"] for r in rows[:300]],
        })
    buf = io.BytesIO()  # UI用: 全vdom分をまとめたZIP
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for v in vdoms:
            sf = suffix(v["name"])
            z.writestr(f"scenario{sf}.csv", v["csv"].encode("utf-8"))
            z.writestr(f"scenario{sf}.detail.csv", ("\ufeff" + v["detail_csv"]).encode("utf-8"))
            if v["vrouter_toml"]:
                z.writestr(f"vrouter{sf}.toml", v["vrouter_toml"].encode("utf-8"))
    return {
        "vendor": vendor,
        "multi": names != [None],
        "policies": sum(v["policies"] for v in vdoms),
        "count": sum(v["count"] for v in vdoms),
        "vdoms": vdoms,
        "zip_b64": base64.b64encode(buf.getvalue()).decode("ascii"),
    }


def read_text(path: str) -> str:
    raw = open(path, "rb").read()
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("cp932", errors="replace")


# ---------------------------------------------------------------------------
# ブラウザUI
# ---------------------------------------------------------------------------
HTML = r"""<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><title>シナリオ生成ツール</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{--bg:#f4f5f7;--card:#fff;--tx:#1f2933;--mut:#6b7785;--ac:#0aa6d6;--bd:#d9dee4;--ok:#1b9a5a;--dr:#e8742c;--bl:#d6452f}
@media (prefers-color-scheme:dark){:root{--bg:#161a1f;--card:#1f252c;--tx:#e6eaee;--mut:#97a3b0;--bd:#33404d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 system-ui,"Hiragino Sans","Yu Gothic UI",sans-serif}
header{background:#24383f;color:#fff;padding:12px 24px;font-weight:600}
main{max-width:1200px;margin:0 auto;padding:20px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:16px;margin-bottom:16px}
h2{margin:0 0 12px;font-size:15px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px}
label{display:block;font-size:12px;color:var(--mut);margin-bottom:2px}
input,select,textarea{width:100%;padding:6px 8px;border:1px solid var(--bd);border-radius:5px;background:var(--card);color:var(--tx);font:inherit}
textarea{min-height:64px;font-family:ui-monospace,Consolas,monospace;font-size:12px}
button{background:var(--ac);color:#fff;border:0;border-radius:5px;padding:8px 16px;font:inherit;font-weight:600;cursor:pointer}
button.sec{background:transparent;color:var(--ac);border:1px solid var(--ac)}button:disabled{opacity:.5;cursor:default}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.drop{border:2px dashed var(--bd);border-radius:8px;padding:22px;text-align:center;color:var(--mut)}.drop.on{border-color:var(--ac)}
.tbl{overflow:auto;max-height:480px;border:1px solid var(--bd);border-radius:6px}
table{border-collapse:collapse;width:100%;font-size:12px}th,td{padding:5px 8px;border-bottom:1px solid var(--bd);text-align:left;white-space:nowrap}
th{position:sticky;top:0;background:var(--card)}td.d{white-space:normal;min-width:320px;color:var(--mut)}
.pass{color:var(--ok);font-weight:600}.drop_{color:var(--dr);font-weight:600}.block{color:var(--bl);font-weight:600}
.warn{color:var(--dr)}.pol{color:var(--mut);font-size:12px;word-break:break-all}.err{color:var(--bl);font-weight:600}small{color:var(--mut)}ul{margin:6px 0 0 18px;padding:0}
</style></head><body>
<header>シナリオ生成ツール　FortiGate / Palo Alto → NEEDLEWORK CSV</header>
<main>
<div class="card"><h2>1. コンフィグを読み込む</h2>
 <div class="drop" id="drop">ここにコンフィグファイルをドロップ、または <input type="file" id="file" style="width:auto"><div id="fname"><small>FortiGate(.conf) / Palo Alto(XML または set形式)</small></div></div>
</div>
<div class="card"><h2>2. オプション</h2>
 <div class="grid">
  <div><label>ベンダー</label><select id="vendor"><option value="auto">自動判定</option><option value="fortigate">FortiGate</option><option value="palo">Palo Alto</option></select></div>
  <div><label>サブネット/範囲1つあたりの代表IP数</label><input id="max_addr" type="number" min="1" value="3"></div>
  <div><label>ポート範囲の代表ポート数</label><input id="max_port" type="number" min="1" value="3"></div>
  <div><label>ポリシーあたり最大シナリオ数 (0=無制限)</label><input id="max_per_policy" type="number" min="0" value="0"></div>
  <div><label>denyのexpect値</label><select id="deny_as"><option>drop</option><option>block</option></select></div>
  <div><label>allのときの送信元IP</label><input id="any_src" value="192.0.2.1"></div>
  <div><label>allのときの宛先IP</label><input id="any_dst" value="198.51.100.1"></div>
  <div><label>&nbsp;</label><label style="color:var(--tx);font-size:14px"><input id="negative" type="checkbox" style="width:auto"> 境界の拒否テストも生成</label></div>
  <div><label>&nbsp;</label><label style="color:var(--tx);font-size:14px"><input id="include_disabled" type="checkbox" style="width:auto" checked> 無効(disable)のポリシーも生成</label></div>
  <div><label>無効ポリシーのexpect</label><select id="disabled_mode"><option value="actual">実際の動作(マッチしない)</option><option value="policy">enable扱い(actionどおり)</option></select></div>
 </div>
 <div class="grid" style="margin-top:12px;grid-template-columns:1fr 1fr">
  <div><label>アプリ層の指定 (1行1件: tcp/8080=http)</label><textarea id="map"></textarea></div>
  <div><label>FQDNのIP指定 (1行1件: www.example.com=203.0.113.10)</label><textarea id="fqdn_map"></textarea></div>
 </div>
</div>
<div class="card"><div class="row"><button id="go" disabled>シナリオを生成</button>
 <select id="vdsel" style="width:auto" hidden></select>
 <button id="dl" class="sec" disabled>CSVをダウンロード</button><button id="dl2" class="sec" disabled>詳細CSV(追跡用)</button><button id="dl3" class="sec" disabled>仮想ルーター設定(.toml)</button>
 <button id="dlzip" class="sec" hidden>全vdomをZIPでダウンロード</button>
 <span id="msg"></span></div><div id="info"></div></div>
<div class="card" id="prev" hidden><h2>プレビュー <small id="pn"></small></h2><div class="tbl"><table><thead><tr>
 <th>protocol</th><th>src-ip</th><th>dst-ip</th><th>dst-port</th><th>url/domain</th><th>dst-nat</th><th>expect</th><th>description</th></tr></thead><tbody id="tb"></tbody></table></div></div>
</main>
<script>
const $=id=>document.getElementById(id);let text="",base="scenario",last=null;
function setFile(f){if(!f)return;base=f.name.replace(/\.[^.]+$/,"");$("fname").textContent=f.name;
 const r=new FileReader();r.onload=()=>{text=r.result;$("go").disabled=false};r.readAsText(f)}
$("file").onchange=e=>setFile(e.target.files[0]);
const dz=$("drop");dz.ondragover=e=>{e.preventDefault();dz.classList.add("on")};dz.ondragleave=()=>dz.classList.remove("on");
dz.ondrop=e=>{e.preventDefault();dz.classList.remove("on");setFile(e.dataTransfer.files[0])};
function dl(name,t,type){const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([t],{type:type||"text/csv;charset=utf-8"}));a.download=name;a.click()}
function suf(v){return v.name?"_"+v.name.replace(/[^\w.\-]/g,"_"):""}
let cur=null;
$("dl").onclick=()=>dl(base+suf(cur)+"_scenario.csv",cur.csv);
$("dl2").onclick=()=>dl(base+suf(cur)+"_scenario.detail.csv","﻿"+cur.detail_csv);
$("dl3").onclick=()=>dl(base+suf(cur)+"_vrouter.toml",cur.vrouter_toml,"text/plain;charset=utf-8");
$("dlzip").onclick=()=>{const b=atob(last.zip_b64),u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);dl(base+"_scenarios.zip",u,"application/zip")};
function el(t,c,x){const e=document.createElement(t);if(c)e.className=c;if(x!==undefined)e.textContent=x;return e}
function show(i){
 cur=last.vdoms[i];const info=$("info");info.textContent="";
 $("dl").disabled=$("dl2").disabled=false;$("dl3").disabled=!cur.vrouter_toml;
 if(cur.skipped.length){const d=el("div","warn","スキップしたポリシー");const u=el("ul");cur.skipped.forEach(s=>u.append(el("li","",`${s[0]}: ${s[1]}`)));d.append(u);info.append(d)}
 if(cur.warnings.length){const d=el("div","warn","警告");const u=el("ul");cur.warnings.forEach(w=>{const li=el("li","",`${w[0]} (×${w[1]})`);const p=w[2]||[];if(p.length){li.append(el("div","pol",`ポリシー(${p.length}件): `+p.slice(0,50).join(", ")+(p.length>50?` …他${p.length-50}件`:"")))}u.append(li)});d.append(u);info.append(d)}
 const tb=$("tb");tb.textContent="";
 cur.preview.forEach(r=>{const tr=el("tr");
  [r["protocol"],r["src-ip"],r["dst-ip"],r["dst-port"],r["url/domain(option)"],[r["dst-nat-ip(option)"],r["dst-nat-port (option)"]].filter(Boolean).join(":")].forEach(v=>tr.append(el("td","",v)));
  tr.append(el("td",r.expect==="pass"?"pass":r.expect==="block"?"block":"drop_",r.expect));tr.append(el("td","d",r.description));tb.append(tr)});
 $("prev").hidden=false;$("pn").textContent=cur.count>cur.preview.length?`(先頭${cur.preview.length}件を表示。CSVには全${cur.count}件)`:""}
$("vdsel").onchange=()=>show(+$("vdsel").value);
$("go").onclick=async()=>{
 const o={};for(const k of ["max_addr","max_port","max_per_policy","deny_as","any_src","any_dst","map","fqdn_map"])o[k]=$(k).value;o.negative=$("negative").checked;o.include_disabled=$("include_disabled").checked;o.disabled_mode=$("disabled_mode").value;
 $("msg").textContent="生成中…";$("msg").className="";
 let res;try{res=await (await fetch("/api/generate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text,vendor:$("vendor").value,options:o})})).json()}catch(e){res={ok:false,error:String(e)}}
 if(!res.ok){$("msg").textContent=res.error;$("msg").className="err";return}
 last=res;const sel=$("vdsel");sel.textContent="";
 res.vdoms.forEach((v,i)=>{const op=el("option","",`${v.name||"(vdomなし)"}: ${v.count}件`);op.value=i;sel.append(op)});
 sel.hidden=$("dlzip").hidden=!res.multi;
 $("msg").textContent=`${res.vendor==="palo"?"Palo Alto":"FortiGate"}: ${res.multi?`vdom ${res.vdoms.length}個 / `:""}ポリシー ${res.policies}件 → シナリオ ${res.count}件`;
 show(0)};
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, HTML.encode("utf-8"), "text/html; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if self.path != "/api/generate":
            return self._send(404, b"not found", "text/plain")
        try:
            n = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(n).decode("utf-8"))
            res = run(data.get("text", ""), data.get("options", {}), data.get("vendor", "auto"))
            res["ok"] = True
        except Exception as ex:  # UIにそのまま表示する
            res = {"ok": False, "error": f"{type(ex).__name__}: {ex}"}
        self._send(200, json.dumps(res, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")


def serve(port: int, open_browser: bool):
    srv = None
    for p in range(port, port + 20):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), Handler)
            break
        except OSError:
            continue
    if srv is None:
        sys.exit("使用可能なポートが見つかりません")
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    print(f"シナリオ生成ツールを起動しました: {url}  (終了: Ctrl+C)")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="FortiGate/Palo Altoコンフィグからシナリオ CSV を生成")
    ap.add_argument("config", nargs="?", help="コンフィグファイル (省略するとブラウザUIを起動)")
    ap.add_argument("-o", "--output", default="scenarios.csv")
    ap.add_argument("--vendor", default="auto", choices=["auto", "fortigate", "palo"])
    ap.add_argument("--max-addr", type=int)
    ap.add_argument("--max-port", type=int)
    ap.add_argument("--max-svc", type=int)
    ap.add_argument("--max-per-policy", type=int)
    ap.add_argument("--map", action="append", default=[], help="例: tcp/8080=http")
    ap.add_argument("--fqdn-map", action="append", default=[], help="例: www.example.com=203.0.113.10")
    ap.add_argument("--negative", action="store_true", help="許可の境界(隣のポート/IP)の拒否テストも生成")
    ap.add_argument("--deny-as", choices=["drop", "block"])
    ap.add_argument("--any-src")
    ap.add_argument("--any-dst")
    ap.add_argument("--exclude-disabled", action="store_true", help="無効(disable)のポリシーを生成対象から外す")
    ap.add_argument("--disabled-expect", choices=["actual", "policy"], default="actual",
                    help="無効ポリシーのexpect: actual=マッチしない前提(既定) / policy=enable扱い")
    ap.add_argument("--vrouter", metavar="FILE", help="仮想ルーター設定(.toml)も出力 (FortiGateのみ)")
    ap.add_argument("--tester-if", action="append", default=[], help="FG親IF=テスターIF 例: port1=eth0/2")
    ap.add_argument("--tester-ip", action="append", default=[], help="FGのIF名=テスター側IP 例: wan2=10.20.28.5")
    ap.add_argument("--vr-name", action="append", default=[], help="FGのIF名=仮想ルーター名 例: wan2=default")
    ap.add_argument("--no-internal", action="store_true", help="仮想ルーターのinternalルートを書かない")
    ap.add_argument("--os-if", default="", help="OSインターフェース名をeth0/1から順にカンマ区切りで指定 "
                    "(既定: イーサネット,イーサネット 2,イーサネット 3,...)")
    ap.add_argument("--vdom", action="append", default=[], help="対象vdom (複数指定可。省略すると全vdom)")
    ap.add_argument("--detail", action="store_true", help="追跡用の詳細CSV (<output>.detail.csv) も出力")
    ap.add_argument("--port", type=int, default=8765, help="UIのポート")
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()

    if not a.config:
        return serve(a.port, not a.no_browser)

    opts = {k: getattr(a, k) for k in ("max_addr", "max_port", "max_svc", "max_per_policy", "deny_as",
                                       "any_src", "any_dst")}
    opts["negative"] = a.negative
    opts["include_disabled"] = not a.exclude_disabled
    opts["disabled_mode"] = a.disabled_expect
    opts["tester_if"] = "\n".join(a.tester_if)
    opts["tester_ip"] = "\n".join(a.tester_ip)
    opts["vr_name"] = "\n".join(a.vr_name)
    opts["os_if"] = a.os_if
    opts["no_internal"] = a.no_internal
    opts["vdoms"] = "\n".join(a.vdom)
    opts["map"] = "\n".join(a.map)
    opts["fqdn_map"] = "\n".join(a.fqdn_map)
    try:
        res = run(read_text(a.config), opts, a.vendor)
    except Exception as ex:
        sys.exit(f"エラー: {ex}")

    def with_suffix(path: str, vd: str) -> str:  # out.csv -> out_<vdom>.csv (vdomなしは変えない)
        stem, ext = os.path.splitext(path)
        return f"{stem}{suffix(vd)}{ext}"

    for v in res["vdoms"]:
        out = with_suffix(a.output, v["name"])
        with open(out, "w", newline="", encoding="utf-8") as f:
            f.write(v["csv"])
        if a.detail:
            with open(out + ".detail.csv", "w", newline="", encoding="utf-8-sig") as f:
                f.write(v["detail_csv"])
        if a.vrouter:
            if v["vrouter_toml"]:
                vr = with_suffix(a.vrouter, v["name"])
                with open(vr, "w", newline="", encoding="utf-8") as f:
                    f.write(v["vrouter_toml"])
                print(f"  仮想ルーター設定 -> {vr}", file=sys.stderr)
            else:
                print("  [warn] 仮想ルーター設定はFortiGateのみ対応です", file=sys.stderr)
        tag = f"[{res['vendor']}" + (f" vdom:{v['name']}" if v["name"] else "") + "]"
        print(f"{tag} ポリシー {v['policies']}件 -> シナリオ {v['count']}件 -> {out}", file=sys.stderr)
        for pid, reason in v["skipped"]:
            print(f"  [skip] {pid}: {reason}", file=sys.stderr)
        for msg, n, pols in v["warnings"]:
            more = f" …他{len(pols) - 20}件" if len(pols) > 20 else ""
            who = f"  ポリシー: {', '.join(pols[:20])}{more}" if pols else ""
            print(f"  [warn] {msg} (x{n}){who}", file=sys.stderr)

if __name__ == "__main__":
    main()
