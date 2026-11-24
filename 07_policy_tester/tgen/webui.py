"""ブラウザUI (127.0.0.1:8080)。NEEDLEWORK風: CSVをそのまま表示・編集できるグリッド + 結果表示。標準ライブラリのみ。"""
import argparse
import io
import json
import os
import sys
import threading
import time
import webbrowser
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import engine

LOCK = threading.Lock()
ST = {"state": "idle", "events": [], "runner": None, "total": 0, "done": 0, "error": "",
      "started": 0.0, "finished": 0.0, "warnings": [], "sim": False}

SAMPLE_CSV = """protocol,src-ip,src-port(option),src-nat-ip(option),is-receiver-physical(option),dst-nat-ip(option),dst-nat-port (option),dst-ip,dst-port,url/domain(option),anti-virus(option),timeout(option),try(option),expect,result,ping-traceroute,description
icmp,192.0.2.1,,,,,,198.51.100.1,,,,,,pass,,,sample
tcp,192.0.2.1,,,,,,198.51.100.1,5000,,,,,pass,,,sample
udp,192.0.2.1,,,,,,198.51.100.1,5001,,,,,pass,,,sample
dns,192.0.2.1,,,,,,198.51.100.1,53,www.example.com,,,,pass,,,sample
http,192.0.2.1,,,,,,198.51.100.1,80,www.example.com,,,,pass,,,sample
https,192.0.2.1,,,,,,198.51.100.1,443,www.example.com,,,,pass,,,sample
ftp,192.0.2.1,,,,,,198.51.100.1,21,,,,,pass,,,sample
smtp,192.0.2.1,,,,,,198.51.100.1,25,,,,,pass,,,sample
imap,192.0.2.1,,,,,,198.51.100.1,143,,,,,pass,,,sample
http,192.0.2.1,,,,,,198.51.100.1,80,,eicar,,,block,,,AV sample
"""


def _args(o):
    return argparse.Namespace(sim=bool(o.get("sim")), workers=int(o.get("workers") or 64),
                              timeout=float(o.get("timeout") or 3), tries=int(o.get("tries") or 1),
                              lenient=bool(o.get("lenient")), pcap=(o.get("pcap") or None),
                              hosts=[o["hosts"]] if o.get("hosts") else None)


def start_job(body):
    import trafficgen
    with LOCK:
        if ST["state"] == "running":
            return "実行中です"
    try:
        cfg = engine.load_config_text(body.get("toml", ""))
    except Exception as e:
        return "仮想ルーター設定(TOML)の読み込みエラー: %s" % e
    items = body.get("items", [])
    rows = [it["row"] for it in items]
    idxs = [it["idx"] for it in items]
    if not rows:
        return "実行できるシナリオがありません"
    try:
        ns = _args(body.get("options", {}))
    except ValueError as e:
        return "オプションが不正です: %s" % e
    with LOCK:
        ST.update(state="running", events=[], error="", total=len(rows), done=0, started=time.time(),
                  finished=0.0, warnings=[], sim=ns.sim, runner=None)
    threading.Thread(target=_job, args=(trafficgen, rows, idxs, cfg, ns), daemon=True).start()
    return ""


def _job(trafficgen, rows, idxs, cfg, ns):
    def cb(i, r):
        with LOCK:
            ST["done"] += 1
            ST["events"].append(dict(r, idx=idxs[i]))

    def on_runner(rn):
        with LOCK:
            ST["runner"] = rn

    try:
        rn, _ = trafficgen.execute(rows, cfg, ns, on_result=cb, on_runner=on_runner)
        with LOCK:
            ST["warnings"] = rn.warnings
            ST["state"] = "stopped" if rn.stop_flag.is_set() else "done"
    except Exception as e:
        import traceback
        traceback.print_exc()
        with LOCK:
            ST["state"] = "error"
            ST["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        ST["finished"] = time.time()


def status(since):
    with LOCK:
        ev = ST["events"][since:]
        return {"state": ST["state"], "total": ST["total"], "done": ST["done"], "error": ST["error"],
                "elapsed": round((ST["finished"] or time.time()) - ST["started"], 1) if ST["started"] else 0,
                "next": since + len(ev), "events": ev, "warnings": ST["warnings"], "sim": ST["sim"]}


def api_env():
    try:
        from .link import list_devices
        return {"npcap": True, "devices": list_devices(), "error": ""}
    except Exception as e:
        return {"npcap": False, "devices": [], "error": str(e)}


def api_config(body):
    try:
        cfg = engine.load_config_text(body.get("toml", ""))
        vrs = engine.static_vrs(cfg)
    except Exception as e:
        return {"ok": False, "error": "TOMLを読み込めません: %s" % e}
    ifs = cfg.get("interfaces", [])
    return {"ok": True, "conf": cfg, "l2": bool(cfg.get("l2_mode")), "interfaces": len(ifs),
            "vrs": [{"name": v.name, "ifs": [i.name for i in v.ifaces], "nh": [x[2] for x in v.external]} for v in vrs],
            "noos": [i["name"] for i in ifs if i.get("type") != "vlan" and not i.get("os_if") and
                     any(i["name"] in (v.get("if_names") or []) or any(j.get("base_if") == i["name"] and j["name"] in (v.get("if_names") or []) for j in ifs)
                         for v in cfg.get("vRouters", []))]}


def api_tomlgen(body):
    try:
        return {"ok": True, "toml": engine.dump_toml(body.get("conf", {}))}
    except (KeyError, TypeError) as e:
        return {"ok": False, "error": "設定を保存できません: %r" % (e,)}


def api_validate(body):
    try:
        e, w = engine.validate_conf(body.get("conf", {}))
    except Exception as ex:
        return {"errors": ["検証中にエラー: %r" % (ex,)], "warnings": []}
    return {"errors": e, "warnings": w}


def api_annotate(body):
    try:
        cfg = engine.load_config_text(body.get("toml", ""))
    except Exception:
        return {"rows": [{} for _ in body.get("rows", [])]}
    return {"rows": engine.annotate(body.get("rows", []), cfg)}


def api_pathcheck(body):
    import trafficgen
    try:
        cfg = engine.load_config_text(body.get("toml", ""))
        ns = _args(body.get("options", {}))
        rows = [r for r in body.get("rows", []) if r.get("protocol")]
        names = body.get("vrs")
        st, fw, pw = trafficgen.open_stack(rows, cfg, ns)
    except Exception as e:
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
    try:
        return {"ok": True, "results": engine.pathcheck(st, set(names) if names else None)}
    finally:
        trafficgen.close_stack(st, fw, pw)


def api_generate(body):
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if here not in sys.path:
        sys.path.insert(0, here)
    try:
        import scenario_gen
    except ImportError as e:
        return {"ok": False, "error": "scenario_gen.py が見つかりません: %s" % e}
    try:
        r = scenario_gen.run(body.get("text", ""), body.get("opts", {}) or {}, body.get("vendor", "auto"))
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "vendor": r["vendor"], "vdoms": [
        {"name": v["name"], "count": v["count"], "csv": v["csv"], "toml": v["vrouter_toml"],
         "warn_total": len(v["warnings"]),
         "warnings": [(w[0], w[1], w[2][:5]) for w in v["warnings"]][:30]} for v in r["vdoms"]]}


def build_evidence(body):
    ts = time.strftime("%Y%m%d_%H%M%S")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("result.csv", "﻿" + body.get("csv", ""))
        z.writestr("vrouter.toml", body.get("toml", ""))
        det = body.get("details", [])
        if det:
            import csv as _csv
            o = io.StringIO()
            cols = ["no", "result", "judge", "detail", "elapsed_ms", "observed_src", "observed_dst", "cert_issuer", "ssl_inspected"]
            w = _csv.writer(o, lineterminator="\n")
            w.writerow(cols)
            for d in det:
                w.writerow([d.get(c, "") for c in cols])
            z.writestr("result_detail.csv", "﻿" + o.getvalue())
        z.writestr("summary.txt", body.get("summary", ""))
        p = (body.get("options") or {}).get("pcap")
        if p and os.path.isfile(p):
            z.write(p, "capture.pcap")
    return "evidence_%s.zip" % ts, buf.getvalue()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj):
        self._send(200, json.dumps(obj, ensure_ascii=False))

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/":
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if u.path == "/api/status":
            return self._json(status(int(q.get("since", ["0"])[0])))
        if u.path == "/api/env":
            return self._json(api_env())
        if u.path == "/api/sample.csv":
            return self._send(200, "﻿" + SAMPLE_CSV, "text/csv; charset=utf-8",
                              {"Content-Disposition": 'attachment; filename="sample_scenarios.csv"'})
        self._send(404, "not found", "text/plain")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, "{}")
        p = self.path
        try:
            if p == "/api/run":
                err = start_job(body)
                return self._json({"ok": not err, "error": err})
            if p == "/api/stop":
                rn = ST["runner"]
                if rn:
                    rn.stop()
                return self._json({"ok": True})
            if p == "/api/config":
                return self._json(api_config(body))
            if p == "/api/tomlgen":
                return self._json(api_tomlgen(body))
            if p == "/api/validate":
                return self._json(api_validate(body))
            if p == "/api/annotate":
                return self._json(api_annotate(body))
            if p == "/api/pathcheck":
                return self._json(api_pathcheck(body))
            if p == "/api/generate":
                return self._json(api_generate(body))
            if p == "/api/evidence":
                name, data = build_evidence(body)
                return self._send(200, data, "application/zip", {"Content-Disposition": 'attachment; filename="%s"' % name,
                                                                 "X-Filename": name})
        except Exception as e:
            import traceback
            traceback.print_exc()
            return self._json({"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
        self._send(404, "{}")


def serve(port=8080, open_browser=True):
    srv = None
    for p in range(port, port + 20):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), H)
            break
        except OSError:
            continue
    if srv is None:
        raise SystemExit("ポートを確保できません")
    url = "http://127.0.0.1:%d/" % srv.server_address[1]
    print("ポリシーテスト UI: %s  (Ctrl+Cで終了)" % url)
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


from .webpage import PAGE  # noqa: E402
