#!/usr/bin/env python3
"""トラフィックジェネレーター / ポリシーテスト (NEEDLEWORK風)

  python trafficgen.py devices                       # Npcapで見えるNIC一覧 (os_ifに書く名前)
  python trafficgen.py run シナリオ.csv --vrouter 設定.toml [-o 結果.csv]
  python trafficgen.py run ... --sim                 # 実機なし: 疑似FWで自己診断
  python trafficgen.py                               # ブラウザUI (127.0.0.1:8080)
"""
import argparse
import sys
import time

from tgen import engine


def make_links(cfg_path_unused=None):
    from tgen.link import PcapLink, PcapError

    def factory(name, os_if):
        if not os_if:
            raise PcapError("インターフェース %s の os_if が空です。TOMLで os_if を設定してください" % name)
        return PcapLink(os_if)
    return factory


def cmd_devices(a):
    from tgen.link import list_devices
    for d in list_devices():
        print("%-14s %-40s %s" % (d["friendly"] or "-", d["desc"], d["name"]))


def apply_hosts(rows, hosts_args):
    hosts = {}
    for h in hosts_args or []:
        for kv in h.split(","):
            if "=" in kv:
                k, v = kv.split("=", 1)
                hosts[k.strip().lower()] = v.strip()
    if hosts:
        for r in rows:
            for col in ("dst-ip", "src-ip"):
                v = r[col].lower()
                if v in hosts:
                    if col == "dst-ip" and not r["url/domain(option)"]:
                        r["url/domain(option)"] = r[col]
                    r[col] = hosts[v]


def open_stack(rows, cfg, args):
    """スタック(+疑似FW/pcap)を組んで開始する。-> (stack, fw, pcapwriter)"""
    fw = None
    if args.sim:
        from tgen import simdemo
        st, fw = simdemo.build(cfg, rows)
    else:
        st, _ = engine.build_stack(cfg, make_links())
    pw = None
    if getattr(args, "pcap", None):
        pw = engine.PcapWriter(args.pcap)
        st.taps.append(pw)
    st.start()
    return st, fw, pw


def close_stack(st, fw, pw):
    st.stop()
    if fw:
        fw.stop()
    if pw:
        pw.close()


def execute(rows, cfg, args, on_result=None, on_runner=None):
    """スタックを組んで実行して結果を返す (CLI/UIで共用)。-> (runner, seconds)"""
    apply_hosts(rows, getattr(args, "hosts", None))
    st, fw, pw = open_stack(rows, cfg, args)
    try:
        rn = engine.Runner(st, rows, workers=args.workers, timeout=args.timeout, tries=args.tries,
                           lenient=args.lenient, on_result=on_result)
        if on_runner:
            on_runner(rn)
        t0 = time.time()
        rn.run()
        return rn, time.time() - t0
    finally:
        close_stack(st, fw, pw)


def cmd_run(a):
    rows = engine.load_scenarios(a.scenario)
    cfg = engine.load_config(a.vrouter)
    if a.only:
        rows = [r for r in rows if r["protocol"].lower() in a.only.split(",")]
    n = {"done": 0}

    def cb(i, r):
        n["done"] += 1
        if a.verbose or r["judge"] == "NG":
            sys.stderr.write("[%d/%d] %s %s -> %s  %s\n" % (n["done"], len(rows), rows[i]["protocol"],
                             rows[i]["src-ip"], r["status"].upper(), r["detail"]))
    rn, sec = execute(rows, cfg, a, on_result=cb)
    s = rn.summary()
    out = a.output or "result.csv"
    with open(out, "w", encoding="utf-8-sig", newline="") as f:
        f.write(rn.csv_text())
    with open(out + ".detail.csv", "w", encoding="utf-8-sig", newline="") as f:
        f.write(rn.csv_text(extended=True))
    for w in rn.warnings:
        print("[warn]", w)
    print("実行 %d件 %.1f秒: Pass %d / Drop %d / Block %d / Error %d  | 期待どおり %d / 不一致 %d  -> %s" % (
        s["total"], sec, s["pass"], s["drop"], s["block"], s["error"], s["ok"], s["ng"], out))
    return 1 if s["ng"] or s["error"] else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("devices")
    r = sub.add_parser("run")
    r.add_argument("scenario")
    r.add_argument("--vrouter", required=True, help="仮想ルーター設定(TOML)")
    r.add_argument("-o", "--output")
    r.add_argument("--workers", type=int, default=64)
    r.add_argument("--timeout", type=float, default=3.0, help="秒 (シナリオのtimeout列が優先)")
    r.add_argument("--tries", type=int, default=1)
    r.add_argument("--lenient", action="store_true", help="expect が drop/block のとき drop と block を同一視")
    r.add_argument("--hosts", action="append", help="FQDN→IP置換 例: www.example.com=203.0.113.10,a.local=10.0.0.5 (繰り返し可)")
    r.add_argument("--pcap", help="送受信フレームをpcapに保存")
    r.add_argument("--sim", action="store_true", help="疑似FWで実行 (NIC不要)")
    r.add_argument("--only", help="プロトコル絞り込み 例: http,https")
    r.add_argument("-v", "--verbose", action="store_true")
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--no-browser", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "devices":
        return cmd_devices(a)
    if a.cmd == "run":
        return cmd_run(a)
    from tgen import webui
    return webui.serve(getattr(a, "port", 8080), not getattr(a, "no_browser", False))


if __name__ == "__main__":
    sys.exit(main())
