"""シナリオCSV / 仮想ルーターTOML の読み込み、スタック構築、シナリオ実行(並列)、結果出力。"""
import csv
import io
import ipaddress
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import apps
from .stack import Iface, Stack, VR, _net

NW_COLUMNS = ["protocol", "src-ip", "src-port(option)", "src-nat-ip(option)",
              "is-receiver-physical(option)", "dst-nat-ip(option)", "dst-nat-port (option)",
              "dst-ip", "dst-port", "url/domain(option)", "anti-virus(option)",
              "timeout(option)", "try(option)", "expect", "result", "ping-traceroute", "description"]
EXTRA_COLUMNS = ["no", "judge", "detail", "elapsed_ms", "observed_src", "observed_dst", "cert_issuer", "ssl_inspected"]
FALSE_WORDS = {"", "0", "false", "no", "off", "-", "none", "disable", "disabled"}


# ---------------------------------------------------------------- 読み込み
def _decode(b: bytes) -> str:
    for enc in ("utf-8-sig", "cp932"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            pass
    return b.decode("utf-8", "replace")


def load_scenarios_text(text: str):
    rd = csv.reader(io.StringIO(text))
    rows = list(rd)
    if not rows:
        return []
    head = [h.strip() for h in rows[0]]
    idx = {h: i for i, h in enumerate(head)}
    out = []
    for r in rows[1:]:
        if not any(x.strip() for x in r):
            continue
        d = {c: (r[idx[c]].strip() if c in idx and idx[c] < len(r) else "") for c in NW_COLUMNS}
        # 列名ゆれ (例: "dst-nat-port (option)" / "dst-nat-port(option)")
        if not d["dst-nat-port (option)"] and "dst-nat-port(option)" in idx and idx["dst-nat-port(option)"] < len(r):
            d["dst-nat-port (option)"] = r[idx["dst-nat-port(option)"]].strip()
        if d["protocol"]:
            out.append(d)
    return out


def load_scenarios(path):
    with open(path, "rb") as f:
        return load_scenarios_text(_decode(f.read()))


def load_config_text(text: str):
    try:
        import tomllib
    except ImportError:          # Python 3.10以下
        from . import minitoml as tomllib
    return tomllib.loads(text)


def load_config(path):
    with open(path, "rb") as f:
        return load_config_text(_decode(f.read()))


def _alias_list(v):
    out = []
    for a in v or []:
        if isinstance(a, dict):
            a = a.get("ipaddress") or a.get("ip") or a.get("address") or ""
        if a:
            out.append(str(a))
    return out


def build_stack(cfg, link_factory, only_used=True):
    """TOML設定 → Stack。link_factory(name, os_if) -> Link。-> (stack, info)"""
    st = Stack()
    vrs_cfg = cfg.get("vRouters", []) or []
    used = {n for v in vrs_cfg for n in v.get("if_names", [])}
    ifs = {i["name"]: i for i in cfg.get("interfaces", [])}
    phys_links = {}
    ifaces = {}
    n = 0

    def link_of(pname):
        if pname not in phys_links:
            pi = ifs.get(pname)
            if pi is None:
                raise ValueError("base_if '%s' が interfaces にありません" % pname)
            phys_links[pname] = link_factory(pname, pi.get("os_if", ""))
        return phys_links[pname]

    for name in [i["name"] for i in cfg.get("interfaces", [])]:
        i = ifs[name]
        if only_used and name not in used:
            continue
        ips = [x for x in [i.get("ipaddress", "")] if x] + _alias_list(i.get("ip_aliases"))
        n += 1
        mac = bytes([0x02, 0x54, 0x47, 0x00, n >> 8, n & 255])
        if i.get("type") == "vlan":
            ifc = Iface(name, link_of(i["base_if"]), int(i.get("vlan_id") or 0), ips, mac)
        else:
            ifc = Iface(name, link_of(name), 0, ips, mac)
        ifaces[name] = ifc
        st.add_iface(ifc)
    for v in vrs_cfg:
        vr = VR(v["name"])
        vr.ifaces = [ifaces[x] for x in v.get("if_names", []) if x in ifaces]
        routes = v.get("routes", {}) or {}
        for r in routes.get("internal", []) or []:
            vr.internal.append(_net(r["destination"]))
        for r in routes.get("external", []) or []:
            net, mask = _net(r["destination"])
            vr.external.append((net, mask, r["next_hop"]))
        st.add_vr(vr)
    return st, {"interfaces": ifaces, "links": phys_links}


# ---------------------------------------------------------------- シナリオ正規化
def norm_scenario(d, defaults):
    app = d["protocol"].strip().lower()
    sc = {"app": app, "src": d["src-ip"], "dst": d["dst-ip"], "raw": d}
    port = d["dst-port"]
    sc["dport"] = int(port) if port.isdigit() else apps.DEFAULT_PORT.get(app, 0)
    sc["nat_ip"] = d["dst-nat-ip(option)"]
    sc["nat_port"] = int(d["dst-nat-port (option)"]) if d["dst-nat-port (option)"].isdigit() else 0
    sc["snat_ip"] = d["src-nat-ip(option)"]
    sc["sport"] = int(d["src-port(option)"]) if d["src-port(option)"].isdigit() else 0
    sc["real"] = d["is-receiver-physical(option)"].lower() not in FALSE_WORDS
    sc["url"] = d["url/domain(option)"]
    sc["av"] = d["anti-virus(option)"].lower() not in FALSE_WORDS
    t = d["timeout(option)"]
    try:
        sc["timeout"] = float(t) if t else defaults.get("timeout", 3.0)
    except ValueError:
        sc["timeout"] = defaults.get("timeout", 3.0)
    t = d["try(option)"]
    sc["tries"] = int(t) if t.isdigit() and int(t) > 0 else defaults.get("tries", 1)
    e = d["expect"].strip().lower()
    sc["expect"] = {"accept": "pass", "allow": "pass", "deny": "drop"}.get(e, e)
    return sc


def _isip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


class Runner:
    def __init__(self, stack, rows, workers=64, timeout=3.0, tries=1, lenient=False, on_result=None):
        self.stack = stack
        self.defaults = {"timeout": timeout, "tries": tries}
        self.scs = [norm_scenario(r, self.defaults) for r in rows]
        self.workers = workers
        self.lenient = lenient
        self.obs = apps.Observer()
        self.on_result = on_result
        self.results = [None] * len(self.scs)
        self.stop_flag = threading.Event()
        self.t0 = 0.0
        self.warnings = []

    # ---- 受信側サーバーの登録
    def _register(self):
        reg = {}
        for sc in self.scs:
            if sc["real"] or sc["app"] == "icmp" or sc["app"] not in apps.CLIENTS:
                continue
            ip = sc["nat_ip"] or sc["dst"]
            port = sc["nat_port"] or sc["dport"]
            if not _isip(ip):
                continue
            k = (ip, port, "udp" if sc["app"] in apps.UDP_APPS else "tcp")
            old = reg.get(k)
            if old is None or old == "tcp" and sc["app"] != "tcp":
                reg[k] = sc["app"]
            elif old != sc["app"] and sc["app"] != "tcp":
                self.warnings.append("%s:%d で %s と %s が衝突 (%s を使用)" % (ip, port, old, sc["app"], old))
        for (ip, port, _), app in reg.items():
            apps.register_server(self.stack, self.obs, app, ip, port)

    # ---- 1件実行
    def _one(self, i):
        sc = self.scs[i]
        t_start = time.monotonic()
        app = sc["app"]
        res = None
        def E(code, msg):
            return apps.Result("error", msg, err=apps.make_err(code, {"msg": msg}, msg))
        if app not in apps.CLIENTS:
            res = E("unsupported", "プロトコル: %s" % app)
        elif not _isip(sc["src"]):
            res = E("invalidIp", "送信元IP: %r" % sc["src"])
        elif not _isip(sc["dst"]):
            res = E("invalidIp", "宛先IP: %r (FQDNはFQDN→IP指定で置換してください)" % sc["dst"])
        elif app not in ("icmp",) and not sc["dport"]:
            res = E("noPort", "プロトコル %s" % app)
        else:
            exp = sc["expect"] or "pass"
            for _ in range(sc["tries"]):
                if self.stop_flag.is_set():
                    res = apps.Result("error", "中止されました", err=apps.make_err("stopped", {}))
                    break
                res = apps.CLIENTS[app](self.stack, sc["src"], sc["dst"], sc["dport"], sc)
                if res.status == exp:
                    break
        elapsed = int((time.monotonic() - t_start) * 1000)
        err = res.extra.get("err")
        out = {"no": i + 1, "status": res.status, "detail": res.detail, "elapsed_ms": elapsed,
               "result_text": err["text"] if err else res.status, "err": err,
               "observed_src": "", "observed_dst": "",
               "cert_issuer": res.extra.get("cert_issuer", ""),
               "ssl_inspected": "yes" if res.extra.get("ssl_inspected") else ""}
        # NAT検証 (受信側で観測した値)
        nat_note = ""
        if res.status == "pass" and not sc["real"] and app != "icmp":
            ip = sc["nat_ip"] or sc["dst"]
            port = sc["nat_port"] or sc["dport"]
            o = self.obs.find("udp" if app in apps.UDP_APPS else "tcp", ip, port, t_start - 0.001, sc["sport"] or None)
            if o:
                out["observed_src"], out["observed_dst"] = o["rip"], "%s:%d" % (o["lip"], o["lport"])
                if sc["snat_ip"] and o["rip"] != sc["snat_ip"]:
                    nat_note = "送信元NG: 受信側で観測=%s / 期待(src-nat-ip)=%s" % (o["rip"], sc["snat_ip"])
        exp = sc["expect"]
        ok = (res.status == exp) or (self.lenient and {res.status, exp} <= {"drop", "block"})
        if nat_note:
            ok = False
            out["detail"] += " / " + nat_note
        out["judge"] = "" if not exp else ("OK" if ok else "NG")
        self.results[i] = out
        if self.on_result:
            self.on_result(i, out)
        return out

    def run(self):
        self.t0 = time.monotonic()
        self._register()
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            list(ex.map(self._one, range(len(self.scs))))
        return self.results

    def stop(self):
        self.stop_flag.set()

    def summary(self):
        s = {"total": len(self.scs), "pass": 0, "drop": 0, "block": 0, "error": 0, "ok": 0, "ng": 0}
        for r in self.results:
            if r:
                s[r["status"]] += 1
                if r["judge"] == "OK":
                    s["ok"] += 1
                elif r["judge"] == "NG":
                    s["ng"] += 1
        return s

    # ---- 出力
    def csv_text(self, extended=False):
        buf = io.StringIO()
        cols = NW_COLUMNS + (EXTRA_COLUMNS if extended else [])
        w = csv.DictWriter(buf, fieldnames=cols, lineterminator="\n")
        w.writeheader()
        for sc, r in zip(self.scs, self.results):
            row = dict(sc["raw"])
            if r:
                row["result"] = r["result_text"]
                if extended:
                    row.update({k: r[k] for k in EXTRA_COLUMNS})
            w.writerow({c: row.get(c, "") for c in cols})
        return buf.getvalue()


# ---------------------------------------------------------------- pcap 書き出し (証跡)
class PcapWriter:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.lock = threading.Lock()
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def __call__(self, direction, iface, frame):
        t = time.time()
        with self.lock:
            self.f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(frame), len(frame)) + frame)

    def close(self):
        with self.lock:
            self.f.close()


# ---------------------------------------------------------------- 静的解析 (UIの 送信元VR / ネクストホップ 表示用)
def static_vrs(cfg):
    ifs = {i["name"]: i for i in cfg.get("interfaces", [])}
    vrs = []
    for v in cfg.get("vRouters", []) or []:
        vr = VR(v["name"])
        for n in v.get("if_names", []):
            i = ifs.get(n)
            if not i:
                continue
            ips = [x for x in [i.get("ipaddress", "")] if x] + _alias_list(i.get("ip_aliases"))
            vr.ifaces.append(Iface(n, None, int(i.get("vlan_id") or 0) if i.get("type") == "vlan" else 0, ips))
        routes = v.get("routes", {}) or {}
        for r in routes.get("internal", []) or []:
            vr.internal.append(_net(r["destination"]))
        for r in routes.get("external", []) or []:
            net, mask = _net(r["destination"])
            vr.external.append((net, mask, r["next_hop"]))
        vrs.append(vr)
    return vrs


def annotate(rows, cfg):
    """各行の (送信元VR, 送信元ネクストホップ, 宛先VR, 宛先ネクストホップ)"""
    from .stack import _ipint
    vrs = static_vrs(cfg)

    def find(ip):
        if not _isip(ip):
            return "", ""
        i = _ipint(ip)
        for v in vrs:
            if v.owns(i) and ip not in v.gateways:
                nh = v.external[0][2] if v.external else ""
                return v.name, nh
        return "", ""
    out = []
    for r in rows:
        d = r.get("dst-nat-ip(option)") or r.get("dst-ip", "")
        s = find(r.get("src-ip", ""))
        t = find(d)
        out.append({"svr": s[0], "snh": s[1], "dvr": t[0], "dnh": t[1]})
    return out


def pathcheck(stack, only=None):
    """各VRの次ホップのARP解決を確認 -> [{vr, ip, if, ok, mac}]"""
    from .stack import ConnError
    res = []
    for vr in stack.vrs:
        if only is not None and vr.name not in only:
            continue
        for net, mask, nh in vr.external:
            iface = vr.iface_for(nh)
            dest = "%s/%d" % (ipaddress.ip_address(net), bin(mask).count("1"))
            try:
                mac = stack.resolve_nexthop(vr, iface, nh, 2.0)
                from .pkt import b2mac
                res.append({"vr": vr.name, "ip": nh, "if": iface.name, "dest": dest, "ok": True, "mac": b2mac(mac)})
            except ConnError:
                res.append({"vr": vr.name, "ip": nh, "if": iface.name, "dest": dest, "ok": False, "mac": ""})
    return res


# ---------------------------------------------------------------- 設定の保存・検証 (画面での編集用)
def _q(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def dump_toml(conf):
    """画面で編集した設定 → vrouter_gen と同じ書式のTOML"""
    L = ['version = %s' % _q(conf.get("version") or "1902"),
         'l2_mode = %s' % ("true" if conf.get("l2_mode") else "false"), ""]

    def aliases(i):
        a = _alias_list(i.get("ip_aliases"))
        return "[ ]" if not a else "[" + ", ".join(_q(x) for x in a) + "]"
    for i in conf.get("interfaces", []):
        L.append("[[interfaces]]")
        L.append("name = %s" % _q(i["name"]))
        if i.get("type") == "vlan":
            L += ['type = "vlan"', "ipaddress = %s" % _q(i.get("ipaddress", "")),
                  "vlan_id = %s" % _q(i.get("vlan_id", "")), "base_if = %s" % _q(i.get("base_if", "")),
                  "ip_aliases = %s" % aliases(i)]
        else:
            L += ['type = "physical"', "os_if = %s" % _q(i.get("os_if", "")),
                  "ip_aliases = %s" % aliases(i), "ipaddress = %s" % _q(i.get("ipaddress", ""))]
        L.append("")
    for v in conf.get("vRouters", []):
        L.append("[[vRouters]]")
        L.append("name = %s" % _q(v["name"]))
        L.append("if_names = [%s]" % ", ".join(_q(x) for x in v.get("if_names", [])))
        L.append("[vRouters.routes]")
        r = v.get("routes", {}) or {}
        if r.get("internal"):
            L.append("internal = [")
            L.append(",\n".join('  {destination = %s, comment = %s}' % (_q(x["destination"]), _q(x.get("comment", "")))
                                for x in r["internal"]))
            L.append("]")
        if r.get("external"):
            L.append("external = [")
            L.append(",\n".join('  {destination = %s, next_hop = %s, comment = %s}' % (
                _q(x["destination"]), _q(x.get("next_hop", "")), _q(x.get("comment", ""))) for x in r["external"]))
            L.append("]")
        L.append("")
    return "\n".join(L).rstrip("\n") + "\n"


def validate_conf(conf):
    """-> (errors, warnings)  文字列のリスト"""
    E, W = [], []
    ifs = conf.get("interfaces", [])
    names = [i.get("name", "") for i in ifs]
    byname = {i.get("name"): i for i in ifs}
    for n in set(names):
        if not n:
            E.append("インターフェース名が空です")
        elif names.count(n) > 1:
            E.append("インターフェース名が重複しています: %s" % n)
    nets = []   # (network, label, group)

    def net_of(s, label, strict_prefix=True):
        try:
            n = ipaddress.ip_interface(s)
        except ValueError:
            E.append("%s: IPアドレス/CIDRが不正です (%r)" % (label, s))
            return None
        if n.network.prefixlen == 31:
            E.append("%s: /31 は使えません (%s)" % (label, s))
        return n

    seen_vlan = set()
    for i in ifs:
        n = i.get("name", "")
        if i.get("type") == "vlan":
            try:
                vid = int(i.get("vlan_id"))
                if not 1 <= vid <= 4094:
                    raise ValueError
            except (TypeError, ValueError):
                E.append("%s: VLAN IDは 1〜4094 で指定してください" % n)
                vid = None
            b = byname.get(i.get("base_if"))
            if b is None or b.get("type") == "vlan":
                E.append("%s: Baseインターフェースが不正です (%r)" % (n, i.get("base_if")))
            elif vid is not None:
                if (i["base_if"], vid) in seen_vlan:
                    E.append("%s: %s に同じVLAN ID(%d)が既にあります" % (n, i["base_if"], vid))
                seen_vlan.add((i["base_if"], vid))
        ips = [x for x in [i.get("ipaddress", "")] if x]
        for k, a in enumerate(ips + _alias_list(i.get("ip_aliases"))):
            x = net_of(a, "%s%s" % (n, "" if k == 0 else " (alias)"))
            if x and k == 0:
                nets.append((x.network, "インターフェース %s" % n, n))
    vrn = [v.get("name", "") for v in conf.get("vRouters", [])]
    used = {}
    for v in conf.get("vRouters", []):
        vn = v.get("name", "")
        if not vn:
            E.append("仮想ルーター名が空です")
        elif vrn.count(vn) > 1:
            E.append("仮想ルーター名が重複しています: %s" % vn)
        members = []
        for m in v.get("if_names", []):
            if m not in byname:
                E.append("仮想ルーター %s: インターフェース %s が存在しません" % (vn, m))
            elif m in used:
                E.append("インターフェース %s が複数の仮想ルーター(%s, %s)に属しています" % (m, used[m], vn))
            else:
                used[m] = vn
                members.append(byname[m])
        r = v.get("routes", {}) or {}
        for x in r.get("internal", []) or []:
            try:
                n = ipaddress.ip_network(x["destination"], strict=False)
                if n.prefixlen == 31:
                    E.append("仮想ルーター %s: internal %s は /31 です (使えません)" % (vn, x["destination"]))
                nets.append((n, "仮想ルーター %s の internal %s" % (vn, x["destination"]), "vr:%s:%s" % (vn, x["destination"])))
            except (ValueError, KeyError):
                E.append("仮想ルーター %s: internalの宛先が不正です (%r)" % (vn, x.get("destination")))
        ext = r.get("external", []) or []
        if not ext:
            W.append("仮想ルーター %s に external ルートがありません (ファイアウォールへ送信できません)" % vn)
        for x in ext:
            try:
                ipaddress.ip_network(x["destination"], strict=False)
                nh = ipaddress.ip_address(x.get("next_hop", ""))
            except (ValueError, KeyError):
                E.append("仮想ルーター %s: externalの宛先/ネクストホップが不正です (%r / %r)" % (vn, x.get("destination"), x.get("next_hop")))
                continue
            ok = False
            for mi in members:
                for a in [mi.get("ipaddress", "")] + _alias_list(mi.get("ip_aliases")):
                    try:
                        if a and nh in ipaddress.ip_interface(a).network:
                            ok = True
                    except ValueError:
                        pass
            if not ok:
                W.append("仮想ルーター %s: ネクストホップ %s が所属インターフェースのサブネットにありません" % (vn, x.get("next_hop")))
        for mi in members:
            if mi.get("type") != "vlan" and not mi.get("os_if"):
                W.append("インターフェース %s: OSインターフェースが未設定です (実機では送受信できません)" % mi["name"])
    for a in range(len(nets)):
        for b in range(a + 1, len(nets)):
            if nets[a][2] != nets[b][2] and nets[a][0].version == nets[b][0].version and nets[a][0].overlaps(nets[b][0]):
                E.append("ネットワークが重複しています: %s (%s) と %s (%s)" % (nets[a][0], nets[a][1], nets[b][0], nets[b][1]))
    if conf.get("l2_mode"):
        W.append("L2モードはこのツールでは未対応です (OFFとして動作します)")
    return E, W
