# -*- coding: utf-8 -*-
"""
palo2scenario.py - Palo Alto Networks コンフィグ -> fg2scenario共通のPolicyモデル

対応形式:
  * XML (running-config.xml / Panoramaのエクスポート)
  * set形式 (CLIの `show` / `set` 出力。 set rulebase security rules ... 等)
対応オブジェクト: security rules / address / address-group(static) / service /
                  service-group / application-group
アプリケーション(App-ID)は、組み込みテーブルで既定ポートに落とす。
"""
from __future__ import annotations

import ipaddress
import re
import shlex
import xml.etree.ElementTree as ET
from collections import Counter

from fg2scenario import Addr, BitMatcher, Policy, Svc, MAXIP, ip2s, s2ip

ADDR_KINDS = ("ip-netmask", "ip-range", "fqdn", "ip-wildcard")

# App-ID -> [(l4, port, ツールのprotocol)]  (アプリケーションの既定ポート)
APP_PORTS = {
    "web-browsing": [("tcp", 80, "http")],
    "ssl": [("tcp", 443, "https")],
    "ping": [("icmp", 0, "icmp")],
    "icmp": [("icmp", 0, "icmp")],
    "dns": [("udp", 53, "dns")],
    "ftp": [("tcp", 21, "ftp")],
    "smtp": [("tcp", 25, "smtp")],
    "imap": [("tcp", 143, "imap")],
    "pop3": [("tcp", 110, "tcp")],
    "ssh": [("tcp", 22, "tcp")],
    "telnet": [("tcp", 23, "tcp")],
    "ntp": [("udp", 123, "udp")],
    "snmp": [("udp", 161, "udp")],
    "syslog": [("udp", 514, "udp")],
    "tftp": [("udp", 69, "udp")],
    "ldap": [("tcp", 389, "tcp")],
    "ms-rdp": [("tcp", 3389, "tcp")],
    "ms-ds-smb": [("tcp", 445, "tcp")],
    "mysql": [("tcp", 3306, "tcp")],
    "mssql-db": [("tcp", 1433, "tcp")],
    "kerberos": [("tcp", 88, "tcp")],
}


def _any_svc() -> Svc:
    return Svc("any", "any", 0, 65535, [("udp", 53, "dns", False), ("tcp", 80, "http", False),
                                        ("tcp", 443, "https", False)])


# ---------------------------------------------------------------------------
# 1. パーサー (XML / set形式 -> PaloConfig)
# ---------------------------------------------------------------------------
class PaloConfig:
    def __init__(self):
        self.addresses: dict = {}       # name -> (kind, value)
        self.addr_groups: dict = {}     # name -> [member]
        self.dynamic_groups: set = set()
        self.edls: set = set()          # 外部動的リスト(EDL)の名前
        self.services: dict = {}        # name -> [(proto, ports)]
        self.svc_groups: dict = {}
        self.app_groups: dict = {}
        self.rules: dict = {}           # key -> {field: [values]}  (評価順)
        self.nat_rules: dict = {}       # key -> {field: [values]}  (評価順)
        self.interfaces: dict = {}      # name -> {kind, ips, tag, parent, dhcp}
        self.zones: dict = {}           # (vsys, zone) -> {"layer3": [if], "other": [(type, if)]}
        self.vrouters: dict = {}        # name -> {"interfaces": [], "routes": [{...}]}
        self.imports: dict = {}         # vsys -> [インターフェース] (importされたIF = そのvsysの所有)
        self.vsys_names: list = []      # ルール/ゾーンを持つvsys (出現順)

    # -- 登録の補助 ---------------------------------------------------------
    def seen_vsys(self, v):
        if v and v not in self.vsys_names:
            self.vsys_names.append(v)

    @staticmethod
    def _unique(d: dict, name: str, vsys) -> str:
        """同名のルールが別スコープ(vsys/device-group)にあるときは、キーを変えて両方残す"""
        if name not in d:
            return name
        k = f"{name}@{vsys}" if vsys else name
        n = 1
        while k in d:
            n += 1
            k = f"{name}#{n}"
        return k

    def add_rule(self, name: str, f: dict, vsys, stage: int, nat: bool = False):
        f["vsys"] = [vsys] if vsys else []
        f["stage"] = [stage]
        d = self.nat_rules if nat else self.rules
        d[self._unique(d, name, vsys)] = f
        self.seen_vsys(vsys)

    def zone_members(self, vsys, name: str) -> list:
        """ゾーン名 -> レイヤー3インターフェース (そのvsysのゾーン→無印のゾーン→他vsysのゾーン の順に探す)"""
        for key in ((vsys, name), (None, name)):
            z = self.zones.get(key)
            if z is not None:
                return z["layer3"]
        for (v, n), z in self.zones.items():
            if n == name:
                return z["layer3"]
        return []

    def finish(self):
        """評価順を確定する: Panoramaのpre-rulebase -> ローカル -> post-rulebase"""
        for attr in ("rules", "nat_rules"):
            d = getattr(self, attr)
            ordered = sorted(d.items(), key=lambda kv: kv[1]["stage"][0])  # 安定ソート
            setattr(self, attr, dict(ordered))


def _members(e, tag):
    x = e.find(tag)
    if x is None:
        return []
    return [v for v in ((m.text or "").strip() for m in x.findall("member")) if v]


def _text(e, tag):
    x = e.find(tag)
    return (x.text or "").strip() if x is not None else ""


# XMLを走査するときに中へ入らない要素 (ルールやプロファイル等の中身は専用の処理で読む)
_SKIP_TAGS = {"rules", "profiles", "deviceconfig", "mgt-config", "log-settings", "reports", "report-group",
              "email-scheduler", "external-list", "tag", "schedule", "network", "import", "dynamic-user-group",
              "application-filter", "region", "pre-rulebase", "post-rulebase", "rulebase", "setting"}


def _xml_rule(en) -> dict:
    f: dict = {}
    for tag in ("from", "to", "source", "destination", "application", "service"):
        f[tag] = _members(en, tag)
    for tag in ("action", "disabled", "negate-source", "negate-destination", "rule-type", "description"):
        v = _text(en, tag)
        f[tag] = [v] if v else []
    ps = en.find("profile-setting")
    f["profile-setting"] = [t.strip() for t in ps.itertext() if t.strip()] if ps is not None else []
    return f


def _xml_nat_rule(en) -> dict:
    f: dict = {"from": _members(en, "from"), "to": _members(en, "to"), "source": _members(en, "source"),
               "destination": _members(en, "destination")}
    sv = en.find("service")  # NATルールのserviceは単一 (テキスト)。メンバー形式にも対応
    f["service"] = ([(sv.text or "").strip()] if sv is not None and (sv.text or "").strip() else _members(en, "service"))
    for tag in ("disabled", "description", "to-interface", "nat-type"):
        v = _text(en, tag)
        f[tag] = [v] if v else []
    st = en.find("source-translation")
    if st is not None and len(st):
        kind = st[0]
        f["stype"] = [kind.tag]
        ia = kind.find("interface-address")
        if ia is not None:
            f["s_iface"] = [_text(ia, "interface")] if _text(ia, "interface") else []
            f["s_ifip"] = [_text(ia, "ip")] if _text(ia, "ip") else []
        ta = kind.find("translated-address")
        if ta is not None:
            mem = [(m.text or "").strip() for m in ta.findall("member") if (m.text or "").strip()]
            f["s_addrs"] = mem or ([(ta.text or "").strip()] if (ta.text or "").strip() else [])
        f["bidir"] = [_text(kind, "bi-directional")] if _text(kind, "bi-directional") else []
    dt = en.find("destination-translation")
    if dt is not None:
        f["d_addr"] = [_text(dt, "translated-address")] if _text(dt, "translated-address") else []
        f["d_port"] = [_text(dt, "translated-port")] if _text(dt, "translated-port") else []
    return f


def _xml_iface(cfg: PaloConfig, name: str, kind: str, en, parent=None):
    mode = next((c.tag for c in en if c.tag in ("layer3", "layer2", "virtual-wire", "tap", "ha",
                                                  "decrypt-mirror", "log-card", "aggregate-group")), kind)
    info = {"kind": mode, "ips": [], "tag": None, "parent": parent, "dhcp": False, "units": []}
    l3 = en.find("layer3")
    if l3 is not None:
        info["ips"] = [e.get("name") for e in l3.findall("ip/entry") if e.get("name")]
        dh = l3.find("dhcp-client")
        info["dhcp"] = dh is not None and _text(dh, "enable") != "no"
        for u in l3.findall("units/entry"):
            un = u.get("name")
            if not un:
                continue
            tag = _text(u, "tag")
            ui = {"kind": "layer3", "ips": [e.get("name") for e in u.findall("ip/entry") if e.get("name")],
                  "tag": int(tag) if tag.isdigit() else None, "parent": name, "units": [],
                  "dhcp": u.find("dhcp-client") is not None and _text(u.find("dhcp-client"), "enable") != "no"}
            cfg.interfaces[un] = ui
            info["units"].append(un)
    elif kind in ("loopback", "tunnel", "vlan"):  # units/entry/ip/entry 形式
        info["kind"] = kind
        info["ips"] = [e.get("name") for e in en.findall("ip/entry") if e.get("name")]
    cfg.interfaces[name] = info


def _xml_network(cfg: PaloConfig, net):
    itf = net.find("interface")
    if itf is not None:
        for kind in ("ethernet", "aggregate-ethernet"):
            for en in itf.findall(f"{kind}/entry"):
                if en.get("name"):
                    _xml_iface(cfg, en.get("name"), kind, en)
        for kind in ("loopback", "tunnel", "vlan"):
            for en in itf.findall(f"{kind}/units/entry"):
                if en.get("name"):
                    _xml_iface(cfg, en.get("name"), kind, en)
    for ve in net.findall("virtual-router/entry"):
        vr = cfg.vrouters.setdefault(ve.get("name", ""), {"interfaces": [], "routes": []})
        vr["interfaces"] += _members(ve, "interface")
        for r in ve.findall("routing-table/ip/static-route/entry"):
            vr["routes"].append({"name": r.get("name", ""), "dest": _text(r, "destination"),
                                 "nexthop": _text(r, "nexthop/ip-address"), "iface": _text(r, "interface"),
                                 "metric": _text(r, "metric")})


def parse_xml(text: str) -> PaloConfig:
    root = ET.fromstring(text.strip())
    cfg = PaloConfig()

    def objects(node):
        for sec in node.findall("address"):
            for en in sec.findall("entry"):
                for kind in ADDR_KINDS:
                    if en.find(kind) is not None:
                        cfg.addresses[en.get("name")] = (kind, _text(en, kind))
                        break
        for en in node.findall("external-list/entry"):
            cfg.edls.add(en.get("name"))
        for sec in node.findall("address-group"):
            for en in sec.findall("entry"):
                if en.find("static") is not None:
                    cfg.addr_groups[en.get("name")] = _members(en, "static")
                else:
                    cfg.dynamic_groups.add(en.get("name"))
        for sec in node.findall("service"):
            for en in sec.findall("entry"):
                prs = []
                for proto in ("tcp", "udp"):
                    x = en.find(f"protocol/{proto}/port")
                    if x is not None and x.text:
                        prs.append((proto, x.text.strip()))
                if prs:
                    cfg.services[en.get("name")] = prs
        for sec in node.findall("service-group"):
            for en in sec.findall("entry"):
                cfg.svc_groups[en.get("name")] = _members(en, "members")
        for sec in node.findall("application-group"):
            for en in sec.findall("entry"):
                cfg.app_groups[en.get("name")] = _members(en, "members")

    def scope(node, vsys):
        objects(node)
        for en in node.findall("zone/entry"):
            net = en.find("network")
            z = {"layer3": [], "other": []}
            if net is not None:
                for c in net:
                    mem = [(m.text or "").strip() for m in c.findall("member") if (m.text or "").strip()]
                    if c.tag == "layer3":
                        z["layer3"] += mem
                    else:
                        z["other"] += [(c.tag, m) for m in mem]
            cfg.zones[(vsys, en.get("name"))] = z
            cfg.seen_vsys(vsys)
        for tag, stage in (("pre-rulebase", 0), ("rulebase", 1), ("post-rulebase", 2)):
            for rb in node.findall(tag):
                for en in rb.findall("security/rules/entry"):
                    cfg.add_rule(en.get("name"), _xml_rule(en), vsys, stage)
                for en in rb.findall("nat/rules/entry"):
                    cfg.add_rule(en.get("name"), _xml_nat_rule(en), vsys, stage, nat=True)
        for net in node.findall("network"):
            _xml_network(cfg, net)
        for imp in node.findall("import/network/interface"):
            cfg.imports.setdefault(vsys, []).extend((m.text or "").strip() for m in imp.findall("member"))

    def walk(node, vsys):
        scope(node, vsys)
        for c in node:
            if c.tag in _SKIP_TAGS or len(c) == 0:
                continue
            if node.tag == "vsys" and c.tag == "entry":
                walk(c, c.get("name"))
            elif node.tag == "device-group" and c.tag == "entry":
                walk(c, None)
            else:
                walk(c, vsys)

    walk(root, None)
    cfg.finish()
    return cfg


def parse_set(text: str) -> PaloConfig:
    cfg = PaloConfig()
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("set "):
            continue
        try:
            toks = shlex.split(line)
        except ValueError:
            toks = line.split()
        toks = [t for t in toks[1:] if t not in ("[", "]")]
        vsys = None
        while toks:  # スコープ接頭辞を除去
            if toks[0] == "shared":
                toks = toks[1:]
            elif toks[0] == "vsys" and len(toks) > 1:
                vsys = toks[1]
                toks = toks[2:]
            elif toks[0] in ("device-group", "template", "template-stack") and len(toks) > 1:
                toks = toks[2:]
            elif toks[0] == "config" and len(toks) > 1:  # テンプレートの set template X config devices <名前> ...
                toks = toks[1:]
            elif toks[0] == "devices" and len(toks) > 1:
                toks = toks[2:]
            else:
                break
        stage = 1
        if toks and toks[0] in ("pre-rulebase", "post-rulebase"):
            stage = 0 if toks[0] == "pre-rulebase" else 2
            toks[0] = "rulebase"
        if len(toks) < 3:
            continue
        k = toks[0]
        if k == "address" and len(toks) >= 4 and toks[2] in ADDR_KINDS:
            cfg.addresses[toks[1]] = (toks[2], toks[3])
        elif k == "external-list":
            cfg.edls.add(toks[1])
        elif k == "address-group":
            if toks[2] == "static":
                cfg.addr_groups.setdefault(toks[1], []).extend(toks[3:])
            elif toks[2] == "dynamic":
                cfg.dynamic_groups.add(toks[1])
        elif k == "service" and len(toks) >= 6 and toks[2] == "protocol" and toks[4] == "port":
            cfg.services.setdefault(toks[1], []).append((toks[3], toks[5]))
        elif k == "service-group" and toks[2] == "members":
            cfg.svc_groups.setdefault(toks[1], []).extend(toks[3:])
        elif k == "application-group" and toks[2] == "members":
            cfg.app_groups.setdefault(toks[1], []).extend(toks[3:])
        elif toks[:3] == ["rulebase", "security", "rules"] and len(toks) >= 5:
            key = (vsys, stage, toks[3])
            r = _set_rules(cfg, "rules").setdefault(key, {})
            r.setdefault(toks[4], []).extend(toks[5:])
        elif toks[:3] == ["rulebase", "nat", "rules"] and len(toks) >= 5:
            key = (vsys, stage, toks[3])
            r = _set_rules(cfg, "nat_rules").setdefault(key, {})
            _set_nat_field(r, toks[4], toks[5:])
        elif k == "zone" and len(toks) >= 4 and toks[2] == "network":
            z = cfg.zones.setdefault((vsys, toks[1]), {"layer3": [], "other": []})
            cfg.seen_vsys(vsys)
            if toks[3] == "layer3":
                z["layer3"] += toks[4:]
            else:
                z["other"] += [(toks[3], m) for m in toks[4:]]
        elif k == "network" and toks[1] == "interface" and len(toks) >= 5:
            _set_iface(cfg, toks[2:])
        elif k == "network" and toks[1] == "virtual-router":
            _set_vrouter(cfg, toks[2:])
        elif k == "import" and toks[1:3] == ["network", "interface"]:
            cfg.imports.setdefault(vsys, []).extend(toks[3:])
    _finish_set(cfg)
    return cfg


def parse(text: str) -> PaloConfig:
    """XML か set形式かを判定して解析する"""
    return parse_xml(text) if text.lstrip().startswith("<") else parse_set(text)


def _set_rules(cfg: PaloConfig, attr: str) -> dict:
    tmp = getattr(cfg, "_tmp_" + attr, None)
    if tmp is None:
        tmp = {}
        setattr(cfg, "_tmp_" + attr, tmp)
    return tmp


def _set_nat_field(r: dict, field: str, vals: list):
    """setの NATルール1行を、XMLと同じ形の辞書に取り込む"""
    if field == "source-translation" and vals:
        kind, rest = vals[0], vals[1:]
        r["stype"] = [kind]
        if rest[:1] == ["interface-address"]:
            if rest[1:2] == ["interface"] and len(rest) > 2:
                r["s_iface"] = [rest[2]]
            elif rest[1:2] == ["ip"] and len(rest) > 2:
                r["s_ifip"] = [rest[2]]
        elif rest[:1] == ["translated-address"]:
            r.setdefault("s_addrs", []).extend(rest[1:])
        elif rest[:1] == ["bi-directional"] and len(rest) > 1:
            r["bidir"] = [rest[1]]
    elif field == "destination-translation" and vals:
        if vals[0] == "translated-address" and len(vals) > 1:
            r["d_addr"] = [vals[1]]
        elif vals[0] == "translated-port" and len(vals) > 1:
            r["d_port"] = [vals[1]]
    else:
        r.setdefault(field, []).extend(vals)


def _set_iface(cfg: PaloConfig, t: list):
    """t = ['ethernet', 'ethernet1/1', 'layer3', 'ip', '10.0.0.1/24', ...]"""
    kind, name = t[0], t[1]
    if kind not in ("ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan"):
        return
    info = cfg.interfaces.setdefault(name, {"kind": kind, "ips": [], "tag": None, "parent": None,
                                            "dhcp": False, "units": []})
    rest = t[2:]
    if not rest:
        return
    if rest[0] in ("layer3", "layer2", "virtual-wire", "tap", "ha", "aggregate-group", "decrypt-mirror"):
        info["kind"] = rest[0]
        rest = rest[1:]
        if info["kind"] == "layer3":
            if rest[:1] == ["ip"]:
                info["ips"] += rest[1:]
            elif rest[:1] == ["dhcp-client"]:
                en = rest[1:]
                info["dhcp"] = not (en[:1] == ["enable"] and en[1:2] == ["no"])
            elif rest[:1] == ["units"] and len(rest) >= 3:
                un = rest[1]
                ui = cfg.interfaces.setdefault(un, {"kind": "layer3", "ips": [], "tag": None, "parent": name,
                                                    "dhcp": False, "units": []})
                if un not in info["units"]:
                    info["units"].append(un)
                sub = rest[2:]
                if sub[:1] == ["tag"] and len(sub) > 1 and sub[1].isdigit():
                    ui["tag"] = int(sub[1])
                elif sub[:1] == ["ip"]:
                    ui["ips"] += sub[1:]
                elif sub[:1] == ["dhcp-client"]:
                    ui["dhcp"] = not (sub[1:2] == ["enable"] and sub[2:3] == ["no"])
    elif kind in ("loopback", "tunnel", "vlan") and rest[:1] == ["units"] and len(rest) >= 3:
        un = rest[1]
        ui = cfg.interfaces.setdefault(un, {"kind": kind, "ips": [], "tag": None, "parent": None,
                                            "dhcp": False, "units": []})
        if rest[2:3] == ["ip"]:
            ui["ips"] += rest[3:]


def _set_vrouter(cfg: PaloConfig, t: list):
    vr = cfg.vrouters.setdefault(t[0], {"interfaces": [], "routes": []})
    rest = t[1:]
    if rest[:1] == ["interface"]:
        vr["interfaces"] += rest[1:]
    elif rest[:4] == ["routing-table", "ip", "static-route"] and len(rest) >= 6:
        name = rest[3]
        rt = next((r for r in vr["routes"] if r["name"] == name), None)
        if rt is None:
            rt = {"name": name, "dest": "", "nexthop": "", "iface": "", "metric": ""}
            vr["routes"].append(rt)
        f = rest[4:]
        if f[:1] == ["destination"] and len(f) > 1:
            rt["dest"] = f[1]
        elif f[:2] == ["nexthop", "ip-address"] and len(f) > 2:
            rt["nexthop"] = f[2]
        elif f[:1] == ["interface"] and len(f) > 1:
            rt["iface"] = f[1]
        elif f[:1] == ["metric"] and len(f) > 1:
            rt["metric"] = f[1]


def _finish_set(cfg: PaloConfig):
    for attr in ("rules", "nat_rules"):
        tmp = getattr(cfg, "_tmp_" + attr, {})
        for (vsys, stage, name), f in tmp.items():
            cfg.add_rule(name, f, vsys, stage, nat=(attr == "nat_rules"))
        if hasattr(cfg, "_tmp_" + attr):
            delattr(cfg, "_tmp_" + attr)
    cfg.finish()


# ---------------------------------------------------------------------------
# 2. オブジェクト解決 -> Policy
# ---------------------------------------------------------------------------
class PaloResolver:
    intrazone_allow = True  # Paloは同一ゾーン間が既定でallow

    def __init__(self, text: str, args, vsys=None, cfg: PaloConfig = None):
        """vsys: 指定したvsysのルール(とshared/device-groupのルール)だけを対象にする。
        cfg: 解析済みの設定 (vsysごとに作り直すときの再解析を避ける)"""
        self.args = args
        self.warnings: Counter = Counter()
        self.warn_pols: dict = {}  # 警告メッセージ -> 該当ポリシー名のリスト
        self.cur = ""
        self.skipped: list = []
        self.cfg = cfg or parse(text)
        self.vsys = vsys
        self.vdom = vsys           # generate()が説明欄に出す名前 (vsysが複数あるときだけ指定される)
        self._memo_store: dict = {}
        self._captured = None   # 展開中に出た警告 (メモ化して再生するため)
        self.nat_pols: list = []
        self.nat_info: dict = {}
        self._nat_matcher = None
        self.dnat_used: dict = {}  # ポリシーID -> {宛先IP(pre-NAT): 実宛先IP}  (仮想ルーターのinternal用)
        self.nat_hits: Counter = Counter()

    def warn(self, msg: str):
        if self._captured is not None:
            self._captured.append(msg)
        self.warnings[msg] += 1
        if self.cur:  # どのポリシーの処理中に出た警告かを記録する
            lst = self.warn_pols.setdefault(msg, [])
            if self.cur not in lst:
                lst.append(self.cur)

    # ---- アドレス ----
    def _net_addr(self, name: str, value: str) -> Addr:
        try:
            net = ipaddress.ip_network(value.strip(), strict=False)
        except ValueError:
            self.warn(f"アドレス '{name}' の値を解析できません: {value}")
            return Addr("unsupported", name)
        if net.version != 4:
            self.warn(f"IPv6アドレス '{name}' は未対応")
            return Addr("unsupported", name)
        if net.prefixlen == 0:
            return Addr("any", name, 0, MAXIP, text=str(net))
        return Addr("range", name, int(net.network_address), int(net.broadcast_address),
                    text=str(net), cidr=net.prefixlen < 32)

    def _obj_addr(self, name: str, kind: str, value: str) -> Addr:
        if kind == "ip-netmask":
            return self._net_addr(name, value)
        if kind == "ip-range":
            try:
                a, b = value.split("-", 1)
                lo, hi = s2ip(a.strip()), s2ip(b.strip())
            except ValueError:
                self.warn(f"アドレス '{name}' のip-rangeを解析できません: {value}")
                return Addr("unsupported", name)
            if lo > hi:
                self.warn(f"アドレス '{name}' のip-rangeの開始が終了より大きい: {value}")
                return Addr("unsupported", name)
            return Addr("range", name, lo, hi, text=f"{ip2s(lo)}-{ip2s(hi)}")
        if kind == "fqdn":
            ip = self.args.fqdn_map.get(value)  # --fqdn-map指定があればマッチ判定にも使う
            n = s2ip(ip) if ip else None
            return Addr("fqdn", name, n, n, text=value)
        self.warn(f"未対応のアドレスタイプ '{kind}' はスキップ (例: {name})")
        return Addr("unsupported", name, text=kind)

    def _memo(self, kind: str, key, fn):
        """結果と、その計算中に出た警告をキャッシュする。2回目以降は結果を再利用し、警告は同じ件数ぶん再生する
        (件数と「どのポリシーで出たか」は、メモ化しない場合と同じになる)"""
        store = self._memo_store.setdefault(kind, {})
        got = store.get(key)
        if got is None:
            outer = self._captured
            self._captured = []
            try:
                res = fn()
                got = store[key] = (res, self._captured)
            finally:
                inner = self._captured
                self._captured = outer
            if outer is not None:
                outer.extend(inner)
            return got[0]
        for m in got[1]:
            self.warn(m)
        return got[0]

    def resolve_addr(self, name: str, seen: tuple = ()) -> list:
        """名前 -> Addrのリスト。同じ名前は一度だけ展開する
        (グループが何千ものルールから参照されても展開コストは1回分)。Addrは書き換えない前提で共有する"""
        if seen:  # 循環参照の検出中は、途中経過なのでメモ化しない
            return self._resolve_addr(name, seen)
        return self._memo("addr", name, lambda: self._resolve_addr(name, seen))

    def _resolve_addr(self, name: str, seen: tuple = ()) -> list:
        if name in seen:
            self.warn(f"アドレスグループの循環参照: {name}")
            return []
        seen = seen + (name,)
        cfg = self.cfg
        if name == "any":
            return [Addr("any", name, 0, MAXIP, text="any")]
        if name in cfg.addresses:
            return [self._obj_addr(name, *cfg.addresses[name])]
        if name in cfg.addr_groups:
            return [a for m in cfg.addr_groups[name] for a in self.resolve_addr(m, seen)]
        if name in cfg.dynamic_groups:
            self.warn(f"動的アドレスグループ '{name}' は未対応")
            return [Addr("unsupported", name)]
        if name in cfg.edls:
            self.warn(f"外部動的リスト(EDL) '{name}' は中身を取得できないため未対応")
            return [Addr("unsupported", name)]
        try:  # ルールに直接書かれたIP/範囲
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+\s*-\s*\d+\.\d+\.\d+\.\d+", name):
                return [self._obj_addr(name, "ip-range", name)]
            ipaddress.ip_network(name, strict=False)
            return [self._net_addr(name, name)]
        except ValueError:
            self.warn(f"未定義のアドレス: {name}")
            return [Addr("unsupported", name)]

    # ---- サービス / アプリケーション ----
    def _sample_ports(self, lo: int, hi: int) -> list:
        pts = [lo]
        if hi != lo:
            pts.append(hi)
        if hi - lo >= 2:
            pts.append((lo + hi) // 2)
        return pts[: self.args.max_port]

    def resolve_service(self, name: str, seen: tuple = ()) -> list:
        if name in seen:
            return []
        seen = seen + (name,)
        cfg = self.cfg
        if name in cfg.services:
            out: list = []
            for proto, ports in cfg.services[name]:
                for tok in ports.replace(" ", "").split(","):
                    if not tok:
                        continue
                    try:
                        a, b = tok.split("-", 1) if "-" in tok else (tok, tok)
                        lo, hi = int(a), int(b)
                    except ValueError:
                        self.warn(f"サービス '{name}' のポート書式を解析できません: {tok}")
                        continue
                    out.append(Svc(name, proto, lo, hi,
                                   [(proto, p, proto, lo == hi) for p in self._sample_ports(lo, hi)]))
            return out
        if name in cfg.svc_groups:
            return [s for m in cfg.svc_groups[name] for s in self.resolve_service(m, seen)]
        if name == "service-http":
            return [Svc(name, "tcp", 80, 80, [("tcp", 80, "http", True)]),
                    Svc(name, "tcp", 8080, 8080, [("tcp", 8080, "http", True)])]
        if name == "service-https":
            return [Svc(name, "tcp", 443, 443, [("tcp", 443, "https", True)])]
        self.warn(f"未定義/未対応のサービス: {name}")
        return []

    def expand_apps(self, names: list, seen: tuple = ()) -> list:
        out: list = []
        for n in names:
            if n in self.cfg.app_groups and n not in seen:
                out += self.expand_apps(self.cfg.app_groups[n], seen + (n,))
            else:
                out.append(n)
        return out

    def _app_default(self, apps: list) -> list:
        out: list = []
        for app in apps:
            if app == "any":
                out.append(_any_svc())
            elif app in APP_PORTS:
                out += [Svc(app, l4, port, port, [(l4, port, tool, True)]) for l4, port, tool in APP_PORTS[app]]
            else:
                self.warn(f"アプリ '{app}' の既定ポートが不明のためスキップ")
        return out

    def rule_services(self, apps: list, services: list) -> list:
        return self._memo("svc", (tuple(apps), tuple(services)), lambda: self._rule_services(apps, services))

    def _rule_services(self, apps: list, services: list) -> list:
        known = bool(apps) and "any" not in apps and all(a in APP_PORTS for a in apps)
        out: list = []
        for sn in services:
            if sn == "application-default" or (sn == "any" and known):
                out += self._app_default(apps)
            elif sn == "any":
                out.append(_any_svc())
            else:
                out += self.resolve_service(sn)
        # アプリが特定できる場合、カスタムサービスのアプリ層protocolを上書き (ssl -> https など)
        if known:
            over: dict = {}
            conflict: set = set()
            for app in apps:
                for l4, _, tool in APP_PORTS[app]:
                    if tool in (l4, "icmp"):
                        continue
                    if over.get(l4, tool) != tool:
                        conflict.add(l4)
                    over[l4] = tool
            for c in conflict:
                over.pop(c, None)
            for sv in out:
                sv.probes = [(l4, port, over.get(l4, app) if app == l4 else app, single)
                             for l4, port, app, single in sv.probes]
        return out

    # ---- ルール ----
    def _in_scope(self, f: dict) -> bool:
        """このvsysに属するルールか (shared / device-group のルールは全vsysに適用)"""
        v = f.get("vsys") or []
        return self.vsys is None or not v or v[0] == self.vsys

    def build_policies(self) -> list:
        out = self._build_security()
        self.build_nat()
        return out

    def _build_security(self) -> list:
        def first(f, k, d=""):
            v = f.get(k, [])
            return v[0] if v else d

        out: list = []
        for name, f in self.cfg.rules.items():
            if not self._in_scope(f):
                continue
            self.cur = name
            disabled = first(f, "disabled") == "yes"
            if disabled and not getattr(self.args, "include_disabled", True):
                self.skipped.append((name, "disabled"))
                continue
            raw = first(f, "action", "deny")
            action = "accept" if raw == "allow" else ("reject" if raw.startswith("reset") else "deny")
            src_if = f.get("from") or ["any"]
            dst_if = f.get("to") or ["any"]
            if first(f, "rule-type") == "intrazone":
                dst_if = src_if
            apps = self.expand_apps(f.get("application") or ["any"])
            p = Policy(pid=name, name=name, action=action, srcintf=src_if, dstintf=dst_if,
                       nsrc=first(f, "negate-source") == "yes",
                       ndst=first(f, "negate-destination") == "yes",
                       comments=first(f, "description"),
                       utm=" ".join(f.get("profile-setting", [])), disabled=disabled)
            p.src_names, p.dst_names = f.get("source", []), f.get("destination", [])
            p.svc_names = list(dict.fromkeys(apps + [s for s in f.get("service", []) if s != "application-default"]))
            p.src = [a for n in p.src_names for a in self.resolve_addr(n)]
            p.dst = [a for n in p.dst_names for a in self.resolve_addr(n)]
            p.svc = self.rule_services(apps, f.get("service") or ["application-default"])
            if not (p.src_names and p.dst_names):
                p.gen_skip = "source/destination未設定"
            elif p.nsrc or p.ndst:
                p.gen_skip = "negate指定 (テスト生成対象外。マッチ判定には反映)"
            elif not p.svc:
                p.gen_skip = "サービス/アプリを解決できない"
            if p.gen_skip:
                self.skipped.append((name, p.gen_skip))
            out.append(p)
        return out

    # ---- NAT ----
    def _addr_ip(self, token: str) -> str:
        """アドレスオブジェクト名 / IP / IP/マスク -> 先頭のIP文字列 (解決できなければ空)"""
        addrs = self.resolve_addr(token)
        for a in addrs:
            if a.lo is not None:
                return ip2s(a.lo + 1 if a.cidr and a.hi - a.lo >= 3 else a.lo)
        return ""

    def _if_ip(self, ifname: str) -> str:
        """インターフェース名 -> IPアドレス (マスクなし)。未設定/DHCPなら空"""
        info = self.cfg.interfaces.get(ifname)
        if not info or not info["ips"]:
            return ""
        tok = info["ips"][0]
        try:
            return str(ipaddress.ip_interface(tok).ip)
        except ValueError:
            return self._addr_ip(tok)  # アドレスオブジェクト名で指定されている場合

    def build_nat(self):
        """NATルールを、セキュリティルールと同じマッチ判定(BitMatcher)で引ける形にする。
        ゾーン: 送信元ゾーンはそのまま比較。宛先ゾーン(to)は、宛先NATがあるルールでは判定に使わない
        (toは変換前の宛先のルーティングで決まり、コンフィグだけからは分からないため)。"""
        first = lambda f, k, d="": (f.get(k) or [d])[0]  # noqa: E731
        dnat_rules = 0
        for key, f in self.cfg.nat_rules.items():
            if not self._in_scope(f) or first(f, "disabled") == "yes":
                continue
            self.cur = key
            has_d = bool(f.get("d_addr"))
            dnat_rules += has_d
            stype = first(f, "stype")
            if first(f, "nat-type") not in ("", "ipv4"):
                self.warn(f"NAT種別 {first(f, 'nat-type')} は未対応 (NAT64等)。このNATルールは判定から除外")
                continue
            sv = f.get("service") or ["any"]
            svc: list = []
            for n in sv:
                svc += [_any_svc()] if n in ("any", "") else self.resolve_service(n)
            pol = Policy(pid=key, name=key, action="nat", srcintf=f.get("from") or ["any"],
                         dstintf=["any"] if has_d else (f.get("to") or ["any"]),
                         src=[a for n in (f.get("source") or ["any"]) for a in self.resolve_addr(n)],
                         dst=[a for n in (f.get("destination") or ["any"]) for a in self.resolve_addr(n)],
                         svc=svc)
            info = {"kind": "fwd", "stype": stype, "src_nat": "", "dst_ip": "", "dst_port": first(f, "d_port"),
                    "pool": [], "to": f.get("to") or ["any"], "orig_src": pol.src, "note": ""}
            if stype == "dynamic-ip-and-port" and f.get("s_iface"):
                ip = self._if_ip(f["s_iface"][0])
                if f.get("s_ifip"):
                    ip = self._addr_ip(f["s_ifip"][0]) or ip
                if ip:
                    info["src_nat"] = ip
                else:
                    self.warn(f"NAT: インターフェース '{f['s_iface'][0]}' のIPを取得できず、src-nat-ipを空にした (DHCP/未設定)")
            elif stype in ("dynamic-ip-and-port", "dynamic-ip", "static-ip"):
                pool = [a for n in f.get("s_addrs", []) for a in self.resolve_addr(n)]
                info["pool"] = [a for a in pool if a.lo is not None]
                if not info["pool"]:
                    self.warn(f"NAT: 変換後の送信元アドレスを解決できない ({stype})")
                elif stype != "static-ip":
                    a = info["pool"][0]
                    info["src_nat"] = ip2s(a.lo + 1 if a.cidr and a.hi - a.lo >= 3 else a.lo)
                    if len(info["pool"]) > 1 or a.hi != a.lo:
                        info["note"] = "変換後送信元はプール内のいずれか。先頭を期待値に使用"
            elif stype:
                self.warn(f"NAT: 送信元変換タイプ '{stype}' は未対応")
            if has_d:
                tok = f["d_addr"][0]
                ds = [a for a in self.resolve_addr(tok) if a.lo is not None]
                if ds:
                    info["dst_ip"] = ip2s(ds[0].lo)
                    if ds[0].hi != ds[0].lo:
                        info["note"] = (info["note"] + " / " if info["note"] else "") + "変換後宛先が範囲: 先頭を使用"
                else:
                    self.warn(f"NAT: 変換後の宛先 '{tok}' をIPに解決できない (FQDN等)")
            self.nat_pols.append(pol)
            self.nat_info[key] = info
            if stype == "static-ip" and first(f, "bidir") == "yes" and info["pool"]:
                rev = Policy(pid=key + " (bi-directional)", name=key, action="nat",
                             srcintf=["any"], dstintf=["any"], src=[Addr("any", "any", 0, MAXIP, text="any")],
                             dst=info["pool"], svc=[_any_svc()])
                self.nat_pols.append(rev)
                self.nat_info[rev.pid] = {"kind": "rev", "pool": info["pool"], "orig": pol.src, "src_nat": "",
                                          "dst_ip": "", "dst_port": "", "note": "", "stype": "static-ip"}
        if dnat_rules:
            self.cur = ""
            self.warn("NAT: 宛先NATルールのtoゾーンは、変換前の宛先のルーティングで決まるため照合に使っていません")
        if self.nat_pols:
            self._nat_matcher = BitMatcher.create(self.nat_pols, False)
        self.cur = ""

    @staticmethod
    def _static_map(sip: int, src_addrs: list, pool: list) -> str:
        """static-ip: 元アドレス内の位置(オフセット)を、変換後アドレス内の同じ位置に写す。
        変換後が単一IPなら、そのIP (N:1)"""
        for a in src_addrs:
            if a.contains(sip):
                off = sip - a.lo
                for t in pool:
                    if t.lo == t.hi:
                        return ip2s(t.lo)
                    if t.hi - t.lo >= off:
                        return ip2s(t.lo + off)
                return ""
        return ""

    def nat_lookup(self, p, si, di, sip: str, dip: str, l4: str, port: int):
        """シナリオ1件に最初にマッチするNATルールから、期待値 (src-nat-ip / dst-nat-ip / dst-nat-port) を求める。
        マッチするNATがなければ None。戻り値: dict(name, src_nat, dst_ip, dst_port, note)"""
        if self._nat_matcher is None:
            return None
        q = self._nat_matcher.first(si, di, sip, dip, l4, port)
        if q is None:
            return None
        info = self.nat_info[q.pid]
        self.nat_hits[q.pid] += 1
        out = {"name": q.pid, "src_nat": "", "dst_ip": "", "dst_port": "", "notes": []}
        if info["kind"] == "rev":  # static-ip bi-directional: 変換後アドレス宛 -> 元のアドレス
            try:
                dnum = s2ip(dip)
            except ValueError:
                return out
            m = self._static_map(dnum, info["pool"], info["orig"])
            if m:
                out["dst_ip"] = m
                self.dnat_used.setdefault(p.pid, {})[dip] = m
                out["notes"].append("static NAT(bi-directional)の逆方向: 宛先を元アドレスに変換")
            return out
        stype = info["stype"]
        if stype == "static-ip":
            try:
                m = self._static_map(s2ip(sip), info["orig_src"], info["pool"])
            except ValueError:
                m = ""
            out["src_nat"] = m
            if not m:
                out["notes"].append("static NAT: 変換後アドレスを求められない (src-nat-ipは空)")
        else:
            out["src_nat"] = info["src_nat"]
        if info["dst_ip"]:
            out["dst_ip"], out["dst_port"] = info["dst_ip"], info["dst_port"]
            self.dnat_used.setdefault(p.pid, {})[dip] = info["dst_ip"]
        if info["note"]:
            out["notes"].append(info["note"])
        if not stype and not info["dst_ip"]:
            out["notes"].append("変換なし(no-nat)")
        return out
