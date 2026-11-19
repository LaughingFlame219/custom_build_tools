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
import shlex
import xml.etree.ElementTree as ET
from collections import Counter

from fg2scenario import Addr, Policy, Svc, MAXIP, ip2s, s2ip

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
        self.services: dict = {}        # name -> [(proto, ports)]
        self.svc_groups: dict = {}
        self.app_groups: dict = {}
        self.rules: dict = {}           # name -> {field: [values]}  (定義順 = 評価順)


def parse_xml(text: str) -> PaloConfig:
    root = ET.fromstring(text.strip())
    cfg = PaloConfig()

    def members(e, tag):
        x = e.find(tag)
        if x is None:
            return []
        return [v for v in ((m.text or "").strip() for m in x.findall("member")) if v]

    def text_of(e, tag):
        x = e.find(tag)
        return (x.text or "").strip() if x is not None else ""

    for sec in root.iter("address"):
        for en in sec.findall("entry"):
            for kind in ADDR_KINDS:
                if en.find(kind) is not None:
                    cfg.addresses[en.get("name")] = (kind, text_of(en, kind))
                    break
    for sec in root.iter("address-group"):
        for en in sec.findall("entry"):
            if en.find("static") is not None:
                cfg.addr_groups[en.get("name")] = members(en, "static")
            else:
                cfg.dynamic_groups.add(en.get("name"))
    for sec in root.iter("service"):
        for en in sec.findall("entry"):
            prs = []
            for proto in ("tcp", "udp"):
                x = en.find(f"protocol/{proto}/port")
                if x is not None and x.text:
                    prs.append((proto, x.text.strip()))
            if prs:
                cfg.services[en.get("name")] = prs
    for sec in root.iter("service-group"):
        for en in sec.findall("entry"):
            cfg.svc_groups[en.get("name")] = members(en, "members")
    for sec in root.iter("application-group"):
        for en in sec.findall("entry"):
            cfg.app_groups[en.get("name")] = members(en, "members")
    for sec in root.iter("security"):
        rules = sec.find("rules")
        if rules is None:
            continue
        for en in rules.findall("entry"):
            f: dict = {}
            for tag in ("from", "to", "source", "destination", "application", "service"):
                f[tag] = members(en, tag)
            for tag in ("action", "disabled", "negate-source", "negate-destination", "rule-type", "description"):
                v = text_of(en, tag)
                f[tag] = [v] if v else []
            ps = en.find("profile-setting")
            f["profile-setting"] = [t.strip() for t in ps.itertext() if t.strip()] if ps is not None else []
            cfg.rules[en.get("name")] = f
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
        while toks:  # スコープ接頭辞を除去
            if toks[0] == "shared":
                toks = toks[1:]
            elif toks[0] in ("vsys", "device-group", "template") and len(toks) > 1:
                toks = toks[2:]
            else:
                break
        if toks and toks[0] in ("pre-rulebase", "post-rulebase"):
            toks[0] = "rulebase"
        if len(toks) < 3:
            continue
        k = toks[0]
        if k == "address" and len(toks) >= 4 and toks[2] in ADDR_KINDS:
            cfg.addresses[toks[1]] = (toks[2], toks[3])
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
            r = cfg.rules.setdefault(toks[3], {})
            r.setdefault(toks[4], []).extend(toks[5:])
    return cfg


# ---------------------------------------------------------------------------
# 2. オブジェクト解決 -> Policy
# ---------------------------------------------------------------------------
class PaloResolver:
    intrazone_allow = True  # Paloは同一ゾーン間が既定でallow

    def __init__(self, text: str, args):
        self.args = args
        self.warnings: Counter = Counter()
        self.warn_pols: dict = {}  # 警告メッセージ -> 該当ポリシー名のリスト
        self.cur = ""
        self.skipped: list = []
        self.cfg = parse_xml(text) if text.lstrip().startswith("<") else parse_set(text)

    def warn(self, msg: str):
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
            return Addr("range", name, lo, hi, text=f"{ip2s(lo)}-{ip2s(hi)}")
        if kind == "fqdn":
            ip = self.args.fqdn_map.get(value)  # --fqdn-map指定があればマッチ判定にも使う
            n = s2ip(ip) if ip else None
            return Addr("fqdn", name, n, n, text=value)
        self.warn(f"未対応のアドレスタイプ '{kind}' はスキップ (例: {name})")
        return Addr("unsupported", name, text=kind)

    def resolve_addr(self, name: str, seen: tuple = ()) -> list:
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
        try:  # ルールに直接書かれたIP/範囲
            if "-" in name:
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
    def build_policies(self) -> list:
        def first(f, k, d=""):
            v = f.get(k, [])
            return v[0] if v else d

        out: list = []
        for name, f in self.cfg.rules.items():
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
