#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fg2scenario.py - FortiGateコンフィグ -> ポリシーテスト用シナリオCSV

使い方:
  python fg2scenario.py fortigate.conf -o scenarios.csv
  python fg2scenario.py fortigate.conf -o scenarios.csv --negative --map tcp/8080=http
  python fg2scenario.py fortigate.conf -o scenarios.csv --fqdn-map www.example.com=203.0.113.10 --detail

出力はNEEDLEWORKのシナリオインポート形式 (protocol,src-ip,...,expect,result,ping-traceroute,description)。

対応: firewall policy / address / addrgrp / vip / service custom / service group
      (IPv4のみ。定義済みサービスは組み込みテーブルで解決)
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
import csv
import ipaddress
import shlex
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

MAXIP = 2**32 - 1


def ip2s(n: int) -> str:
    return str(ipaddress.IPv4Address(n))


def s2ip(s: str) -> int:
    return int(ipaddress.IPv4Address(s))


def policy_label(pid, name: str = "") -> str:
    """警告・一覧に出すポリシー名: 'ID' または 'ID (名前)'"""
    return f"{pid} ({name})" if name and name != str(pid) else str(pid)


# ---------------------------------------------------------------------------
# 1. 汎用コンフィグパーサー
# ---------------------------------------------------------------------------
def tokenize(line: str) -> list:
    try:
        return shlex.split(line, posix=True)
    except ValueError:
        return line.split()


def parse_config(text: str) -> dict:
    """config / edit / set / next / end を読み、入れ子の辞書にする。
    root[テーブル名][キー] = {項目: [値...], "_sub": {入れ子テーブル}}"""
    root: dict = {}
    stack: list = []  # ["config", container] / ["edit", entry]
    for raw in text.splitlines():
        t = tokenize(raw.strip())
        if not t:
            continue
        cmd = t[0]
        if cmd == "config":
            name = " ".join(t[1:])
            if stack:
                cont = stack[-1][1].setdefault("_sub", {}).setdefault(name, {})
            else:
                cont = root.setdefault(name, {})
            stack.append(["config", cont])
        elif cmd == "edit":
            if stack and stack[-1][0] == "config":
                entry: dict = {}
                stack[-1][1][t[1] if len(t) > 1 else ""] = entry
                stack.append(["edit", entry])
        elif cmd == "next":
            if stack and stack[-1][0] == "edit":
                stack.pop()
        elif cmd == "end":
            if stack and stack[-1][0] == "edit":
                stack.pop()
            if stack:
                stack.pop()
        elif cmd == "set" and stack and len(t) >= 2:
            stack[-1][1][t[1]] = t[2:]
        elif cmd == "append" and stack and stack[-1][0] == "edit" and len(t) >= 2:
            stack[-1][1].setdefault(t[1], []).extend(t[2:])
        elif cmd == "unset" and stack and stack[-1][0] == "edit" and len(t) >= 2:
            stack[-1][1].pop(t[1], None)
    return root


def vdom_names(root: dict) -> list:
    """マルチvdomコンフィグ (config vdom / edit <名前>) の、設定内容を持つvdom名 (定義順)。vdomなしなら空"""
    v = root.get("vdom", {})
    return [n for n, e in v.items() if isinstance(e, dict) and e.get("_sub")]


def get_table(root: dict, name: str, vdom: Optional[str] = None) -> dict:
    """テーブルを取得する。vdom指定ならそのvdom内を優先し、トップレベル(vdomなしコンフィグ)と
    config global (system interface など)も探す。vdom間でオブジェクトが混ざらない。"""
    scopes: list = []
    if vdom is not None:
        e = root.get("vdom", {}).get(vdom)
        if isinstance(e, dict):
            scopes.append(e.get("_sub", {}))
    scopes.append(root)
    g = root.get("global")
    if isinstance(g, dict):
        scopes.append(g.get("_sub", {}))
    out: dict = {}
    for sc in scopes:
        cont = sc.get(name)
        if isinstance(cont, dict):
            for k, e in cont.items():
                if k != "_sub" and isinstance(e, dict) and k not in out:
                    out[k] = e
    return out


def vals(e: dict, key: str) -> list:
    v = e.get(key, [])
    return v if isinstance(v, list) else []


def val(e: dict, key: str, default: str = "") -> str:
    v = vals(e, key)
    return v[0] if v else default


# ---------------------------------------------------------------------------
# 2. データモデル
# ---------------------------------------------------------------------------
@dataclass
class Addr:
    kind: str  # range | any | fqdn | unsupported
    name: str
    lo: Optional[int] = None
    hi: Optional[int] = None
    text: str = ""
    cidr: bool = False
    note: str = ""
    nat_ip: str = ""    # VIPのmappedip (dst-nat-ip)
    nat_port: str = ""  # VIPのmappedport (dst-nat-port)

    def contains(self, ip: int) -> bool:
        return self.lo is not None and self.hi is not None and self.lo <= ip <= self.hi


@dataclass
class Svc:
    name: str
    l4: str  # tcp / udp / icmp / any
    lo: int = 0
    hi: int = 65535
    # probes: (l4, port, アプリ層プロトコル, 単一ポートか)
    probes: list = field(default_factory=list)

    def matches(self, l4: str, port: int) -> bool:
        return (self.l4 == "any" or self.l4 == l4) and self.lo <= port <= self.hi


@dataclass
class Policy:
    pid: str
    name: str
    action: str
    srcintf: list
    dstintf: list
    nsrc: bool = False
    ndst: bool = False
    nsvc: bool = False
    src: list = field(default_factory=list)
    dst: list = field(default_factory=list)
    svc: list = field(default_factory=list)
    nat: str = ""
    utm: str = ""
    comments: str = ""
    gen_skip: str = ""
    disabled: bool = False
    src_names: list = field(default_factory=list)
    dst_names: list = field(default_factory=list)
    svc_names: list = field(default_factory=list)


# 定義済みサービス (名前 -> [(l4, port, app)])
BUILTIN = {
    "HTTP": [("tcp", 80, "http")],
    "HTTPS": [("tcp", 443, "https")],
    "DNS": [("udp", 53, "dns"), ("tcp", 53, "tcp")],
    "PING": [("icmp", 0, "icmp")],
    "ALL_ICMP": [("icmp", 0, "icmp")],
    "FTP": [("tcp", 21, "ftp")],
    "SMTP": [("tcp", 25, "smtp")],
    "SMTPS": [("tcp", 465, "tcp")],
    "IMAP": [("tcp", 143, "imap")],
    "IMAPS": [("tcp", 993, "tcp")],
    "POP3": [("tcp", 110, "tcp")],
    "SSH": [("tcp", 22, "tcp")],
    "TELNET": [("tcp", 23, "tcp")],
    "NTP": [("udp", 123, "udp")],
    "SNMP": [("udp", 161, "udp")],
    "SYSLOG": [("udp", 514, "udp")],
    "TFTP": [("udp", 69, "udp")],
    "LDAP": [("tcp", 389, "tcp")],
    "LDAPS": [("tcp", 636, "tcp")],
    "RDP": [("tcp", 3389, "tcp")],
    "SMB": [("tcp", 445, "tcp")],
    "MYSQL": [("tcp", 3306, "tcp")],
    "MS-SQL": [("tcp", 1433, "tcp")],
    "KERBEROS": [("tcp", 88, "tcp")],
}


# ---------------------------------------------------------------------------
# 3. オブジェクト解決
# ---------------------------------------------------------------------------
class Resolver:
    intrazone_allow = False  # 同一ゾーン間の既定動作 (Paloはallow)

    def __init__(self, root: dict, args, vdom: Optional[str] = None):
        self.args = args
        self.vdom = vdom
        self.addrs = get_table(root, "firewall address", vdom)
        self.grps = get_table(root, "firewall addrgrp", vdom)
        self.vips = get_table(root, "firewall vip", vdom)
        self.custom = get_table(root, "firewall service custom", vdom)
        self.sgrps = get_table(root, "firewall service group", vdom)
        self.raw_policies = get_table(root, "firewall policy", vdom)
        self.warnings: Counter = Counter()
        self.warn_pols: dict = {}  # 警告メッセージ -> 該当ポリシー名のリスト
        self.cur = ""
        self.skipped: list = []

    def warn(self, msg: str):
        self.warnings[msg] += 1
        if self.cur:  # どのポリシーの処理中に出た警告かを記録する
            lst = self.warn_pols.setdefault(msg, [])
            if self.cur not in lst:
                lst.append(self.cur)

    # ---- アドレス ----
    def resolve_addr(self, name: str, seen: Optional[set] = None) -> list:
        seen = seen or set()
        if name in seen:
            self.warn(f"アドレスグループの循環参照: {name}")
            return []
        seen = seen | {name}
        if name in self.addrs:
            return [self._addr_obj(name, self.addrs[name])]
        if name in self.grps:
            out: list = []
            for m in vals(self.grps[name], "member"):
                out += self.resolve_addr(m, seen)
            return out
        if name in self.vips:
            e = self.vips[name]
            extip = val(e, "extip").split("-")[0]
            try:
                n = s2ip(extip)
            except ValueError:
                self.warn(f"VIP '{name}' のextipを解析できません")
                return [Addr("unsupported", name)]
            note = f"VIP {name}: mappedip={' '.join(vals(e, 'mappedip'))}"
            nat_port = val(e, "mappedport").split("-")[0] if val(e, "portforward") == "enable" else ""
            return [Addr("range", name, n, n, text=extip, note=note,
                         nat_ip=val(e, "mappedip").split("-")[0], nat_port=nat_port)]
        if name.lower() == "all":
            return [Addr("any", name, 0, MAXIP, text="all")]
        self.warn(f"未定義のアドレス: {name}")
        return [Addr("unsupported", name)]

    def _addr_obj(self, name: str, e: dict) -> Addr:
        t = val(e, "type", "ipmask")
        try:
            if t in ("ipmask", "interface-subnet"):
                s = e.get("subnet")
                if not s:
                    if t == "ipmask":  # FortiGateは既定値(0.0.0.0 0.0.0.0)を出力しない
                        return Addr("any", name, 0, MAXIP, text="0.0.0.0/0")
                    raise ValueError("subnet未設定")
                net = ipaddress.ip_network("/".join(s[:2]), strict=False)
                if net.prefixlen == 0:
                    return Addr("any", name, 0, MAXIP, text=str(net))
                return Addr("range", name, int(net.network_address),
                            int(net.broadcast_address), text=str(net), cidr=True)
            if t == "iprange":
                a, b = s2ip(val(e, "start-ip")), s2ip(val(e, "end-ip"))
                return Addr("range", name, a, b, text=f"{ip2s(a)}-{ip2s(b)}")
            if t == "fqdn":
                fq = val(e, "fqdn")
                ip = self.args.fqdn_map.get(fq)  # --fqdn-map指定があればマッチ判定にも使う
                n = s2ip(ip) if ip else None
                return Addr("fqdn", name, n, n, text=fq)
        except ValueError as ex:
            self.warn(f"アドレス '{name}' の解析失敗: {ex}")
            return Addr("unsupported", name)
        self.warn(f"未対応のアドレスタイプ '{t}' はスキップ (例: {name})")
        return Addr("unsupported", name, text=t)

    # ---- サービス ----
    def resolve_service(self, name: str, seen: Optional[set] = None) -> list:
        seen = seen or set()
        if name in seen:
            return []
        seen = seen | {name}
        if name in self.custom and name != "ALL":
            return self._custom_svc(name, self.custom[name])
        if name in self.sgrps:
            out: list = []
            for m in vals(self.sgrps[name], "member"):
                out += self.resolve_service(m, seen)
            return out
        key = name if name in BUILTIN else name.upper()
        if key == "ALL":
            return [Svc(name, "any", 0, 65535, [("udp", 53, "dns", False),
                                                 ("tcp", 80, "http", False),
                                                 ("tcp", 443, "https", False)])]
        if key == "ALL_TCP":
            return [Svc(name, "tcp", 1, 65535, [("tcp", 80, "tcp", False), ("tcp", 443, "tcp", False)])]
        if key == "ALL_UDP":
            return [Svc(name, "udp", 1, 65535, [("udp", 53, "udp", False)])]
        if key in BUILTIN:
            return [Svc(name, l4, port, port, [(l4, port, app, True)]) for l4, port, app in BUILTIN[key]]
        self.warn(f"未定義/未対応のサービス: {name}")
        return []

    def _sample_ports(self, lo: int, hi: int) -> list:
        pts = [lo]
        if hi != lo:
            pts.append(hi)
        if hi - lo >= 2:
            pts.append((lo + hi) // 2)
        return pts[: self.args.max_port]

    def _custom_svc(self, name: str, e: dict) -> list:
        out: list = []
        proto = val(e, "protocol", "TCP/UDP/SCTP").upper()
        if proto in ("TCP/UDP/SCTP", "TCP/UDP"):
            for l4, key in (("tcp", "tcp-portrange"), ("udp", "udp-portrange")):
                for tok in vals(e, key):
                    dport = tok.split(":")[0]  # "8080:1024" の後半は送信元ポート指定
                    try:
                        a, b = dport.split("-", 1) if "-" in dport else (dport, dport)
                        lo, hi = int(a), int(b)
                    except ValueError:
                        self.warn(f"サービス '{name}' のポート書式を解析できません: {tok}")
                        continue
                    out.append(Svc(name, l4, lo, hi,
                                   [(l4, p, l4, lo == hi) for p in self._sample_ports(lo, hi)]))
            if "sctp-portrange" in e:
                self.warn(f"サービス '{name}': sctpは未対応")
            if not out:
                self.warn(f"サービス '{name}': ポート指定なしのためスキップ")
        elif proto == "ICMP":
            out.append(Svc(name, "icmp", 0, 0, [("icmp", 0, "icmp", False)]))
        else:
            self.warn(f"サービス '{name}': protocol {proto} は未対応")
        return out

    # ---- ポリシー ----
    def build_policies(self) -> list:
        out: list = []
        for pid, e in self.raw_policies.items():
            disabled = val(e, "status", "enable") == "disable"
            if disabled and not getattr(self.args, "include_disabled", True):
                self.skipped.append((pid, "status disable"))
                continue
            p = Policy(
                pid=pid, name=val(e, "name"),
                action=val(e, "action", "deny"),  # actionの省略時はdeny
                srcintf=vals(e, "srcintf"), dstintf=vals(e, "dstintf"),
                nsrc=val(e, "negate-srcaddr") == "enable",
                ndst=val(e, "negate-dstaddr") == "enable",
                nsvc=val(e, "negate-service") == "enable",
                nat=val(e, "nat"), comments=val(e, "comments"), disabled=disabled,
            )
            self.cur = policy_label(pid, p.name)
            p.src_names, p.dst_names = vals(e, "srcaddr"), vals(e, "dstaddr")
            p.svc_names = vals(e, "service")
            p.src = [a for n in vals(e, "srcaddr") for a in self.resolve_addr(n)]
            p.dst = [a for n in vals(e, "dstaddr") for a in self.resolve_addr(n)]
            p.svc = [s for n in vals(e, "service") for s in self.resolve_service(n)]
            if val(e, "utm-status") == "enable":
                parts = []
                for k, label in (("av-profile", "av"), ("webfilter-profile", "web"),
                                 ("ips-sensor", "ips"), ("application-list", "app")):
                    if val(e, k):
                        parts.append(f"{label}={val(e, k)}")
                p.utm = ";".join(parts)
            if val(e, "internet-service") == "enable" or val(e, "internet-service-src") == "enable":
                p.gen_skip = "internet-service使用 (未対応)"
            elif not (vals(e, "srcaddr") and vals(e, "dstaddr") and vals(e, "service")):
                p.gen_skip = "srcaddr/dstaddr/service未設定"
            elif p.nsrc or p.ndst or p.nsvc:
                p.gen_skip = "negate指定 (テスト生成対象外。マッチ判定には反映)"
            elif p.action not in ("accept", "deny", "ipsec"):
                p.gen_skip = f"action {p.action} は未対応"
            elif not p.svc:
                p.gen_skip = "サービスが未対応/未定義のためシナリオを生成できない"
            elif all(a.kind == "unsupported" for a in p.src) or all(a.kind == "unsupported" for a in p.dst):
                p.gen_skip = "アドレスが未対応/未定義のためシナリオを生成できない"
            if p.gen_skip:
                self.skipped.append((policy_label(pid, p.name), p.gen_skip))
            out.append(p)
        return out


# ---------------------------------------------------------------------------
# 4. シナリオ生成
# ---------------------------------------------------------------------------
def pick(lst: list, n: int) -> list:
    """先頭・末尾・中間を残して n 個に間引く"""
    if n <= 0 or len(lst) <= n:
        return lst
    if n == 1:
        return lst[:1]
    idx = sorted({round(i * (len(lst) - 1) / (n - 1)) for i in range(n)})
    return [lst[i] for i in idx]


def uniq(seq) -> list:
    return list(dict.fromkeys(seq))


def addr_samples(a: Addr, any_ip: str, args, rs: Resolver) -> list:
    """アドレスオブジェクト1つ分の代表IP。
    (ip文字列, 単一IPか, fqdn, dst-nat-ip, dst-nat-port, オブジェクト名) のリスト。
    グループは呼び出し側で全メンバーに展開済みなので、メンバーごとに1回呼ばれる。"""
    if a.kind == "any":
        return [(any_ip, False, "", "", "", a.name)]
    if a.kind == "fqdn":
        ip = args.fqdn_map.get(a.text)  # --fqdn-map があればIP、なければFQDN文字列をそのまま記載
        return [(ip or a.text, False, a.text, "", "", a.name)]
    if a.kind == "range" and a.lo is not None and a.hi is not None:
        if a.lo == a.hi:
            return [(ip2s(a.lo), True, "", a.nat_ip, a.nat_port, a.name)]
        lo, hi = a.lo, a.hi
        if a.cidr and hi - lo >= 3:  # ネットワーク/ブロードキャストアドレスを避ける
            lo, hi = lo + 1, hi - 1
        n = max(1, args.max_addr)  # 1=先頭 / 2=先頭+末尾 / 3以上=先頭+末尾+中間
        pts = [lo]
        if n >= 2:
            pts.append(hi)
        if n >= 3 and hi - lo >= 2:
            pts.append((lo + hi) // 2)
        return [(ip2s(x), False, "", "", "", a.name) for x in pts]
    return []


def policy_matches(p: Policy, si, di, sip: int, dip: int, l4: str, port: int) -> bool:
    # テスト側のインターフェース/ゾーンが "any" の場合は、どのポリシーのIFにも合うものとして扱う
    if si != "any" and "any" not in p.srcintf and si not in p.srcintf:
        return False
    if di != "any" and "any" not in p.dstintf and di not in p.dstintf:
        return False
    s = any(a.contains(sip) for a in p.src)
    d = any(a.contains(dip) for a in p.dst)
    v = any(x.matches(l4, port) for x in p.svc)
    return (s != p.nsrc) and (d != p.ndst) and (v != p.nsvc)


def _ipint(x: str) -> Optional[int]:
    try:
        return s2ip(x)
    except ValueError:
        return None


class FastMatcher:
    """先にマッチするポリシーを高速に求める (policy_matches と同じ判定結果)。
    * アドレス/サービスは事前にまとめて範囲を結合し、二分探索で判定
    * インターフェースの組ごとに、対象になり得るポリシーだけを (評価順のまま) 絞り込んでキャッシュ
    * 同じ条件の問い合わせはメモ化"""

    def __init__(self, policies: list, include_disabled_as_enabled: bool):
        self.items = []
        for q in policies:
            if q.disabled and not include_disabled_as_enabled:
                continue  # 無効ポリシーは実際にはマッチしない
            self.items.append((q, self._side(q.src), self._side(q.dst),
                               [(x.l4, x.lo, x.hi) for x in q.svc]))
        self.by_if: dict = {}
        self.memo: dict = {}

    @classmethod
    def _side(cls, addrs: list) -> tuple:
        """(範囲, FQDN名の集合, anyを含むか)"""
        return (cls._ranges(addrs), {a.text for a in addrs if a.kind == "fqdn"},
                any(a.kind == "any" for a in addrs))

    @staticmethod
    def _ranges(addrs: list) -> tuple:
        rs = sorted((a.lo, a.hi) for a in addrs if a.lo is not None and a.hi is not None)
        merged: list = []
        for lo, hi in rs:
            if merged and lo <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        return [m[0] for m in merged], [m[1] for m in merged]

    @staticmethod
    def _in(rng: tuple, x: int) -> bool:
        i = bisect_right(rng[0], x) - 1
        return i >= 0 and x <= rng[1][i]

    def _hit(self, side: tuple, ip: Optional[int], raw: str) -> bool:
        rng, names, anyflag = side
        if anyflag:
            return True
        return raw in names if ip is None else self._in(rng, ip)

    def _candidates(self, si, di) -> list:
        key = (si, di)
        c = self.by_if.get(key)
        if c is None:
            c = [it for it in self.items
                 if (si == "any" or "any" in it[0].srcintf or si in it[0].srcintf)
                 and (di == "any" or "any" in it[0].dstintf or di in it[0].dstintf)]
            self.by_if[key] = c
        return c

    def first(self, si, di, sip: str, dip: str, l4: str, port: int):
        key = (si, di, sip, dip, l4, port)
        if key in self.memo:
            return self.memo[key]
        s, d = _ipint(sip), _ipint(dip)  # IPでなければ None (FQDN名のまま照合する)
        res = None
        for q, src, dst, svc in self._candidates(si, di):
            v = any((k == "any" or k == l4) and lo <= port <= hi for k, lo, hi in svc)
            if v == q.nsvc:
                continue
            if self._hit(src, s, sip) == q.nsrc or self._hit(dst, d, dip) == q.ndst:
                continue
            res = q
            break
        self.memo[key] = res
        return res


# NEEDLEWORKのシナリオインポート列 (ヘッダー名はサンプルCSVと同一)
NW_COLUMNS = ["protocol", "src-ip", "src-port(option)", "src-nat-ip(option)",
              "is-receiver-physical(option)", "dst-nat-ip(option)", "dst-nat-port (option)",
              "dst-ip", "dst-port", "url/domain(option)", "anti-virus(option)",
              "timeout(option)", "try(option)", "expect", "result", "ping-traceroute", "description"]
# 追跡用の詳細CSV (--detail)
DETAIL_COLUMNS = ["scenario_name", "vdom", "policy_id", "kind", "src_intf", "dst_intf", "src_ip", "dst_ip",
                  "dst_port", "protocol", "expect", "nat", "utm", "note"]


def generate(rs: Resolver, policies: list, args) -> list:
    rows: list = []
    seen: set = set()
    counters: Counter = Counter()

    # 無効ポリシーは実際にはマッチしない (disabled_mode=policy のときだけ有効扱い)
    matcher = FastMatcher(policies, getattr(args, "disabled_mode", "actual") != "actual")
    first_match = matcher.first

    def emit(p, kind, si, di, sip, dip, fqdn, l4, port, app, nat_ip="", nat_port="", extra="", objs=("", "")):
        key = (p.pid, si, di, sip, dip, l4, port, app)
        if key in seen:
            return
        seen.add(key)
        notes = [extra] if extra else []
        q = first_match(si, di, sip, dip, l4, port)
        if q is None:
            if rs.intrazone_allow and si == di:
                action = "accept"
                notes.append("どのルールにもマッチせずintrazone-default(allow)")
            else:
                action = "deny"
                notes.append("どのポリシーにもマッチせず暗黙deny")
        else:
            action = q.action
            if q is not p:
                notes.append(f"policy {q.pid}が先にマッチ")
        if _ipint(sip) is None or _ipint(dip) is None:
            notes.append("FQDNをIP解決せず記載: ポリシー照合はFQDN名で実施")
        if p.nat == "enable":
            notes.append("SNAT有効(src-nat-ipは要設定)")
        if p.disabled:
            if getattr(args, "disabled_mode", "actual") == "actual":
                notes.append("ポリシーはdisable: マッチしない前提で期待値を算出")
            else:
                notes.append("ポリシーはdisable: enable扱いで期待値を算出")
        if action in ("accept", "ipsec"):
            expect = "pass"
        elif action == "reject":  # RSTやICMP unreachableを返す拒否
            expect = "block"
        else:
            expect = args.deny_as
        desc = (f"policy: {p.name or p.pid} | action: {p.action} | src: {','.join(p.src_names)}"
                f" | dst: {','.join(p.dst_names)} | services: {','.join(p.svc_names)}")
        if p.disabled:
            desc += " | status: disable"
        if getattr(rs, "vdom", None):
            desc += f" | vdom: {rs.vdom}"
        # グループ指定のときは、実際に使ったメンバーのオブジェクト名も残す
        if objs[0] and objs[0] not in p.src_names:
            desc += f" | src-obj: {objs[0]}"
        if objs[1] and objs[1] not in p.dst_names:
            desc += f" | dst-obj: {objs[1]}"
        if kind != "policy":
            desc += f" | test: {kind}"
        if notes:
            desc += " | note: " + " / ".join(notes)
        counters[p.pid] += 1
        nw = {c: "" for c in NW_COLUMNS}
        nw.update({
            "protocol": app, "src-ip": sip, "dst-ip": dip,
            "dst-port": "" if l4 == "icmp" else port,
            "dst-nat-ip(option)": nat_ip, "dst-nat-port (option)": nat_port,
            "url/domain(option)": fqdn if app in ("http", "https", "dns") else "",
            "expect": expect, "description": desc,
        })
        detail = {"scenario_name": f"policy{p.pid}-{counters[p.pid]}", "vdom": getattr(rs, "vdom", None) or "",
                  "policy_id": p.pid, "kind": kind,
                  "src_intf": si, "dst_intf": di, "src_ip": sip, "dst_ip": dip,
                  "dst_port": nw["dst-port"], "protocol": app, "expect": expect,
                  "nat": p.nat, "utm": p.utm, "note": " / ".join(notes)}
        rows.append({"nw": nw, "detail": detail})

    for p in policies:
        rs.cur = policy_label(p.pid, p.name)
        if p.gen_skip:
            continue
        # 送信元/宛先がグループ・オブジェクトなら、全メンバーを対象にする (間引かない)
        srcs = uniq(s for a in p.src for s in addr_samples(a, args.any_src, args, rs))
        dsts = uniq(s for a in p.dst for s in addr_samples(a, args.any_dst, args, rs))
        probes = pick(uniq(x for sv in p.svc for x in sv.probes), args.max_svc)
        pairs = [(a, b) for a in p.srcintf for b in p.dstintf]
        combos = [(pr, s, d, pb) for pr in pairs for s in srcs for d in dsts for pb in probes]
        for (si, di), (sip, ssingle, _, _, _, sobj), (dip, _, fqdn, nip, nport, dobj), (l4, port, app, single) in pick(
                combos, args.max_per_policy):  # max_per_policy=0 なら無制限
            objs = (sobj, dobj)
            app = args.map.get((l4, port), app)
            emit(p, "policy", si, di, sip, dip, fqdn, l4, port, app, nip, nport, objs=objs)
            if args.negative and p.action == "accept" and not p.disabled:
                if l4 in ("tcp", "udp") and single and port < 65535:
                    emit(p, "neg-port", si, di, sip, dip, fqdn, l4, port + 1, l4, nip, nport, "許可ポートの隣", objs)
                if ssingle and s2ip(sip) < MAXIP:
                    emit(p, "neg-src", si, di, ip2s(s2ip(sip) + 1), dip, fqdn, l4, port, app, nip, nport,
                         "許可送信元の隣のIP", objs)
    return rows


# ---------------------------------------------------------------------------
# 5. CLI
# ---------------------------------------------------------------------------
def parse_map(items: list) -> dict:
    m = {}
    for it in items or []:
        try:
            left, app = it.split("=", 1)
            l4, port = left.split("/", 1)
            m[(l4.lower(), int(port))] = app.lower()
        except ValueError:
            sys.exit(f"--map の書式が不正です: {it} (例: tcp/8080=http)")
    return m


def parse_fqdn_map(items: list) -> dict:
    m = {}
    for it in items or []:
        if "=" not in it:
            sys.exit(f"--fqdn-map の書式が不正です: {it} (例: www.example.com=203.0.113.10)")
        k, v = it.split("=", 1)
        m[k.strip()] = v.strip()
    return m


def main():
    ap = argparse.ArgumentParser(description="FortiGateコンフィグからシナリオCSVを生成")
    ap.add_argument("config", help="FortiGateコンフィグファイル")
    ap.add_argument("-o", "--output", default="scenarios.csv")
    ap.add_argument("--max-addr", type=int, default=3, help="サブネット/範囲オブジェクト1つあたりの代表IP数 (既定3: 先頭/末尾/中間)")
    ap.add_argument("--max-port", type=int, default=3, help="ポート範囲の代表ポート数 (既定3)")
    ap.add_argument("--max-svc", type=int, default=6, help="ポリシーあたりの代表サービス上限")
    ap.add_argument("--max-per-policy", type=int, default=0, help="ポリシーあたりの最大シナリオ数 (0=無制限)")
    ap.add_argument("--map", action="append", help="例: tcp/8080=http (カスタムサービスのアプリ層指定)")
    ap.add_argument("--negative", action="store_true", help="許可の境界(隣のポート/IP)の拒否テストも生成")
    ap.add_argument("--deny-as", default="drop", choices=["drop", "block"], help="denyのexpect値 (既定drop)")
    ap.add_argument("--fqdn-map", action="append", help="FQDN宛先のIP指定。例: www.example.com=203.0.113.10")
    ap.add_argument("--detail", action="store_true", help="追跡用の詳細CSV (<output>.detail.csv) も出力")
    ap.add_argument("--any-src", default="192.0.2.1", help="srcaddrがallの時の代表IP")
    ap.add_argument("--any-dst", default="198.51.100.1", help="dstaddrがallの時の代表IP")
    args = ap.parse_args()
    args.map = parse_map(args.map)
    args.fqdn_map = parse_fqdn_map(args.fqdn_map)

    with open(args.config, encoding="utf-8", errors="replace") as f:
        root = parse_config(f.read())
    rs = Resolver(root, args)
    policies = rs.build_policies()
    rows = generate(rs, policies, args)

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=NW_COLUMNS)
        w.writeheader()
        w.writerows(r["nw"] for r in rows)
    if args.detail:
        with open(args.output + ".detail.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=DETAIL_COLUMNS)
            w.writeheader()
            w.writerows(r["detail"] for r in rows)

    print(f"ポリシー {len(policies)}件 -> シナリオ {len(rows)}件 -> {args.output}", file=sys.stderr)
    for pid, reason in rs.skipped:
        print(f"  [skip] policy{pid}: {reason}", file=sys.stderr)
    for msg, n in rs.warnings.items():
        print(f"  [warn] {msg} (x{n})", file=sys.stderr)


if __name__ == "__main__":
    main()
