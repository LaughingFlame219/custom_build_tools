# -*- coding: utf-8 -*-
"""
vrouter_gen.py - FortiGateコンフィグ -> NEEDLEWORK仮想ルーター設定ファイル (.toml)

出力はNEEDLEWORKが保存する形式 (version = "1902"、二重引用符) に合わせている。

考え方:
  FortiGateの「ポリシーで使われているインターフェース/ゾーン」1つにつき、テスター側に
    * インターフェース
        - FGがVLANインターフェース: eth0/N(物理)には設定を入れず、eth0/Nをbase_ifとする
          VLANインターフェースを作る。名前はFGのVLANインターフェース名に揃える
        - VLANなし: eth0/N 自身にIPを置く
    * 仮想ルーター (所属IF=そのインターフェース、external 0.0.0.0/0 -> FGのインターフェースIP)
  を1組作る。テスターは「FGの各セグメントにいるホスト」として振る舞う。
  VRをセグメントごとに分けるのは、1つのVRに入れるとテスター内部で直接ルーティングされ、
  FWを経由しなくなるため。

  テスター側IP = そのサブネットの先頭ホスト (FGのIP/セカンダリIPと被る場合は次のホスト)
  FGインターフェースの親(物理)ごとに eth0/1, eth0/2, ... を順に割り当てる。
  使用するeth0/Nには、OSインターフェースを イーサネット, イーサネット 2, イーサネット 3, ... の順に割り当てる。

  internalルート:
    ポリシーの 送信元アドレス を送信元インターフェースの仮想ルーターに、宛先アドレス を宛先インターフェースの
    仮想ルーターに書く。ただし、そのインターフェースのサブネットに含まれるアドレスは書かない
    (所属インターフェースのネットワークは、適用時にNEEDLEWORKがinternalへ自動追加するため)。
    * アドレスオブジェクトのサブネット/IPをそのまま書く (範囲はCIDRに分解、包含/隣接は1つにまとめる)。コメントは空
    * all (any) は 0.0.0.0/0 にせず、シナリオで使う代表IP (/32) を書く
    * /31 は書かない (/32 を2つに分ける)
    * ネットワークの重複は許されない: インターフェースのネットワークと internal の宛先ネットワークは、
      他の仮想ルーターとも重複させない。重なる部分は除いた別のセグメントに分けて書く。
      同じ範囲を取り合う場合は、ポリシーの順に先に使ったほうの仮想ルーターが持つ (送信元 -> 宛先の順)。
"""
from __future__ import annotations

import ipaddress
from bisect import bisect_left, bisect_right
from collections import Counter

from fg2scenario import get_table, policy_label, val, vals

VERSION = "1902"


class Warns(Counter):
    """警告メッセージ -> 件数。ポリシーに関する警告は .pols にポリシー名のリストも持つ"""

    def __init__(self):
        super().__init__()
        self.pols: dict = {}

    def add(self, msg: str, label: str = ""):
        self[msg] += 1
        if label:
            lst = self.pols.setdefault(msg, [])
            if label not in lst:
                lst.append(label)


def q(s) -> str:
    """TOMLの基本文字列 (二重引用符)。 \\ と " だけエスケープする"""
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def default_os_if(n: int) -> str:
    """eth0/N に割り当てるOSインターフェース名 (Windowsの既定名)。1=イーサネット, 2=イーサネット 2, ..."""
    return "イーサネット" if n == 1 else f"イーサネット {n}"


def _used_names(policies: list, zones: dict) -> list:
    out: list = []
    for p in policies:
        for n in list(p.srcintf) + list(p.dstintf):
            if n == "any":
                continue
            out += vals(zones[n], "interface") if n in zones else [n]
    return list(dict.fromkeys(out))


def _nets(a, dummy: str):
    """アドレスオブジェクト -> [(IPv4Network, ラベル)]。IPが決まらなければ None"""
    if a.kind == "any":  # all は 0.0.0.0/0 にせず、シナリオで使う代表IPにする
        return [(ipaddress.ip_network(f"{dummy}/32"), f"{a.name}(代表IP)")]
    if a.lo is None or a.hi is None:
        return None
    return [(n, a.name) for n in ipaddress.summarize_address_range(
        ipaddress.IPv4Address(a.lo), ipaddress.IPv4Address(a.hi))]


def _final_nets(nets: list) -> list:
    """包含/隣接するものを1つにまとめ、/31 は /32 を2つに分ける (どちらも元の範囲は変わらない)"""
    out: list = []
    for n in ipaddress.collapse_addresses(nets):
        out += [ipaddress.ip_network(h) for h in n] if n.prefixlen == 31 else [n]
    return sorted(out, key=lambda n: (int(n.network_address), n.prefixlen))


class _Occupied:
    """使用済みのIP範囲 (重ならない区間を開始アドレス順に保持)。持ち主は ("if", i) / ("vr", i)"""

    def __init__(self):
        self.starts: list = []
        self.items: list = []

    def add(self, s: int, e: int, owner) -> None:
        i = bisect_left(self.starts, s)
        self.starts.insert(i, s)
        self.items.insert(i, (s, e, owner))

    def claim(self, S: int, E: int, ignore: set) -> tuple:
        """[S,E] のうち未使用の区間 parts と、他の持ち主との重複 conflicts を返す。
        ignore に含まれる持ち主 (自分自身) との重複は、衝突として数えない"""
        parts: list = []
        conflicts: list = []
        cur = S
        j = bisect_right(self.starts, S) - 1
        if j < 0 or self.items[j][1] < S:
            j += 1
        while j < len(self.items) and self.items[j][0] <= E:
            s0, e0, o = self.items[j]
            if s0 > cur:
                parts.append((cur, s0 - 1))
            if o not in ignore:
                conflicts.append(o)
            cur = max(cur, e0 + 1)
            j += 1
        if cur <= E:
            parts.append((cur, E))
        return parts, conflicts


def build_fortigate(root: dict, policies: list, if_map: dict = None, tester_ips: dict = None,
                    vr_names: dict = None, vdom: str = None, os_ifs: list = None,
                    any_src: str = "192.0.2.1", any_dst: str = "198.51.100.1",
                    with_internal: bool = True) -> tuple:
    """(toml文字列, 警告Counter, セグメントのリスト) を返す。
    if_map:     {"port1": "eth0/2"}      FG側の親IF -> テスターの物理IF
    tester_ips: {"wan2": "10.20.28.5"}   FGインターフェース名 -> テスター側IP
    vr_names:   {"wan2": "default"}      FGインターフェース名 -> 仮想ルーター名
    os_ifs:     ["イーサネット", ...]    eth0/1から順に割り当てるOSインターフェース名 (省略時は既定名)
    any_src/any_dst: アドレスが all のときにシナリオで使う代表IP (internalにはこの/32を書く)
    with_internal: False ならinternalルートを書かない"""
    if_map, tester_ips, vr_names = if_map or {}, tester_ips or {}, vr_names or {}
    warn = Warns()
    ifs = get_table(root, "system interface", vdom)
    zones = get_table(root, "system zone", vdom)

    segs: list = []
    for name in _used_names(policies, zones):
        e = ifs.get(name)
        if e is None:
            warn[f"インターフェース '{name}' の定義が見つからないためスキップ"] += 1
            continue
        if vdom is not None and val(e, "vdom", "root") != vdom:
            warn[f"インターフェース '{name}' は別vdom({val(e, 'vdom', 'root')})のためスキップ"] += 1
            continue
        parts = vals(e, "ip")
        try:
            if len(parts) < 2 or parts[0] == "0.0.0.0":
                raise ValueError("IP未設定 (DHCP/PPPoE含む)")
            ifc = ipaddress.ip_interface(f"{parts[0]}/{parts[1]}")
            if ifc.network.prefixlen >= 32:
                raise ValueError("/32 はテスターのIPを置けない")
        except ValueError as ex:
            warn[f"インターフェース '{name}' をスキップ: {ex}"] += 1
            continue
        vlanid = val(e, "vlanid")
        parent = (val(e, "interface") or name) if vlanid else name
        reserved = {ifc.ip}
        for sec in (e.get("_sub", {}).get("secondaryip", {}) or {}).values():
            sp = vals(sec, "ip")
            if len(sp) >= 2:
                try:
                    reserved.add(ipaddress.ip_interface(f"{sp[0]}/{sp[1]}").ip)
                except ValueError:
                    pass
        if name in tester_ips:
            tip = ipaddress.ip_address(tester_ips[name])
        else:
            tip = next((h for h in ifc.network.hosts() if h not in reserved), None)
            if tip is None:
                warn[f"インターフェース '{name}' のサブネットに空きホストがありません"] += 1
                continue
        segs.append({"fg": name, "vlan": vlanid, "parent": parent, "fgip": str(ifc.ip),
                     "tip": str(tip), "prefix": ifc.network.prefixlen, "net": ifc.network, "inet": []})

    return _assemble(segs, policies, warn, lambda n: vals(zones[n], "interface") if n in zones else [n],
                     if_map, vr_names, os_ifs, any_src, any_dst, with_internal)


def _assemble(segs: list, policies: list, warn: Counter, expand, if_map: dict, vr_names: dict, os_ifs,
              any_src: str, any_dst: str, with_internal: bool, extra_claims: list = None,
              skip_dst: dict = None) -> tuple:
    """セグメント一覧 -> TOML。FortiGate/Paloで共通。
    segs:   [{"fg": FG側インターフェース名, "vlan": VLAN ID or None, "parent": 親IF名, "fgip", "tip", "prefix",
              "net", "inet": [], "vr": 仮想ルーター名(省略時は fg)}]
    expand: ゾーン/インターフェース名 -> インターフェース名のリスト
    extra_claims: [(インターフェース/ゾーン名のリスト, IP, ラベル)]  追加でinternalに書くIP (宛先NATの実宛先など)
    skip_dst:     {ポリシーID: {IP}}  そのポリシーの宛先としては internal に書かないIP (宛先NATの変換前アドレス)"""
    if_map, vr_names = if_map or {}, vr_names or {}
    skip_dst = skip_dst or {}
    # 親IF -> eth0/N
    mapping = dict(if_map)
    taken = set(mapping.values())
    n = 0
    for s in segs:
        if s["parent"] not in mapping:
            while True:
                n += 1
                cand = f"eth0/{n}"
                if cand not in taken:
                    break
            mapping[s["parent"]] = cand
            taken.add(cand)
    for s in segs:
        s["eth"] = mapping[s["parent"]]

    def vrname(seg: dict) -> str:
        return vr_names.get(seg["fg"], seg.get("vr") or seg["fg"])

    # internalルート: 送信元/宛先アドレスのネットワークを、該当インターフェースの仮想ルーターに書く
    if with_internal:
        for i, sg in enumerate(segs):
            sg["idx"] = i
        seg_by_fg = {sg["fg"]: sg for sg in segs}
        claims: dict = {}  # (セグメント番号, ネットワーク) -> [ポリシー名]  (ポリシー順・送信元->宛先の順)
        for p in policies:
            if p.gen_skip:  # シナリオを生成しないポリシーは対象外
                continue
            label = policy_label(p.pid, p.name)
            for what, addrs, intfs, dummy in (("送信元", p.src, p.srcintf, any_src),
                                              ("宛先", p.dst, p.dstintf, any_dst)):
                if "any" in intfs:
                    warn.add(f"{what}インターフェースが any のため internal ルートを決められない", label)
                    continue
                names = [x for n in intfs for x in expand(n)]
                targets = [seg_by_fg[n] for n in dict.fromkeys(names) if n in seg_by_fg]
                skip = skip_dst.get(p.pid, ()) if what == "宛先" else ()
                for a in addrs:
                    got = _nets(a, dummy)
                    if got is None:
                        if a.kind == "fqdn":
                            warn.add("FQDNアドレスはIPがないため internal ルートに書けない (FQDNのIP指定を入れると書ける)", label)
                        continue
                    for net, _ in got:
                        if skip and net.prefixlen == 32 and str(net.network_address) in skip:
                            continue  # 宛先NATの変換前アドレス (実宛先は extra_claims 側で書く)
                        for t in targets:
                            lst = claims.setdefault((t["idx"], net), [])
                            if label not in lst:
                                lst.append(label)

        for intfs, ip, label in extra_claims or []:
            names = [x for n in intfs if n != "any" for x in expand(n)]
            for n in dict.fromkeys(names):
                if n in seg_by_fg:
                    lst = claims.setdefault((seg_by_fg[n]["idx"], ipaddress.ip_network(f"{ip}/32")), [])
                    if label not in lst:
                        lst.append(label)

        # 先にインターフェースのネットワークを確保し、重複するものは書かない
        occ = _Occupied()
        for sg in segs:
            n = sg["net"]
            parts, conflicts = occ.claim(int(n.network_address), int(n.broadcast_address), set())
            if conflicts:
                warn.add(f"インターフェース '{sg['fg']}' のネットワーク {n} が他のインターフェースと重複しています")
            for ps, pe in parts:
                occ.add(ps, pe, ("if", sg["idx"]))

        def owner_name(o) -> str:
            return (f"インターフェース '{segs[o[1]]['fg']}'" if o[0] == "if"
                    else f"仮想ルーター '{vrname(segs[o[1]])}'")

        for (i, net), labels in claims.items():
            mine = {("vr", i), ("if", i)}  # 自分のインターフェース/internalと重なる部分は、書かなくてよい
            parts, conflicts = occ.claim(int(net.network_address), int(net.broadcast_address), mine)
            if conflicts:
                others = ", ".join(dict.fromkeys(owner_name(o) for o in conflicts))
                tail = "重複部分を除いて書く" if parts else "書かない"
                for lb in labels:
                    warn.add(f"internal {net} ('{vrname(segs[i])}') は {others} と重複するため{tail}", lb)
            for ps, pe in parts:
                occ.add(ps, pe, ("vr", i))
                segs[i]["inet"].extend(ipaddress.summarize_address_range(
                    ipaddress.IPv4Address(ps), ipaddress.IPv4Address(pe)))

    def eth_no(eth: str) -> int:
        return int(eth.split("/")[-1])

    def os_name(i: int) -> str:
        return os_ifs[i - 1] if os_ifs and i - 1 < len(os_ifs) else default_os_if(i)

    # 物理インターフェース (eth0/1〜は最低3つ)。使うものだけOSインターフェースを割り当てる
    max_n = max([3] + [eth_no(m) for m in taken if m.startswith("eth0/")])
    used_no = {eth_no(s["eth"]) for s in segs}
    eth_ip = {s["eth"]: f"{s['tip']}/{s['prefix']}" for s in segs if not s["vlan"]}
    lines = [f'version = {q(VERSION)}', "l2_mode = false", ""]
    names_in_use = {f"eth0/{i}" for i in range(1, max_n + 1)}
    for i in range(1, max_n + 1):
        nm = f"eth0/{i}"
        lines.extend(["[[interfaces]]", f"name = {q(nm)}", 'type = "physical"',
                      f"os_if = {q(os_name(i) if i in used_no else '')}",
                      "ip_aliases = [ ]", f"ipaddress = {q(eth_ip.get(nm, ''))}", ""])

    # VLANインターフェース: 物理には設定を入れず、その物理をbase_ifにする。名前はFGのVLAN名に揃える
    for s in segs:
        if s["vlan"]:
            nm, k = s["fg"], 1
            while nm in names_in_use:  # 名前が被るときだけ連番を付ける
                k += 1
                nm = f"{s['fg']}_{k}"
            names_in_use.add(nm)
            s["ifname"] = nm
            lines.extend(["[[interfaces]]", f"name = {q(nm)}", 'type = "vlan"',
                          f"ipaddress = {q(s['tip'] + '/' + str(s['prefix']))}",
                          f"vlan_id = {q(s['vlan'])}", f"base_if = {q(s['eth'])}",
                          "ip_aliases = [ ]", ""])
        else:
            s["ifname"] = s["eth"]

    for s in segs:
        lines.extend(["[[vRouters]]", f"name = {q(vrname(s))}",
                      f"if_names = [{q(s['ifname'])}]", "[vRouters.routes]"])
        nets = _final_nets(s["inet"])
        if nets:  # 内部ネットワーク (next_hopは書かない)
            lines.append("internal = [")
            lines.append(",\n".join(f'  {{destination = {q(str(n))}, comment = ""}}' for n in nets))
            lines.append("]")
        lines.extend(["external = [",
            f'  {{destination = "0.0.0.0/0", next_hop = {q(s["fgip"])}, comment = {q(s["tip"] + ", " + s["fg"])}}}',
            "]", ""])
    if not segs:
        warn["仮想ルーターを作れるインターフェースがありませんでした"] += 1
    return "\n".join(lines).rstrip("\n") + "\n", warn, segs


def _palo_ip(cfg, token: str):
    """インターフェースのIP指定 ('10.0.0.1/24' またはアドレスオブジェクト名) -> ip_interface。解決できなければ None"""
    try:
        return ipaddress.ip_interface(token)
    except ValueError:
        pass
    kind_val = cfg.addresses.get(token)
    if kind_val and kind_val[0] == "ip-netmask":
        try:
            return ipaddress.ip_interface(kind_val[1])
        except ValueError:
            return None
    return None


def build_palo(cfg, policies: list, vsys: str = None, if_map: dict = None, tester_ips: dict = None,
               vr_names: dict = None, os_ifs: list = None, any_src: str = "192.0.2.1",
               any_dst: str = "198.51.100.1", with_internal: bool = True, nat=None) -> tuple:
    """Palo Alto版。(toml文字列, 警告Counter, セグメントのリスト) を返す。考え方は build_fortigate と同じ。
    ポリシーで使うゾーンごとに、そのゾーンのレイヤー3インターフェース1つにつき テスター側のインターフェース+仮想ルーターを作る。
    * サブインターフェース (ethernet1/1.100 等) はVLANインターフェース (tag = VLAN ID、親が base_if)
    * 仮想ルーター名: ゾーンのインターフェースが1つならゾーン名、複数なら インターフェース名
    * テスター側IP = サブネットの先頭ホスト (Paloのインターフェース/セカンダリIPと被る場合は次のホスト)
    nat: PaloResolver (宛先NATのため、変換前のIPは宛先として書かず、実宛先を書く)"""
    if_map, tester_ips, vr_names = if_map or {}, tester_ips or {}, vr_names or {}
    warn = Warns()

    zone_names: list = []
    for p in policies:
        for n in list(p.srcintf) + list(p.dstintf):
            if n != "any" and n not in zone_names:
                zone_names.append(n)

    if any("any" in (p.srcintf + p.dstintf) for p in policies):
        # ゾーンが any のポリシーがあるときは、定義されている全ゾーンのセグメントも作る (internalは決められない)
        for (zv, zn) in cfg.zones:
            if (vsys is None or zv in (vsys, None)) and zn not in zone_names:
                zone_names.append(zn)

    def zone_defined(n: str) -> bool:
        return (vsys, n) in cfg.zones or (None, n) in cfg.zones or any(k[1] == n for k in cfg.zones)

    def expand(n: str) -> list:
        return list(cfg.zone_members(vsys, n)) if zone_defined(n) else [n]

    names: list = []
    zone_of: dict = {}
    for zn in zone_names:
        if not zone_defined(zn):
            if zn in cfg.interfaces:  # ゾーンではなくインターフェース名が直接書かれている
                names.append(zn)
            else:
                warn[f"ゾーン '{zn}' の定義が見つからないため仮想ルーターを作れない"] += 1
            continue
        ifl = expand(zn)
        z = cfg.zones.get((vsys, zn)) or cfg.zones.get((None, zn))
        if z is not None and not ifl:
            other = ", ".join(sorted({t for t, _ in z["other"]})) or "インターフェースなし"
            warn[f"ゾーン '{zn}' にレイヤー3インターフェースがない ({other}): 仮想ルーターを作れない"] += 1
        for n in ifl:
            if n not in names:
                names.append(n)
            zone_of.setdefault(n, zn)

    segs: list = []
    for name in names:
        e = cfg.interfaces.get(name)
        if e is None:
            warn[f"インターフェース '{name}' の定義が見つからないためスキップ"] += 1
            continue
        if e["kind"] != "layer3" and not e["ips"]:
            warn[f"インターフェース '{name}' をスキップ: レイヤー3ではない ({e['kind']})"] += 1
            continue
        try:
            ips = [_palo_ip(cfg, t) for t in e["ips"]]
            if not e["ips"]:
                raise ValueError("DHCPクライアント (IPが固定でない)" if e["dhcp"] else "IP未設定")
            if ips[0] is None:
                raise ValueError(f"IPを解決できない ({e['ips'][0]})")
            ifc = ips[0]
            if ifc.network.prefixlen >= 32:
                raise ValueError("/32 はテスターのIPを置けない")
        except ValueError as ex:
            warn[f"インターフェース '{name}' をスキップ: {ex}"] += 1
            continue
        if len(e["ips"]) > 1:
            warn[f"インターフェース '{name}' の2つ目以降のIPは未対応 (テスターには先頭のIPのネットワークだけ設定)"] += 1
        vlanid = e["tag"]
        if e["parent"] and vlanid is None:
            warn[f"サブインターフェース '{name}' にtag(VLAN ID)がない: スキップ"] += 1
            continue
        parent = e["parent"] if vlanid is not None and e["parent"] else name
        reserved = {i.ip for i in ips if i is not None}
        if name in tester_ips:
            tip = ipaddress.ip_address(tester_ips[name])
        else:
            tip = next((h for h in ifc.network.hosts() if h not in reserved), None)
            if tip is None:
                warn[f"インターフェース '{name}' のサブネットに空きホストがありません"] += 1
                continue
        segs.append({"fg": name, "vlan": str(vlanid) if vlanid is not None else "", "parent": parent,
                     "fgip": str(ifc.ip), "tip": str(tip), "prefix": ifc.network.prefixlen, "net": ifc.network,
                     "inet": [], "zone": zone_of.get(name, "")})
    # 仮想ルーター名: ゾーンのIFが1つだけならゾーン名
    per_zone = Counter(s["zone"] for s in segs)
    for s in segs:
        s["vr"] = s["zone"] if s["zone"] and per_zone[s["zone"]] == 1 else s["fg"]

    extra, skip = [], {}
    if nat is not None:
        by_pid = {p.pid: p for p in policies}
        for pid, m in nat.dnat_used.items():
            p = by_pid.get(pid)
            if p is None:
                continue
            skip[pid] = set(m)
            for real in dict.fromkeys(m.values()):
                extra.append((list(p.dstintf), real, f"NAT宛先: {policy_label(p.pid, p.name)}"))
    return _assemble(segs, policies, warn, expand, if_map, vr_names, os_ifs, any_src, any_dst, with_internal,
                     extra, skip)
