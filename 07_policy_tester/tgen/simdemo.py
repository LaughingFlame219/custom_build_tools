"""デモ/自己診断用: シナリオCSVとvRouter TOMLから「疑似ファイアウォール」を自動構成する。
各シナリオの expect に従う1対1のポリシー (pass→accept / drop→deny / block→reject) を作るので、
生成ツールの出力(仮想ルーター・internalルート・VLAN)が実際に疎通することを実機なしで確認できる。
"""
from .engine import build_stack, norm_scenario, _isip
from .link import MemLink
from .sim import Policy, SimFW
from .stack import _ipint


def build(cfg, rows):
    fw_links = {}

    def factory(name, os_if):
        a, b = MemLink.pair(name + "-tester", name + "-fw")
        fw_links[id(a)] = b
        return a

    st, info = build_stack(cfg, factory)
    fw = SimFW()
    ifname = {}
    for vr in st.vrs:
        if not vr.external:
            continue
        nh = vr.external[0][2]
        tif = vr.iface_for(nh)
        plen = next((p for ip, p in tif.ips if _ipint(ip) & (0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF ==
                     _ipint(nh) & (0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF), tif.ips[0][1])
        fw.add_iface(vr.name, fw_links[id(tif.link)], "%s/%d" % (nh, plen), tif.vlan)
        ifname[vr.name] = vr
        for n, m in vr.internal:
            fw.routes.append(("%s/%d" % (_ip(n), bin(m).count("1")), vr.name, tif.ip))
    pid = 0
    for r in rows:
        sc = norm_scenario(r, {})
        if not (_isip(sc["src"]) and _isip(sc["dst"])):
            continue
        sv = st.vr_of(sc["src"])
        dv = st.vr_of(sc["nat_ip"] or sc["dst"])
        if sv is None or dv is None or sv is dv:
            continue
        pid += 1
        app = sc["app"]
        proto = "icmp" if app == "icmp" else ("udp" if app in ("udp", "dns") else "tcp")
        ports = (sc["dport"], sc["dport"]) if proto != "icmp" and sc["dport"] else None
        act = {"pass": "accept", "drop": "deny", "block": "reject"}.get(sc["expect"], "accept")
        fw.policies.append(Policy(pid, sv.name, dv.name, sc["src"] + "/32", sc["dst"] + "/32", proto, ports, act))
        if app == "ftp" and act == "accept":
            pid += 1
            fw.policies.append(Policy(pid, sv.name, dv.name, sc["src"] + "/32", sc["dst"] + "/32", "tcp", (1024, 65535)))
        if sc["nat_ip"]:
            fw.vips.append((sc["dst"], sc["nat_ip"], sc["dport"] or None, sc["nat_port"] or None))
    # 実行を速くするため: 先頭一致の線形探索を避けるインデックスは付けない (デモ規模前提)
    fw.start()
    return st, fw


def _ip(i):
    import socket, struct
    return socket.inet_ntoa(struct.pack("!I", i))
