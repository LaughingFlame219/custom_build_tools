"""疑似ファイアウォール (テスト用)。Linuxサンドボックスなど実機NICが使えない環境で、
トラフィックジェネレーター本体の動作と判定(Pass/Drop/Block)を自動テストするために使う。
MemLink で結線した L3 ルーター + ステートフルポリシー + 簡易 NAT/VIP + 簡易 L7(URL/SNI/EICAR)。
"""
import ipaddress
import threading

from . import pkt

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _n(s):
    return ipaddress.ip_network(s, strict=False)


class FwIface:
    def __init__(self, name, link, cidr, vlan=0):
        self.name, self.link, self.vlan = name, link, vlan
        i = ipaddress.ip_interface(cidr)
        self.ip, self.net = str(i.ip), i.network
        self.mac = pkt.mac2b("02:fa:fa:00:%02x:%02x" % (abs(hash(name)) % 256, vlan % 256))


class Policy:
    def __init__(self, pid, srcintf, dstintf, src="0.0.0.0/0", dst="0.0.0.0/0", proto=None, ports=None,
                 action="accept", snat=False, av=False, block_hosts=(), block_sni=(), l7="rst"):
        self.pid, self.srcintf, self.dstintf = pid, srcintf, dstintf
        self.src, self.dst = _n(src), _n(dst)
        self.proto = proto            # 'tcp'/'udp'/'icmp'/None(any)
        self.ports = ports            # None or (lo,hi)
        self.action, self.snat, self.av = action, snat, av
        self.block_hosts, self.block_sni, self.l7 = set(block_hosts), set(block_sni), l7


class SimFW:
    def __init__(self):
        self.ifaces = []
        self.by_link = {}
        self.routes = []       # (net, ifname, nexthop)
        self.policies = []
        self.vips = []         # (extip, mappedip, extport|None, mappedport|None)
        self.sess = {}
        self.arp = {}
        self.pending = {}
        self.lock = threading.RLock()
        self.log = []

    def add_iface(self, name, link, cidr, vlan=0):
        i = FwIface(name, link, cidr, vlan)
        self.ifaces.append(i)
        self.by_link[(id(link), vlan)] = i
        return i

    def start(self):
        for l in {i.link for i in self.ifaces}:
            l.start(lambda f, l=l: self.rx(l, f))

    def stop(self):
        for l in {i.link for i in self.ifaces}:
            l.stop()

    # ---- L2
    def _tx(self, iface, dmac, et, payload):
        iface.link.send(pkt.eth(dmac, iface.mac, et, payload, iface.vlan))

    def rx(self, link, frame):
        e = pkt.parse_eth(frame)
        if not e:
            return
        dmac, smac, et, vlan, payload = e
        with self.lock:
            iface = self.by_link.get((id(link), vlan))
            if iface is None or (dmac != iface.mac and not dmac[0] & 1):
                return
            if et == pkt.ETH_ARP:
                a = pkt.parse_arp(payload)
                if not a:
                    return
                op, sm, sip, tm, tip = a
                self.arp[(iface.name, sip)] = sm
                for fn in self.pending.pop((iface.name, sip), []):
                    fn(sm)
                if op == 1 and tip == iface.ip:
                    self._tx(iface, sm, pkt.ETH_ARP, pkt.arp(2, iface.mac, iface.ip, sm, sip))
            elif et == pkt.ETH_IP:
                ip = pkt.parse_ip(payload)
                if ip:
                    self._forward(iface, ip)

    def _send_ip(self, out, nh, packet):
        m = self.arp.get((out.name, nh))
        if m:
            self._tx(out, m, pkt.ETH_IP, packet)
            return
        self.pending.setdefault((out.name, nh), []).append(lambda mm: self._tx(out, mm, pkt.ETH_IP, packet))
        self._tx(out, pkt.BCAST, pkt.ETH_ARP, pkt.arp(1, out.mac, out.ip, b"\0" * 6, nh))

    # ---- L3
    def _route(self, dst):
        d = ipaddress.ip_address(dst)
        for i in self.ifaces:
            if d in i.net:
                return i, dst
        best = None
        for net, ifn, nh in self.routes:
            if d in _n(net) and (best is None or _n(net).prefixlen > best[0]):
                best = (_n(net).prefixlen, ifn, nh)
        if best:
            return next(i for i in self.ifaces if i.name == best[1]), best[2]
        return None, None

    def _l4key(self, ip):
        pr = ip["proto"]
        if pr == pkt.P_TCP:
            t = pkt.parse_tcp(ip["payload"])
            return (pr, t["sport"], t["dport"], t) if t else None
        if pr == pkt.P_UDP:
            u = pkt.parse_udp(ip["payload"])
            return (pr, u["sport"], u["dport"], u) if u else None
        if pr == pkt.P_ICMP:
            m = pkt.parse_icmp(ip["payload"])
            if m and m["type"] in (0, 8):
                return (pr, m["ident"], m["ident"], m)
        return None

    def _rebuild(self, ip, src, dst, sport, dport, l4):
        pr = ip["proto"]
        if pr == pkt.P_TCP:
            t = l4
            body = pkt.tcp(src, dst, sport, dport, t["seq"], t["ack"], t["flags"], t["data"], t["win"], t["mss"])
        elif pr == pkt.P_UDP:
            body = pkt.udp(src, dst, sport, dport, l4["data"])
        else:
            body = ip["payload"]
        return pkt.ip4(src, dst, pr, body, ip["ttl"] - 1, ip["id"])

    def _match(self, p, inif, outif, ip, k):
        if p.srcintf not in (inif.name, "any") or p.dstintf not in (outif.name, "any"):
            return False
        if ipaddress.ip_address(ip["src"]) not in p.src or ipaddress.ip_address(ip["dst"]) not in p.dst:
            return False
        names = {pkt.P_TCP: "tcp", pkt.P_UDP: "udp", pkt.P_ICMP: "icmp"}
        if p.proto and names.get(ip["proto"]) != p.proto:
            return False
        if p.ports and ip["proto"] in (pkt.P_TCP, pkt.P_UDP) and not (p.ports[0] <= k[2] <= p.ports[1]):
            return False
        return True

    def _forward(self, inif, ip):
        if ip["ttl"] <= 1:
            return
        k = self._l4key(ip)
        if k is None:
            return
        pr, sp, dp, l4 = k
        skey = (pr, ip["src"], sp, ip["dst"], dp, inif.name)
        s = self.sess.get(skey)
        if s is None:
            # --- 新規セッション判定 (VIP → 経路 → ポリシー)
            if pr == pkt.P_TCP and not (l4["flags"] & pkt.SYN) or pr == pkt.P_ICMP and l4["type"] != 8:
                return
            dst, dport = ip["dst"], dp
            for ext, mapped, xp, mp in self.vips:
                if dst == ext and (xp is None or xp == dp):
                    dst, dport = mapped, (mp or dp)
                    break
            outif, nh = self._route(dst)
            if outif is None:
                return
            pol = next((p for p in self.policies if self._match(p, inif, outif, ip, k)), None)
            self.log.append((pol.pid if pol else 0, pol.action if pol else "implicit-deny", ip["src"], ip["dst"], dp))
            if pol is None or pol.action == "deny":
                return
            if pol.action == "reject":
                self._reject(inif, ip, k)
                return
            src, sport = ip["src"], sp
            if pol.snat:
                src = outif.ip
            if pr == pkt.P_ICMP:
                dport = dp
            fwd = {"src": src, "sport": sport, "dst": dst, "dport": dport, "out": outif, "nh": nh}
            rkey = (pr, dst, dport, src, sport, outif.name)
            _, rnh = self._route(ip["src"])
            rev = {"src": ip["dst"], "sport": dp, "dst": ip["src"], "dport": sp, "out": inif, "nh": rnh}
            self.sess[skey] = {"pol": pol, "dead": False, "d": fwd, "key": skey, "other": rkey}
            self.sess[rkey] = {"pol": pol, "dead": False, "d": rev, "key": rkey, "other": skey, "reply": True}
            s = self.sess[skey]
        if s["dead"]:
            return
        pol = s["pol"]
        d = s["d"]
        # --- L7
        if pr == pkt.P_TCP and l4["data"] and self._l7(inif, ip, l4, s, pol):
            return
        out = d["out"]
        self._send_ip(out, d["nh"], self._rebuild(ip, d["src"], d["dst"], d["sport"], d["dport"], l4))

    def _reject(self, inif, ip, k):
        pr, sp, dp, l4 = k
        _, nh = self._route(ip["src"])
        if pr == pkt.P_TCP:
            ack = (l4["seq"] + 1) & 0xFFFFFFFF
            self._send_ip(inif, nh, pkt.ip4(ip["dst"], ip["src"], pkt.P_TCP,
                          pkt.tcp(ip["dst"], ip["src"], dp, sp, 0, ack, pkt.RST | pkt.ACK)))
        else:
            body = ip["hdr"] + ip["payload"][:8]
            self._send_ip(inif, nh, pkt.ip4(inif.ip, ip["src"], pkt.P_ICMP, pkt.icmp(3, 13, b"\0\0\0\0", body)))

    def _l7(self, inif, ip, l4, s, pol):
        data = l4["data"]
        hit = None
        if pol.av and EICAR in data:
            hit = "av"
        elif pol.block_hosts and data.startswith((b"GET ", b"POST ", b"HEAD ")):
            for line in data.split(b"\r\n"):
                if line.lower().startswith(b"host:") and line[5:].strip().decode(errors="ignore") in pol.block_hosts:
                    hit = "url"
        elif pol.block_sni and data[:1] == b"\x16":
            sni = parse_sni(data)
            if sni in pol.block_sni:
                hit = "sni"
        if not hit:
            return False
        self.sess[s["key"]]["dead"] = True
        self.sess[s["other"]]["dead"] = True
        # 違反パケットは破棄し、ブロックページ(URL違反でクライアント発の時のみ)またはRSTを注入する
        d = s["d"]
        src_ip, dst_ip, sp, dp = ip["src"], ip["dst"], l4["sport"], l4["dport"]
        seq_end = (l4["seq"] + len(data)) & 0xFFFFFFFF
        _, nh_src = self._route(src_ip)
        from_client = not s.get("reply")
        if hit == "url" and pol.l7 == "blockpage" and from_client:
            page = (b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
                    b"<html><title>Web Page Blocked</title><body>FortiGuard Web Filtering: "
                    b"this page is blocked.</body></html>")
            self._send_ip(inif, nh_src, pkt.ip4(dst_ip, src_ip, pkt.P_TCP,
                          pkt.tcp(dst_ip, src_ip, dp, sp, l4["ack"], seq_end, pkt.PSH | pkt.ACK | pkt.FIN, page)))
        else:
            self._send_ip(inif, nh_src, pkt.ip4(dst_ip, src_ip, pkt.P_TCP,
                          pkt.tcp(dst_ip, src_ip, dp, sp, l4["ack"], seq_end, pkt.RST | pkt.ACK)))
            # 反対側 (NAT後のアドレスで) にもRST
            self._send_ip(d["out"], d["nh"], pkt.ip4(d["src"], d["dst"], pkt.P_TCP,
                          pkt.tcp(d["src"], d["dst"], d["sport"], d["dport"], seq_end, l4["ack"], pkt.RST | pkt.ACK)))
        self.log.append((pol.pid, "l7-" + hit, src_ip, dst_ip, dp))
        return True


def parse_sni(rec: bytes):
    """TLS ClientHello から SNI を取り出す (なければ None)"""
    try:
        if rec[0] != 0x16 or rec[5] != 1:
            return None
        p = 5 + 4 + 2 + 32
        p += 1 + rec[p]                       # session id
        p += 2 + int.from_bytes(rec[p:p + 2], "big")   # cipher suites
        p += 1 + rec[p]                       # compression
        ext_end = p + 2 + int.from_bytes(rec[p:p + 2], "big")
        p += 2
        while p + 4 <= ext_end:
            t = int.from_bytes(rec[p:p + 2], "big")
            ln = int.from_bytes(rec[p + 2:p + 4], "big")
            if t == 0:
                nl = int.from_bytes(rec[p + 7:p + 9], "big")
                return rec[p + 9:p + 9 + nl].decode(errors="ignore")
            p += 4 + ln
    except IndexError:
        pass
    return None
