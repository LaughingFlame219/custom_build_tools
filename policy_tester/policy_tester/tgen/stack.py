"""ミニTCP/IPスタック + 仮想ルーター。

  Iface : リンク(+VLANタグ)上の仮想NIC (MAC・IP・サブネット)
  VR    : 仮想ルーター。Iface群 / internalネットワーク / externalルート(next hop)を持つ
  Stack : ARP・ICMP応答・UDP・TCP を実装。すべて1個のRLockで保護し、
          受信スレッド(各Link)とタイマースレッド、ワーカースレッド(シナリオ実行)から使う。

ブロッキングI/Oはワーカースレッドだけで行い、受信スレッドからの送信(ACK等)はARP未解決でも
ブロックしない (ARPキャッシュ未解決なら保留して解決後に送る)。
"""
import ipaddress
import itertools
import os
import random
import threading
import time

from . import pkt

MASK = 0xFFFFFFFF
MSS = 1400
CLOSED, SYN_SENT, SYN_RCVD, ESTAB, FIN_WAIT1, FIN_WAIT2, CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT = range(10)


class ConnError(Exception):
    """kind: reset | icmp | timeout | arpRequest | noRoute | srcNotOwned | noroute(ポート枯渇)"""

    def __init__(self, kind, detail="", info=None):
        super().__init__("%s %s" % (kind, detail))
        self.kind = kind
        self.detail = detail
        self.info = info or {}


def _net(s):
    n = ipaddress.ip_network(s, strict=False)
    return int(n.network_address), int(n.netmask)


def _ipint(s):
    return int(ipaddress.ip_address(s))


class Iface:
    def __init__(self, name, link, vlan=0, ips=None, mac=None):
        self.name = name
        self.link = link
        self.vlan = int(vlan or 0)
        self.ips = []      # [(ip_str, prefixlen)]
        for a in ips or []:
            self.add_ip(a)
        self.mac = mac or pkt.mac2b("02:54:47:%02x:%02x:%02x" % (
            random.randrange(256), random.randrange(256), random.randrange(256)))
        self.vr = None

    def add_ip(self, cidr):
        i = ipaddress.ip_interface(cidr)
        self.ips.append((str(i.ip), i.network.prefixlen))

    def nets(self):
        return [_net("%s/%d" % (ip, p)) for ip, p in self.ips]

    @property
    def ip(self):
        return self.ips[0][0] if self.ips else None


class VR:
    def __init__(self, name):
        self.name = name
        self.ifaces = []
        self.internal = []   # [(net,mask)]
        self.external = []   # [(net,mask,nexthop_str)]

    def owns(self, ipi):
        for i in self.ifaces:
            for n, m in i.nets():
                if ipi & m == n:
                    return True
        for n, m in self.internal:
            if ipi & m == n:
                return True
        return False

    def nexthop(self, dst_i):
        best = None
        for n, m, nh in self.external:
            if dst_i & m == n and (best is None or m > best[0]):
                best = (m, nh)
        return best[1] if best else None

    def iface_for(self, nexthop):
        nh = _ipint(nexthop)
        for i in self.ifaces:
            for n, m in i.nets():
                if nh & m == n:
                    return i
        return self.ifaces[0] if self.ifaces else None

    @property
    def gateways(self):
        return {nh for _, _, nh in self.external}


class Stack:
    def __init__(self):
        self.lock = threading.RLock()
        self.ifaces = []
        self.vrs = []
        self.by_link = {}          # (id(link), vlan) -> Iface
        self.arp = {}              # (iface, ip) -> mac
        self.pending = {}          # (iface, ip) -> [frame builders]
        self.arp_tries = {}        # (iface, ip) -> (n, t)
        self.conns = {}
        self.listeners = {}        # (ip|None, port) -> handler
        self.udp_socks = {}        # (ip|None, port) -> UdpSock/handler
        self.pings = {}            # (ident, seq) -> Ping
        self.taps = []             # callable(direction, iface, frame)
        self._vr_cache = {}
        self._eph = itertools.count(random.randrange(20000, 40000))
        self._ident = itertools.count(random.randrange(1, 60000))
        self._run = True
        self.links = []
        self.stats = {"rx": 0, "tx": 0}
        threading.Thread(target=self._timer, daemon=True, name="stack-timer").start()

    # ---------------------------------------------------------------- 構成
    def add_link(self, link):
        if link not in self.links:
            self.links.append(link)

    def add_iface(self, i):
        self.ifaces.append(i)
        self.by_link[(id(i.link), i.vlan)] = i
        self.add_link(i.link)
        return i

    def add_vr(self, vr):
        for i in vr.ifaces:
            i.vr = vr
        self.vrs.append(vr)
        self._vr_cache.clear()
        return vr

    def start(self):
        for l in self.links:
            l.start(lambda f, l=l: self.rx(l, f))

    def stop(self):
        self._run = False
        for l in self.links:
            l.stop()

    def vr_of(self, ip):
        """ipを所有するVR (なければNone)"""
        if ip in self._vr_cache:
            return self._vr_cache[ip]
        ipi = _ipint(ip)
        r = None
        for v in self.vrs:
            if v.owns(ipi) and ip not in v.gateways:
                r = v
                break
        self._vr_cache[ip] = r
        return r

    def new_port(self):
        with self.lock:
            for _ in range(40000):
                p = 20000 + next(self._eph) % 40000
                if not any(k[1] == p for k in self.conns) and (None, p) not in self.udp_socks:
                    return p
        raise ConnError("noroute", "no free port")

    # ---------------------------------------------------------------- 送受信 (L2)
    def _emit(self, iface, dst_mac, etype, payload):
        f = pkt.eth(dst_mac, iface.mac, etype, payload, iface.vlan)
        for t in self.taps:
            t("tx", iface, f)
        self.stats["tx"] += 1
        iface.link.send(f)

    def rx(self, link, frame):
        e = pkt.parse_eth(frame)
        if not e:
            return
        dmac, smac, et, vlan, payload = e
        with self.lock:
            iface = self.by_link.get((id(link), vlan))
            if iface is None:
                return
            if dmac != iface.mac and dmac[0] & 1 == 0:
                return
            if smac == iface.mac:
                return
            self.stats["rx"] += 1
            for t in self.taps:
                t("rx", iface, frame)
            if et == pkt.ETH_ARP:
                self._arp_in(iface, payload)
            elif et == pkt.ETH_IP:
                ip = pkt.parse_ip(payload)
                if ip and not ip["frag"]:
                    self._ip_in(iface, ip)

    # ---------------------------------------------------------------- ARP
    def _arp_in(self, iface, p):
        a = pkt.parse_arp(p)
        if not a:
            return
        op, smac, sip, tmac, tip = a
        if sip != "0.0.0.0":
            self._learn(iface, sip, smac)
        if op == 1 and iface.vr is not None:
            vr = iface.vr
            tipi = _ipint(tip)
            mine = tip in [x[0] for x in iface.ips] or (
                tip not in vr.gateways and any(tipi & m == n for n, m in iface.nets()))
            if mine:
                self._emit(iface, smac, pkt.ETH_ARP, pkt.arp(2, iface.mac, tip, smac, sip))

    def _learn(self, iface, ip, mac):
        self.arp[(iface, ip)] = mac
        self.arp_tries.pop((iface, ip), None)
        for build in self.pending.pop((iface, ip), []):
            build(mac)

    def _arp_request(self, iface, ip):
        n, _ = self.arp_tries.get((iface, ip), (0, 0))
        self.arp_tries[(iface, ip)] = (n + 1, time.monotonic())
        self._emit(iface, pkt.BCAST, pkt.ETH_ARP, pkt.arp(1, iface.mac, iface.ip or "0.0.0.0", b"\0" * 6, ip))

    def resolve(self, ip_src, dst, timeout=2.0):
        """ワーカー用: src発dst宛の次ホップMACが解決されるまで待つ。失敗でConnError('arp'等)"""
        with self.lock:
            vr = self.vr_of(ip_src)
            if vr is None:
                raise ConnError("srcNotOwned", "送信元 %s を持つ仮想ルーターがありません" % ip_src, {"ip": ip_src})
            nh = vr.nexthop(_ipint(dst))
            if nh is None:
                raise ConnError("noRoute", "%s への経路がありません (VR %s)" % (dst, vr.name),
                                {"ip": dst, "vr": vr.name})
            iface = vr.iface_for(nh)
        return self.resolve_nexthop(vr, iface, nh, timeout)

    def resolve_nexthop(self, vr, iface, nh, timeout=2.0):
        end = time.monotonic() + timeout
        last = 0.0
        while True:
            with self.lock:
                mac = self.arp.get((iface, nh))
                if mac:
                    return mac
                now = time.monotonic()
                if now >= end:
                    raise ConnError("arpRequest", "次ホップ %s のMACを解決できません (VR %s / %s)" % (nh, vr.name, iface.name),
                                    {"ip": nh, "vr": vr.name, "if": iface.name})
                if now - last > 0.4:
                    self._arp_request(iface, nh)
                    last = now
            time.sleep(0.02)

    # ---------------------------------------------------------------- IP 出力
    def ip_out(self, src, dst, proto, payload, ttl=64):
        """src(自分のVR管轄IP)→dst。次ホップMAC未解決なら保留してARP要求。"""
        with self.lock:
            vr = self.vr_of(src)
            if vr is None:
                return False
            nh = vr.nexthop(_ipint(dst))
            if nh is None:
                return False
            iface = vr.iface_for(nh)
            if iface is None:
                return False
            packet = pkt.ip4(src, dst, proto, payload, ttl)
            mac = self.arp.get((iface, nh))
            if mac:
                self._emit(iface, mac, pkt.ETH_IP, packet)
            else:
                self.pending.setdefault((iface, nh), []).append(
                    lambda m, i=iface, p=packet: self._emit(i, m, pkt.ETH_IP, p))
                if (iface, nh) not in self.arp_tries:
                    self._arp_request(iface, nh)
            return True

    # ---------------------------------------------------------------- IP 入力
    def _ip_in(self, iface, ip):
        dst = ip["dst"]
        vr = iface.vr
        if vr is None or not vr.owns(_ipint(dst)) or dst in vr.gateways:
            return
        pr = ip["proto"]
        if pr == pkt.P_ICMP:
            self._icmp_in(iface, ip)
        elif pr == pkt.P_TCP:
            t = pkt.parse_tcp(ip["payload"])
            if t:
                self._tcp_in(ip, t)
        elif pr == pkt.P_UDP:
            u = pkt.parse_udp(ip["payload"])
            if u:
                self._udp_in(ip, u)

    # ---------------------------------------------------------------- ICMP
    def _icmp_in(self, iface, ip):
        m = pkt.parse_icmp(ip["payload"])
        if not m:
            return
        t = m["type"]
        if t == 8:   # echo request → 応答
            body = ip["payload"][8:]
            self.ip_out(ip["dst"], ip["src"], pkt.P_ICMP, pkt.echo(0, m["ident"], m["seq"], body))
        elif t == 0:
            pg = self.pings.get((m["ident"], m["seq"]))
            if pg and pg.dst == ip["src"]:
                pg.set("reply", ip["src"])
        elif t in (3, 4, 5, 11, 12):
            self._icmp_err(ip, m)

    def _icmp_err(self, ip, m):
        inner = pkt.parse_ip(m["data"] if len(m["data"]) >= 20 else b"")
        if not inner:
            return
        pl = inner["payload"]
        info = (m["type"], m["code"], ip["src"])
        if inner["proto"] == pkt.P_ICMP and len(pl) >= 8:
            ident, seq = int.from_bytes(pl[4:6], "big"), int.from_bytes(pl[6:8], "big")
            pg = self.pings.get((ident, seq))
            if pg:
                pg.set("icmp", ip["src"], info)
        elif inner["proto"] in (pkt.P_TCP, pkt.P_UDP) and len(pl) >= 4:
            sp, dp = int.from_bytes(pl[0:2], "big"), int.from_bytes(pl[2:4], "big")
            if inner["proto"] == pkt.P_TCP:
                c = self.conns.get((inner["src"], sp, inner["dst"], dp))
                if c and c.state in (SYN_SENT, SYN_RCVD):
                    c._fail("icmp", info)
                elif c and m["type"] == 3 and c.state != CLOSED:
                    c.icmp_info = info
            else:
                s = self.udp_socks.get((inner["src"], sp)) or self.udp_socks.get((None, sp))
                if s is not None and hasattr(s, "icmp_err"):
                    s.set_icmp(info)

    def send_icmp_unreach(self, ip_in_raw_hdr, payload8, src, dst, code=3):
        body = ip_in_raw_hdr + payload8[:8]
        self.ip_out(src, dst, pkt.P_ICMP, pkt.icmp(3, code, b"\0\0\0\0", body))

    # ---------------------------------------------------------------- ping
    def ping(self, src, dst, timeout=3.0, size=32):
        """-> ('reply'|'icmp'|'timeout', 応答元, info)"""
        self.resolve(src, dst)
        ident = next(self._ident) & 0xFFFF
        seq = 1
        pg = Ping(self, dst)
        with self.lock:
            self.pings[(ident, seq)] = pg
        try:
            end = time.monotonic() + timeout
            data = bytes(range(size & 0xFF)) if size else b""
            sent = 0
            while True:
                self.ip_out(src, dst, pkt.P_ICMP, pkt.echo(8, ident, seq, data))
                sent += 1
                if pg.ev.wait(min(1.0, max(0.0, end - time.monotonic()))):
                    return pg.res
                if time.monotonic() >= end:
                    return ("timeout", None, None)
        finally:
            with self.lock:
                self.pings.pop((ident, seq), None)

    # ---------------------------------------------------------------- UDP
    def _udp_in(self, ip, u):
        h = self.udp_socks.get((ip["dst"], u["dport"])) or self.udp_socks.get((None, u["dport"]))
        if h is None:
            raw = ip["hdr"] + b""
            self.send_icmp_unreach(raw, ip["payload"], ip["dst"], ip["src"], 3)
            return
        if callable(h):
            threading.Thread(target=h, args=(ip["src"], u["sport"], ip["dst"], u["dport"], u["data"]),
                             daemon=True).start()
        else:
            h.deliver(ip["src"], u["sport"], ip["dst"], u["data"])

    def udp_listen(self, ip, port, handler):
        """handler(src, sport, dst, dport, data) を別スレッドで呼ぶ"""
        with self.lock:
            self.udp_socks[(ip, port)] = handler

    def udp_sock(self, src, sport=0):
        return UdpSock(self, src, sport or self.new_port())

    def udp_send(self, src, sport, dst, dport, data):
        self.ip_out(src, dst, pkt.P_UDP, pkt.udp(src, dst, sport, dport, data))

    # ---------------------------------------------------------------- TCP
    def tcp_listen(self, ip, port, handler):
        with self.lock:
            self.listeners[(ip, port)] = handler

    def tcp_connect(self, src, dst, dport, timeout=3.0, sport=0):
        self.resolve(src, dst)
        with self.lock:
            sport = sport or self.new_port()
            c = TcpConn(self, src, sport, dst, dport)
            self.conns[(src, sport, dst, dport)] = c
            c._open_active()
        end = time.monotonic() + timeout
        with c.cond:
            while c.state == SYN_SENT and not c.error:
                rem = end - time.monotonic()
                if rem <= 0:
                    break
                c.cond.wait(rem)
            if c.error:
                err = c.error
                c._drop()
                raise ConnError(*err) if isinstance(err, tuple) else ConnError(err)
            if c.state != ESTAB:
                c._drop()
                raise ConnError("timeout", "SYN応答なし")
        return c

    def _tcp_in(self, ip, t):
        key = (ip["dst"], t["dport"], ip["src"], t["sport"])
        c = self.conns.get(key)
        if c is not None:
            c._input(t)
            return
        fl = t["flags"]
        if fl & pkt.RST:
            return
        if (fl & pkt.SYN) and not (fl & pkt.ACK):
            h = self.listeners.get((ip["dst"], t["dport"])) or self.listeners.get((None, t["dport"]))
            if h is not None:
                c = TcpConn(self, ip["dst"], t["dport"], ip["src"], t["sport"])
                self.conns[key] = c
                c._open_passive(t, h)
                return
        # 未知のコネクション → RST (実ホストと同じ挙動)
        if fl & pkt.ACK:
            seq, ack, f = t["ack"], 0, pkt.RST
        else:
            seq = 0
            ack = (t["seq"] + len(t["data"]) + (1 if fl & pkt.SYN else 0) + (1 if fl & pkt.FIN else 0)) & MASK
            f = pkt.RST | pkt.ACK
        self.ip_out(ip["dst"], ip["src"], pkt.P_TCP,
                    pkt.tcp(ip["dst"], ip["src"], t["dport"], t["sport"], seq, ack, f))

    # ---------------------------------------------------------------- タイマー
    def _timer(self):
        while self._run:
            time.sleep(0.05)
            now = time.monotonic()
            with self.lock:
                for c in list(self.conns.values()):
                    c._tick(now)
                for k, (n, t) in list(self.arp_tries.items()):
                    if now - t > 0.5:
                        if n >= 6:
                            self.arp_tries.pop(k, None)
                            self.pending.pop(k, None)
                        else:
                            self._arp_request(*k)


class Ping:
    def __init__(self, stack, dst):
        self.dst = dst
        self.ev = threading.Event()
        self.res = None

    def set(self, kind, src, info=None):
        if self.res is None:
            self.res = (kind, src, info)
            self.ev.set()


class UdpSock:
    def __init__(self, stack, src, port):
        self.stack, self.src, self.port = stack, src, port
        self.q = []
        self.cv = threading.Condition(stack.lock)
        self.icmp_err = None
        with stack.lock:
            stack.udp_socks[(src, port)] = self

    def deliver(self, src, sport, dst, data):
        self.q.append((src, sport, data))
        self.cv.notify_all()

    def set_icmp(self, info):
        self.icmp_err = info
        self.cv.notify_all()

    def sendto(self, dst, dport, data):
        self.stack.udp_send(self.src, self.port, dst, dport, data)

    def recv(self, timeout=3.0):
        """-> (src, sport, data) / TimeoutError / ConnError('icmp')"""
        end = time.monotonic() + timeout
        with self.cv:
            while not self.q:
                if self.icmp_err:
                    raise ConnError("icmp", self.icmp_err)
                rem = end - time.monotonic()
                if rem <= 0:
                    raise TimeoutError()
                self.cv.wait(rem)
            return self.q.pop(0)

    def close(self):
        with self.stack.lock:
            self.stack.udp_socks.pop((self.src, self.port), None)


class TcpConn:
    def __init__(self, stack, lip, lport, rip, rport):
        self.stack = stack
        self.lip, self.lport, self.rip, self.rport = lip, lport, rip, rport
        self.cond = threading.Condition(stack.lock)
        self.state = CLOSED
        self.iss = random.getrandbits(32)
        self.snd_una = self.snd_nxt = self.iss
        self.rcv_nxt = 0
        self.peer_mss = 536
        self.unacked = []      # [seq, flags, data, t_sent, tries]
        self.sendq = bytearray()
        self.rbuf = bytearray()
        self.fin_rcvd = False
        self.want_close = False
        self.fin_sent = False
        self.error = None
        self.icmp_info = None
        self.tw_until = 0
        self.handler = None
        self.created = time.monotonic()

    # ---- 送信プリミティブ
    def _xmit(self, flags, seq, data=b"", mss=0):
        ack = self.rcv_nxt if (flags & pkt.ACK) else 0
        self.stack.ip_out(self.lip, self.rip, pkt.P_TCP,
                          pkt.tcp(self.lip, self.rip, self.lport, self.rport, seq, ack, flags, data, mss=mss))

    def _queue_seg(self, flags, data=b""):
        seq = self.snd_nxt
        self.unacked.append([seq, flags, data, time.monotonic(), 0])
        self.snd_nxt = (self.snd_nxt + len(data) + (1 if flags & (pkt.SYN | pkt.FIN) else 0)) & MASK
        self._xmit(flags, seq, data, mss=MSS if flags & pkt.SYN else 0)

    def _open_active(self):
        self.state = SYN_SENT
        self._queue_seg(pkt.SYN)

    def _open_passive(self, t, handler):
        self.handler = handler
        self.peer_mss = t["mss"] or 536
        self.rcv_nxt = (t["seq"] + 1) & MASK
        self.state = SYN_RCVD
        self._queue_seg(pkt.SYN | pkt.ACK)

    def _flush(self):
        while self.sendq and self.state in (ESTAB, CLOSE_WAIT) and \
                ((self.snd_nxt - self.snd_una) & MASK) < 60000:
            n = min(len(self.sendq), min(self.peer_mss, MSS))
            chunk = bytes(self.sendq[:n])
            del self.sendq[:n]
            self._queue_seg(pkt.ACK | pkt.PSH, chunk)
        if self.want_close and not self.sendq and not self.fin_sent and self.state in (ESTAB, CLOSE_WAIT):
            self.fin_sent = True
            self._queue_seg(pkt.FIN | pkt.ACK)
            self.state = FIN_WAIT1 if self.state == ESTAB else LAST_ACK

    def _ack(self):
        self._xmit(pkt.ACK, self.snd_nxt)

    def _fail(self, kind, detail=""):
        self.error = (kind, detail)
        self.state = CLOSED
        self.unacked.clear()
        self.cond.notify_all()

    def _drop(self):
        self.state = CLOSED
        self.stack.conns.pop((self.lip, self.lport, self.rip, self.rport), None)
        self.cond.notify_all()

    # ---- 受信
    def _input(self, t):
        fl = t["flags"]
        if fl & pkt.RST:
            if self.state == SYN_SENT:
                if (fl & pkt.ACK) and t["ack"] == self.iss + 1 & MASK:
                    self._fail("reset", "SYNにRST")
            elif self.state != CLOSED and (((t["seq"] - self.rcv_nxt) & MASK) < 65535 or
                                           ((self.rcv_nxt - t["seq"]) & MASK) < 65535):
                self._fail("reset", "RST受信")
            return
        if self.state == SYN_SENT:
            if (fl & pkt.SYN) and (fl & pkt.ACK) and t["ack"] == (self.iss + 1) & MASK:
                self.peer_mss = t["mss"] or 536
                self.rcv_nxt = (t["seq"] + 1) & MASK
                self.snd_una = t["ack"]
                self.unacked.clear()
                self.state = ESTAB
                self._ack()
                self.cond.notify_all()
            return
        if self.state == CLOSED:
            return
        if fl & pkt.SYN:
            return   # 再送SYN等 (SYN_RCVDの再送はタイマーが行う)
        if fl & pkt.ACK:
            adv = (t["ack"] - self.snd_una) & MASK
            if 0 < adv <= ((self.snd_nxt - self.snd_una) & MASK):
                self.snd_una = t["ack"]
                while self.unacked:
                    s, f, d, _, _ = self.unacked[0]
                    end = (s + len(d) + (1 if f & (pkt.SYN | pkt.FIN) else 0)) & MASK
                    if ((t["ack"] - end) & MASK) < 0x80000000:
                        self.unacked.pop(0)
                    else:
                        break
                if self.state == SYN_RCVD:
                    self.state = ESTAB
                    h = self.handler
                    threading.Thread(target=self._run_handler, args=(h,), daemon=True).start()
                fin_acked = self.fin_sent and not self.unacked
                if fin_acked:
                    if self.state == FIN_WAIT1:
                        self.state = FIN_WAIT2
                    elif self.state == CLOSING:
                        self._enter_tw()
                    elif self.state == LAST_ACK:
                        self._drop()
                self._flush()
                self.cond.notify_all()
        data = t["data"]
        fin = bool(fl & pkt.FIN)
        if data or fin:
            d = (self.rcv_nxt - t["seq"]) & MASK
            if d > 0x7FFFFFFF:          # 先のデータ(順序入替) → 破棄して dup ACK
                self._ack()
                return
            if d:
                data = data[d:] if d < len(data) else b""
                seq = self.rcv_nxt
            else:
                seq = t["seq"]
            if data:
                self.rbuf += data
                self.rcv_nxt = (self.rcv_nxt + len(data)) & MASK
            if fin and (seq + len(data)) & MASK == self.rcv_nxt and not self.fin_rcvd:
                self.fin_rcvd = True
                self.rcv_nxt = (self.rcv_nxt + 1) & MASK
                if self.state == ESTAB:
                    self.state = CLOSE_WAIT
                elif self.state == FIN_WAIT1:
                    self.state = CLOSING
                elif self.state == FIN_WAIT2:
                    self._enter_tw()
            self._ack()
            self.cond.notify_all()

    def _run_handler(self, h):
        try:
            h(self)
        except Exception:
            import traceback
            traceback.print_exc()
        finally:
            try:
                self.close()
            except Exception:
                pass

    def _enter_tw(self):
        self.state = TIME_WAIT
        self.tw_until = time.monotonic() + 0.5

    def _tick(self, now):
        if self.state == TIME_WAIT and now >= self.tw_until:
            self._drop()
            return
        if self.state == CLOSED and not self.unacked:
            if now - self.created > 1.0 and (self.lip, self.lport, self.rip, self.rport) in self.stack.conns:
                # エラー終了後の残骸は少し置いてから掃除
                self.stack.conns.pop((self.lip, self.lport, self.rip, self.rport), None)
            return
        if self.unacked:
            e = self.unacked[0]
            rto = (0.4 if e[1] & pkt.SYN else 0.25) * (2 ** min(e[4], 4))
            if now - e[3] > rto:
                if e[4] >= (5 if e[1] & pkt.SYN else 10):
                    self._fail("timeout", "再送上限")
                    return
                e[4] += 1
                e[3] = now
                self._xmit(e[1], e[0], e[2], mss=MSS if e[1] & pkt.SYN else 0)

    # ---- アプリ向けAPI
    def send(self, data: bytes):
        with self.cond:
            if self.error:
                raise ConnError(*self.error)
            if self.state not in (ESTAB, CLOSE_WAIT):
                raise ConnError("reset", "送信不可の状態")
            self.sendq += data
            self._flush()

    def recv(self, n=65536, timeout=None):
        end = None if timeout is None else time.monotonic() + timeout
        with self.cond:
            while not self.rbuf:
                if self.error:
                    raise ConnError(*self.error)
                if self.fin_rcvd or self.state == CLOSED:
                    return b""
                rem = None if end is None else end - time.monotonic()
                if rem is not None and rem <= 0:
                    raise TimeoutError()
                self.cond.wait(rem)
            out = bytes(self.rbuf[:n])
            del self.rbuf[:n]
            return out

    def recv_until(self, marker: bytes, timeout=3.0, limit=1 << 20):
        buf = b""
        end = time.monotonic() + timeout
        while marker not in buf:
            rem = end - time.monotonic()
            if rem <= 0:
                raise TimeoutError()
            d = self.recv(timeout=rem)
            if not d:
                break
            buf += d
            if len(buf) > limit:
                break
        return buf

    def recv_all(self, timeout=3.0, limit=1 << 22):
        buf = b""
        end = time.monotonic() + timeout
        while True:
            rem = end - time.monotonic()
            if rem <= 0:
                raise TimeoutError()
            d = self.recv(timeout=rem)
            if not d:
                return buf
            buf += d
            if len(buf) > limit:
                return buf

    def close(self):
        with self.cond:
            if self.state in (ESTAB, CLOSE_WAIT):
                self.want_close = True
                self._flush()
            elif self.state in (SYN_SENT, SYN_RCVD):
                self._drop()

    def abort(self):
        with self.cond:
            if self.state not in (CLOSED, TIME_WAIT, SYN_SENT):
                self._xmit(pkt.RST | pkt.ACK, self.snd_nxt)
            self._drop()
