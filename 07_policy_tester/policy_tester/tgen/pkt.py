"""パケットの組み立て・解析 (Ethernet / 802.1Q / ARP / IPv4 / ICMP / TCP / UDP)。標準ライブラリのみ。"""
import socket
import struct

ETH_IP, ETH_ARP, ETH_VLAN = 0x0800, 0x0806, 0x8100
P_ICMP, P_TCP, P_UDP = 1, 6, 17
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
BCAST = b"\xff" * 6


def csum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def mac2b(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.replace("-", ":").split(":"))


def b2mac(b: bytes) -> str:
    return ":".join("%02x" % x for x in b)


def ip2b(s: str) -> bytes:
    return socket.inet_aton(s)


def b2ip(b: bytes) -> str:
    return socket.inet_ntoa(b)


# ---------- Ethernet ----------
def eth(dst: bytes, src: bytes, etype: int, payload: bytes, vlan: int = 0) -> bytes:
    if vlan:
        return dst + src + struct.pack("!HHH", ETH_VLAN, vlan & 0x0FFF, etype) + payload
    return dst + src + struct.pack("!H", etype) + payload


def parse_eth(f: bytes):
    """-> (dst, src, ethertype, vlan(0=なし), payload) / 不正は None"""
    if len(f) < 14:
        return None
    dst, src = f[0:6], f[6:12]
    et = struct.unpack("!H", f[12:14])[0]
    vlan = 0
    off = 14
    if et == ETH_VLAN:
        if len(f) < 18:
            return None
        tci, et = struct.unpack("!HH", f[14:18])
        vlan = tci & 0x0FFF
        off = 18
    return dst, src, et, vlan, f[off:]


# ---------- ARP ----------
def arp(op: int, smac: bytes, sip: str, tmac: bytes, tip: str) -> bytes:
    return struct.pack("!HHBBH", 1, ETH_IP, 6, 4, op) + smac + ip2b(sip) + tmac + ip2b(tip)


def parse_arp(p: bytes):
    """-> (op, smac, sip, tmac, tip)"""
    if len(p) < 28:
        return None
    op = struct.unpack("!H", p[6:8])[0]
    return op, p[8:14], b2ip(p[14:18]), p[18:24], b2ip(p[24:28])


# ---------- IPv4 ----------
_ident = [1]


def ip4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64, ident: int = None, df: bool = True) -> bytes:
    if ident is None:
        _ident[0] = (_ident[0] + 1) & 0xFFFF
        ident = _ident[0]
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident,
                      0x4000 if df else 0, ttl, proto, 0, ip2b(src), ip2b(dst))
    return hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:] + payload


def parse_ip(p: bytes):
    """-> dict(src,dst,proto,ttl,payload,frag) / 不正・フラグメントは frag=True"""
    if len(p) < 20 or p[0] >> 4 != 4:
        return None
    ihl = (p[0] & 0x0F) * 4
    tot = struct.unpack("!H", p[2:4])[0]
    if ihl < 20 or len(p) < ihl:
        return None
    tot = min(tot, len(p)) if tot >= ihl else len(p)
    ff = struct.unpack("!H", p[6:8])[0]
    return {"src": b2ip(p[12:16]), "dst": b2ip(p[16:20]), "proto": p[9], "ttl": p[8],
            "payload": p[ihl:tot], "frag": bool(ff & 0x3FFF), "hdr": p[:ihl], "id": struct.unpack("!H", p[4:6])[0]}


def _pseudo(src: str, dst: str, proto: int, ln: int) -> bytes:
    return ip2b(src) + ip2b(dst) + struct.pack("!BBH", 0, proto, ln)


# ---------- ICMP ----------
def icmp(typ: int, code: int, rest: bytes, data: bytes = b"") -> bytes:
    b = struct.pack("!BBH", typ, code, 0) + rest + data
    return b[:2] + struct.pack("!H", csum(b)) + b[4:]


def echo(typ: int, ident: int, seq: int, data: bytes = b"") -> bytes:
    return icmp(typ, 0, struct.pack("!HH", ident, seq), data)


def parse_icmp(p: bytes):
    """-> dict(type,code,ident,seq,data)  data=8バイト目以降"""
    if len(p) < 8:
        return None
    typ, code = p[0], p[1]
    ident, seq = struct.unpack("!HH", p[4:8])
    return {"type": typ, "code": code, "ident": ident, "seq": seq, "data": p[8:]}


# ---------- UDP ----------
def udp(src: str, dst: str, sport: int, dport: int, data: bytes = b"") -> bytes:
    ln = 8 + len(data)
    h = struct.pack("!HHHH", sport, dport, ln, 0)
    c = csum(_pseudo(src, dst, P_UDP, ln) + h + data) or 0xFFFF
    return struct.pack("!HHHH", sport, dport, ln, c) + data


def parse_udp(p: bytes):
    if len(p) < 8:
        return None
    sp, dp, ln, _ = struct.unpack("!HHHH", p[:8])
    return {"sport": sp, "dport": dp, "data": p[8:max(8, ln)]}


# ---------- TCP ----------
def tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int,
        data: bytes = b"", win: int = 65535, mss: int = 0) -> bytes:
    opts = struct.pack("!BBH", 2, 4, mss) if mss else b""
    off = (20 + len(opts)) // 4
    h = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                    off << 4, flags, win, 0, 0) + opts
    c = csum(_pseudo(src, dst, P_TCP, len(h) + len(data)) + h + data)
    return h[:16] + struct.pack("!H", c) + h[18:] + data


def parse_tcp(p: bytes):
    if len(p) < 20:
        return None
    sp, dp, seq, ack, off, fl, win = struct.unpack("!HHIIBBH", p[:16])
    off = (off >> 4) * 4
    if off < 20 or len(p) < off:
        return None
    mss = 0
    o = p[20:off]
    i = 0
    while i < len(o):
        k = o[i]
        if k == 0:
            break
        if k == 1:
            i += 1
            continue
        if i + 1 >= len(o) or o[i + 1] < 2:
            break
        if k == 2 and o[i + 1] == 4 and i + 4 <= len(o):
            mss = struct.unpack("!H", o[i + 2:i + 4])[0]
        i += o[i + 1]
    return {"sport": sp, "dport": dp, "seq": seq, "ack": ack, "flags": fl, "win": win,
            "mss": mss, "data": p[off:]}
