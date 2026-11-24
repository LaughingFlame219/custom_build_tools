"""アプリケーション層: 各プロトコルの疑似サーバー(受信側)とクライアント(送信側)と判定。

判定 (status):
  pass  : 相手(疑似サーバー)まで正常に届き、期待どおりの応答を受け取れた
  drop  : 応答なし (タイムアウト)           … FWが黙って破棄
  block : RST / ICMP unreachable / ブロックページ / 改ざん応答 … FWが明示的に遮断
  error : ARP未解決・経路なし・内部エラー      … テスター側の問題
"""
import re
import ssl
import struct
import threading
import time

from . import tlsdata
from .sim import EICAR, parse_sni
from .stack import ConnError

DNS_ANSWER = "203.0.113.10"
OK_MARK = b"TGEN-OK"
BLOCK_PAGE = re.compile(rb"(?i)(web ?page blocked|fortiguard|block(ed)? page|access denied|"
                        rb"palo alto networks|has been blocked|policy violation|virus|threat)")


class Result:
    def __init__(self, status, detail="", **extra):
        self.status, self.detail, self.extra = status, detail, extra

    def __repr__(self):
        return "Result(%s, %s, %s)" % (self.status, self.detail, self.extra)


ERRS = {
    "arpRequest": ("ARP応答がありません。", [("ip", "IP"), ("vr", "仮想ルーター"), ("if", "ARP送信元I/F")],
                   "全ネクストホップIPアドレスからのARP応答がない場合、テストパケットを送信できません。\n"
                   "ネクストホップIPアドレス、ネットワーク構成の見直しを行いテストを再実行してください。",
                   [("ip", "ip"), ("vr", "vr"), ("if", "srcif")]),
    "noRoute": ("宛先への経路がありません。", [("ip", "宛先IP"), ("vr", "仮想ルーター")],
                "仮想ルーターの external ルート(0.0.0.0/0 など)を確認してください。", [("vr", "vr"), ("ip", "ip")]),
    "srcNotOwned": ("送信元IPを持つ仮想ルーターがありません。", [("ip", "送信元IP")],
                    "送信元IPがインターフェースのサブネット、または仮想ルーターのinternalルートに含まれているか確認してください。",
                    [("ip", "ip")]),
    "invalidIp": ("IPアドレスが不正です。", [("msg", "内容")],
                  "送信元IP・宛先IPにはIPアドレスを入力してください (FQDNはツール側のFQDN→IP指定で置換できます)。", [("msg", "msg")]),
    "noPort": ("宛先Portがありません。", [("msg", "内容")], "tcp/udp系のシナリオには宛先Portが必要です。", [("msg", "msg")]),
    "unsupported": ("未対応のプロトコルです。", [("msg", "内容")],
                    "icmp / tcp / udp / dns / http / https / ftp / smtp / imap が使えます。", [("msg", "msg")]),
    "noPortLeft": ("送信元ポートを確保できません。", [("msg", "内容")], "同時実行数を減らして再実行してください。", [("msg", "msg")]),
    "internal": ("内部エラーが発生しました。", [("msg", "内容")], "詳細を添えて開発者に連絡してください。", [("msg", "msg")]),
    "stopped": ("実行が中止されました。", [], "", []),
}


def make_err(code, info, detail=""):
    code = {"noroute": "noPortLeft"}.get(code, code)
    t = ERRS.get(code)
    info = dict(info or {})
    if t is None:
        return {"code": code, "title": detail or code, "fields": [], "advice": "", "text": "error(%s)" % code}
    title, fields, advice, keys = t
    if "msg" not in info and ("msg", "msg") in keys:
        info["msg"] = detail
    text = "error(%s:%s)" % (code, "".join("%s{%s}" % (k, info.get(f, "")) for f, k in keys))
    return {"code": code, "title": title, "fields": [(lbl, info.get(f, "")) for f, lbl in fields],
            "advice": advice, "text": text}


def classify(e, stage=""):
    """例外 → Result"""
    pre = stage + ": " if stage else ""
    if isinstance(e, ConnError):
        if e.kind == "timeout":
            return Result("drop", pre + "応答なし(タイムアウト)")
        if e.kind in ("reset", "icmp"):
            d = e.detail
            if isinstance(d, tuple):
                t, c, who = d
                names = {(3, 0): "net unreachable", (3, 1): "host unreachable", (3, 3): "port unreachable",
                         (3, 9): "net prohibited", (3, 10): "host prohibited", (3, 13): "admin prohibited"}
                d = "ICMP %s (type%d/code%d) from %s" % (names.get((t, c), "unreachable"), t, c, who)
            return Result("block", pre + (d or "RST"))
        return Result("error", pre + e.detail, err=make_err(e.kind, e.info, e.detail))
    if isinstance(e, TimeoutError):
        return Result("drop", pre + "応答なし(タイムアウト)")
    if isinstance(e, ssl.SSLError):
        return Result("block", pre + "TLSエラー: %s" % (e.reason or e))
    return Result("error", pre + "内部エラー: %r" % (e,), err=make_err("internal", {"msg": repr(e)}, repr(e)))


class Observer:
    """受信側が実際に観測した接続 (NAT検証用)"""

    def __init__(self):
        self.lock = threading.Lock()
        self.items = []

    def record(self, proto, lip, lport, rip, rport, **extra):
        with self.lock:
            self.items.append(dict(t=time.monotonic(), proto=proto, lip=lip, lport=lport, rip=rip, rport=rport, **extra))

    def find(self, proto, lip, lport, since, rport=None):
        with self.lock:
            c = [x for x in self.items if x["proto"] == proto and x["lip"] == lip and x["lport"] == lport and x["t"] >= since]
        if rport is not None:
            m = [x for x in c if x["rport"] == rport]
            if m:
                return m[-1]
        return c[-1] if len(c) == 1 else (c[-1] if c else None)


# ======================================================================= TLS over TcpConn
class Tls:
    def __init__(self, conn, server, hostname=None):
        self.conn = conn
        self.inb, self.outb = ssl.MemoryBIO(), ssl.MemoryBIO()
        if server:
            self.obj = tlsdata.server_context().wrap_bio(self.inb, self.outb, server_side=True)
        else:
            self.obj = tlsdata.client_context().wrap_bio(self.inb, self.outb, server_hostname=hostname)
        self.plain = bytearray()

    def _flush(self):
        d = self.outb.read()
        if d:
            self.conn.send(d)

    def handshake(self, timeout):
        end = time.monotonic() + timeout
        while True:
            try:
                self.obj.do_handshake()
                self._flush()
                return
            except ssl.SSLWantReadError:
                self._flush()
                rem = end - time.monotonic()
                if rem <= 0:
                    raise TimeoutError()
                d = self.conn.recv(timeout=rem)
                if not d:
                    raise ConnError("reset", "TLSハンドシェイク中に接続が閉じられた")
                self.inb.write(d)

    def send(self, data):
        self.obj.write(data)
        self._flush()

    def recv(self, timeout):
        """平文を返す。b'' = EOF"""
        end = time.monotonic() + timeout
        while True:
            try:
                d = self.obj.read(65536)
                self._flush()
                return d
            except ssl.SSLWantReadError:
                self._flush()
                rem = end - time.monotonic()
                if rem <= 0:
                    raise TimeoutError()
                r = self.conn.recv(timeout=rem)
                if not r:
                    return b""
                self.inb.write(r)
            except ssl.SSLZeroReturnError:
                return b""

    def peer_der(self):
        return self.obj.getpeercert(binary_form=True)


class Plain:
    """TcpConn を Tls と同じ send/recv で扱うためのラッパ"""

    def __init__(self, conn):
        self.conn = conn

    def send(self, d):
        self.conn.send(d)

    def recv(self, timeout):
        return self.conn.recv(timeout=timeout)


def read_until(ch, marker, timeout, limit=1 << 20):
    buf = b""
    end = time.monotonic() + timeout
    while marker not in buf and len(buf) < limit:
        rem = end - time.monotonic()
        if rem <= 0:
            raise TimeoutError()
        d = ch.recv(rem)
        if not d:
            break
        buf += d
    return buf


# ======================================================================= HTTP
def http_response_for(req: bytes, rip):
    head = req.split(b"\r\n\r\n", 1)[0].decode("latin1")
    lines = head.split("\r\n")
    path = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else "/"
    host = ""
    for l in lines[1:]:
        if l.lower().startswith("host:"):
            host = l[5:].strip()
    if "eicar" in path.lower():
        body = EICAR
        ctype = "application/octet-stream"
    else:
        body = OK_MARK + b" host=" + host.encode() + b" src=" + rip.encode()
        ctype = "text/plain"
    h = ("HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (ctype, len(body))).encode()
    return h + body, host, path


def serve_http(obs, tls=False):
    def handler(conn):
        try:
            ch = Plain(conn)
            sni = None
            if tls:
                ch = Tls(conn, True)
                ch.handshake(5)
            req = read_until(ch, b"\r\n\r\n", 5)
            if not req:
                return
            resp, host, path = http_response_for(req, conn.rip)
            obs.record("tcp", conn.lip, conn.lport, conn.rip, conn.rport, app="https" if tls else "http", host=host)
            ch.send(resp)
        except (ConnError, TimeoutError, ssl.SSLError):
            pass
    return handler


def _http_exchange(ch, host, path, timeout):
    req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: tgen/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n" % (path, host)).encode()
    ch.send(req)
    buf = b""
    end = time.monotonic() + timeout
    got_err = None
    while True:
        rem = end - time.monotonic()
        if rem <= 0:
            got_err = TimeoutError()
            break
        try:
            d = ch.recv(rem)
        except TimeoutError as e:
            got_err = e
            break
        except (ConnError, ssl.SSLError) as e:
            got_err = e
            break
        if not d:
            break
        buf += d
        if len(buf) > 1 << 20:
            break
    return buf, got_err


def judge_http(buf, err, av, stage="HTTP", real=False):
    if not buf:
        if err is not None:
            return classify(err, stage)
        return Result("block", stage + ": 応答なしで接続が閉じられた")
    status = buf.split(b"\r\n", 1)[0].decode("latin1")
    body = buf.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in buf else b""
    code = status.split(" ")[1] if len(status.split(" ")) > 1 else ""
    if av:
        if EICAR in body:
            return Result("pass", "EICARを受信できた (AVでブロックされていない)")
        return Result("block", "%s: EICARが届かない (%s)" % (stage, status), http_status=code)
    if real and code.isdigit() and int(code) < 400 and not BLOCK_PAGE.search(buf[:4096]):
        return Result("pass", "HTTP %s (実サーバー)" % code, http_status=code)
    if code == "200" and OK_MARK in body:
        return Result("pass", "HTTP 200", http_status=code)
    if BLOCK_PAGE.search(buf[:4096]) or code in ("403", "451", "502", "503"):
        return Result("block", "%s: ブロックページ/拒否応答 (%s)" % (stage, status), http_status=code)
    return Result("block", "%s: 想定外の応答 (%s)" % (stage, status), http_status=code)


def client_http(stack, src, dst, dport, sc, tls=False):
    to = sc["timeout"]
    host = sc["url"] or dst
    try:
        c = stack.tcp_connect(src, dst, dport, to, sc.get("sport", 0))
    except Exception as e:
        return classify(e, "TCP接続")
    extra = {}
    try:
        ch = Plain(c)
        if tls:
            ch = Tls(c, False, sc["url"] or None)
            try:
                ch.handshake(to)
            except Exception as e:
                r = classify(e, "TLS")
                if isinstance(e, TimeoutError):
                    r.detail = "TLS: ServerHello応答なし (SNI/ハンドシェイクをFWが破棄?)"
                return r
            iss = tlsdata.issuer_of(ch.peer_der() or b"")
            extra = {"cert_issuer": iss, "ssl_inspected": bool(iss) and iss != tlsdata.TEST_ISSUER}
        path = "/eicar.com" if sc["av"] else "/"
        buf, err = _http_exchange(ch, host, path, to)
        r = judge_http(buf, err, sc["av"], "HTTPS" if tls else "HTTP", sc.get("real", False))
        r.extra.update(extra)
        if extra.get("ssl_inspected"):
            r.detail += " [SSL復号を検出: issuer=%s]" % extra["cert_issuer"]
        return r
    finally:
        c.close()


# ======================================================================= TCP / UDP / ICMP
def serve_tcp(obs):
    def handler(conn):
        obs.record("tcp", conn.lip, conn.lport, conn.rip, conn.rport, app="tcp")
        try:
            while conn.recv(timeout=2):
                pass
        except (TimeoutError, ConnError):
            pass
    return handler


def client_tcp(stack, src, dst, dport, sc):
    try:
        c = stack.tcp_connect(src, dst, dport, sc["timeout"], sc.get("sport", 0))
    except Exception as e:
        return classify(e, "TCP接続")
    time.sleep(0.05)
    c.close()
    return Result("pass", "TCP接続確立 (SYN/ACK受信)")


def serve_udp(obs, stack):
    def handler(src, sport, dst, dport, data):
        obs.record("udp", dst, dport, src, sport, app="udp")
        stack.udp_send(dst, dport, src, sport, b"TGEN-UDP:" + data[:512])
    return handler


def client_udp(stack, src, dst, dport, sc):
    try:
        stack.resolve(src, dst)
    except Exception as e:
        return classify(e)
    s = stack.udp_sock(src, sc.get("sport", 0))
    try:
        end = time.monotonic() + sc["timeout"]
        s.sendto(dst, dport, b"TGEN-UDP-PROBE")
        last = time.monotonic()
        while True:
            rem = end - time.monotonic()
            if rem <= 0:
                return Result("drop", "応答なし(タイムアウト)")
            try:
                r = s.recv(min(rem, 1.0))
            except TimeoutError:
                if time.monotonic() - last >= 1.0:
                    s.sendto(dst, dport, b"TGEN-UDP-PROBE")
                    last = time.monotonic()
                continue
            except ConnError as e:
                return classify(e, "UDP")
            if r[2].startswith(b"TGEN-UDP:") or sc.get("real"):
                return Result("pass", "UDP応答を受信")
            return Result("block", "UDP: 想定外の応答")
    finally:
        s.close()


def client_icmp(stack, src, dst, dport, sc):
    try:
        k, who, info = stack.ping(src, dst, sc["timeout"])
    except Exception as e:
        return classify(e)
    if k == "reply":
        return Result("pass", "echo reply")
    if k == "icmp":
        t, c, w = info
        if t == 11:
            return Result("error", "ICMP time exceeded from %s (ルーティングループ?)" % w)
        return classify(ConnError("icmp", info), "ICMP")
    return Result("drop", "応答なし(タイムアウト)")


# ======================================================================= DNS
def _qname(buf, i):
    labels = []
    while buf[i]:
        n = buf[i]
        labels.append(buf[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return ".".join(labels), i + 1


def serve_dns(obs, stack):
    def handler(src, sport, dst, dport, data):
        try:
            tid = data[:2]
            name, i = _qname(data, 12)
            qtype = struct.unpack("!H", data[i:i + 2])[0]
            q = data[12:i + 4]
            obs.record("udp", dst, dport, src, sport, app="dns", qname=name)
            if qtype == 1:
                ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + bytes(int(x) for x in DNS_ANSWER.split("."))
                resp = tid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + q + ans
            else:
                resp = tid + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0) + q
            stack.udp_send(dst, dport, src, sport, resp)
        except (IndexError, struct.error):
            pass
    return handler


def build_dns_query(name, tid):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def client_dns(stack, src, dst, dport, sc):
    try:
        stack.resolve(src, dst)
    except Exception as e:
        return classify(e)
    name = sc["url"] or "example.com"
    if name.replace(".", "").isdigit():
        name = "example.com"
    s = stack.udp_sock(src, sc.get("sport", 0))
    tid = (s.port * 7 + 1) & 0xFFFF
    try:
        end = time.monotonic() + sc["timeout"]
        s.sendto(dst, dport, build_dns_query(name, tid))
        last = time.monotonic()
        while True:
            rem = end - time.monotonic()
            if rem <= 0:
                return Result("drop", "DNS応答なし(タイムアウト)")
            try:
                _, _, d = s.recv(min(rem, 1.0))
            except TimeoutError:
                if time.monotonic() - last >= 1.0:
                    s.sendto(dst, dport, build_dns_query(name, tid))
                    last = time.monotonic()
                continue
            except ConnError as e:
                return classify(e, "DNS")
            if len(d) < 12 or d[:2] != struct.pack("!H", tid):
                continue
            rcode = d[3] & 0x0F
            an = struct.unpack("!H", d[6:8])[0]
            if rcode != 0:
                return Result("block", "DNS: rcode=%d (NXDOMAIN等で遮断)" % rcode)
            ip = ""
            if an:
                _, i = _qname(d, 12)
                i += 4
                # 先頭アンサーのRDATA(A)を読む
                if d[i] & 0xC0 == 0xC0:
                    i += 2
                else:
                    _, i = _qname(d, i)
                rtype, _, _, rl = struct.unpack("!HHIH", d[i:i + 10])
                if rtype == 1 and rl == 4:
                    ip = ".".join(str(x) for x in d[i + 10:i + 14])
            if ip and ip != DNS_ANSWER and not sc.get("real"):
                return Result("block", "DNS: 応答が書き換えられた (sinkhole? %s)" % ip, dns_answer=ip)
            return Result("pass", "DNS応答 %s" % (ip or "(no A)"), dns_answer=ip)
    finally:
        s.close()


# ======================================================================= FTP
def serve_ftp(obs, stack):
    def handler(conn):
        dataq = []
        ev = threading.Event()
        pasv_port = [0]

        def reply(s):
            conn.send((s + "\r\n").encode())

        def dh(dc):
            dataq.append(dc)
            ev.set()
            time.sleep(3.0)   # 制御側が使い終わるまで保持

        try:
            obs.record("tcp", conn.lip, conn.lport, conn.rip, conn.rport, app="ftp")
            reply("220 TGEN FTP ready")
            buf = b""
            while True:
                while b"\r\n" not in buf:
                    d = conn.recv(timeout=5)
                    if not d:
                        return
                    buf += d
                line, buf = buf.split(b"\r\n", 1)
                cmd, _, arg = line.decode(errors="replace").partition(" ")
                cmd = cmd.upper()
                if cmd == "USER":
                    reply("331 password required")
                elif cmd == "PASS":
                    reply("230 logged in")
                elif cmd == "SYST":
                    reply("215 UNIX Type: L8")
                elif cmd == "TYPE":
                    reply("200 type set")
                elif cmd in ("PASV", "EPSV"):
                    p = stack.new_port()
                    pasv_port[0] = p
                    ev.clear()
                    dataq.clear()
                    stack.tcp_listen(conn.lip, p, dh)
                    if cmd == "PASV":
                        a = conn.lip.split(".")
                        reply("227 Entering Passive Mode (%s,%s,%s,%s,%d,%d)" % (*a, p >> 8, p & 255))
                    else:
                        reply("229 Entering Extended Passive Mode (|||%d|)" % p)
                elif cmd in ("LIST", "RETR", "NLST"):
                    if not ev.wait(4):
                        reply("425 can't open data connection")
                        continue
                    dc = dataq[-1]
                    reply("150 opening data connection")
                    data = EICAR if (cmd == "RETR" and "eicar" in arg.lower()) else b"-rw-r--r-- 1 tgen tgen 10 Jan 1 00:00 tgen.txt\r\n"
                    dc.send(data)
                    dc.close()
                    time.sleep(0.1)
                    reply("226 transfer complete")
                    with stack.lock:
                        stack.listeners.pop((conn.lip, pasv_port[0]), None)
                elif cmd == "QUIT":
                    reply("221 bye")
                    return
                else:
                    reply("502 not implemented")
        except (ConnError, TimeoutError):
            pass
        finally:
            if pasv_port[0]:
                with stack.lock:
                    stack.listeners.pop((conn.lip, pasv_port[0]), None)
    return handler


def client_ftp(stack, src, dst, dport, sc):
    to = sc["timeout"]
    try:
        c = stack.tcp_connect(src, dst, dport, to, sc.get("sport", 0))
    except Exception as e:
        return classify(e, "TCP接続")
    try:
        def rd():
            b = c.recv_until(b"\r\n", to)
            if not b:
                raise ConnError("reset", "接続が閉じられた")
            return b.decode(errors="replace")
        try:
            g = rd()
            if not g.startswith("220"):
                return Result("block", "FTP: バナー異常 %r" % g[:60])
            if sc.get("real"):
                c.send(b"QUIT\r\n")
                return Result("pass", "FTPバナー受信 (実サーバー)")
            for cmd, code in ((b"USER anonymous\r\n", "331"), (b"PASS tgen@example.com\r\n", "230")):
                c.send(cmd)
                r = rd()
                if not r.startswith(code):
                    return Result("block", "FTP: %r" % r[:60])
            if not sc["av"]:
                c.send(b"QUIT\r\n")
                return Result("pass", "FTPログイン成功")
            c.send(b"PASV\r\n")
            r = rd()
            m = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", r)
            if not m:
                return Result("block", "FTP: PASV失敗 %r" % r[:60])
            port = int(m.group(5)) * 256 + int(m.group(6))
            c.send(b"RETR eicar.com\r\n")
            try:
                dc = stack.tcp_connect(src, dst, port, to, 0)
            except Exception as e:
                return classify(e, "FTPデータ接続")
            try:
                data = dc.recv_all(to)
            except (ConnError, TimeoutError) as e:
                data = b""
                err = e
            if EICAR in data:
                return Result("pass", "EICARを受信できた (AVでブロックされていない)")
            return Result("block", "FTP: EICARが届かない (データ%dバイト)" % len(data))
        except Exception as e:
            return classify(e, "FTP")
    finally:
        c.close()


# ======================================================================= SMTP
def serve_smtp(obs):
    def handler(conn):
        try:
            obs.record("tcp", conn.lip, conn.lport, conn.rip, conn.rport, app="smtp")
            conn.send(b"220 tgen ESMTP ready\r\n")
            buf = b""
            while True:
                while b"\r\n" not in buf:
                    d = conn.recv(timeout=5)
                    if not d:
                        return
                    buf += d
                line, buf = buf.split(b"\r\n", 1)
                u = line.upper()
                if u.startswith((b"EHLO", b"HELO")):
                    conn.send(b"250-tgen\r\n250 8BITMIME\r\n")
                elif u.startswith((b"MAIL", b"RCPT", b"RSET", b"NOOP")):
                    conn.send(b"250 OK\r\n")
                elif u.startswith(b"DATA"):
                    conn.send(b"354 end with <CRLF>.<CRLF>\r\n")
                    while b"\r\n.\r\n" not in buf:
                        d = conn.recv(timeout=5)
                        if not d:
                            return
                        buf += d
                    buf = buf.split(b"\r\n.\r\n", 1)[1]
                    conn.send(b"250 queued\r\n")
                elif u.startswith(b"QUIT"):
                    conn.send(b"221 bye\r\n")
                    return
                else:
                    conn.send(b"502 not implemented\r\n")
        except (ConnError, TimeoutError):
            pass
    return handler


def client_smtp(stack, src, dst, dport, sc):
    to = sc["timeout"]
    try:
        c = stack.tcp_connect(src, dst, dport, to, sc.get("sport", 0))
    except Exception as e:
        return classify(e, "TCP接続")
    try:
        def rd(code, what):
            b = b""
            while True:
                d = c.recv(timeout=to)
                if not d:
                    if not b:
                        raise ConnError("reset", "接続が閉じられた")
                    break
                b += d
                last = b.rstrip(b"\r\n").split(b"\r\n")[-1]
                if b.endswith(b"\r\n") and re.match(rb"\d{3}( |$)", last):
                    break
            if not b.startswith(code):
                return b.decode(errors="replace")[:60]
            return None
        try:
            for cmd, code, what in ((None, b"220", "バナー"), (b"EHLO tgen.local\r\n", b"250", "EHLO"),
                                    (b"MAIL FROM:<tgen@example.com>\r\n", b"250", "MAIL"),
                                    (b"RCPT TO:<test@example.com>\r\n", b"250", "RCPT"),
                                    (b"DATA\r\n", b"354", "DATA")):
                if cmd:
                    c.send(cmd)
                bad = rd(code, what)
                if bad:
                    return Result("block", "SMTP %s: %r" % (what, bad))
                if sc.get("real") and what == "EHLO":
                    c.send(b"QUIT\r\n")
                    return Result("pass", "SMTP EHLO成功 (実サーバー)")
            body = b"Subject: tgen test\r\nFrom: tgen@example.com\r\nTo: test@example.com\r\n\r\ntgen test mail\r\n"
            if sc["av"]:
                body += EICAR + b"\r\n"
            c.send(body + b".\r\n")
            bad = rd(b"250", "本文")
            if bad:
                return Result("block", "SMTP 本文送信: %r" % bad)
            c.send(b"QUIT\r\n")
            return Result("pass", "SMTP送信成功" + (" (EICAR添付が通過)" if sc["av"] else ""))
        except Exception as e:
            return classify(e, "SMTP")
    finally:
        c.close()


# ======================================================================= IMAP
def serve_imap(obs):
    def handler(conn):
        try:
            obs.record("tcp", conn.lip, conn.lport, conn.rip, conn.rport, app="imap")
            conn.send(b"* OK [CAPABILITY IMAP4rev1] tgen IMAP ready\r\n")
            buf = b""
            while True:
                while b"\r\n" not in buf:
                    d = conn.recv(timeout=5)
                    if not d:
                        return
                    buf += d
                line, buf = buf.split(b"\r\n", 1)
                tag, _, rest = line.decode(errors="replace").partition(" ")
                cmd = rest.split(" ")[0].upper()
                if cmd == "CAPABILITY":
                    conn.send(("* CAPABILITY IMAP4rev1\r\n%s OK done\r\n" % tag).encode())
                elif cmd == "LOGIN":
                    conn.send(("%s OK logged in\r\n" % tag).encode())
                elif cmd == "SELECT":
                    conn.send(("* 2 EXISTS\r\n%s OK [READ-WRITE] selected\r\n" % tag).encode())
                elif cmd == "FETCH":
                    msg = b"Subject: tgen\r\n\r\ntgen imap body\r\n"
                    if rest.split(" ")[1:2] == ["2"]:
                        msg += EICAR + b"\r\n"
                    conn.send(b"* %s FETCH (BODY[] {%d}\r\n" % (rest.split(" ")[1].encode(), len(msg)) + msg +
                              (")\r\n%s OK fetch done\r\n" % tag).encode())
                elif cmd == "LOGOUT":
                    conn.send(("* BYE\r\n%s OK logout\r\n" % tag).encode())
                    return
                else:
                    conn.send(("%s BAD unknown\r\n" % tag).encode())
        except (ConnError, TimeoutError):
            pass
    return handler


def client_imap(stack, src, dst, dport, sc):
    to = sc["timeout"]
    try:
        c = stack.tcp_connect(src, dst, dport, to, sc.get("sport", 0))
    except Exception as e:
        return classify(e, "TCP接続")
    try:
        def rd_tag(tag):
            b = c.recv_until((tag + " ").encode() if tag else b"\r\n", to)
            if not b:
                raise ConnError("reset", "接続が閉じられた")
            if tag:
                while not re.search((tag + r" (OK|NO|BAD)[^\r]*\r\n").encode(), b):
                    d = c.recv(timeout=to)
                    if not d:
                        break
                    b += d
            return b
        try:
            g = rd_tag(None)
            if not g.startswith(b"* OK"):
                return Result("block", "IMAP: バナー異常 %r" % g[:60])
            if sc.get("real"):
                c.send(b"a1 LOGOUT\r\n")
                return Result("pass", "IMAPバナー受信 (実サーバー)")
            seq = [("a1", "LOGIN tgen tgen"), ("a2", "SELECT INBOX"), ("a3", "FETCH %d BODY[]" % (2 if sc["av"] else 1))]
            last = b""
            for tag, cmd in seq:
                c.send(("%s %s\r\n" % (tag, cmd)).encode())
                last = rd_tag(tag)
                if (tag + " OK").encode() not in last:
                    return Result("block", "IMAP %s: %r" % (cmd.split(" ")[0], last[-60:]))
            c.send(b"a4 LOGOUT\r\n")
            if sc["av"]:
                if EICAR in last:
                    return Result("pass", "EICARを受信できた (AVでブロックされていない)")
                return Result("block", "IMAP: EICARが届かない")
            return Result("pass", "IMAPログイン/取得成功")
        except Exception as e:
            return classify(e, "IMAP")
    finally:
        c.close()


# ======================================================================= 登録表
CLIENTS = {
    "icmp": client_icmp, "tcp": client_tcp, "udp": client_udp, "dns": client_dns,
    "http": client_http, "https": lambda *a: client_http(*a, tls=True),
    "ftp": client_ftp, "smtp": client_smtp, "imap": client_imap,
}
DEFAULT_PORT = {"dns": 53, "http": 80, "https": 443, "ftp": 21, "smtp": 25, "imap": 143}
UDP_APPS = {"udp", "dns"}


def register_server(stack, obs, app, ip, port):
    """受信側(ip:port)にその app の疑似サーバーを立てる (icmpは不要)"""
    if app == "icmp":
        return
    if app in UDP_APPS:
        h = serve_dns(obs, stack) if app == "dns" else serve_udp(obs, stack)
        stack.udp_listen(ip, port, h)
        return
    h = {"tcp": lambda: serve_tcp(obs), "http": lambda: serve_http(obs), "https": lambda: serve_http(obs, True),
         "ftp": lambda: serve_ftp(obs, stack), "smtp": lambda: serve_smtp(obs), "imap": lambda: serve_imap(obs)}[app]()
    stack.tcp_listen(ip, port, h)
