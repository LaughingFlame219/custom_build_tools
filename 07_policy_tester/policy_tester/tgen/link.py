"""リンク層。Link = フレームを送受信する物理ポート1本。
 - PcapLink : Npcap (wpcap.dll) を ctypes で直接叩く (Windows実機用)
 - MemLink  : メモリ上の仮想ケーブル (テスト・疑似FW用)
"""
import ctypes
import os
import queue
import sys
import threading


class Link:
    name = "link"

    def __init__(self):
        self.on_frame = None  # callable(bytes)
        self._run = False

    def send(self, frame: bytes):
        raise NotImplementedError

    def start(self, on_frame):
        self.on_frame = on_frame
        self._run = True

    def stop(self):
        self._run = False


# ------------------------------------------------------------------ MemLink
class MemLink(Link):
    """peer と繋がったポート。send() は peer の受信キューに入る。受信は専用スレッド。"""

    def __init__(self, name="mem"):
        super().__init__()
        self.name = name
        self.peer = None
        self.q = queue.Queue()
        self.th = None
        self.tx_hook = None  # テスト用: 送信フレームの観測
        self.loss = None  # callable(frame)->bool True なら捨てる

    @staticmethod
    def pair(a_name="a", b_name="b"):
        a, b = MemLink(a_name), MemLink(b_name)
        a.peer, b.peer = b, a
        return a, b

    def send(self, frame: bytes):
        if self.tx_hook:
            self.tx_hook(frame)
        if self.loss and self.loss(frame):
            return
        if self.peer is not None:
            self.peer.q.put(bytes(frame))

    def start(self, on_frame):
        super().start(on_frame)
        self.th = threading.Thread(target=self._loop, daemon=True, name="memlink-" + self.name)
        self.th.start()

    def _loop(self):
        while self._run:
            try:
                f = self.q.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                self.on_frame(f)
            except Exception:  # 1フレームの失敗でスレッドを止めない
                import traceback
                traceback.print_exc()

    def stop(self):
        super().stop()


# ------------------------------------------------------------------ Npcap
class PcapError(RuntimeError):
    pass


def _load_wpcap():
    if sys.platform != "win32":
        raise PcapError("Npcap(wpcap.dll)はWindowsでのみ使えます")
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    d = os.path.join(sysroot, "System32", "Npcap")
    cands = [os.path.join(d, "wpcap.dll"), "wpcap.dll"]
    err = None
    for c in cands:
        try:
            if os.path.isdir(d) and hasattr(os, "add_dll_directory"):
                os.add_dll_directory(d)
            return ctypes.CDLL(c)
        except OSError as e:
            err = e
    raise PcapError("Npcap が見つかりません。https://npcap.com/ から "
                    "「WinPcap API-compatible Mode」を有効にしてインストールしてください (%s)" % err)


class _pcap_if(ctypes.Structure):
    pass


_pcap_if._fields_ = [("next", ctypes.POINTER(_pcap_if)), ("name", ctypes.c_char_p),
                     ("description", ctypes.c_char_p), ("addresses", ctypes.c_void_p),
                     ("flags", ctypes.c_uint32)]


class _pkthdr(ctypes.Structure):
    # Windows の struct timeval は long(4byte) x2
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long),
                ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]


_lib = None


def lib():
    global _lib
    if _lib is None:
        L = _load_wpcap()
        L.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(_pcap_if)), ctypes.c_char_p]
        L.pcap_freealldevs.argtypes = [ctypes.POINTER(_pcap_if)]
        L.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
        L.pcap_open_live.restype = ctypes.c_void_p
        L.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(_pkthdr)),
                                   ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
        L.pcap_sendpacket.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
        L.pcap_close.argtypes = [ctypes.c_void_p]
        L.pcap_geterr.argtypes = [ctypes.c_void_p]
        L.pcap_geterr.restype = ctypes.c_char_p
        _lib = L
    return _lib


def friendly_names():
    """{GUID(大文字): 'イーサネット'} をレジストリから取得 (NEEDLEWORKのos_ifに書く名前)"""
    out = {}
    try:
        import winreg
        base = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as k:
            i = 0
            while True:
                try:
                    g = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(k, g + r"\Connection") as c:
                        out[g.upper()] = winreg.QueryValueEx(c, "Name")[0]
                except OSError:
                    pass
    except Exception:
        pass
    return out


def list_devices():
    """-> [{'name': r'\\Device\\NPF_{GUID}', 'desc': ..., 'friendly': 'イーサネット'}]"""
    L = lib()
    err = ctypes.create_string_buffer(256)
    head = ctypes.POINTER(_pcap_if)()
    if L.pcap_findalldevs(ctypes.byref(head), err) != 0:
        raise PcapError(err.value.decode(errors="replace"))
    fn = friendly_names()
    res = []
    p = head
    while p:
        d = p.contents
        name = d.name.decode()
        guid = name[name.find("{"):].upper() if "{" in name else ""
        res.append({"name": name, "desc": (d.description or b"").decode(errors="replace"),
                    "friendly": fn.get(guid, "")})
        p = d.next
    L.pcap_freealldevs(head)
    return res


def resolve_device(os_if: str):
    """os_if (イーサネット / 説明文 / \\Device\\NPF_{..}) から Npcap デバイス名を探す"""
    devs = list_devices()
    norm = lambda s: s.replace("\u3000", " ").replace(" ", "").lower()
    for d in devs:
        if os_if in (d["name"], d["friendly"], d["desc"]):
            return d["name"]
    for d in devs:
        if norm(os_if) and norm(os_if) in (norm(d["friendly"]), norm(d["desc"])):
            return d["name"]
    raise PcapError("NIC '%s' が見つかりません。候補: %s" % (
        os_if, ", ".join(d["friendly"] or d["desc"] for d in devs) or "(なし)"))


class PcapLink(Link):
    def __init__(self, os_if: str):
        super().__init__()
        self.name = os_if
        self.dev = resolve_device(os_if)
        L = lib()
        err = ctypes.create_string_buffer(256)
        self.h = L.pcap_open_live(self.dev.encode(), 65535, 1, 20, err)
        if not self.h:
            raise PcapError("%s を開けません: %s" % (os_if, err.value.decode(errors="replace")))
        self.th = None
        self.slock = threading.Lock()

    def send(self, frame: bytes):
        with self.slock:
            if self._run and lib().pcap_sendpacket(self.h, bytes(frame), len(frame)) != 0:
                raise PcapError("送信失敗: " + (lib().pcap_geterr(self.h) or b"").decode(errors="replace"))

    def start(self, on_frame):
        super().start(on_frame)
        self.th = threading.Thread(target=self._loop, daemon=True, name="pcap-" + self.name)
        self.th.start()

    def _loop(self):
        L = lib()
        hdr = ctypes.POINTER(_pkthdr)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        while self._run:
            r = L.pcap_next_ex(self.h, ctypes.byref(hdr), ctypes.byref(data))
            if r == 1:
                n = hdr.contents.caplen
                try:
                    self.on_frame(ctypes.string_at(data, n))
                except Exception:
                    import traceback
                    traceback.print_exc()
            elif r < 0:
                break

    def stop(self):
        super().stop()
        if self.th:
            self.th.join(1.0)
        if self.h:
            lib().pcap_close(self.h)
            self.h = None
