import os, sys, unittest, time
sys.path.insert(0, os.path.dirname(__file__)); sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import rig
from tgen import apps
from tgen.sim import Policy

S, D = "192.0.2.1", "198.51.100.1"


def run(app, port, st, obs, url="", av=False, timeout=2.0, dst=D):
    apps.register_server(st, obs, app, dst, port)
    return apps.CLIENTS[app](st, S, dst, port, {"url": url, "av": av, "timeout": timeout})


class T(unittest.TestCase):
    def setUp(self):
        self.obs = apps.Observer()

    def mk(self, *pols):
        st, fw = rig.make(list(pols))
        self.st, self.fw = st, fw
        return st, fw

    def tearDown(self):
        self.st.stop(); self.fw.stop()

    ALL = [("icmp", 0), ("tcp", 5000), ("udp", 5001), ("dns", 53), ("http", 80), ("https", 443),
           ("ftp", 21), ("smtp", 25), ("imap", 143)]

    def test_all_pass(self):
        st, fw = self.mk(Policy(1, "port1", "port2"))
        for app, port in self.ALL:
            r = run(app, port, st, self.obs)
            self.assertEqual(r.status, "pass", (app, r))

    def test_av_pass_when_no_av(self):
        st, fw = self.mk(Policy(1, "port1", "port2"))
        for app, port in (("http", 80), ("ftp", 21), ("smtp", 25), ("imap", 143), ("https", 443)):
            r = run(app, port, st, self.obs, av=True)
            self.assertEqual(r.status, "pass", (app, r))

    def test_av_block(self):
        st, fw = self.mk(Policy(1, "port1", "port2", av=True))
        for app, port in (("http", 80), ("ftp", 21), ("smtp", 25), ("imap", 143)):
            r = run(app, port, st, self.obs, av=True)
            self.assertEqual(r.status, "block", (app, r))
        r = run("http", 80, st, self.obs)       # AVなしの通常通信は通る
        self.assertEqual(r.status, "pass")

    def test_drop(self):
        st, fw = self.mk()  # implicit deny
        for app, port in self.ALL:
            r = run(app, port, st, self.obs, timeout=1.2)
            self.assertEqual(r.status, "drop", (app, r))

    def test_reject(self):
        st, fw = self.mk(Policy(1, "port1", "port2", action="reject"))
        for app, port in self.ALL:
            if app == "dns":
                continue   # DNS(UDP)のrejectはICMPで来る→下で確認
            r = run(app, port, st, self.obs, timeout=1.2)
            self.assertEqual(r.status, "block", (app, r))
        r = run("dns", 53, st, self.obs, timeout=1.2)
        self.assertEqual(r.status, "block", r)

    def test_url_and_sni_block(self):
        st, fw = self.mk(Policy(1, "port1", "port2", block_hosts=["bad.example.com"], block_sni=["bad.example.com"]))
        self.assertEqual(run("http", 80, st, self.obs, url="good.example.com").status, "pass")
        r = run("http", 80, st, self.obs, url="bad.example.com")
        self.assertEqual(r.status, "block", r)
        self.assertEqual(run("https", 443, st, self.obs, url="good.example.com").status, "pass")
        r = run("https", 443, st, self.obs, url="bad.example.com")
        self.assertEqual(r.status, "block", r)

    def test_blockpage(self):
        st, fw = self.mk(Policy(1, "port1", "port2", block_hosts=["bad.example.com"], l7="blockpage"))
        r = run("http", 80, st, self.obs, url="bad.example.com")
        self.assertEqual(r.status, "block", r)
        self.assertIn("ブロックページ", r.detail)

    def test_nat(self):
        st, fw = rig.make([Policy(1, "port1", "port2", snat=True)], vips=[("10.0.1.200", "198.51.100.1", 80, 8080)])
        self.st, self.fw = st, fw
        st.tcp_listen("198.51.100.1", 8080, apps.serve_http(self.obs))
        r = apps.CLIENTS["http"](st, S, "10.0.1.200", 80, {"url": "", "av": False, "timeout": 2})
        self.assertEqual(r.status, "pass", r)
        o = self.obs.find("tcp", "198.51.100.1", 8080, 0)
        self.assertEqual(o["rip"], "10.0.2.254")     # SNAT後の送信元
        # NAT後の宛先(8080)に受け側が待っていなければRST → block
        with st.lock:
            st.listeners.pop(("198.51.100.1", 8080))
        r = apps.CLIENTS["tcp"](st, S, "10.0.1.200", 80, {"url": "", "av": False, "timeout": 1})
        self.assertEqual(r.status, "block", r)

    def test_ssl_inspection_detected(self):
        from tgen import tlsdata
        st, fw = self.mk(Policy(1, "port1", "port2"))
        r = run("https", 443, st, self.obs, url="a.example.com")
        self.assertEqual(r.extra["ssl_inspected"], False)
        self.assertEqual(r.extra["cert_issuer"], tlsdata.TEST_ISSUER)
        old = tlsdata.TEST_ISSUER
        tlsdata.TEST_ISSUER = "CN=Some Firewall CA"      # 受信側の証明書issuerがFWのCAに変わった状況を模擬
        try:
            r = run("https", 443, st, self.obs, url="a.example.com")
        finally:
            tlsdata.TEST_ISSUER = old
        self.assertTrue(r.extra["ssl_inspected"])
        self.assertIn("SSL復号を検出", r.detail)

    def test_arp_error(self):
        st, fw = self.mk(Policy(1, "port1", "port2"))
        fw.stop()   # FWを止める → ゲートウェイのARPが解決できない
        time.sleep(0.6)
        st.arp.clear()
        r = run("http", 80, st, self.obs, timeout=1)
        self.assertEqual(r.status, "error", r)


if __name__ == "__main__":
    unittest.main(verbosity=2)
