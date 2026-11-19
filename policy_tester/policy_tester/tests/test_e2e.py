"""生成ツールの出力 → エンジン → 疑似FW を通しで確認"""
import os, sys, unittest, csv, io, random
HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
from tgen import engine, simdemo

APPS = ["icmp", "tcp", "udp", "dns", "http", "https", "ftp", "smtp", "imap"]


def mkargs(**kw):
    import argparse
    return argparse.Namespace(**{"sim": True, "workers": 64, "timeout": 1.2, "tries": 1, "lenient": False, "pcap": None, "hosts": None, **kw})


class E2E(unittest.TestCase):
    def setUp(self):
        self.cfg = engine.load_config(os.path.join(HERE, "data", "int.toml"))
        self.rows = [r for r in engine.load_scenarios(os.path.join(HERE, "data", "int.csv")) if r["dst-ip"][0].isdigit()]

    def run_rows(self, rows):
        import trafficgen
        rn, sec = trafficgen.execute(rows, self.cfg, mkargs())
        return rn

    def test_generated_scenarios_pass(self):
        rn = self.run_rows(self.rows)
        s = rn.summary()
        self.assertEqual(s["ng"], 0, [r for r in rn.results if r["judge"] == "NG"][:3])
        self.assertEqual(s["pass"], len(self.rows))

    def test_mixed_expect_all_apps(self):
        random.seed(1)
        rows = []
        base = self.rows
        for i in range(60):
            r = dict(base[i % len(base)])
            app = APPS[i % len(APPS)]
            r["protocol"] = app
            r["dst-port"] = {"icmp": "", "tcp": "5000", "udp": "5001", "dns": "53", "http": "80", "https": "443",
                              "ftp": "21", "smtp": "25", "imap": "143"}[app]
            r["expect"] = ["pass", "drop", "block"][i % 3]
            r["timeout(option)"] = "1.2"
            rows.append(r)
        rn = self.run_rows(rows)
        bad = [(i + 1, rows[i]["protocol"], rows[i]["expect"], x["status"], x["detail"]) for i, x in enumerate(rn.results) if x["judge"] != "OK"]
        self.assertEqual(bad, [])
        out = rn.csv_text()
        self.assertTrue(out.splitlines()[0].startswith("protocol,src-ip"))
        self.assertIn(",drop,drop,", out)
        self.assertIn(",block,block,", out)

    def test_nat_scenario(self):
        r = dict(self.rows[0])
        r.update({"protocol": "http", "dst-port": "80", "expect": "pass", "dst-nat-ip(option)": "203.0.113.50",
                  "dst-nat-port (option)": "8080", "dst-ip": "203.0.113.1"})
        rn = self.run_rows([r])
        self.assertEqual(rn.results[0]["judge"], "OK", rn.results[0])
        self.assertEqual(rn.results[0]["observed_dst"], "203.0.113.50:8080")


if __name__ == "__main__":
    unittest.main(verbosity=2)
