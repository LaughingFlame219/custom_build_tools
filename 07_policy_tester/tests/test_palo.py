"""Palo Alto: NAT / 仮想ルーター(TOML) / 大量ポリシー / vsys / XMLとset形式の一致 のテスト"""
import csv, io, os, random, sys, time, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, ROOT)
import fg2scenario as fg
import palo2scenario as palo
import scenario_gen as sg
from tgen import engine

def D(n):
    with open(os.path.join(HERE, "data", n), encoding="utf-8") as f:
        return f.read()


def rows_of(v):
    return list(csv.DictReader(io.StringIO(v["csv"])))


class Nat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r_set = sg.run(D("palo_nat.set"), {}, "auto")["vdoms"][0]
        cls.r_xml = sg.run(D("palo_nat.xml"), {}, "auto")["vdoms"][0]

    def test_xml_and_set_give_same_result(self):
        self.assertEqual(self.r_set["csv"], self.r_xml["csv"])
        self.assertEqual(self.r_set["vrouter_toml"], self.r_xml["vrouter_toml"])

    def find(self, **kw):
        for x in rows_of(self.r_set):
            if all(x[k] == v for k, v in kw.items()):
                return x
        self.fail(f"該当する行がない: {kw}")

    def test_interface_address_snat(self):
        x = self.find(**{"src-ip": "10.0.0.1", "dst-port": "80"})
        self.assertEqual(x["src-nat-ip(option)"], "203.0.113.2")      # ethernet1/3のIP
        self.assertEqual(x["dst-nat-ip(option)"], "")

    def test_dnat_ip_and_port(self):
        x = self.find(**{"dst-ip": "203.0.113.50"})
        self.assertEqual((x["dst-nat-ip(option)"], x["dst-nat-port (option)"], x["dst-port"]), ("172.16.0.10", "8443", "443"))
        self.assertEqual(x["src-nat-ip(option)"], "")

    def test_static_nat_bidirectional_reverse(self):
        x = self.find(**{"dst-ip": "203.0.113.60"})
        self.assertEqual(x["dst-nat-ip(option)"], "10.0.0.10")

    def test_dynamic_pool_uses_first_address(self):
        x = self.find(**{"src-ip": "192.168.100.1"})
        self.assertEqual(x["src-nat-ip(option)"], "203.0.113.100")

    def test_vrouter_toml(self):
        t = self.r_set["vrouter_toml"]
        c = engine.load_config_text(t)
        self.assertEqual(engine.validate_conf(c)[0], [])
        names = [v["name"] for v in c["vRouters"]]
        self.assertEqual(names, ["trust", "untrust", "dmz", "guest"])     # ゾーン名
        vl = [i for i in c["interfaces"] if i["type"] == "vlan"]
        self.assertEqual([(i["name"], i["vlan_id"], i["ipaddress"]) for i in vl], [("ethernet1/4.100", "100", "192.168.100.2/24")])
        gw = {v["name"]: v["routes"]["external"][0]["next_hop"] for v in c["vRouters"]}
        self.assertEqual(gw["trust"], "10.0.0.1")
        self.assertEqual(gw["guest"], "192.168.100.1")
        # 宛先NATの変換前アドレス(VIP)はdmzのinternalに書かない。実宛先はdmzのネットワーク内
        dmz = next(v for v in c["vRouters"] if v["name"] == "dmz")
        self.assertNotIn("203.0.113.50/32", [x["destination"] for x in dmz["routes"].get("internal", [])])

    def test_no_nat_match_means_no_translation(self):
        # srv1(10.0.0.10)以外の trust 送信元は srv1-static にマッチせず lan-out になる
        x = self.find(**{"src-ip": "10.0.0.254"})
        self.assertEqual(x["src-nat-ip(option)"], "203.0.113.2")


class Scale(unittest.TestCase):
    @staticmethod
    def big(n, seed=3):
        """グループを多用した大量ポリシーのコンフィグ (set形式)"""
        R = random.Random(seed)
        o = ["set network interface ethernet ethernet1/1 layer3 ip 10.0.0.1/16",
             "set network interface ethernet ethernet1/2 layer3 ip 172.16.0.1/16",
             "set zone a network layer3 ethernet1/1", "set zone b network layer3 ethernet1/2"]
        for i in range(400):
            o.append(f"set address h{i} ip-netmask 10.0.{i // 200}.{i % 200 + 1}/32")
        for i in range(40):
            o.append(f"set address-group g{i} static [ {' '.join('h%d' % R.randrange(400) for _ in range(30))} ]")
        for i in range(n):
            b = f"set rulebase security rules r{i} "
            o += [b + "from a", b + "to b", b + f"source g{R.randrange(40)}", b + f"destination g{R.randrange(40)}",
                  b + "application any", b + "service any", b + "action allow"]
        return "\n".join(o)

    def test_many_policies_are_thinned_and_fast(self):
        text = self.big(1500)
        t = time.time()
        r = sg.run(text, {}, "palo")["vdoms"][0]
        dt = time.time() - t
        self.assertLess(dt, 60)                                        # 以前は全組合せ展開で数百万行・メモリ不足
        self.assertLess(r["count"], 1500 * 100)
        self.assertTrue(any("間引" in w[0] for w in r["warnings"]))
        self.assertTrue(r["vrouter_toml"])

    def test_max_combo_zero_keeps_full_product(self):
        text = self.big(3)
        full = sg.run(text, {"max_combo": 0}, "palo")["vdoms"][0]["count"]
        thin = sg.run(text, {"max_combo": 100}, "palo")["vdoms"][0]["count"]
        self.assertGreater(full, thin)

    def test_every_value_still_covered_when_thinned(self):
        text = self.big(1, seed=9)
        cfg = palo.parse(text)
        rs = palo.PaloResolver(text, sg.make_args({"max_combo": 100}), None, cfg)
        pol = rs.build_policies()
        rows = fg.generate(rs, pol, rs.args)
        got_src = {r["nw"]["src-ip"] for r in rows}
        want_src = {fg.ip2s(a.lo) for a in pol[0].src}
        self.assertTrue(want_src <= got_src)

    def test_bitmatcher_equals_fastmatcher(self):
        text = self.big(300, seed=5)
        rs = palo.PaloResolver(text, sg.make_args({}))
        pols = rs.build_policies()
        for d in (False, True):
            a, b = fg.FastMatcher(pols, d), fg.BitMatcher.create(pols, d)
            R = random.Random(1)
            for _ in range(3000):
                q = (R.choice(["a", "b", "any", "zz"]), R.choice(["a", "b", "any"]),
                     "10.0.%d.%d" % (R.randrange(2), R.randrange(1, 255)), "10.0.%d.%d" % (R.randrange(2), R.randrange(1, 255)),
                     R.choice(["tcp", "udp", "icmp"]), R.choice([0, 80, 443, 5000]))
                self.assertIs(a.first(*q), b.first(*q))


class Vsys(unittest.TestCase):
    def test_vsys_split_like_vdom(self):
        r = sg.run(D("palo_vsys.xml"), {}, "auto")
        self.assertTrue(r["multi"])
        self.assertEqual([v["name"] for v in r["vdoms"]], ["vsys1", "vsys2"])
        for v, ip in zip(r["vdoms"], ("10.1.0.10", "10.3.0.10")):
            self.assertEqual({x["src-ip"] for x in rows_of(v)}, {ip})
            self.assertIn("vsys", rows_of(v)[0]["description"])
            c = engine.load_config_text(v["vrouter_toml"])
            self.assertEqual(len(c["vRouters"]), 2)


class Misc(unittest.TestCase):
    def test_edl_and_bad_range_warn(self):
        t = ("set address bad ip-range 10.0.0.9-10.0.0.1\nset external-list edl1 type ip url http://x\n"
             "set rulebase security rules r from a\nset rulebase security rules r to b\n"
             "set rulebase security rules r source [ bad edl1 ]\nset rulebase security rules r destination any\n"
             "set rulebase security rules r application any\nset rulebase security rules r service any\n"
             "set rulebase security rules r action allow\n")
        w = [x[0] for x in sg.run(t, {}, "palo")["vdoms"][0]["warnings"]]
        self.assertTrue(any("開始が終了より大きい" in x for x in w))
        self.assertTrue(any("EDL" in x for x in w))


if __name__ == "__main__":
    unittest.main(verbosity=2)
