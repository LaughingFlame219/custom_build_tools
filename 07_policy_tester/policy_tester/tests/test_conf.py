import os, sys, unittest
HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
from tgen import engine


class C(unittest.TestCase):
    def conf(self):
        return engine.load_config_text(open(os.path.join(HERE, "data", "int.toml"), encoding="utf-8").read())

    def test_roundtrip_identical(self):
        t = open(os.path.join(HERE, "data", "int.toml"), encoding="utf-8").read()
        self.assertEqual(engine.dump_toml(engine.load_config_text(t)), t)

    def test_valid_generated(self):
        self.assertEqual(engine.validate_conf(self.conf())[0], [])

    def test_overlap_31_dup(self):
        c = self.conf()
        c["vRouters"][1]["routes"]["internal"].append({"destination": "10.113.20.0/24", "comment": ""})   # 他VRのinternalと重複
        c["vRouters"][0]["routes"]["internal"].append({"destination": "203.0.113.4/31", "comment": ""})
        c["vRouters"][1]["if_names"].append("vlan10")                                                   # 複数VRに所属
        e = "\n".join(engine.validate_conf(c)[0])
        self.assertIn("重複", e)
        self.assertIn("/31", e)
        self.assertIn("複数の仮想ルーター", e)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class Path(unittest.TestCase):
    def test_pathcheck_reports_missing_gateway(self):
        sys.path.insert(0, HERE)
        import rig
        st, fw = rig.make([])
        try:
            fw.ifaces[1].ip = "10.0.2.253"   # 2番目のVRのゲートウェイ(10.0.2.254)にだけ応答しない
            r = engine.pathcheck(st)
            self.assertEqual([(x["vr"], x["ok"], x["dest"], x["ip"]) for x in r],
                             [("port1", True, "0.0.0.0/0", "10.0.1.254"), ("port2", False, "0.0.0.0/0", "10.0.2.254")])
        finally:
            st.stop(); fw.stop()
