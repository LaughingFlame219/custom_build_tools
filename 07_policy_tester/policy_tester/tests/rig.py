"""テスト用の結線: テスター(eth0/1,eth0/2) ⇄ 疑似FW"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tgen.link import MemLink
from tgen.stack import Stack, Iface, VR
from tgen.sim import SimFW, Policy


def make(policies=None, vips=(), internal_src=("192.0.2.0/24",), internal_dst=("198.51.100.0/24",)):
    a_t, a_f = MemLink.pair("t1", "f1")
    b_t, b_f = MemLink.pair("t2", "f2")
    fw = SimFW()
    fw.add_iface("port1", a_f, "10.0.1.254/24")
    fw.add_iface("port2", b_f, "10.0.2.254/24")
    for n in internal_src:
        fw.routes.append((n, "port1", "10.0.1.100"))
    for n in internal_dst:
        fw.routes.append((n, "port2", "10.0.2.100"))
    fw.policies = policies if policies is not None else []
    fw.vips = list(vips)
    st = Stack()
    i1 = Iface("eth0/1", a_t, 0, ["10.0.1.100/24"])
    i2 = Iface("eth0/2", b_t, 0, ["10.0.2.100/24"])
    v1 = VR("port1"); v1.ifaces = [i1]; v1.internal = [__import__("tgen.stack", fromlist=["_net"])._net(n) for n in internal_src]
    v1.external = [(0, 0, "10.0.1.254")]
    v2 = VR("port2"); v2.ifaces = [i2]; v2.internal = [__import__("tgen.stack", fromlist=["_net"])._net(n) for n in internal_dst]
    v2.external = [(0, 0, "10.0.2.254")]
    st.add_iface(i1); st.add_iface(i2); st.add_vr(v1); st.add_vr(v2)
    fw.start(); st.start()
    return st, fw
