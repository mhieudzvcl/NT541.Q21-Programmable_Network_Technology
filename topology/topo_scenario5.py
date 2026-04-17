#!/usr/bin/env python3
"""
topo_scenario5.py - Topology Mininet riêng cho Kịch bản 5 (NAC / Captive Portal)

Topology đơn giản hơn để test NAC dễ hơn:

                    [Controller: 127.0.0.1:6633]
                               |
         +------------------------------------------+
         |          Switch s1 (OpenFlow 1.3)          |
         +------------------------------------------+
         |           |           |           |
       [h1]        [h2]      [authserver]  [hnew]
    10.0.0.1    10.0.0.2     10.0.0.200   10.0.0.50
  (established) (established)  (auth srv)  (NEW - cần xác thực)

Kịch bản:
  - h1, h2 đã có trong hệ thống → giao tiếp bình thường
  - hnew là host mới chưa xác thực → bị hạn chế
  - hnew chỉ kết nối được authserver (port 8080)
  - Sau xác thực → hnew truy cập mọi host
"""

from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import os
import time


def build_nac_topology():
    """Xây dựng topology NAC đơn giản."""

    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=False,
        autoStaticArp=False
    )

    # Controller
    info("*** Thêm Remote Controller\n")
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6633
    )

    # Switch
    info("*** Thêm Switch s1\n")
    s1 = net.addSwitch("s1", cls=OVSKernelSwitch, protocols="OpenFlow13")

    # Hosts
    info("*** Thêm Hosts\n")

    # Host đã được nhận diện (giả lập bằng cách ping trước khi hnew vào)
    h1 = net.addHost("h1",  ip="10.0.0.1/24",  mac="00:00:00:00:00:01")
    h2 = net.addHost("h2",  ip="10.0.0.2/24",  mac="00:00:00:00:00:02")

    # Authentication Server
    h_auth = net.addHost(
        "authserver",
        ip="10.0.0.200/24",
        mac="00:00:00:00:00:c8"
    )

    # Host mới (chưa xác thực)
    h_new = net.addHost(
        "hnew",
        ip="10.0.0.50/24",
        mac="00:00:00:00:00:50"
    )

    # Links
    info("*** Kết nối Links\n")
    net.addLink(h1,     s1)   # port 1
    net.addLink(h2,     s1)   # port 2
    net.addLink(h_auth, s1)   # port 3
    net.addLink(h_new,  s1)   # port 4

    # Khởi động
    info("*** Khởi động mạng\n")
    net.start()

    s1.cmd("ovs-vsctl set bridge s1 protocols=OpenFlow13")
    s1.cmd("ovs-vsctl set-controller s1 tcp:127.0.0.1:6633")
    time.sleep(2)

    # Khởi động Auth Server
    auth_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "auth_server.py"
    )
    info(f"*** Khởi động Auth Server tại {h_auth.IP()}:8080\n")
    h_auth.cmd(f"python3 {auth_path} --port 8080 &")
    time.sleep(1)

    # Demo có hướng dẫn rõ ràng để test nhé
    info("\n" + "=" * 60 + "\n")
    info(" KỊCH BẢN 5: NAC / Captive Portal Demo\n")
    info("=" * 60 + "\n")
    info(f" h1         : {h1.IP():15s} MAC={h1.MAC()}  (established)\n")
    info(f" h2         : {h2.IP():15s} MAC={h2.MAC()}  (established)\n")
    info(f" authserver : {h_auth.IP():15s} MAC={h_auth.MAC()} (Auth Server)\n")
    info(f" hnew       : {h_new.IP():15s} MAC={h_new.MAC()} (NEW - chưa xác thực)\n")
    info("=" * 60 + "\n")
    info(" DEMO STEPS:\n")
    info("  1. h1 ping h2   → SUCCESS (đã biết nhau)\n")
    info("  2. hnew ping h2 → FAIL (chưa xác thực)\n")
    info("  3. hnew gọi Auth Server:\n")
    info("     hnew curl -X POST http://10.0.0.200:8080/authenticate \\\n")
    info('       -H "Content-Type: application/json" \\\n')
    info('       -d \'{"mac":"00:00:00:00:00:50","token":"TOKEN_NEW"}\'\n')
    info("  4. hnew ping h2 → SUCCESS (sau xác thực)\n")
    info(" Xem flow table: sh ovs-ofctl dump-flows s1 -O OpenFlow13\n")
    info(" Xem log: tail -f /tmp/dynamic_acl.log\n")
    info("=" * 60 + "\n")

    CLI(net)

    info("*** Dừng mạng\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    build_nac_topology()
