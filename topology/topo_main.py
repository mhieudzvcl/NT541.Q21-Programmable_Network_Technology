#!/usr/bin/env python3
"""
topo_main.py - Mininet Topology chính cho dự án Dynamic ACL

Topology:
                          [Controller: 127.0.0.1:6633]
                                    |
              +-------------------------------------------+
              |          Switch s1 (OpenFlow 1.3)          |
              +-------------------------------------------+
              |         |         |         |         |
           [h1]      [h2]      [h3]     [webserver] [authserver]
        10.0.0.1  10.0.0.2  10.0.0.3   10.0.0.100  10.0.0.200

Host mô tả:
  - h1: Host thông thường (dùng để test các kịch bản)
  - h2: Host thông thường (mục tiêu tấn công giả lập)
  - h3: Host Guest (dùng cho Kịch bản 2 - Time-based ACL)
  - h_web: Web Server nội bộ (IP: 10.0.0.100)
  - h_auth: Authentication Server (IP: 10.0.0.200)
  - h_quarantine: Quarantine Server (IP: 10.0.0.254)

Chạy:
  sudo python3 topo_main.py
"""

from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import subprocess
import time
import os


def build_topology():
    """Xây dựng và khởi chạy Mininet topology."""

    # Khởi tạo Mininet với Remote Controller (Ryu)
    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=False
    )

    info("*** Thêm Remote Controller (Ryu) tại 127.0.0.1:6633\n")
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6633
    )

    # Thêm Switch
    info("*** Thêm Switch s1 (OpenFlow 1.3)\n")
    s1 = net.addSwitch("s1", cls=OVSKernelSwitch, protocols="OpenFlow13")

    # Thêm Hosts
    info("*** Thêm các Host\n")

    # Host thông thường
    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")

    # Host Guest (dùng Kịch bản 2 - Time-based ACL)
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")

    # Web Server nội bộ
    h_web = net.addHost(
        "webserver",
        ip="10.0.0.100/24",
        mac="00:00:00:00:00:64"
    )

    # Authentication Server (Kịch bản 5 - NAC)
    h_auth = net.addHost(
        "authserver",
        ip="10.0.0.200/24",
        mac="00:00:00:00:00:c8"
    )

    # Quarantine Server (Kịch bản 4 - Port Scan)
    h_quarantine = net.addHost(
        "quarantine",
        ip="10.0.0.254/24",
        mac="00:00:00:00:00:fe"
    )

    # Host lạ (Kịch bản 5 - NAC, sẽ cần xác thực)
    h_new = net.addHost(
        "hnew",
        ip="10.0.0.50/24",
        mac="00:00:00:00:00:50"
    )

    # Kết nối các Host vào Switch
    info("*** Kết nối các Host vào Switch s1\n")
    net.addLink(h1,          s1, bw=100)  # Port 1
    net.addLink(h2,          s1, bw=100)  # Port 2
    net.addLink(h3,          s1, bw=100)  # Port 3
    net.addLink(h_web,       s1, bw=100)  # Port 4
    net.addLink(h_auth,      s1, bw=100)  # Port 5
    net.addLink(h_quarantine, s1, bw=100) # Port 6
    net.addLink(h_new,       s1, bw=100)  # Port 7

    # Khởi động mạng
    info("*** Khởi động mạng\n")
    net.start()

    # Cấu hình OVS Switch: OpenFlow 1.3 + kết nối Controller
    info("*** Cấu hình s1: OpenFlow 1.3 + Controller\n")
    s1.cmd("ovs-vsctl set bridge s1 protocols=OpenFlow13")
    s1.cmd("ovs-vsctl set-controller s1 tcp:127.0.0.1:6633")
    time.sleep(2)

    # Khởi động các dịch vụ trên Host
    info("*** Khởi động HTTP Server trên webserver (port 80)\n")
    h_web.cmd("python3 -m http.server 80 &")

    info("*** Khởi động Authentication Server\n")
    auth_server_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "auth_server.py"
    )
    h_auth.cmd(f'python3 "{auth_server_path}" &')
    time.sleep(1)

    # Hiển thị thông tin topology
    info("\n" + "=" * 60 + "\n")
    info(" TOPOLOGY THÔNG TIN\n")
    info("=" * 60 + "\n")
    info(" Hosts:\n")
    for host in net.hosts:
        info(f"   {host.name:12s} IP={host.IP():15s} MAC={host.MAC()}\n")
    info("\n Switch:\n")
    info(f"   s1 (dpid={s1.dpid})\n")
    info("\n Ports:\n")
    for intf in s1.intfList():
        if intf.link:
            info(f"   {intf.name}: {intf.link}\n")
    info("=" * 60 + "\n")
    info(" Kiểm tra kết nối: chạy lệnh 'pingall' trong Mininet CLI\n")
    info(" Xem flow table: 'sh ovs-ofctl dump-flows s1 -O OpenFlow13'\n")
    info("=" * 60 + "\n")

    # Vào Mininet CLI
    info("*** Vào Mininet CLI\n")
    CLI(net)

    # Dọn dẹp sau khi thoát CLI
    info("*** Dừng mạng\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    build_topology()
