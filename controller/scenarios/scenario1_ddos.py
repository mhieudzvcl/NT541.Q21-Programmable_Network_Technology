"""
scenario1_ddos.py - Kịch bản 1: Rate Limiting / DDoS Mitigation
Logic:
  - Nhận Packet-In → kiểm tra ICMP hoặc TCP SYN
  - Nếu số gói từ 1 IP vượt ngưỡng trong 1s → block 60s
  - Đẩy flow DROP xuống switch (hard_timeout = 60s)
  - Hết thời gian → switch tự xóa flow, mạng hoạt động lại
"""

import logging
from ryu.lib import hub
from ryu.lib.packet import ipv4, tcp, icmp as icmp_pkt
import config

logger = logging.getLogger(__name__)


class DDoSMitigation:
    """
    Phát hiện và chặn DDoS (ICMP Flood / SYN Flood).
    Được gọi mỗi khi controller nhận Packet-In.
    """

    def __init__(self, acl_manager, monitor):
        """
        :param acl_manager: ACLManager
        :param monitor: TrafficMonitor
        """
        self.acl = acl_manager
        self.mon = monitor
        # Lưu trạng thái đã áp DROP: {ip: {dpid: True}}
        self.drop_applied = {}

    def handle_packet(self, datapath, in_port, pkt):
        """
        Xử lý packet, phát hiện flood.

        :return: True nếu packet bị chặn
        """
        ip_layer = pkt.get_protocol(ipv4.ipv4)
        if not ip_layer:
            return False

        ip_src = ip_layer.src

        # Nếu IP đang bị block → bỏ qua
        if self.mon.is_ip_blocked(ip_src):
            return True

        # ICMP Echo Request
        icmp_layer = pkt.get_protocol(icmp_pkt.icmp)
        if icmp_layer and icmp_layer.type == 8:
            if self.mon.is_ddos_icmp(ip_src):
                self._apply_block(datapath, ip_src, "ICMP_FLOOD")
                return True

        # TCP SYN 
        tcp_layer = pkt.get_protocol(tcp.tcp)
        if tcp_layer and (tcp_layer.bits & 0x02) and not (tcp_layer.bits & 0x10):
            if self.mon.is_ddos_syn(ip_src):
                self._apply_block(datapath, ip_src, "SYN_FLOOD")
                return True

        return False

    def _apply_block(self, datapath, ip_src, reason):
        #Đẩy rule DROP xuống switch và ghi nhận block, tránh apply trùng trên cùng switch.
        dpid = datapath.id
        if ip_src in self.drop_applied and dpid in self.drop_applied[ip_src]:
            return
        logger.warning(
            f"[Scenario1-DDoS] BLOCK ip={ip_src} dpid={dpid} "
            f"reason={reason} duration={config.DDOS_BLOCK_DURATION}s"
        )

        # Push flow DROP xuống switch
        self.acl.add_ip_drop_flow(
            datapath,
            ip_src,
            block_duration=config.DDOS_BLOCK_DURATION
        )

        # Lưu vào monitor
        self.mon.block_ip(ip_src, duration=config.DDOS_BLOCK_DURATION)
        # Đánh dấu đã apply
        self.drop_applied.setdefault(ip_src, {})[dpid] = True

        # Set timer để cleanup
        hub.spawn_after(
            config.DDOS_BLOCK_DURATION,
            self.on_block_expired,
            ip_src,
            dpid
        )

    def on_block_expired(self, ip_src, dpid):
        #Hết thời gian block → cleanup state.

        if ip_src in self.drop_applied:
            self.drop_applied[ip_src].pop(dpid, None)
            if not self.drop_applied[ip_src]:
                del self.drop_applied[ip_src]

        # Xóa khỏi monitor
        self.mon.blocked_ips.pop(ip_src, None)
        self.mon.icmp_counter.pop(ip_src, None)

        logger.info(
            f"[Scenario1-DDoS] Block expired: ip={ip_src} dpid={dpid}"
        )

    def get_status(self):
        """Trạng thái hiện tại của module."""
        return {
            "description": "DDoS / Rate Limiting Module",
            "thresholds": {
                "icmp_per_second": config.DDOS_ICMP_THRESHOLD,
                "syn_per_second": config.DDOS_SYN_THRESHOLD,
                "block_duration": config.DDOS_BLOCK_DURATION,
            },
            "currently_blocked_ips": list(self.mon.blocked_ips.keys()),
        }