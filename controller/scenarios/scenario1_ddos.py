"""
scenario1_ddos.py - Kịch bản 1: Rate Limiting / DDoS Mitigation

Logic:
  - Mỗi khi nhận Packet-In từ switch, kiểm tra gói ICMP hoặc TCP SYN
  - Nếu số gói từ một IP vượt ngưỡng trong 1 giây → DROP 60 giây
  - Flow entry DROP được đẩy xuống switch với hard_timeout = 60s
  - Sau 60 giây, switch tự xóa flow → mạng trở lại bình thường
"""

import logging
import time
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, tcp, icmp as icmp_pkt
import config

logger = logging.getLogger(__name__)


class DDoSMitigation:
    """
    Module phát hiện và ngăn chặn DDoS (ICMP Flood / SYN Flood).
    Được gọi từ Controller chính mỗi khi nhận Packet-In.
    """

    def __init__(self, acl_manager, monitor):
        """
        :param acl_manager: Instance của ACLManager
        :param monitor:     Instance của TrafficMonitor
        """
        self.acl  = acl_manager
        self.mon  = monitor
        # Lưu danh sách switch đã áp luật DROP: {ip: {dpid: True}}
        self.drop_applied = {}

    def handle_packet(self, datapath, in_port, pkt):
        """
        Xử lý gói tin: phát hiện ICMP flood / SYN flood.

        :param datapath: Switch nhận gói tin
        :param in_port:  Cổng vào
        :param pkt:      Packet object (Ryu)
        :return: True nếu gói bị chặn (controller không cần xử lý tiếp)
        """
        ip_layer  = pkt.get_protocol(ipv4.ipv4)
        if not ip_layer:
            return False

        ip_src = ip_layer.src

        # Nếu IP đã bị chặn → bỏ qua (flow trên switch đã DROP)
        if self.mon.is_ip_blocked(ip_src):
            return True

        # Kiểm tra ICMP Flood
        icmp_layer = pkt.get_protocol(icmp_pkt.icmp)
        if icmp_layer and icmp_layer.type == 8:  # ICMP Echo Request
            if self.mon.is_ddos_icmp(ip_src):
                self._apply_block(datapath, ip_src, reason="ICMP_FLOOD")
                return True

        # Kiểm tra TCP SYN Flood
        tcp_layer = pkt.get_protocol(tcp.tcp)
        if tcp_layer:
            # Kiểm tra flag SYN (bit 1 của flags)
            if tcp_layer.bits & 0x02 and not (tcp_layer.bits & 0x10):
                if self.mon.is_ddos_syn(ip_src):
                    self._apply_block(datapath, ip_src, reason="SYN_FLOOD")
                    return True

        return False

    def _apply_block(self, datapath, ip_src, reason="FLOOD"):
        """
        Đẩy luật DROP xuống switch và ghi nhận vào monitor.
        Tránh áp luật trùng lặp.
        """
        dpid = datapath.id
        if ip_src in self.drop_applied and dpid in self.drop_applied[ip_src]:
            return  # Nếu đã áp rồi, bỏ qua

        logger.warning(
            f"[Scenario1-DDoS] BLOCKING ip_src={ip_src} on dpid={dpid} "
            f"reason={reason} duration={config.DDOS_BLOCK_DURATION}s"
        )
        # Đẩy flow DROP xuống switch (hard_timeout = DDOS_BLOCK_DURATION)
        self.acl.add_ip_drop_flow(
            datapath, ip_src,
            block_duration=config.DDOS_BLOCK_DURATION
        )
        # Ghi nhận trong monitor
        self.mon.block_ip(ip_src, duration=config.DDOS_BLOCK_DURATION)

        # Đánh dấu đã áp
        if ip_src not in self.drop_applied:
            self.drop_applied[ip_src] = {}
        self.drop_applied[ip_src][dpid] = True
        
        # Dùng `hub.spawn_after` để set Timer
        hub.spawn_after(
            config.DDOS_BLOCK_DURATION, 
            self.on_block_expired, 
            ip_src, 
            dpid
        )

        logger.info(
            f"[Scenario1-DDoS] Timer set: Will remove memory block for "
            f"{ip_src} after {config.DDOS_BLOCK_DURATION}s"
        )

    def on_block_expired(self, ip_src, dpid):
        """
        Callback khi thời gian chặn hết hạn.
        Xóa khỏi danh sách theo dõi nội bộ và monitor.
        """
        # Xóa cờ chặn trong module này
        if ip_src in self.drop_applied:
            self.drop_applied[ip_src].pop(dpid, None)
            if not self.drop_applied[ip_src]:
                del self.drop_applied[ip_src]
        # Xóa cờ chặn trong monitor để tránh IP mãi bị liệt trong RAM
        self.mon.blocked_ips.pop(ip_src, None)
        # Reset bộ đếm ICMP để kỳ flood tiếp theo được đếm sạch từ đầu
        self.mon.icmp_counter.pop(ip_src, None)
        self.mon.syn_counter.pop(ip_src, None)
        logger.info(f"[Scenario1-DDoS] Block expired: ip={ip_src} dpid={dpid} \u2192 IP is now FREE again")

    def get_status(self):
        """Trả về trạng thái hiện tại của module."""
        return {
            "description": "DDoS / Rate Limiting Module",
            "thresholds": {
                "icmp_per_second": config.DDOS_ICMP_THRESHOLD,
                "syn_per_second":  config.DDOS_SYN_THRESHOLD,
                "block_duration":  config.DDOS_BLOCK_DURATION,
            },
            "currently_blocked_ips": list(self.mon.blocked_ips.keys()),
        }
