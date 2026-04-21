"""
scenario4_portscan.py - Kịch bản 4: Port Scan Detection & Quarantine

Logic:
  - Theo dõi số cổng TCP đích khác nhau mà một Host kết nối đến trong cửa sổ thời gian
  - Nếu vượt ngưỡng PORTSCAN_THRESHOLD trong PORTSCAN_TIME_WINDOW giây
    -> Phat hien Port Scan
    -> Cach ly Host vao Quarantine:
        * DROP tất cả traffic từ IP đó đi ra ngoài
        * ALLOW traffic từ IP đó đến QUARANTINE_SERVER_IP (nếu cần)
  - Luật cách ly có hard_timeout = QUARANTINE_DURATION giây
  - Sau khi hết hạn, Host tự động được thoát Quarantine
"""

import logging
from ryu.lib import hub
import config

logger = logging.getLogger(__name__)


class PortScanDetection:
    """
    Phát hiện quét port và cách ly host vào Quarantine Zone.
    """

    def __init__(self, acl_manager, monitor):
        """
        :param acl_manager: Instance của ACLManager
        :param monitor:     Instance của TrafficMonitor
        """
        self.acl = acl_manager
        self.mon = monitor
        # Theo dõi host đã bị cách ly: {ip: {dpid: True}}
        self.quarantine_applied = {}

    def handle_packet(self, datapath, in_port, ip_src, ip_dst, tcp_dst):
        """
        Kiểm tra gói TCP SYN mới để phát hiện Port Scan.

        :param datapath: Switch nhận gói
        :param in_port:  Cổng vào
        :param ip_src:   IP nguồn (host nghi vấn)
        :param ip_dst:   IP đích
        :param tcp_dst:  Port TCP đích
        :return: True nếu đây là hành vi quét port và đã áp luật Quarantine
        """
        # Nếu IP đã bị cách ly -> bỏ qua
        if self.mon.is_quarantined(ip_src):
            return True

        # Kiểm tra Port Scan
        if self.mon.is_port_scanning(ip_src, ip_dst, tcp_dst):
            self._apply_quarantine(datapath, ip_src)
            return True

        return False

    def _apply_quarantine(self, datapath, ip_src):
        """
        Áp luật Quarantine lên switch:
        1. DROP tất cả traffic từ ip_src (high priority)
        2. ALLOW traffic từ ip_src đến QUARANTINE_SERVER_IP (medium priority)
        """
        dpid = datapath.id
        if ip_src in self.quarantine_applied and dpid in self.quarantine_applied[ip_src]:
            return  # Đã áp rồi

        logger.warning(
            f"[Scenario4-PortScan] QUARANTINE: ip_src={ip_src} on dpid={dpid} "
            f"duration={config.QUARANTINE_DURATION}s"
        )

        # Bước 1: DROP tất cả traffic từ ip_src
        self.acl.add_ip_drop_flow(
            datapath, ip_src,
            block_duration=config.QUARANTINE_DURATION,
            priority=config.DROP_PRIORITY + 5  # Ưu tiên cao nhất
        )

        # Bước 2: ALLOW traffic từ ip_src đến Quarantine Server (exception rule)
        # Ưu tiên ALLOW > DROP để gói đến quarantine server vẫn qua được
        ofp_parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        match = ofp_parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_src,
            ipv4_dst=config.QUARANTINE_SERVER_IP
        )
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]

        # Override: ALLOW traffic từ ip_src đến Quarantine Server (exception rule)
        # Priority cao hơn DROP để override
        self.acl._send_flow_mod(
            datapath,
            priority=config.DROP_PRIORITY + 10,  # Cao hơn DROP rule
            match=match,
            actions=actions,
            idle_timeout=0,
            hard_timeout=config.QUARANTINE_DURATION
        )

        # Ghi nhận vào monitor
        self.mon.quarantine_ip(ip_src, duration=config.QUARANTINE_DURATION)

        # Đánh dấu đã áp
        if ip_src not in self.quarantine_applied:
            self.quarantine_applied[ip_src] = {}
        self.quarantine_applied[ip_src][dpid] = True

        # Timer: xóa cờ nhớ sau khi rule hết hạn ở switch
        hub.spawn_after(
            config.QUARANTINE_DURATION,
            self.on_quarantine_expired,
            ip_src, dpid
        )

        logger.info(
            f"[Scenario4-PortScan] Quarantine applied. "
            f"ip={ip_src} can only reach {config.QUARANTINE_SERVER_IP}. "
            f"Auto-release in {config.QUARANTINE_DURATION}s"
        )

    def on_quarantine_expired(self, ip_src, dpid):
        """Callback khi thời gian cách ly hết hạn."""
        if ip_src in self.quarantine_applied:
            self.quarantine_applied[ip_src].pop(dpid, None)
            if not self.quarantine_applied[ip_src]:
                del self.quarantine_applied[ip_src]
        # Xóa trạng thái trong monitor
        self.mon.quarantined.pop(ip_src, None)
        logger.info(f"[Scenario4-PortScan] Quarantine expired for ip={ip_src} on dpid={dpid}")

    def get_status(self):
        """Trả về trạng thái hiện tại."""
        return {
            "description": "Port Scan Detection & Quarantine Module",
            "config": {
                "portscan_threshold":  config.PORTSCAN_THRESHOLD,
                "time_window_seconds": config.PORTSCAN_TIME_WINDOW,
                "quarantine_duration": config.QUARANTINE_DURATION,
                "quarantine_server":   config.QUARANTINE_SERVER_IP,
            },
            "quarantined_hosts": list(self.quarantine_applied.keys()),
        }
