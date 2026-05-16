"""
scenario3_spoofing.py - Kịch bản 3: MAC/IP Spoofing / Flow Anomaly Prevention

Logic:
  - Mỗi khi học MAC (Packet-In), kiểm tra địa chỉ MAC và IP
  - Nếu MAC xuất hiện trên dpid/port khác trong < SPOOF_TIME_WINDOW giây
    → Phát hiện MAC Spoofing → DROP toàn bộ traffic vào port đó
  - Nếu IP xuất hiện với MAC khác trong < SPOOF_TIME_WINDOW giây
    → Phát hiện IP Spoofing → DROP port đó
  - Luật DROP áp bằng hard_timeout = SPOOF_BLOCK_DURATION giây
"""

import logging
from ryu.lib import hub
import config

logger = logging.getLogger(__name__)


class SpoofingDetection:
    """
    Phát hiện và ngăn chặn MAC Spoofing / IP Spoofing.
    """

    def __init__(self, acl_manager, monitor):
        """
        :param acl_manager: Instance của ACLManager
        :param monitor:     Instance của TrafficMonitor
        """
        self.acl = acl_manager
        self.mon = monitor
        # Theo dõi port đã bị chặn tránh gửi lệnh trùng
        self.blocked_ports_applied = set()  # {(dpid, port)}

    def handle_packet(self, datapath, in_port, eth_src, ip_src=None):
        """
        Kiểm tra gói tin đến từ eth_src tại in_port của datapath.

        :param datapath: Switch nhận gói
        :param in_port:  Cổng vào
        :param eth_src:  Địa chỉ MAC nguồn
        :param ip_src:   Địa chỉ IP nguồn (nếu là IPv4)
        :return: True nếu phát hiện giả mạo và đã áp luật DROP
        """
        dpid = datapath.id

        # Nếu port đã bị chặn → bỏ qua
        if self.mon.is_port_blocked(dpid, in_port):
            return True

        # Kiểm tra MAC Spoofing
        is_mac_spoofed, old_mac_loc = self.mon.update_mac_location(
            eth_src, dpid, in_port, ip=ip_src
        )
        if is_mac_spoofed:
            logger.warning(
                f"[Scenario3-Spoof] MAC SPOOF: mac={eth_src} "
                f"was at dpid={old_mac_loc['dpid']}/port={old_mac_loc['port']}, "
                f"now at dpid={dpid}/port={in_port}"
            )
            # Chỉ chặn port của kẻ tấn công (in_port), KHÔNG chặn port của nạn nhân
            self._block_port(datapath, in_port,
                             reason=f"MAC_SPOOF mac={eth_src}")
            return True

        # Kiểm tra IP Spoofing (nếu có IP)
        if ip_src and ip_src not in ("0.0.0.0", "255.255.255.255"):
            is_ip_spoofed, old_ip_loc = self.mon.update_ip_location(
                ip_src, eth_src, dpid, in_port
            )
            if is_ip_spoofed:
                logger.warning(
                    f"[Scenario3-Spoof] IP SPOOF: ip={ip_src} "
                    f"old_mac={old_ip_loc['mac']} new_mac={eth_src} "
                    f"at dpid={dpid}/port={in_port}"
                )
                self._block_port(datapath, in_port,
                                 reason=f"IP_SPOOF ip={ip_src}")
                return True

        return False

    def _block_port(self, datapath, port, reason="SPOOF"):
        """Áp luật DROP toàn bộ traffic vào port và ghi nhận."""
        dpid = datapath.id
        key = (dpid, port)
        if key in self.blocked_ports_applied:
            return

        logger.warning(
            f"[Scenario3-Spoof] BLOCKING port={port} on dpid={dpid} "
            f"reason={reason} duration={config.SPOOF_BLOCK_DURATION}s"
        )
        self.acl.add_port_drop_flow(
            datapath, port,
            block_duration=config.SPOOF_BLOCK_DURATION
        )
        self.mon.block_port(dpid, port, duration=config.SPOOF_BLOCK_DURATION)
        self.blocked_ports_applied.add(key)
        # Timer: xóa cờ nhớ sau khi rule hết hạn ở switch
        hub.spawn_after(
            config.SPOOF_BLOCK_DURATION,
            self.on_block_expired,
            dpid, port
        )



    def set_datapaths_map(self, datapaths_map):
        """
        Truyền tham chiếu đến dict datapaths của controller.
        :param datapaths_map: {dpid: datapath}
        """
        self.datapaths_map = datapaths_map

    def on_block_expired(self, dpid, port):
        """Callback khi thời gian chặn port hết hạn."""
        self.blocked_ports_applied.discard((dpid, port))
        logger.info(f"[Scenario3-Spoof] Block expired: dpid={dpid}/port={port}")

    def get_status(self):
        """Trả về trạng thái hiện tại."""
        return {
            "description": "MAC/IP Spoofing Detection Module",
            "config": {
                "spoof_time_window": config.SPOOF_TIME_WINDOW,
                "block_duration":    config.SPOOF_BLOCK_DURATION,
            },
            "blocked_ports": [
                {"dpid": d, "port": p}
                for (d, p) in self.blocked_ports_applied
            ],
            "known_mac_locations": dict(self.mon.mac_location),
            "known_ip_locations":  dict(self.mon.ip_location),
        }
