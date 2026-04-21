"""
scenario5_nac.py - Kịch bản 5: Network Access Control (NAC) / Captive Portal

Logic:
  - Khi Host mới kết nối (MAC chưa biết):
      * Mặc định chỉ cho phép kết nối đến AUTH_SERVER_IP (port AUTH_SERVER_PORT)
      * DROP tất cả traffic khác
  - Auth Server gọi lại REST API của Controller (/authenticate) sau khi xác thực
  - Sau khi xác thực thành công:
      * Xóa luật hạn chế
      * Host được truy cập mạng đầy đủ (table-miss L2 forwarding bình thường)
  - Danh sách host đã xác thực được lưu trong bộ nhớ controller
"""

import logging
from ryu.lib import hub
import config

logger = logging.getLogger(__name__)


class NACPortal:
    """
    Network Access Control (Captive Portal) Module.
    Kiểm soát quyền truy cập mạng của Host mới dựa trên xác thực.
    """

    def __init__(self, acl_manager):
        """
        :param acl_manager: Instance của ACLManager
        """
        self.acl = acl_manager
        # Tập hợp các MAC đã được xác thực
        # Pre-authenticate infrastructure hosts in Mininet topology
        self.authenticated_hosts = {
            "00:00:00:00:00:01",  # h1
            "00:00:00:00:00:02",  # h2
            "00:00:00:00:00:03",  # h3
            "00:00:00:00:00:64",  # webserver
            "00:00:00:00:00:c8",  # authserver
            "00:00:00:00:00:fe",  # quarantine
        }
        # Tập hợp các MAC đã bị hạn chế (chờ xác thực)
        self.restricted_hosts = set()
        # Ánh xạ MAC -> IP (cập nhật khi học)
        self.mac_to_ip = {}
        # Lưu datapath cho mỗi host: {mac: (datapath, in_port)}
        self.host_datapath = {}

    # Kiểm tra / áp luật khi Host mới xuất hiện
    def handle_new_host(self, datapath, in_port, eth_src, ip_src=None):
        """
        Xử lý khi phát hiện Host mới (MAC chưa biết).

        :param datapath: Switch phát hiện Host
        :param in_port:  Cổng vào
        :param eth_src:  MAC của Host mới
        :param ip_src:   IP của Host (nếu có)
        :return: True nếu Host bị hạn chế (chưa xác thực)
        """
        # Guard: ENABLE_NAC phải bật mới hoạt động
        if not getattr(config, "ENABLE_NAC", False):
            return False

        # Host đã xác thực -> cho qua
        if eth_src in self.authenticated_hosts:
            return False

        # Lưu thông tin host
        self.host_datapath[eth_src] = (datapath, in_port)
        if ip_src:
            self.mac_to_ip[eth_src] = ip_src

        # Nếu chưa hạn chế -> áp luật hạn chế
        if eth_src not in self.restricted_hosts:
            logger.info(
                f"[Scenario5-NAC] NEW HOST: mac={eth_src} ip={ip_src} "
                f"dpid={datapath.id}/port={in_port} -> RESTRICTED"
            )
            self._apply_restriction(datapath, in_port, eth_src, ip_src)
            self.restricted_hosts.add(eth_src)

        return True

    def _apply_restriction(self, datapath, in_port, eth_src, ip_src):
        """
        Áp luật hạn chế:
        1. ALLOW: Host -> Auth Server (TCP port AUTH_SERVER_PORT)
        2. ALLOW: Host -> DNS (UDP port 53) - để resolve domain
        3. DROP:  Host -> * (tất cả traffic khác, ưu tiên thấp hơn ALLOW)

        Lưu ý: thứ tự cài đặt QUAN TRỌNG - cài ALLOW trước DROP để tránh race.
        """
        ofp_parser = datapath.ofproto_parser
        ofp = datapath.ofproto

        # Luật 1: ALLOW Host -> Auth Server TCP (priority cao nhất)
        match_allow_auth = ofp_parser.OFPMatch(
            in_port=in_port,
            eth_src=eth_src,
            eth_type=0x0800,
            ip_proto=6,    # TCP
            ipv4_dst=config.AUTH_SERVER_IP,
            tcp_dst=config.AUTH_SERVER_PORT
        )
        actions_allow = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        allow_auth_mod = ofp_parser.OFPFlowMod(
            datapath=datapath,
            priority=config.DROP_PRIORITY + 10,
            match=match_allow_auth,
            instructions=[ofp_parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS, actions_allow
            )],
            idle_timeout=0,
            hard_timeout=0
        )
        datapath.send_msg(allow_auth_mod)

        # Luật 2: ALLOW Host -> DNS UDP (để resolve hostname)
        match_dns = ofp_parser.OFPMatch(
            in_port=in_port,
            eth_src=eth_src,
            eth_type=0x0800,
            ip_proto=17,  # UDP
            udp_dst=config.NAC_ALLOW_DNS_PORT
        )
        allow_dns_mod = ofp_parser.OFPFlowMod(
            datapath=datapath,
            priority=config.DROP_PRIORITY + 10,
            match=match_dns,
            instructions=[ofp_parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS, actions_allow
            )],
            idle_timeout=0,
            hard_timeout=0
        )
        datapath.send_msg(allow_dns_mod)

        # Luật 3: DROP tất cả traffic khác từ Host (priority thấp hơn ALLOW)
        match_drop = ofp_parser.OFPMatch(
            in_port=in_port,
            eth_src=eth_src
        )
        drop_mod = ofp_parser.OFPFlowMod(
            datapath=datapath,
            priority=config.DROP_PRIORITY,
            match=match_drop,
            instructions=[],  # Không có action = DROP
            idle_timeout=0,
            hard_timeout=0   # Vô thời hạn đến khi xác thực
        )
        datapath.send_msg(drop_mod)

        logger.info(
            f"[Scenario5-NAC] Restricted Host mac={eth_src}: "
            f"ALLOW only -> {config.AUTH_SERVER_IP}:{config.AUTH_SERVER_PORT}"
        )
        logger.info(
            f"[Scenario5-NAC] Hint: authenticate via "
            f"curl -X POST http://{{AUTH_SERVER_IP}}:{config.AUTH_SERVER_PORT}/authenticate "
            f"-H 'Content-Type: application/json' "
            f"-d '{{\"mac\": \"{eth_src}\", \"token\": \"TOKEN_XXX\"}}'"
        )

    # Xác thực Host - Chạy bất đồng bộ trong Ryu hub greenthread
    def authenticate_host(self, mac, token=None):
        """
        Gọi REST API của Auth Server để xác thực Host.
        Nếu thành công -> gỡ hạn chế và cấp quyền đầy đủ.
        QUAN TRỌNG: Hàm này BLOCKING - gọi trong hub.spawn() để không block event loop.

        :param mac:   MAC address của Host
        :param token: Token xác thực (nếu có)
        :return: (success: bool, message: str)
        """
        try:
            import urllib.request
            import json

            url = f"http://{config.AUTH_SERVER_IP}:{config.AUTH_SERVER_PORT}/authenticate"
            payload = {"mac": mac}
            if token:
                payload["token"] = token

            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                result = json.loads(resp.read())

            if result.get("authenticated"):
                logger.info(f"[Scenario5-NAC] Authentication SUCCESS for mac={mac}")
                self._grant_full_access(mac)
                return True, result.get("message", "Authentication successful")
            else:
                msg = result.get("message", "Authentication failed")
                logger.warning(f"[Scenario5-NAC] Authentication FAILED for mac={mac}: {msg}")
                return False, msg

        except Exception as e:
            logger.error(f"[Scenario5-NAC] Auth Server error for mac={mac}: {e}")
            return False, str(e)

    def _grant_full_access(self, mac):
        """
        Xóa luật hạn chế và cấp quyền truy cập đầy đủ cho Host.
        Traffic sẽ rơi qua table-miss và được L2 forwarding bình thường.
        """
        try:
            logger.info(f"[Scenario5-NAC] Starting _grant_full_access for mac={mac}")
            if mac not in self.host_datapath:
                logger.warning(f"[Scenario5-NAC] Cannot grant access: host {mac} not found in host_datapath")
                return

            datapath, in_port = self.host_datapath[mac]
            ofp_parser = datapath.ofproto_parser
            ofp = datapath.ofproto

            # Xóa TẤT CẢ các luật đã cài trong _apply_restriction bằng cách dùng đúng match
            match_drop = ofp_parser.OFPMatch(in_port=in_port, eth_src=mac)
            del_drop_mod = ofp_parser.OFPFlowMod(
                datapath=datapath,
                command=ofp.OFPFC_DELETE_STRICT,
                priority=config.DROP_PRIORITY,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                match=match_drop
            )
            datapath.send_msg(del_drop_mod)

            match_allow_auth = ofp_parser.OFPMatch(
                in_port=in_port, eth_src=mac, eth_type=0x0800, ip_proto=6,
                ipv4_dst=config.AUTH_SERVER_IP, tcp_dst=config.AUTH_SERVER_PORT
            )
            del_auth_mod = ofp_parser.OFPFlowMod(
                datapath=datapath,
                command=ofp.OFPFC_DELETE_STRICT,
                priority=config.DROP_PRIORITY + 10,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                match=match_allow_auth
            )
            datapath.send_msg(del_auth_mod)

            match_dns = ofp_parser.OFPMatch(
                in_port=in_port, eth_src=mac, eth_type=0x0800, ip_proto=17,
                udp_dst=config.NAC_ALLOW_DNS_PORT
            )
            del_dns_mod = ofp_parser.OFPFlowMod(
                datapath=datapath,
                command=ofp.OFPFC_DELETE_STRICT,
                priority=config.DROP_PRIORITY + 10,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                match=match_dns
            )
            datapath.send_msg(del_dns_mod)

            # Ngoài ra gửi lệnh DELETE chung để phòng hờ
            match_all = ofp_parser.OFPMatch(in_port=in_port, eth_src=mac)
            del_all_mod = ofp_parser.OFPFlowMod(
                datapath=datapath,
                command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                match=match_all
            )
            datapath.send_msg(del_all_mod)

            # Đánh dấu đã xác thực
            self.authenticated_hosts.add(mac)
            self.restricted_hosts.discard(mac)

            logger.info(
                f"[Scenario5-NAC] - FULL ACCESS GRANTED for mac={mac} "
                f"on dpid={datapath.id}/port={in_port} -> All NAC rules REMOVED"
            )
        except Exception as e:
            logger.error(f"[Scenario5-NAC] Exception in _grant_full_access: {e}")

    # REST API callback (được gọi từ controller khi nhận POST /authenticate)
    def handle_auth_callback(self, mac, token=None):
        """
        Endpoint callback khi Auth Server thông báo xác thực thành công.
        Auth Server đã xác thực xong rồi mới gọi đến đây.
        Nên ta chỉ cần grant_full_access luôn, không gọi ngược lại auth server.
        """
        logger.info(f"[Scenario5-NAC] Auth callback received for mac={mac} -> granting access")
        # Chạy trong greenthread để không block Ryu event loop
        hub.spawn(self._grant_full_access, mac)
        return {"mac": mac, "authenticated": True, "status": "access_granted"}

    def _do_auth_async(self, mac, token):
        """Deprecated - giữ lại để tương thích."""
        self._grant_full_access(mac)

    # Revoke access (thu hồi quyền)
    def revoke_access(self, mac):
        """Thu hồi quyền truy cập của Host đã xác thực."""
        if mac not in self.authenticated_hosts:
            return False, "Host not found in authenticated list"

        self.authenticated_hosts.discard(mac)
        if mac in self.host_datapath:
            datapath, in_port = self.host_datapath[mac]
            ip_src = self.mac_to_ip.get(mac)
            self._apply_restriction(datapath, in_port, mac, ip_src)
            self.restricted_hosts.add(mac)

        logger.info(f"[Scenario5-NAC] Access REVOKED for mac={mac}")
        return True, "Access revoked"

    def get_status(self):
        """Trả về trạng thái hiện tại."""
        return {
            "description": "NAC / Captive Portal Module",
            "enabled": getattr(config, "ENABLE_NAC", False),
            "config": {
                "auth_server": f"{config.AUTH_SERVER_IP}:{config.AUTH_SERVER_PORT}",
                "dns_port": config.NAC_ALLOW_DNS_PORT,
            },
            "authenticated_hosts": list(self.authenticated_hosts),
            "restricted_hosts":    list(self.restricted_hosts),
            "host_ip_map": self.mac_to_ip,
        }
