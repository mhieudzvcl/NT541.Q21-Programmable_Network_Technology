"""
scenario2_timebased.py - Kịch bản 2: Time-based Access Control

Logic:
  - Kiểm tra giờ hệ thống định kỳ (mỗi 30 giây)
  - Trong giờ hành chính (8:00 - 18:00):
      → Cài flow ALLOW Guest subnet → Web Server (port 80, 443)
  - Ngoài giờ hành chính:
      → Xóa flow ALLOW, cài flow DROP Guest → Web Server
  - Khi Switch kết nối lần đầu, áp ngay trạng thái phù hợp với giờ hiện tại
"""

import logging
import time
import datetime
from ryu.lib import hub
import config

logger = logging.getLogger(__name__)


class TimeBasedACL:
    """
    Kiểm soát truy cập theo thời gian:
    Guest subnet chỉ được truy cập Web Server trong giờ hành chính.
    """

    def __init__(self, acl_manager):
        """
        :param acl_manager: Instance của ACLManager
        """
        self.acl = acl_manager
        # Lưu danh sách switch đã kết nối: {dpid: datapath}
        self.datapaths = {}
        # Trạng thái hiện tại
        self.is_allowed = None  # None = chưa khởi tạo
        # Hub greenthread (Ryu eventlet)
        self._thread = None
        self._running = False

    # Quản lý Switch
    def register_switch(self, datapath):
        """Gọi khi switch kết nối với controller."""
        self.datapaths[datapath.id] = datapath
        logger.info(f"[Scenario2-Time] Switch dpid={datapath.id} registered")
        # Buộc cài rule ngay lập tức cho switch mới - BYPASS cache is_allowed
        # (không dùng _apply_current_policy vì nó có gác check is_allowed)
        if self._is_business_hours():
            logger.info(f"[Scenario2-Time] Switch dpid={datapath.id}: applying ALLOW (business hours)")
            self._install_allow_rules(datapath)
        else:
            logger.info(f"[Scenario2-Time] Switch dpid={datapath.id}: applying DROP (off-hours)")
            self._install_drop_rules(datapath)

    def unregister_switch(self, dpid):
        """Gọi khi switch ngắt kết nối."""
        self.datapaths.pop(dpid, None)
        logger.info(f"[Scenario2-Time] Switch dpid={dpid} unregistered")

    # Logic kiểm tra giờ
    def _is_business_hours(self):
        """Kiểm tra hiện tại có trong giờ hành chính không."""
        now = datetime.datetime.now()
        return config.TIMEBASED_ALLOW_START <= now.hour < config.TIMEBASED_ALLOW_END

    def _apply_current_policy(self, datapath=None):
        """
        Áp chính sách phù hợp với giờ hiện tại.
        Nếu datapath=None → áp cho tất cả switch đã đăng ký.
        """
        allowed_now = self._is_business_hours()
        targets = [datapath] if datapath else list(self.datapaths.values())

        if allowed_now and self.is_allowed is not True:
            logger.info(
                f"[Scenario2-Time] BUSINESS HOURS → ALLOW Guest→WebServer "
                f"(ports {config.TIMEBASED_WEB_PORTS})"
            )
            for dp in targets:
                self._install_allow_rules(dp)
            self.is_allowed = True

        elif not allowed_now and self.is_allowed is not False:
            logger.info(
                f"[Scenario2-Time] OFF-HOURS → DROP Guest→WebServer "
                f"(ports {config.TIMEBASED_WEB_PORTS})"
            )
            for dp in targets:
                self._install_drop_rules(dp)
            self.is_allowed = False

    def _install_allow_rules(self, datapath):
        """
        Xóa flow DROP để khôi phục trạng thái bình thường (Business Hours).
        Traffic sẽ rơi xuống table-miss và được xử lý bưởi cơ chế L2 learning bình thường.
        """
        ofp_parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        
        guest_ip = config.GUEST_SUBNET.split('/')[0]
        guest_subnet_tuple = (guest_ip, "255.255.255.0")

        for tcp_dst in config.TIMEBASED_WEB_PORTS:
            # Xóa flow DROP cũ (nếu có)
            match = ofp_parser.OFPMatch(
                eth_type=0x0800,
                ip_proto=6,
                ipv4_src=guest_subnet_tuple,
                ipv4_dst=config.INTERNAL_WEB_SERVER_IP,
                tcp_dst=tcp_dst
            )
            mod = ofp_parser.OFPFlowMod(
                datapath=datapath,
                command=ofp.OFPFC_DELETE,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                match=match
            )
            datapath.send_msg(mod)
            logger.info(
                f"[Scenario2-Time] dpid={datapath.id}: "
                f"DELETED DROP rule tcp_dst={tcp_dst} → ALLOW Guest {config.GUEST_SUBNET} to {config.INTERNAL_WEB_SERVER_IP}"
            )

    def _install_drop_rules(self, datapath):
        """Xóa flow ALLOW và cài flow DROP: Guest → Web Server (port 80, 443)."""
        ofp_parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        
        guest_ip = config.GUEST_SUBNET.split('/')[0]
        guest_subnet_tuple = (guest_ip, "255.255.255.0")

        for tcp_dst in config.TIMEBASED_WEB_PORTS:
            # Cài flow DROP (hô thay thế bất kỳ flow cũ nào có cùng match)
            self.acl.add_tcp_drop_flow(
                datapath,
                ip_src=guest_subnet_tuple,
                ip_dst=config.INTERNAL_WEB_SERVER_IP,
                tcp_dst=tcp_dst,
                block_duration=0,  # 0 = vô thời hạn (sẽ bị xóa khi vào giờ)
                priority=config.DROP_PRIORITY
            )
            logger.info(
                f"[Scenario2-Time] dpid={datapath.id}: "
                f"DROP tcp_dst={tcp_dst} → {config.INTERNAL_WEB_SERVER_IP} from Guest {config.GUEST_SUBNET} (OFF-HOURS)"
            )

    # Vòng lặp kiểm tra định kỳ
    def start(self):
        """Bắt đầu vòng lặp kiểm tra giờ định kỳ bằng Ryu hub greenthread."""
        self._running = True
        self._thread = hub.spawn(self._loop)
        logger.info(
            f"[Scenario2-Time] Started. "
            f"Business hours: {config.TIMEBASED_ALLOW_START}:00 - {config.TIMEBASED_ALLOW_END}:00"
        )

    def stop(self):
        """Dừng vòng lặp."""
        self._running = False
        if self._thread:
            self._thread.kill()

    def _loop(self):
        """Vòng lặp chính chạy trong greenthread của Ryu."""
        while self._running:
            self._apply_current_policy()
            hub.sleep(config.TIMEBASED_CHECK_INTERVAL)

    # Status
    def get_status(self):
        """Trả về trạng thái hiện tại."""
        now = datetime.datetime.now()
        return {
            "description": "Time-based Access Control Module",
            "current_time": now.strftime("%H:%M:%S"),
            "business_hours": f"{config.TIMEBASED_ALLOW_START}:00 - {config.TIMEBASED_ALLOW_END}:00",
            "is_business_hours": self._is_business_hours(),
            "guest_access_allowed": self.is_allowed,
            "web_server_ip": config.INTERNAL_WEB_SERVER_IP,
            "controlled_ports": config.TIMEBASED_WEB_PORTS,
            "registered_switches": list(self.datapaths.keys()),
        }
