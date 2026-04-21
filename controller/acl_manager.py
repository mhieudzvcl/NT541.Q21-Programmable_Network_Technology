"""
acl_manager.py - Quản lý các luật ACL (flow entries) trên OpenFlow Switch

Module này cung cấp các hàm tiện ích để thêm/xóa flow rules
thông qua Ryu Controller API.
"""

import logging
from ryu.lib.packet import ethernet, ipv4, tcp, udp, icmp
from ryu.ofproto import ofproto_v1_3 as ofproto
from ryu.ofproto import ofproto_v1_3_parser as parser
import config

logger = logging.getLogger(__name__)


class ACLManager:
    """
    Quản lý luật ACL trên các OpenFlow Switch.
    Cung cấp các phương thức thêm/xóa/kiểm tra flow entry.
    """

    def __init__(self, controller_app):
        """
        :param controller_app: Instance của Ryu Application (self trong RyuApp)
        """
        self.app = controller_app
        # Lưu trạng thái các luật DROP hiện tại: {(dpid, ip_src): expire_time}
        self.active_blocks = {}

    # Hàm nội bộ: gửi lệnh mod-flow xuống switch
    def _send_flow_mod(self, datapath, priority, match, actions,
                       idle_timeout=0, hard_timeout=0,
                       command=None, table_id=0, cookie=0):
        """
        Gửi FLOW_MOD message xuống switch.

        :param datapath:      Đối tượng datapath của switch đích
        :param priority:      Độ ưu tiên của flow entry
        :param match:         OFPMatch object
        :param actions:       Danh sách action (rỗng = DROP)
        :param idle_timeout:  Xóa flow nếu không có traffic sau N giây (0=vô hạn)
        :param hard_timeout:  Xóa flow sau N giây tuyệt đối (0=vô hạn)
        :param command:       OFPFC_ADD / OFPFC_DELETE / OFPFC_MODIFY (mặc định ADD)
        :param table_id:      ID bảng flow (mặc định 0)
        :param cookie:        Cookie để nhận dạng flow (mặc định 0)
        """
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        if command is None:
            command = ofp.OFPFC_ADD

        inst = []
        if actions:
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        # Nếu actions rỗng -> không có instruction -> DROP

        mod = ofp_parser.OFPFlowMod(
            datapath=datapath,
            cookie=cookie,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            command=command,
            table_id=table_id,
        )
        datapath.send_msg(mod)

    # Luật chuyển tiếp bình thường (FORWARD)
    def add_forward_flow(self, datapath, in_port, eth_dst, out_port,
                         idle_timeout=None, hard_timeout=None):
        """
        Thêm flow entry chuyển tiếp L2 (theo địa chỉ MAC đích).

        :param datapath:  Switch
        :param in_port:   Cổng vào
        :param eth_dst:   MAC đích
        :param out_port:  Cổng ra
        """
        ofp_parser = datapath.ofproto_parser
        match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)
        actions = [ofp_parser.OFPActionOutput(out_port)]
        idle = idle_timeout if idle_timeout is not None else config.NORMAL_IDLE_TIMEOUT
        hard = hard_timeout if hard_timeout is not None else config.NORMAL_HARD_TIMEOUT

        logger.info(
            f"[ACLManager] ADD FORWARD: dpid={datapath.id} "
            f"in_port={in_port} eth_dst={eth_dst} out_port={out_port}"
        )
        self._send_flow_mod(
            datapath, config.DEFAULT_PRIORITY, match, actions,
            idle_timeout=idle, hard_timeout=hard
        )

    def add_forward_flow_by_ip(self, datapath, ip_src, ip_dst, out_port,
                               idle_timeout=None, hard_timeout=None):
        """
        Thêm flow entry chuyển tiếp L3 (theo IP nguồn + đích).
        """
        ofp_parser = datapath.ofproto_parser
        match = ofp_parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=ip_src,
            ipv4_dst=ip_dst
        )
        actions = [ofp_parser.OFPActionOutput(out_port)]
        idle = idle_timeout if idle_timeout is not None else config.NORMAL_IDLE_TIMEOUT
        hard = hard_timeout if hard_timeout is not None else config.NORMAL_HARD_TIMEOUT

        self._send_flow_mod(
            datapath, config.DEFAULT_PRIORITY, match, actions,
            idle_timeout=idle, hard_timeout=hard
        )

    # Luật DROP theo IP nguồn
    def add_ip_drop_flow(self, datapath, ip_src,
                         block_duration=None, priority=None):
        """
        Thêm flow entry DROP tất cả gói tin có IP nguồn = ip_src.
        Actions rỗng = DROP (không có OFPActionOutput).

        :param datapath:       Switch cần áp luật
        :param ip_src:         IP nguồn cần chặn (chuỗi, vd "10.0.0.1")
        :param block_duration: hard_timeout (giây), mặc định dùng config
        :param priority:       Priority, mặc định DROP_PRIORITY
        """
        ofp_parser = datapath.ofproto_parser
        hard = block_duration if block_duration is not None else config.DDOS_BLOCK_DURATION
        pri  = priority if priority is not None else config.DROP_PRIORITY

        match = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        # actions = [] -> DROP
        logger.warning(
            f"[ACLManager] DROP IP: dpid={datapath.id} "
            f"ip_src={ip_src} hard_timeout={hard}s"
        )
        self._send_flow_mod(
            datapath, pri, match, actions=[],
            idle_timeout=config.DROP_IDLE_TIMEOUT,
            hard_timeout=hard
        )

    def remove_ip_drop_flow(self, datapath, ip_src):
        """
        Xóa flow entry DROP cho ip_src (dùng OFPFC_DELETE).
        """
        ofp_parser = datapath.ofproto_parser
        match = ofp_parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        self._send_flow_mod(
            datapath, config.DROP_PRIORITY, match, actions=[],
            command=datapath.ofproto.OFPFC_DELETE
        )
        logger.info(f"[ACLManager] REMOVED DROP for ip_src={ip_src} on dpid={datapath.id}")

    # Luật DROP theo Port vật lý (Switch port) - Kịch bản 3
    def add_port_drop_flow(self, datapath, in_port,
                           block_duration=None, priority=None):
        """
        Chặn toàn bộ lưu lượng vào từ một cổng switch vật lý.
        """
        ofp_parser = datapath.ofproto_parser
        hard = block_duration if block_duration is not None else config.SPOOF_BLOCK_DURATION
        pri  = priority if priority is not None else config.DROP_PRIORITY

        match = ofp_parser.OFPMatch(in_port=in_port)
        logger.warning(
            f"[ACLManager] DROP PORT: dpid={datapath.id} "
            f"in_port={in_port} hard_timeout={hard}s"
        )
        self._send_flow_mod(
            datapath, pri, match, actions=[],
            idle_timeout=0, hard_timeout=hard
        )

    def remove_port_drop_flow(self, datapath, in_port):
        """Xóa luật DROP port."""
        ofp_parser = datapath.ofproto_parser
        match = ofp_parser.OFPMatch(in_port=in_port)
        self._send_flow_mod(
            datapath, config.DROP_PRIORITY, match, actions=[],
            command=datapath.ofproto.OFPFC_DELETE
        )
        logger.info(f"[ACLManager] REMOVED DROP PORT {in_port} on dpid={datapath.id}")

    # Luật DROP theo IP + Port TCP/UDP đích - Kịch bản 2, 4
    def add_tcp_drop_flow(self, datapath, ip_src=None, ip_dst=None,
                          tcp_dst=None, block_duration=None, priority=None):
        """
        DROP các gói TCP có IP nguồn/đích và/hoặc cổng TCP đích cụ thể.
        """
        ofp_parser = datapath.ofproto_parser
        hard = block_duration if block_duration is not None else config.DROP_HARD_TIMEOUT
        pri  = priority if priority is not None else config.DROP_PRIORITY

        match_args = {"eth_type": 0x0800, "ip_proto": 6}  # IPv4 + TCP
        if ip_src:
            match_args["ipv4_src"] = ip_src
        if ip_dst:
            match_args["ipv4_dst"] = ip_dst
        if tcp_dst:
            match_args["tcp_dst"] = tcp_dst

        match = ofp_parser.OFPMatch(**match_args)
        logger.warning(
            f"[ACLManager] DROP TCP: dpid={datapath.id} "
            f"ip_src={ip_src} ip_dst={ip_dst} tcp_dst={tcp_dst} hard_timeout={hard}s"
        )
        self._send_flow_mod(
            datapath, pri, match, actions=[],
            idle_timeout=0, hard_timeout=hard
        )

    def add_tcp_allow_flow(self, datapath, ip_src=None, ip_dst=None,
                           tcp_dst=None, out_port=None,
                           idle_timeout=None, hard_timeout=None, priority=None):
        """
        ALLOW (forward) gói TCP với điều kiện cụ thể.
        """
        ofp_parser = datapath.ofproto_parser
        idle = idle_timeout if idle_timeout is not None else config.NORMAL_IDLE_TIMEOUT
        hard = hard_timeout if hard_timeout is not None else config.NORMAL_HARD_TIMEOUT
        pri  = priority if priority is not None else config.DEFAULT_PRIORITY

        match_args = {"eth_type": 0x0800, "ip_proto": 6}
        if ip_src:
            match_args["ipv4_src"] = ip_src
        if ip_dst:
            match_args["ipv4_dst"] = ip_dst
        if tcp_dst:
            match_args["tcp_dst"] = tcp_dst

        match = ofp_parser.OFPMatch(**match_args)

        if out_port is None:
            out_port = datapath.ofproto.OFPP_NORMAL  # Dùng switching bình thường

        actions = [ofp_parser.OFPActionOutput(out_port)]
        self._send_flow_mod(
            datapath, pri, match, actions,
            idle_timeout=idle, hard_timeout=hard
        )

    # Xóa toàn bộ flow (dùng khi reset)
    def clear_all_flows(self, datapath):
        """
        Xóa tất cả flow entry trên switch (trừ table-miss entry nếu có).
        """
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        match = ofp_parser.OFPMatch()
        mod = ofp_parser.OFPFlowMod(
            datapath=datapath,
            command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod)
        logger.info(f"[ACLManager] CLEARED ALL FLOWS on dpid={datapath.id}")

    # Thêm table-miss flow entry (Packet-In cho controller)
    def add_table_miss_flow(self, datapath):
        """
        Thêm table-miss entry: gói tin không khớp flow nào -> gửi lên Controller.
        """
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        match = ofp_parser.OFPMatch()
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                               ofp.OFPCML_NO_BUFFER)]
        self._send_flow_mod(
            datapath,
            priority=config.TABLE_MISS_PRIORITY,
            match=match,
            actions=actions,
            idle_timeout=0,
            hard_timeout=0
        )
        logger.debug(f"[ACLManager] Added table-miss flow on dpid={datapath.id}")

    # Thêm flow entry ép toàn bộ ICMP phải luôn gửi lên Controller (để phục vụ Kịch bản 1)
    def add_icmp_to_controller_flow(self, datapath):
        """
        Thêm flow chặn ICMP: Ưu tiên cao hơn L2 chuyển tiếp (Priority = 5)
        Để đảm bảo mọi gói ICMP đều văng lên Controller đếm chống DDoS.
        """
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        match = ofp_parser.OFPMatch(eth_type=0x0800, ip_proto=1)  # IPv4, ICMP
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                               ofp.OFPCML_NO_BUFFER)]
        self._send_flow_mod(
            datapath,
            priority=config.DEFAULT_PRIORITY + 4, # Cao hơn mặc định 1
            match=match,
            actions=actions,
            idle_timeout=0,
            hard_timeout=0
        )
        logger.info(f"[ACLManager] Added ICMP->Controller flow on dpid={datapath.id}")

    # Thêm flow entry ép toàn bộ TCP phải luôn gửi lên Controller (để phục vụ Kịch bản 4)
    def add_tcp_to_controller_flow(self, datapath):
        """
        Thêm flow gửi tất cả TCP lên Controller (Priority = 3).
        Đảm bảo SYN packet luôn đến controller dù L2 flow đã học.
        Phục vụ Port Scan Detection (KB4).
        Priority thấp hơn DROP rules (10+) nhưng cao hơn table-miss (0).
        """
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        match = ofp_parser.OFPMatch(eth_type=0x0800, ip_proto=6)  # IPv4, TCP
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                               ofp.OFPCML_NO_BUFFER)]
        self._send_flow_mod(
            datapath,
            priority=config.DEFAULT_PRIORITY + 2,  # Priority=3
            match=match,
            actions=actions,
            idle_timeout=0,
            hard_timeout=0
        )
        logger.info(f"[ACLManager] Added TCP->Controller flow on dpid={datapath.id}")
