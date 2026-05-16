"""
dynamic_acl_controller.py - Ryu SDN Controller chính

Ứng dụng Ryu tích hợp tất cả 5 kịch bản Dynamic ACL:
  1. DDoS / Rate Limiting (ICMP Flood, SYN Flood)
  2. Time-based Access Control (Guest → Web Server)
  3. MAC/IP Spoofing Detection
  4. Port Scan Detection & Quarantine
  5. NAC / Captive Portal (xác thực trước khi cấp quyền)

Chạy bằng lệnh:
  ryu-manager dynamic_acl_controller.py --verbose
  ryu-manager dynamic_acl_controller.py --observe-links (nếu cần topology discovery)
  ryu-manager dynamic_acl_controller.py --verbose --wsapi-port 8888 - hỗ trợ cho kịch bản 5
"""

import logging
import sys
import os
import json

# Thêm thư mục cha vào PYTHONPATH để import config và modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp as icmp_lib, arp
from ryu.lib import hub
from ryu.app.wsgi import WSGIApplication, ControllerBase, route, Response

import config
from acl_manager import ACLManager
from monitor import TrafficMonitor
from scenarios.scenario1_ddos import DDoSMitigation
from scenarios.scenario2_timebased import TimeBasedACL
from scenarios.scenario3_spoofing import SpoofingDetection
from scenarios.scenario4_portscan import PortScanDetection
from scenarios.scenario5_nac import NACPortal

# Cấu hình logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(config.LOG_FILE, mode='a')
    ]
)
logger = logging.getLogger("DynamicACL")

# REST API Controller
class DynamicACLRestAPI(ControllerBase):
    """REST API để tương tác với controller qua HTTP."""

    def __init__(self, req, link, data, **config_):
        super().__init__(req, link, data, **config_)
        self.controller_app = data["controller_app"]

    # GET /status - Xem trạng thái tổng quan
    @route("status", "/status", methods=["GET"])
    def get_status(self, req, **kwargs):
        app = self.controller_app
        body = json.dumps({
            "controller": "DynamicACL-Ryu",
            "connected_switches": list(app.datapaths.keys()),
            "monitor_status": app.monitor.get_status(),
            "scenario1_ddos":    app.ddos.get_status(),
            "scenario2_timebased": app.timebased.get_status(),
            "scenario3_spoofing": app.spoofing.get_status(),
            "scenario4_portscan": app.portscan.get_status(),
            "scenario5_nac":     app.nac.get_status(),
        }, indent=2, default=str).encode('utf-8')
        return Response(content_type="application/json", body=body)

    # POST /authenticate - Xác thực host (Kịch bản 5)
    # Được gọi bởi Auth Server sau khi xác thực thành công
    @route("authenticate", "/authenticate", methods=["POST"])
    def authenticate(self, req, **kwargs):
        app = self.controller_app
        try:
            body = req.json if req.content_type == "application/json" else {}
            mac = body.get("mac", "")
            if not mac:
                return Response(
                    status=400,
                    content_type="application/json",
                    body=json.dumps({"error": "Missing 'mac' field"}).encode('utf-8')
                )
            # Gọi trực tiếp _grant_full_access trong greenthread
            # Không gọi handle_auth_callback (tránh vòng lặp gọi lại auth server)
            hub.spawn(app.nac._grant_full_access, mac)
            logger.info(f"[REST /authenticate] Granting full access for mac={mac}")
            return Response(
                content_type="application/json",
                body=json.dumps({
                    "mac": mac,
                    "authenticated": True,
                    "status": "access_granted",
                    "message": f"Full access granted for {mac}"
                }).encode('utf-8')
            )
        except Exception as e:
            logger.error(f"[REST /authenticate] Error: {e}")
            return Response(
                status=500,
                content_type="application/json",
                body=json.dumps({"error": str(e)}).encode('utf-8')
            )

    # POST /block_ip - Chặn IP thủ công
    @route("block_ip", "/block_ip", methods=["POST"])
    def block_ip(self, req, **kwargs):
        app = self.controller_app
        try:
            body = req.json if req.content_type == "application/json" else {}
            ip_src   = body.get("ip", "")
            duration = int(body.get("duration", config.DDOS_BLOCK_DURATION))
            if not ip_src:
                return Response(
                    status=400,
                    content_type="application/json",
                    body=json.dumps({"error": "Missing 'ip' field"}).encode('utf-8')
                )
            # Áp luật DROP cho tất cả switch
            for dpid, dp in app.datapaths.items():
                app.acl_manager.add_ip_drop_flow(dp, ip_src, block_duration=duration)
            app.monitor.block_ip(ip_src, duration=duration)
            return Response(
                content_type="application/json",
                body=json.dumps({
                    "message": f"IP {ip_src} blocked for {duration}s on all switches",
                    "affected_switches": list(app.datapaths.keys())
                }).encode('utf-8')
            )
        except Exception as e:
            return Response(
                status=500,
                content_type="application/json",
                body=json.dumps({"error": str(e)}).encode('utf-8')
            )

    # GET /mac_table - Xem bảng MAC
    @route("mac_table", "/mac_table", methods=["GET"])
    def get_mac_table(self, req, **kwargs):
        app = self.controller_app
        body = json.dumps({
            "mac_to_port": {
                str(dpid): {mac: port for mac, port in table.items()}
                for dpid, table in app.mac_to_port.items()
            }
        }, indent=2).encode('utf-8')
        return Response(content_type="application/json", body=body)

    # DELETE /mac_table - Reset bảng MAC 
    @route("mac_table_reset", "/mac_table", methods=["DELETE"])
    def reset_mac_table(self, req, **kwargs):
        app = self.controller_app
        for dpid in app.mac_to_port:
            app.mac_to_port[dpid].clear()
        logger.info("[REST DELETE /mac_table] MAC table cleared for all switches")
        body = json.dumps({
            "message": "MAC table cleared",
            "switches": list(app.mac_to_port.keys())
        }, indent=2).encode('utf-8')
        return Response(content_type="application/json", body=body)

# Main Ryu Application
class DynamicACLController(app_manager.RyuApp):
    """
    Controller chính tích hợp tất cả 5 kịch bản Dynamic ACL.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # WSGI (REST API)
        wsgi = kwargs["wsgi"]
        wsgi.register(DynamicACLRestAPI, {"controller_app": self})

        # Dữ liệu nội bộ
        # Bảng MAC: dpid -> {eth_dst: out_port}
        self.mac_to_port = {}
        # Danh sách switch đã kết nối: dpid -> datapath
        self.datapaths = {}

        # Khởi tạo các module
        self.monitor     = TrafficMonitor()
        self.acl_manager = ACLManager(self)
        self.ddos        = DDoSMitigation(self.acl_manager, self.monitor)
        self.timebased   = TimeBasedACL(self.acl_manager)
        self.spoofing    = SpoofingDetection(self.acl_manager, self.monitor)
        self.portscan    = PortScanDetection(self.acl_manager, self.monitor)
        self.nac         = NACPortal(self.acl_manager)

        # Truyền tham chiếu datapaths cho module spoofing
        self.spoofing.set_datapaths_map(self.datapaths)

        # Khởi động Time-based ACL
        self.timebased.start()

        logger.info("=" * 60)
        logger.info(" Dynamic ACL Controller (Ryu) - Đã khởi động")
        logger.info(f" REST API: http://0.0.0.0:{config.REST_LISTEN_PORT}")
        logger.info(f" Log file: {config.LOG_FILE}")
        logger.info("=" * 60)
        logger.info(f" Scenario 1: ICMP threshold={config.DDOS_ICMP_THRESHOLD}/s, block={config.DDOS_BLOCK_DURATION}s")
        logger.info(f" Scenario 2: Business hours {config.TIMEBASED_ALLOW_START}:00-{config.TIMEBASED_ALLOW_END}:00")
        logger.info(f" Scenario 3: Spoof window={config.SPOOF_TIME_WINDOW}s, block={config.SPOOF_BLOCK_DURATION}s")
        logger.info(f" Scenario 4: PortScan threshold={config.PORTSCAN_THRESHOLD} ports/{config.PORTSCAN_TIME_WINDOW}s")
        logger.info(f" Scenario 5: Auth Server={config.AUTH_SERVER_IP}:{config.AUTH_SERVER_PORT}")
        logger.info("=" * 60)

    # Event: Switch kết nối (FEATURES_REPLY)
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Được gọi khi switch kết nối với controller.
        Cài đặt table-miss flow entry để gửi gói lạ lên controller.
        """
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.datapaths[dpid] = datapath
        self.mac_to_port.setdefault(dpid, {})

        logger.info(f"[Controller] Switch CONNECTED: dpid={dpid:#016x} ({dpid})")

        # Cài table-miss entry
        self.acl_manager.add_table_miss_flow(datapath)
        
        # Áp đặt cứng luồng ICMP phải luôn đi lên Controller để bắt được DDoS Ping Flood
        self.acl_manager.add_icmp_to_controller_flow(datapath)
        self.acl_manager.add_tcp_to_controller_flow(datapath)

        # Đăng ký với các module cần biết khi switch kết nối
        self.timebased.register_switch(datapath)

    # Event: Switch ngắt kết nối
    @set_ev_cls(ofp_event.EventOFPStateChange, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def state_change_handler(self, ev):
        """Dọn dẹp khi switch ngắt kết nối."""
        from ryu.controller.handler import DEAD_DISPATCHER
        datapath = ev.datapath
        if ev.state == DEAD_DISPATCHER:
            dpid = datapath.id
            logger.warning(f"[Controller] Switch DISCONNECTED: dpid={dpid}")
            self.datapaths.pop(dpid, None)
            self.mac_to_port.pop(dpid, None)
            self.timebased.unregister_switch(dpid)

    # Event: Nhận gói Packet-In
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Xử lý gói tin không khớp flow nào trên switch (table-miss → Packet-In).

        Luồng xử lý:
        1. Parse gói tin
        2. Học địa chỉ MAC (L2 learning)
        3. Chạy các module kiểm tra bảo mật theo thứ tự
        4. Nếu gói hợp lệ → cài flow và forward
        """
        msg = ev.msg
        datapath = msg.datapath
        ofp      = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        dpid     = datapath.id
        in_port  = msg.match["in_port"]

        # Parse packet
        pkt      = packet.Packet(msg.data)
        eth_pkt  = pkt.get_protocol(ethernet.ethernet)

        if eth_pkt is None:
            return

        eth_src = eth_pkt.src
        eth_dst = eth_pkt.dst

        # Bỏ qua gói LLDP (topology discovery)
        if eth_pkt.ethertype == 0x88CC:
            return

        # Parse các tầng cao hơn
        ip_pkt   = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt  = pkt.get_protocol(tcp.tcp)
        udp_pkt  = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp_lib.icmp)
        arp_pkt  = pkt.get_protocol(arp.arp)

        if ip_pkt:
            ip_src = ip_pkt.src
            ip_dst = ip_pkt.dst
        elif arp_pkt:
            ip_src = arp_pkt.src_ip
            ip_dst = arp_pkt.dst_ip
        else:
            ip_src = None
            ip_dst = None

        logger.info(
            f"[PacketIn] dpid={dpid} in_port={in_port} "
            f"eth_src={eth_src} eth_dst={eth_dst} "
            f"ip_src={ip_src} ip_dst={ip_dst}"
        )

        # BƯỚC 1: Học địa chỉ MAC (L2 Learning)
        self.mac_to_port.setdefault(dpid, {})

        # BƯỚC 2: Kịch bản 3 - Kiểm tra Spoofing TRƯỚC KHI học MAC
        # (để phát hiện MAC di chuyển bất thường)
        if self.spoofing.handle_packet(datapath, in_port, eth_src, ip_src):
            logger.warning(
                f"[Controller] SPOOF DETECTED → DROP: "
                f"eth_src={eth_src} ip_src={ip_src} port={in_port}"
            )
            return  # Dừng xử lý, gói bị DROP

        # BƯỚC 3: Kịch bản 5 - NAC: kiểm tra Host mới
        # (ENABLE_NAC được kiểm tra bên trong handle_new_host)
        if eth_src not in self.mac_to_port.get(dpid, {}):
            # Host mới → kiểm tra NAC
            if self.nac.handle_new_host(datapath, in_port, eth_src, ip_src):
                logger.info(
                    f"[Controller] NAC RESTRICTED: eth_src={eth_src} "
                    f"must authenticate at {config.AUTH_SERVER_IP}"
                )
                return

        # Học MAC (sau khi đã kiểm tra NAC và Spoofing)
        self.mac_to_port[dpid][eth_src] = in_port

        # BƯỚC 4: Kịch bản 1 - Kiểm tra DDoS (ICMP / SYN Flood)
        if ip_pkt:
            if self.ddos.handle_packet(datapath, in_port, pkt):
                logger.warning(
                    f"[Controller] DDOS DETECTED → DROP: ip_src={ip_src}"
                )
                return  # Gói bị DROP bởi flow entry đã cài

        # BƯỚC 5: Kịch bản 4 - Kiểm tra Port Scan (TCP SYN)
        if ip_pkt and tcp_pkt:
            # Chỉ kiểm tra SYN (không phải SYN-ACK)
            if tcp_pkt.bits & 0x02 and not (tcp_pkt.bits & 0x10):
                if self.portscan.handle_packet(
                    datapath, in_port,
                    ip_src, ip_dst, tcp_pkt.dst_port
                ):
                    logger.warning(
                        f"[Controller] PORT SCAN DETECTED → QUARANTINE: ip_src={ip_src}"
                    )
                    return  # Gói bị DROP/Quarantine

        # BƯỚC 6: Xác định cổng ra (L2 Forwarding)
        if eth_dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_dst]
        else:
            # Chưa biết MAC đích → Flood
            out_port = ofp.OFPP_FLOOD

        actions = [ofp_parser.OFPActionOutput(out_port)]

        # BƯỚC 7: Cài flow entry nếu biết cổng ra (không Flood)
        if out_port != ofp.OFPP_FLOOD:
            # Không cài flow tự động cho ICMP để controller luôn đếm được gói tin ping -> Phục vụ Kịch bản 1 DDoS
            if not icmp_pkt:
                # Cài flow L2 để lần sau switch tự xử lý (Cấu hình cứng ở phần cứng)
                self.acl_manager.add_forward_flow(
                    datapath, in_port, eth_src, eth_dst, out_port
                )

        # BƯỚC 8: Gửi gói tin hiện tại ra cổng đích (Packet-Out)
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = ofp_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    # Event: Nhận thống kê flow (Flow Stats Reply) - dùng cho giám sát nâng cao
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Nhận và log thống kê flow từ switch."""
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        logger.debug(f"[FlowStats] dpid={dpid} - {len(body)} flows")
        for stat in body:
            logger.debug(
                f"  priority={stat.priority} "
                f"match={stat.match} "
                f"actions={stat.instructions} "
                f"packets={stat.packet_count} bytes={stat.byte_count} "
                f"idle_timeout={stat.idle_timeout} hard_timeout={stat.hard_timeout}"
            )

    # Hàm tiện ích cho các kịch bản: Request flow stats từ switch
    def request_flow_stats(self, datapath):
        """Yêu cầu switch gửi thống kê flow lên controller."""
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
