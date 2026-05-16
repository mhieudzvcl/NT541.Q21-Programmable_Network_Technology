"""
monitor.py - Module giám sát lưu lượng mạng

Thu thập thống kê từ các OpenFlow Switch và phát hiện bất thường
thông qua cơ chế đếm gói tin theo cửa sổ thời gian trượt (sliding window).
"""

import logging
import time
from collections import defaultdict, deque
import config

logger = logging.getLogger(__name__)


class TrafficMonitor:
    """
    Theo dõi lưu lượng mạng và phát hiện các hành vi bất thường.

    Dữ liệu được lưu theo cấu trúc:
    - icmp_counter:  {ip_src: deque([timestamp, ...])}  → đếm ICMP
    - syn_counter:   {ip_src: deque([timestamp, ...])}  → đếm SYN
    - port_counter:  {ip_src: {ip_dst: set(ports)}}     → Port Scan
    - mac_table:     {mac: (dpid, port, timestamp)}     → học MAC/IP
    - ip_mac_map:    {ip: mac}                          → ánh xạ IP→MAC
    """

    def __init__(self):
        # Kịch bản 1: DDoS
        self.icmp_counter = defaultdict(deque)   # {ip_src: deque of timestamps}
        self.syn_counter  = defaultdict(deque)   # {ip_src: deque of timestamps}

        # Kịch bản 3: Spoofing
        # {mac: {"dpid": ..., "port": ..., "ip": ..., "last_seen": ...}}
        self.mac_location = {}
        # {ip:  {"dpid": ..., "port": ..., "mac": ..., "last_seen": ...}}
        self.ip_location  = {}
        # Port HỢP LỆ GỐC: lần đầu tiên thấy MAC này (bất biến, chỉ reset khi restart).
        # Dùng làm tham chiếu khi phát hiện spoof thay vì dùng old_location
        # (vì old_location có thể đã bị nhiễm bởi gói spoof không bị detect).
        # {mac: {"dpid": ..., "port": ...}}
        self.mac_first_port = {}
        # Persistent binding: sau khi phát hiện spoof lần đầu, lưu port hợp lệ
        # để chặn attacker kể cả sau khi time-window hết.
        # {mac: {"dpid": ..., "port": ...}}
        self.mac_legitimate_port = {}

        # Kịch bản 4: Port Scan
        # {ip_src: deque([(timestamp, ip_dst, tcp_dst), ...])}
        self.flow_events  = defaultdict(deque)

        # Danh sách các IP/port đang bị chặn
        self.blocked_ips   = {}    # {ip: expire_time}
        self.blocked_ports = {}    # {(dpid, port): expire_time}
        self.quarantined   = {}    # {ip: expire_time}

    # Kịch bản 1: DDoS / Rate Limiting
    def record_icmp(self, ip_src):
        """Ghi nhận một gói ICMP từ ip_src. Trả về số gói trong 1 giây gần nhất."""
        now = time.time()
        q = self.icmp_counter[ip_src]
        q.append(now)
        # Loại bỏ timestamp cũ hơn DDOS_MONITOR_INTERVAL
        while q and now - q[0] > config.DDOS_MONITOR_INTERVAL:
            q.popleft()
        return len(q)

    def record_syn(self, ip_src):
        """Ghi nhận một gói TCP SYN từ ip_src. Trả về số gói trong 1 giây gần nhất."""
        now = time.time()
        q = self.syn_counter[ip_src]
        q.append(now)
        while q and now - q[0] > config.DDOS_MONITOR_INTERVAL:
            q.popleft()
        return len(q)

    def is_ddos_icmp(self, ip_src):
        """Kiểm tra xem ip_src có đang flood ICMP không."""
        count = self.record_icmp(ip_src)
        if count > config.DDOS_ICMP_THRESHOLD:
            logger.warning(
                f"[Monitor] ICMP FLOOD detected! ip_src={ip_src} "
                f"count={count}/{config.DDOS_ICMP_THRESHOLD} per second"
            )
            return True
        return False

    def is_ddos_syn(self, ip_src):
        """Kiểm tra xem ip_src có đang flood TCP SYN không."""
        count = self.record_syn(ip_src)
        if count > config.DDOS_SYN_THRESHOLD:
            logger.warning(
                f"[Monitor] SYN FLOOD detected! ip_src={ip_src} "
                f"count={count}/{config.DDOS_SYN_THRESHOLD} per second"
            )
            return True
        return False

    def block_ip(self, ip, duration=None):
        """Đánh dấu IP bị chặn trong bộ nhớ."""
        dur = duration if duration else config.DDOS_BLOCK_DURATION
        self.blocked_ips[ip] = time.time() + dur
        logger.info(f"[Monitor] IP {ip} blocked for {dur}s")

    def is_ip_blocked(self, ip):
        """Kiểm tra IP có đang bị chặn không (theo thời gian lưu trong RAM)."""
        expire = self.blocked_ips.get(ip)
        if expire and time.time() < expire:
            return True
        elif expire:
            del self.blocked_ips[ip]
        return False

    # Kịch bản 3: MAC/IP Spoofing Detection
    def update_mac_location(self, mac, dpid, port, ip=None):
        """
        Cập nhật vị trí MAC. Trả về (is_spoofed: bool, old_location: dict).

        Phát hiện spoofing theo 2 tầng:
          1. Persistent binding: MAC đã từng bị flag → luôn kiểm tra với port đầu tiên.
          2. Time-window: MAC di chuyển port trong < SPOOF_TIME_WINDOW giây.

        FIX: Dùng mac_first_port (port lần đầu thấy MAC) làm tham chiếu hợp lệ.
        Không dùng old_location vì có thể bị nhiễm nếu attacker chờ > time_window.
        Khi phát hiện spoof → KHÔNG cập nhật mac_location để tránh false positive.
        """
        now = time.time()
        old = self.mac_location.get(mac)

        # --- Ghi nhận lần đầu thấy MAC (bất biến) ---
        if mac not in self.mac_first_port:
            self.mac_first_port[mac] = {"dpid": dpid, "port": port}
            logger.info(f"[Monitor] MAC {mac} first seen at dpid={dpid}/port={port}")

        first = self.mac_first_port[mac]

        # --- Tầng 1: Persistent binding (sau khi spoof đã bị phát hiện lần đầu) ---
        legitimate = self.mac_legitimate_port.get(mac)
        if legitimate:
            legit_same = (legitimate["dpid"] == dpid and legitimate["port"] == port)
            if not legit_same:
                logger.warning(
                    f"[Monitor] MAC SPOOFING (persistent)! mac={mac} "
                    f"legitimate port=dpid={legitimate['dpid']}/port={legitimate['port']} "
                    f"but packet arrived at dpid={dpid}/port={port}"
                )
                # KHÔNG cập nhật mac_location
                return True, old

        # --- Tầng 2: Time-window (phát hiện lần đầu) ---
        if old:
            same_location = (old["dpid"] == dpid and old["port"] == port)
            time_diff = now - old["last_seen"]

            if not same_location and time_diff < config.SPOOF_TIME_WINDOW:
                logger.warning(
                    f"[Monitor] MAC SPOOFING! mac={mac} "
                    f"moved from dpid={old['dpid']}/port={old['port']} "
                    f"to dpid={dpid}/port={port} in {time_diff:.2f}s"
                )
                # Lưu mac_first_port làm legitimate (không dùng old vì có thể bị nhiễm)
                if mac not in self.mac_legitimate_port:
                    self.mac_legitimate_port[mac] = {
                        "dpid": first["dpid"], "port": first["port"]
                    }
                    logger.info(
                        f"[Monitor] MAC {mac} bound to FIRST-SEEN legitimate "
                        f"dpid={first['dpid']}/port={first['port']} permanently."
                    )
                # KHÔNG cập nhật mac_location
                return True, old

        # Cập nhật vị trí mới (host hợp lệ)
        self.mac_location[mac] = {
            "dpid": dpid, "port": port,
            "ip": ip, "last_seen": now
        }
        return False, old

    def clear_mac_binding(self, mac):
        """
        Xóa persistent binding của MAC (dùng khi admin xác nhận host di chuyển hợp lệ).
        """
        if mac in self.mac_legitimate_port:
            del self.mac_legitimate_port[mac]
            logger.info(f"[Monitor] Cleared persistent binding for MAC {mac}")

    def update_ip_location(self, ip, mac, dpid, port):
        """
        Cập nhật ánh xạ IP→MAC/Port.
        Trả về True nếu phát hiện IP di chuyển bất thường (≠ MAC cũ).
        """
        now = time.time()
        old = self.ip_location.get(ip)

        if old and old["mac"] != mac:
            time_diff = now - old["last_seen"]
            if time_diff < config.SPOOF_TIME_WINDOW:
                logger.warning(
                    f"[Monitor] IP SPOOFING! ip={ip} "
                    f"changed MAC from {old['mac']} to {mac} in {time_diff:.2f}s"
                )
                # KHÔNG lưu đè self.ip_location bằng MAC của kẻ tấn công
                return True, old

        self.ip_location[ip] = {
            "mac": mac, "dpid": dpid, "port": port, "last_seen": now
        }
        return False, old

    def block_port(self, dpid, port, duration=None):
        """Đánh dấu port bị chặn."""
        dur = duration if duration else config.SPOOF_BLOCK_DURATION
        self.blocked_ports[(dpid, port)] = time.time() + dur
        logger.info(f"[Monitor] Port dpid={dpid}/port={port} blocked for {dur}s")

    def is_port_blocked(self, dpid, port):
        """Kiểm tra port có đang bị chặn không."""
        expire = self.blocked_ports.get((dpid, port))
        if expire and time.time() < expire:
            return True
        elif expire:
            del self.blocked_ports[(dpid, port)]
        return False

    # Kịch bản 4: Port Scan Detection
    def record_tcp_flow(self, ip_src, ip_dst, tcp_dst):
        """
        Ghi nhận một luồng TCP mới.
        Trả về số cổng đích khác nhau trong cửa sổ thời gian gần nhất.
        """
        now = time.time()
        q = self.flow_events[ip_src]
        q.append((now, ip_dst, tcp_dst))
        # Loại bỏ sự kiện cũ hơn PORTSCAN_TIME_WINDOW
        while q and now - q[0][0] > config.PORTSCAN_TIME_WINDOW:
            q.popleft()
        # Đếm số cổng đích khác nhau đến ip_dst
        unique_ports = set()
        for (ts, dst, port) in q:
            if dst == ip_dst:
                unique_ports.add(port)
        return len(unique_ports)

    def is_port_scanning(self, ip_src, ip_dst, tcp_dst):
        """Kiểm tra ip_src có đang quét port ip_dst không."""
        count = self.record_tcp_flow(ip_src, ip_dst, tcp_dst)
        if count > config.PORTSCAN_THRESHOLD:
            logger.warning(
                f"[Monitor] PORT SCAN detected! ip_src={ip_src} → ip_dst={ip_dst} "
                f"unique_ports={count}/{config.PORTSCAN_THRESHOLD} in {config.PORTSCAN_TIME_WINDOW}s"
            )
            return True
        return False

    def quarantine_ip(self, ip, duration=None):
        """Đưa IP vào vùng cách ly."""
        dur = duration if duration else config.QUARANTINE_DURATION
        self.quarantined[ip] = time.time() + dur
        logger.warning(f"[Monitor] IP {ip} QUARANTINED for {dur}s")

    def is_quarantined(self, ip):
        """Kiểm tra IP có đang bị cách ly không."""
        expire = self.quarantined.get(ip)
        if expire and time.time() < expire:
            return True
        elif expire:
            del self.quarantined[ip]
        return False

    # Thống kê / Debug
    def get_status(self):
        """Trả về trạng thái tổng quan của monitor dưới dạng dict."""
        now = time.time()
        return {
            "blocked_ips": {
                ip: f"expires in {exp - now:.0f}s"
                for ip, exp in self.blocked_ips.items()
                if exp > now
            },
            "blocked_ports": {
                f"dpid={d}/port={p}": f"expires in {exp - now:.0f}s"
                for (d, p), exp in self.blocked_ports.items()
                if exp > now
            },
            "quarantined_ips": {
                ip: f"expires in {exp - now:.0f}s"
                for ip, exp in self.quarantined.items()
                if exp > now
            },
            "mac_locations":      dict(self.mac_location),
            "ip_locations":       dict(self.ip_location),
            "mac_legitimate_ports": dict(self.mac_legitimate_port),
        }
