# config.py - Cấu hình toàn cục cho Dynamic ACL Controller

# Cấu hình OpenFlow
OPENFLOW_VERSION = 0x04          # OpenFlow 1.3
DEFAULT_PRIORITY = 1             # Priority mặc định cho flow forward
DROP_PRIORITY    = 10            # Priority cao hơn cho flow DROP (override)
TABLE_MISS_PRIORITY = 0          # Priority thấp nhất (table-miss -> Packet-In)

# Kịch bản 1: DDoS / Rate Limiting
DDOS_ICMP_THRESHOLD  = 50        # Số gói ICMP tối đa cho phép / giây
DDOS_SYN_THRESHOLD   = 30        # Số gói TCP SYN tối đa cho phép / giây
DDOS_BLOCK_DURATION  = 60        # Thời gian chặn (giây) khi phát hiện DDoS
DDOS_MONITOR_INTERVAL = 1        # Chu kỳ kiểm tra (giây)

# Kịch bản 2: Time-based Access Control
TIMEBASED_ALLOW_START = 8        # Giờ bắt đầu cho phép (Mặc định là 8:00 AM)
TIMEBASED_ALLOW_END   = 18       # Giờ kết thúc cho phép (Mặc định là 6:00 PM)
TIMEBASED_CHECK_INTERVAL = 30    # Chu kỳ kiểm tra giờ (giây)
TIMEBASED_WEB_PORTS = [80, 443]  # Cổng Web được kiểm soát
# Subnet của mạng Guest (sẽ được áp luật time-based)
GUEST_SUBNET = "10.0.2.0/24"
# IP của Web Server nội bộ
INTERNAL_WEB_SERVER_IP = "10.0.0.100"

# Kịch bản 3: MAC/IP Spoofing Detection
SPOOF_TIME_WINDOW = 5            # Cửa sổ thời gian (giây) để phát hiện di chuyển bất thường
SPOOF_BLOCK_DURATION = 120       # Thời gian chặn port khi phát hiện spoof (giây)

# Kịch bản 4: Port Scan Detection
PORTSCAN_THRESHOLD   = 15        # Số cổng đích khác nhau tối đa / cửa sổ thời gian
PORTSCAN_TIME_WINDOW = 5         # Cửa sổ thời gian (giây)
QUARANTINE_VLAN      = 999       # VLAN ID cho vùng cách ly (nếu dùng VLAN)
# IP của máy chủ Quarantine (nơi redirect traffic của host bị cách ly)
QUARANTINE_SERVER_IP = "10.0.0.254"
QUARANTINE_DURATION  = 300       # Thời gian cách ly (giây)

# Kịch bản 5: NAC / Captive Portal
AUTH_SERVER_IP   = "10.0.0.200"  # IP của Authentication Server
AUTH_SERVER_PORT = 8080          # Port của Authentication Server
NAC_ALLOW_DNS_PORT = 53          # Cho phép DNS kể cả chưa xác thực
ENABLE_NAC       = False         # Cờ BẬT/TẮT kịch bản 5 (Để False khi test KB 1-4)

# Cấu hình REST API
REST_LISTEN_HOST = "0.0.0.0"
REST_LISTEN_PORT = 8888

# Cấu hình Logging
LOG_LEVEL = "INFO"               # DEBUG / INFO / WARNING / ERROR
LOG_FILE  = "/tmp/dynamic_acl.log"

# Cấu hình Idle/Hard Timeout
# Dùng cho các flow entry bình thường (học MAC)
NORMAL_IDLE_TIMEOUT = 300        # 5 phút không có traffic → xóa flow
NORMAL_HARD_TIMEOUT = 0          # 0 = không giới hạn hard timeout

# Dùng cho các flow DROP (kịch bản 1, 3, 4)
DROP_IDLE_TIMEOUT = 0            # DROP flow không xóa vì idle
DROP_HARD_TIMEOUT = DDOS_BLOCK_DURATION  # Tự hết hạn sau khoảng thời gian chặn
