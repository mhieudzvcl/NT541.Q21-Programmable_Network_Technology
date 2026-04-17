# REST API Reference - Dynamic ACL Controller

Base URL: `http://127.0.0.1:8888`

> Controller REST API được cung cấp bởi Ryu WSGI. Chạy đồng thời với Controller trên port 8888.

---

## Endpoints

### `GET /status`

Xem trạng thái tổng quan của toàn bộ hệ thống.

**Response:**
```json
{
  "controller": "DynamicACL-Ryu",
  "connected_switches": [1],
  "monitor_status": {
    "blocked_ips":    {"10.0.0.1": "expires in 45s"},
    "blocked_ports":  {},
    "quarantined_ips": {},
    "mac_locations":  {"00:00:00:00:00:01": {"dpid": 1, "port": 1, "ip": "10.0.0.1"}}
  },
  "scenario1_ddos": {
    "description": "DDoS / Rate Limiting Module",
    "thresholds": {
      "icmp_per_second": 50,
      "syn_per_second":  30,
      "block_duration":  60
    },
    "currently_blocked_ips": ["10.0.0.1"]
  },
  "scenario2_timebased": {
    "description": "Time-based Access Control Module",
    "current_time": "14:30:00",
    "business_hours": "8:00 - 18:00",
    "is_business_hours": true,
    "guest_access_allowed": true,
    "web_server_ip": "10.0.0.100",
    "controlled_ports": [80, 443]
  },
  "scenario3_spoofing": {
    "description": "MAC/IP Spoofing Detection Module",
    "blocked_ports": [],
    "known_mac_locations": {}
  },
  "scenario4_portscan": {
    "description": "Port Scan Detection & Quarantine Module",
    "quarantined_hosts": []
  },
  "scenario5_nac": {
    "description": "NAC / Captive Portal Module",
    "authenticated_hosts": ["00:00:00:00:00:01"],
    "restricted_hosts":    ["00:00:00:00:00:50"]
  }
}
```

---

### `GET /mac_table`

Xem bảng MAC đã học của tất cả switch.

**Response:**
```json
{
  "mac_to_port": {
    "1": {
      "00:00:00:00:00:01": 1,
      "00:00:00:00:00:02": 2,
      "00:00:00:00:00:64": 4
    }
  }
}
```

---

### `POST /authenticate`

Xác thực Host qua MAC address (Kịch bản 5 - NAC).
Được gọi bởi Auth Server sau khi xác thực thành công.

**Request Body:**
```json
{
  "mac":   "00:00:00:00:00:50",
  "token": "TOKEN_NEW"
}
```

**Response (thành công):**
```json
{
  "mac":           "00:00:00:00:00:50",
  "authenticated": true,
  "message":       "Authentication successful"
}
```

**Response (thất bại):**
```json
{
  "mac":           "00:00:00:00:00:99",
  "authenticated": false,
  "message":       "Authentication failed"
}
```

**Ví dụ:**
```bash
curl -X POST http://127.0.0.1:8888/authenticate \
  -H "Content-Type: application/json" \
  -d '{"mac": "00:00:00:00:00:50", "token": "TOKEN_NEW"}'
```

---

### `POST /block_ip`

Chặn thủ công một IP trên tất cả switch đang kết nối.

**Request Body:**
```json
{
  "ip":       "10.0.0.1",
  "duration": 120
}
```

| Field      | Kiểu   | Bắt buộc | Mô tả                               |
|------------|--------|----------|-------------------------------------|
| `ip`       | string | Có        | IPv4 address cần chặn               |
| `duration` | int    | Không     | Thời gian chặn (giây), mặc định 60s |

**Response:**
```json
{
  "message":           "IP 10.0.0.1 blocked for 120s on all switches",
  "affected_switches": [1]
}
```

**Ví dụ:**
```bash
curl -X POST http://127.0.0.1:8888/block_ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.0.0.1", "duration": 120}'
```

---

## Auth Server API (chạy tại `http://10.0.0.200:8080`)

### `GET /health`
Kiểm tra Auth Server đang chạy.
```bash
curl http://10.0.0.200:8080/health
# {"status": "ok"}
```

### `GET /status`
Xem danh sách MAC đã xác thực.
```bash
curl http://10.0.0.200:8080/status
```

### `GET /whitelist`
Xem danh sách MAC được phép.
```bash
curl http://10.0.0.200:8080/whitelist
```

### `POST /authenticate`
Xác thực Host.
```bash
curl -X POST http://10.0.0.200:8080/authenticate \
  -H "Content-Type: application/json" \
  -d '{"mac": "00:00:00:00:00:50", "token": "TOKEN_NEW"}'
```

### `POST /register`
Đăng ký MAC mới vào whitelist (dùng cho demo).
```bash
curl -X POST http://10.0.0.200:8080/register \
  -H "Content-Type: application/json" \
  -d '{"mac": "00:00:00:00:00:99", "name": "TestHost", "token": "MY_TOKEN"}'
```

### `POST /revoke`
Thu hồi quyền của MAC đã xác thực.
```bash
curl -X POST http://10.0.0.200:8080/revoke \
  -H "Content-Type: application/json" \
  -d '{"mac": "00:00:00:00:00:50"}'
```

---

## Lệnh OVS để kiểm tra Flow Table

```bash
# Xem toàn bộ flow entries
sudo ovs-ofctl dump-flows s1 -O OpenFlow13

# Lọc flow DROP
sudo ovs-ofctl dump-flows s1 -O OpenFlow13 | grep "actions=drop"

# Xem flow với thống kê (packet/byte count)
sudo ovs-ofctl dump-flows s1 -O OpenFlow13 | grep -v "n_packets=0"

# Xóa thủ công một flow (IP cụ thể)
sudo ovs-ofctl del-flows s1 "ip,nw_src=10.0.0.1" -O OpenFlow13

# Xóa toàn bộ flow (reset switch)
sudo ovs-ofctl del-flows s1 -O OpenFlow13

# Xem port stats
sudo ovs-ofctl dump-ports s1 -O OpenFlow13

# Xem thông tin switch
sudo ovs-ofctl show s1 -O OpenFlow13
```

---

## Ví dụ Flow Entry điển hình

### Flow DROP (Kịch bản 1 - DDoS)
```
cookie=0x0, duration=5.2s, table=0, n_packets=200, n_bytes=16800,
hard_timeout=60, priority=10,
ip,nw_src=10.0.0.1
actions=drop
```

### Flow DROP PORT (Kịch bản 3 - Spoofing)
```
cookie=0x0, duration=3.1s, table=0, n_packets=50, n_bytes=3000,
hard_timeout=120, priority=10,
in_port=3
actions=drop
```

### Flow Quarantine (Kịch bản 4 - Port Scan)
```
cookie=0x0, duration=2.0s, table=0, n_packets=100, n_bytes=6000,
hard_timeout=300, priority=15,
ip,nw_src=10.0.0.1
actions=drop

cookie=0x0, duration=2.0s, table=0, n_packets=5, n_bytes=300,
hard_timeout=300, priority=20,
ip,nw_src=10.0.0.1,nw_dst=10.0.0.254
actions=NORMAL
```

### Flow TIME-based DROP (Kịch bản 2 - Ngoài giờ)
```
cookie=0x0, duration=10s, table=0, n_packets=30, n_bytes=1800,
hard_timeout=0, priority=10,
tcp,nw_dst=10.0.0.100,tp_dst=80
actions=drop
```

### Flow NAC RESTRICT (Kịch bản 5 - Host chưa xác thực)
```
cookie=0x0, duration=8s, table=0, n_packets=20, n_bytes=1200,
hard_timeout=0, priority=10,
in_port=7,eth_src=00:00:00:00:00:50
actions=drop

cookie=0x0, duration=8s, table=0, n_packets=3, n_bytes=180,
hard_timeout=0, priority=20,
tcp,in_port=7,eth_src=00:00:00:00:00:50,nw_dst=10.0.0.200,tp_dst=8080
actions=NORMAL
```
