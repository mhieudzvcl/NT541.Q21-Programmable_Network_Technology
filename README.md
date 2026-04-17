# Dynamic Access Control trong SDN
## Môn học: Công nghệ mạng khả lập trình - NT541.Q21

---

## Mô tả đề tài

Đề tài xây dựng ứng dụng mạng chạy trên **Ryu SDN Controller** nhằm thực hiện **kiểm soát truy cập động (Dynamic Access Control)** - tự động thay đổi các luật điều khiển lưu lượng (Flow Rules) theo điều kiện thời gian thực mà không cần can thiệp thủ công.

---

## Cấu trúc thư mục

```
Project/
├── controller/
│   ├── dynamic_acl_controller.py   # Controller chính (Ryu App)
│   ├── acl_manager.py              # Quản lý luật ACL
│   ├── monitor.py                  # Giám sát lưu lượng
│   ├── scenarios/
│   │   ├── scenario1_ddos.py       # Kịch bản 1: Rate Limiting / DDoS
│   │   ├── scenario2_timebased.py  # Kịch bản 2: Time-based ACL
│   │   ├── scenario3_spoofing.py   # Kịch bản 3: MAC/IP Spoofing
│   │   ├── scenario4_portscan.py   # Kịch bản 4: Port Scan Detection
│   │   └── scenario5_nac.py        # Kịch bản 5: NAC / Captive Portal
│   └── config.py                   # Cấu hình toàn cục
├── topology/
│   ├── topo_main.py                # Topology chính cho Mininet
│   ├── topo_scenario5.py           # Topology cho Kịch bản 5 (NAC)
│   └── auth_server.py              # Giả lập Authentication Server
├── tests/
│   ├── test_scenario1.sh           # Script kiểm thử Kịch bản 1
│   ├── test_scenario2.sh           # Script kiểm thử Kịch bản 2
│   ├── test_scenario3.sh           # Script kiểm thử Kịch bản 3
│   ├── test_scenario4.sh           # Script kiểm thử Kịch bản 4
│   └── test_scenario5.sh           # Script kiểm thử Kịch bản 5
├── REST_API.md                     # Tài liệu REST API của Controller
└── README.md                       # File này
```

---

## Yêu cầu môi trường

| Thành phần       | Phiên bản khuyến nghị |
|------------------|-----------------------|
| Ubuntu           | 20.04 LTS hoặc 22.04  |
| Python           | 3.8+                  |
| Ryu Controller   | 4.34+                 |
| Mininet          | 2.3.0+                |
| Open vSwitch     | 2.13+                 |
| Wireshark        | (tùy chọn, để phân tích gói tin) |

---

## Hướng dẫn cài đặt

### 1. Cài đặt Mininet
```bash
sudo apt-get update
sudo apt-get install -y mininet
```

### 2. Cài đặt Ryu Controller
```bash
sudo apt-get install -y python3-pip
pip3 install ryu eventlet==0.30.2
```

> **Lưu ý:** eventlet 0.30.2 được khuyến nghị để tránh lỗi tương thích với Python 3.8+

### 3. Clone / Copy project vào máy Ubuntu
```bash
# Ví dụ copy bằng scp từ Windows sang Ubuntu VM:
scp -r ./Project user@<ubuntu-ip>:~/sdn-project
```

---

## Cách chạy

### Bước 1: Khởi động Ryu Controller
Mở terminal thứ nhất:
```bash
cd ~/sdn-project/controller
ryu-manager dynamic_acl_controller.py --verbose
```

### Bước 2: Khởi động Mininet Topology
Mở terminal thứ hai:
```bash
cd ~/sdn-project/topology
sudo python3 topo_main.py
```

### Bước 3: Kiểm tra kết nối ban đầu
Trong Mininet CLI:
```
mininet> pingall
```

### Bước 4: Chạy các kịch bản kiểm thử
Xem thư mục `tests/` để biết cách kích hoạt từng kịch bản.

---

## Các kịch bản (Scenarios)

| # | Tên kịch bản | Mô tả ngắn |
|---|-------------|------------|
| 1 | Rate Limiting / DDoS Mitigation | Phát hiện ICMP/SYN flood -> DROP IP nguồn 60 giây |
| 2 | Time-based Access Control | Cho phép Guest truy cập Web Server chỉ trong giờ hành chính |
| 3 | MAC/IP Spoofing Detection | Phát hiện MAC di chuyển bất thường -> chặn port |
| 4 | Port Scan Detection | Phát hiện quét port -> cách ly Host vào Quarantine |
| 5 | NAC / Captive Portal | Host mới chỉ được duyệt web sau khi xác thực thành công |

---

## Lệnh kiểm tra Flow Table

```bash
# Xem toàn bộ flow entries trên switch s1
sudo ovs-ofctl dump-flows s1

# Xem flow entries với output đẹp hơn
sudo ovs-ofctl dump-flows s1 -O OpenFlow13

# Xem số lượng packets/bytes mỗi flow
sudo ovs-ofctl dump-flows s1 | grep -v "cookie=0x0"
```

---

## Nhóm thực hiện
- Nhóm: 5 
- Đề tài: Dynamic Access Control trong SDN  
- Môn học: Công nghệ mạng khả lập trình - NT541.Q21  
- Học kỳ 2, 2025-2026
### Sinh viên thực hiện
| Họ và tên        | MSSV                  |
|------------------|-----------------------|
| Huỳnh Minh Hiếu  | 23520477              |
| Đỗ Trần Tuấn Kiệt| 23520811              |
| Phùng Gia Kiệt   | 23520818              |
| Nguyễn Phát Đạt  | 23520258              |
| Lê Xuân Hoàng    | 23520524              |
| Đặng Minh Dzũ    | 23520404              |
