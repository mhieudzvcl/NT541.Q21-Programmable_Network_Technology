#!/bin/bash
# test_scenario1.sh - Kiểm thử Kịch bản 1: DDoS / Rate Limiting
# Mô tả:
#   1. Kiểm tra kết nối bình thường giữa h1 và h2 (ping thành công)
#   2. h1 spam ICMP flood vào h2 (vượt ngưỡng 50 gói/giây)
#   3. Kiểm tra flow table trên s1 -> phải có flow DROP cho ip h1
#   4. Kiểm tra h1 không ping được h2 nữa
#   5. Chờ 60 giây -> flow DROP tự xóa -> h1 ping được h2 bình thường
#
# Chạy trong Mininet CLI:
#   sh /path/to/test_scenario1.sh
# Hoặc chạy từng lệnh trong Mininet CLI trực tiếp.


echo "[KỊCH BẢN 1: DDoS / Rate Limiting / ICMP Flood Detection]"
echo ""

# Biến cấu hình
H1_IP="10.0.0.1"
H2_IP="10.0.0.2"
SWITCH="s1"
BLOCK_DURATION=60    # Phải khớp với DDOS_BLOCK_DURATION trong config.py
ICMP_THRESHOLD=50    # Phải khớp với DDOS_ICMP_THRESHOLD trong config.py

echo "[BƯỚC 1] Kiểm tra kết nối bình thường giữa h1 và h2..."
echo "Lệnh: h1 ping -c 3 $H2_IP"
echo ">>> Kỳ vọng: THÀNH CÔNG (3 packets transmitted, 0% packet loss)"
echo ""
echo "Chạy trong Mininet CLI:"
echo "  mininet> h1 ping -c 3 $H2_IP"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 2] Xem flow table TRƯỚC KHI tấn công..."
echo "Lệnh: ovs-ofctl dump-flows $SWITCH -O OpenFlow13"
echo ""
sudo ovs-ofctl dump-flows $SWITCH -O OpenFlow13 2>/dev/null | grep -v "^OFPST" || \
    echo "(Chạy lệnh này trong terminal Ubuntu sau khi khởi động Mininet)"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 3] Mô phỏng ICMP Flood từ h1 vào h2..."
echo "Lệnh: h1 ping -f -c 200 $H2_IP  (flood 200 gói)"
echo ""
echo "Trong Mininet CLI:"
echo "  mininet> h1 ping -f -c 200 $H2_IP"
echo ""
echo ">>> Kỳ vọng: Controller nhận Packet-In, đếm vượt $ICMP_THRESHOLD gói/s"
echo ">>> Controller tự động đẩy flow DROP cho ip_src=$H1_IP xuống $SWITCH"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 4] Xem flow table SAU KHI tấn công..."
echo ">>> Tìm flow DROP với nw_src=$H1_IP và action=drop"
echo ""
echo "Chạy:"
echo "  sudo ovs-ofctl dump-flows $SWITCH -O OpenFlow13"
echo ""
echo "Kết quả mong đợi (ví dụ):"
echo "  cookie=0x0, duration=2.3s, table=0, n_packets=200, n_bytes=19600,"
echo "  hard_timeout=${BLOCK_DURATION}, priority=10,"
echo "  ip,nw_src=$H1_IP actions=drop"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 5] Xác minh h1 không còn ping được h2..."
echo "Lệnh: h1 ping -c 5 $H2_IP"
echo ">>> Kỳ vọng: THẤT BẠI (100% packet loss)"
echo ""
echo "Trong Mininet CLI:"
echo "  mininet> h1 ping -c 5 $H2_IP"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 6] Theo dõi log Controller..."
echo "  tail -f /tmp/dynamic_acl.log | grep -E 'DDOS|FLOOD|DROP|BLOCK'"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 7] Chờ $BLOCK_DURATION giây -> Flow DROP tự hết hạn (hard_timeout)..."
echo "  sleep $BLOCK_DURATION"
echo ""
echo "Sau $BLOCK_DURATION giây:"
echo "  sudo ovs-ofctl dump-flows $SWITCH -O OpenFlow13"
echo ">>> Flow DROP sẽ biến mất"
echo ""
echo "  mininet> h1 ping -c 3 $H2_IP"
echo ">>> Kỳ vọng: h1 ping được h2 bình thường trở lại"
echo ""

echo "------------------------------------------------------------"
echo "Kiểm tra REST API Controller:"
echo "  curl http://127.0.0.1:8888/status | python3 -m json.tool"
echo "------------------------------------------------------------"