#!/bin/bash
# test_scenario2.sh - Kiểm thử Kịch bản 2: Time-based Access Control
# Mô tả:
#   - Trong giờ hành chính (8:00-18:00): h3 (Guest) được truy cập webserver:80
#   - Ngoài giờ: Controller tự đẩy flow DROP chặn kết nối
#   - Demo: Thay đổi TIMEBASED_ALLOW_START/END trong config.py để giả lập
#
# Chạy trong terminal Ubuntu (không cần Mininet CLI):
#   bash test_scenario2.sh

echo "[KỊCH BẢN 2: Time-based Access Control]"
echo "Guest (h3) → Web Server (webserver:80)"
echo ""

H3_IP="10.0.0.3"
WEBSERVER_IP="10.0.0.100"
SWITCH="s1"
CURRENT_HOUR=$(date +%H)

echo "[INFO] Giờ hiện tại: $(date '+%H:%M:%S')"
echo "[INFO] Khung giờ cho phép: 08:00 - 18:00"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 1] Kiểm tra kết nối từ h3 đến webserver port 80..."
echo ""
echo "Trong Mininet CLI:"
echo "  mininet> h3 curl -s --connect-timeout 5 http://$WEBSERVER_IP:80"
echo ""

if [ "$CURRENT_HOUR" -ge 8 ] && [ "$CURRENT_HOUR" -lt 18 ]; then
    echo ">>> Đang trong giờ hành chính → ALLOW: kết nối sẽ thành công"
else
    echo ">>> Ngoài giờ hành chính → DROP: kết nối sẽ bị chặn"
fi
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 2] Xem flow table hiện tại..."
echo ""
echo "Lệnh:"
echo "  sudo ovs-ofctl dump-flows $SWITCH -O OpenFlow13"
echo ""
echo "Tìm flow liên quan đến ip_dst=$WEBSERVER_IP, tcp_dst=80"
echo ""
echo "Ví dụ khi ngoài giờ (FLOW DROP):"
echo "  cookie=0x0, duration=10s, table=0, n_packets=5, n_bytes=350,"
echo "  hard_timeout=0, priority=10,"
echo "  tcp,nw_dst=$WEBSERVER_IP,tp_dst=80 actions=drop"
echo ""
echo "Ví dụ khi trong giờ (FLOW ALLOW):"
echo "  cookie=0x0, duration=10s, table=0, n_packets=100, n_bytes=7000,"
echo "  hard_timeout=0, priority=6,"
echo "  tcp,nw_dst=$WEBSERVER_IP,tp_dst=80 actions=NORMAL"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 3] Thay đổi giờ Config để test (demo nhanh)"
echo ""
echo "Trong config.py:"
echo "  TIMEBASED_ALLOW_START = $((CURRENT_HOUR + 1))  # Đặt bắt đầu sau giờ hiện tại"
echo "  TIMEBASED_ALLOW_END   = $((CURRENT_HOUR + 2))  # Chỉ cho phép 1 tiếng"
echo ""
echo "Khởi động lại Controller, chờ 30 giây → xem flow table thay đổi"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 4] Kiểm tra REST API trạng thái Time-based ACL..."
echo ""
echo "  curl http://127.0.0.1:8888/status | python3 -m json.tool"
echo ""
echo "Xem phần 'scenario2_timebased':"
echo "  - is_business_hours: true/false"
echo "  - guest_access_allowed: true/false"
echo "  - current_time: HH:MM:SS"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 5] Theo dõi log Controller..."
echo "  tail -f /tmp/dynamic_acl.log | grep -E 'Scenario2|Time|ALLOW|DROP.*tcp'"
echo ""

echo "------------------------------------------------------------"
echo "Ghi chú: Controller kiểm tra giờ mỗi 30 giây"
echo "Thay đổi TIMEBASED_CHECK_INTERVAL trong config.py để test nhanh hơn"
echo "------------------------------------------------------------"
