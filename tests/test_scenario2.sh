#!/bin/bash
# test_scenario2.sh - Kiểm thử Kịch bản 2: Time-based Access Control
# Mô tả:
#   - Trong giờ (8:00-18:00): h3 (Guest) truy cập webserver:80 được
#   - Ngoài giờ: bị chặn (DROP)
#   - Có thể chỉnh TIMEBASED_ALLOW_START/END để test nhanh

echo "[SCENARIO 2: Time-based Access Control]"
echo "Guest (h3) → Web Server (port 80)"
echo ""

H3_IP="10.0.0.3"
WEBSERVER_IP="10.0.0.100"
SWITCH="s1"
CURRENT_HOUR=$(date +%H)

echo "[INFO] Thời gian hiện tại: $(date '+%H:%M:%S')"
echo "[INFO] Khung giờ: 08:00 - 18:00"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 1] Test kết nối h3 → webserver:80"
echo ""
echo "mininet> h3 curl -s --connect-timeout 5 http://$WEBSERVER_IP:80"
echo ""

if [ "$CURRENT_HOUR" -ge 8 ] && [ "$CURRENT_HOUR" -lt 18 ]; then
    echo ">>> Trong giờ → ALLOW (kết nối thành công)"
else
    echo ">>> Ngoài giờ → DROP (kết nối thất bại)"
fi
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 2] Xem flow table hiện tại"
echo ""
echo "sudo ovs-ofctl dump-flows $SWITCH -O OpenFlow13"
echo ""
echo "Tìm flow với ip_dst=$WEBSERVER_IP, tcp_dst=80"
echo ""
echo "Ví dụ OFF-HOURS:"
echo "  tcp,nw_dst=$WEBSERVER_IP,tp_dst=80 actions=drop"
echo ""
echo "Ví dụ BUSINESS HOURS:"
echo "  tcp,nw_dst=$WEBSERVER_IP,tp_dst=80 actions=NORMAL"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 3] Test nhanh bằng cách đổi config"
echo ""
echo "config.py:"
echo "  TIMEBASED_ALLOW_START = $((CURRENT_HOUR + 1))"
echo "  TIMEBASED_ALLOW_END   = $((CURRENT_HOUR + 2))"
echo ""
echo "Restart controller → chờ ~30s → kiểm tra lại flow"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 4] Kiểm tra REST API"
echo ""
echo "curl http://127.0.0.1:8888/status | python3 -m json.tool"
echo ""
echo "Xem:"
echo "  - is_business_hours"
echo "  - guest_access_allowed"
echo "  - current_time"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 5] Theo dõi log"
echo "tail -f /tmp/dynamic_acl.log | grep -E 'Scenario2|Time|ALLOW|DROP.*tcp'"
echo ""

echo "------------------------------------------------------------"
echo "Ghi chú:"
echo "- Controller check mỗi 30s"
echo "- Có thể giảm TIMEBASED_CHECK_INTERVAL để test nhanh"
echo "------------------------------------------------------------"