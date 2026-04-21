#!/bin/bash
# test_scenario4.sh - Kiểm thử Kịch bản 4: Port Scan Detection & Quarantine
# Mô tả:
#   1. h1 thực hiện quét port nhiều cổng trên webserver
#   2. Controller phát hiện > 15 cổng khác nhau trong 5 giây
#   3. Controller cách ly h1 vào Quarantine Zone (DROP + redirect)
#   4. h1 không thể truy cập các host khác, chỉ đến quarantine server

echo "[KỊCH BẢN 4: Port Scan Detection & Quarantine]"
echo ""

H1_IP="10.0.0.1"
WEBSERVER_IP="10.0.0.100"
QUARANTINE_IP="10.0.0.254"
SWITCH="s1"
PORTSCAN_THRESHOLD=15
PORTSCAN_WINDOW=5
QUARANTINE_DURATION=300  # 5 phút

echo "[INFO] Ngưỡng phát hiện: $PORTSCAN_THRESHOLD cổng khác nhau trong ${PORTSCAN_WINDOW}s"
echo "[INFO] Thời gian cách ly: ${QUARANTINE_DURATION}s"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 1] Kết nối bình thường trước khi quét port"
echo ""
echo "Trong Mininet CLI:"
echo "  mininet> h1 ping -c 2 $WEBSERVER_IP"
echo "  mininet> h1 curl -s http://$WEBSERVER_IP"
echo ">>> Kỳ vọng: Thành công"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 2] Mô phỏng Port Scan từ h1 vào webserver"
echo ""
echo "Phương án A - Dùng nmap:"
echo "  mininet> h1 nmap -sS -p 1-100 $WEBSERVER_IP  (nếu đã cài nmap)"
echo ""
echo "Phương án B - Dùng bash loop (không cần nmap):"
echo "  mininet> h1 bash -c 'for p in \$(seq 1 100); do"
echo "    timeout 0.1 bash -c \"echo > /dev/tcp/$WEBSERVER_IP/\$p\" 2>/dev/null"
echo "    done'"
echo ""
echo "Phương án C - Dùng hping3:"
echo "  mininet> h1 hping3 -S $WEBSERVER_IP -p ++1 --fast -c 200 2>/dev/null"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 3] Xem log Controller..."
echo ""
echo "  tail -f /tmp/dynamic_acl.log | grep -E 'PORT.SCAN|QUARANTINE|Scenario4'"
echo ""
echo "Kết quả mong đợi:"
echo "  [Monitor] PORT SCAN detected! ip_src=$H1_IP -> ip_dst=$WEBSERVER_IP"
echo "            unique_ports=$PORTSCAN_THRESHOLD/${PORTSCAN_THRESHOLD} in ${PORTSCAN_WINDOW}s"
echo "  [Scenario4-PortScan] QUARANTINE: ip_src=$H1_IP on dpid=... duration=${QUARANTINE_DURATION}s"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 4] Xem flow table - kiểm tra luật Quarantine..."
echo ""
echo "  sudo ovs-ofctl dump-flows $SWITCH -O OpenFlow13"
echo ""
echo "Tìm 2 flow entries:"
echo "  1. DROP với priority=15 cho ip_src=$H1_IP (hard_timeout=$QUARANTINE_DURATION)"
echo "  2. ALLOW với priority=20 cho ip_src=$H1_IP, ip_dst=$QUARANTINE_IP"
echo ""
echo "Ví dụ:"
echo "  priority=15, ip,nw_src=$H1_IP actions=drop"
echo "  priority=20, ip,nw_src=$H1_IP,nw_dst=$QUARANTINE_IP actions=NORMAL"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 5] Xác minh h1 bị cách ly..."
echo ""
echo "Trong Mininet CLI:"
echo "  mininet> h1 ping -c 3 $WEBSERVER_IP"
echo "  >>> FAIL: 100% packet loss (bị DROP)"
echo ""
echo "  mininet> h1 ping -c 3 $QUARANTINE_IP"
echo "  >>> OK: h1 chỉ reach được Quarantine Server"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 6] REST API kiểm tra trạng thái Quarantine..."
echo ""
echo "  curl http://127.0.0.1:8888/status | python3 -m json.tool | grep -A 10 scenario4"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 7] Chờ $QUARANTINE_DURATION giây -> tự động thoát cách ly..."
echo ""
echo "  sleep $QUARANTINE_DURATION"
echo "  sudo ovs-ofctl dump-flows $SWITCH -O OpenFlow13"
echo "  >>> Flow Quarantine biến mất (hard_timeout hết hạn)"
echo ""
echo "  mininet> h1 ping -c 3 $WEBSERVER_IP"
echo "  >>> Thành công trở lại"
echo ""

echo "------------------------------------------------------------"
echo "Ghi chú: Để test nhanh, giảm QUARANTINE_DURATION = 30 trong config.py"
echo "------------------------------------------------------------"
