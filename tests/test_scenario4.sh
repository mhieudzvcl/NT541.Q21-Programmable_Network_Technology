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
echo ""
echo ">>> Kết quả mong đợi: THÀNH CÔNG (0% packet loss, HTTP 200 OK)"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 2] Mô phỏng Port Scan từ h1 vào webserver"
echo ""
echo "Lệnh (chọn 1):"
echo "  mininet> h1 bash -c 'for p in \$(seq 1 100); do timeout 0.05 bash -c \"echo > /dev/tcp/$WEBSERVER_IP/\$p\" 2>/dev/null; done'"
echo ""
echo ">>> Kết quả mong đợi trên log Controller (tail -f /tmp/dynamic_acl.log):"
echo "  [Monitor] PORT SCAN detected! ip_src=10.0.0.1 → ip_dst=10.0.0.100"
echo "  [Monitor] unique_ports=16/15 in 5.0s"
echo "  [Scenario4-PortScan] QUARANTINE: ip_src=10.0.0.1 on dpid=1 duration=300s"
echo "  [ACLManager] DROP IP: ip_src=10.0.0.1 priority=15 hard_timeout=300s on dpid=1"
echo "  [ACLManager] ALLOW IP (Quarantine): src=10.0.0.1 dst=10.0.0.254 priority=20 hard_timeout=300s"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 3] Xem flow table - kiểm tra luật Quarantine..."
echo ""
echo "Lệnh:"
echo "  sudo ovs-ofctl dump-flows $SWITCH -O OpenFlow13"
echo ""
echo ">>> Kết quả mong đợi (xuất hiện 2 dòng priority cao):"
echo "  1. Chặn toàn bộ: priority=15, ip,nw_src=10.0.0.1 actions=drop"
echo "  2. Mở cho Quarantine Server: priority=20, ip,nw_src=10.0.0.1,nw_dst=10.0.0.254 actions=NORMAL"
echo ""
echo "  (Lọc nhanh:)"
echo "  sudo ovs-ofctl dump-flows $SWITCH -O OpenFlow13 | grep 'nw_src=$H1_IP'"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 4] Xác minh h1 bị cách ly..."
echo ""
echo "Trong Mininet CLI:"
echo "  mininet> h1 ping -c 3 $WEBSERVER_IP"
echo "  >>> Kết quả mong đợi: FAIL (100% packet loss - bị DROP bởi priority 15)"
echo ""
echo "  mininet> h1 ping -c 3 $QUARANTINE_IP"
echo "  >>> Kết quả mong đợi: SUCCESS (Thành công - được ALLOW bởi priority 20)"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 5] REST API kiểm tra trạng thái Quarantine..."
echo ""
echo "  curl http://127.0.0.1:8888/status | python3 -m json.tool"
echo ""
echo ">>> Kết quả mong đợi (trong phần scenario4_portscan):"
echo "  \"quarantined_hosts\": ["
echo "    {"
echo "      \"ip\": \"10.0.0.1\","
echo "      \"expires\": \"2026-XX-XX HH:MM:SS\""
echo "    }"
echo "  ]"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 6] Chờ $QUARANTINE_DURATION giây → tự động thoát cách ly..."
echo ""
echo "  sleep $QUARANTINE_DURATION"
echo "  sudo ovs-ofctl dump-flows $SWITCH -O OpenFlow13"
echo "  >>> Kết quả mong đợi: Flow Quarantine biến mất, h1 ping lại được webserver bình thường."
echo "------------------------------------------------------------"
