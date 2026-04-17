#!/bin/bash
# test_scenario3.sh - Kiểm thử Kịch bản 3: MAC/IP Spoofing Detection
# Mô tả:
#   1. h1 giao tiếp bình thường với h2
#   2. Mô phỏng MAC Spoofing: thay đổi MAC của h3 thành MAC của h1
#   3. h3 gửi traffic → Controller phát hiện MAC di chuyển bất thường
#   4. Controller áp luật DROP port của h3

echo "[KỊCH BẢN 3: MAC/IP Spoofing Detection]"
echo ""

H1_IP="10.0.0.1"
H1_MAC="00:00:00:00:00:01"
H2_IP="10.0.0.2"
H3_IP="10.0.0.3"
H3_MAC="00:00:00:00:00:03"
SWITCH="s1"
BLOCK_DURATION=120   # Phải khớp với SPOOF_BLOCK_DURATION trong config.py

echo "------------------------------------------------------------"
echo "[BƯỚC 1] Kết nối bình thường trước khi giả mạo"
echo ""
echo "Trong Mininet CLI:"
echo "  mininet> h1 ping -c 3 $H2_IP"
echo "  mininet> h3 ping -c 3 $H2_IP"
echo ">>> Kỳ vọng: Cả hai THÀNH CÔNG"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 2] Xem MAC table trên Controller..."
echo ""
echo "  curl http://127.0.0.1:8888/mac_table | python3 -m json.tool"
echo ""
echo ">>> Kỳ vọng: h1 MAC=$H1_MAC gắn với port 1, h3 MAC=$H3_MAC gắn với port 3"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 3] Mô phỏng MAC Spoofing: h3 dùng MAC của h1"
echo ""
echo "Trong Mininet CLI (hoặc xterm của h3):"
echo "  mininet> h3 ifconfig h3-eth0 hw ether $H1_MAC"
echo "  mininet> h3 ip link set h3-eth0 address $H1_MAC"
echo "  mininet> h3 ping -c 5 $H2_IP"
echo ""
echo ">>> Gói từ MAC=$H1_MAC xuất hiện ở port 3 (port của h3)"
echo ">>> Controller thấy MAC=$H1_MAC vừa ở port 1 (h1), nay ở port 3 (h3)"
echo ">>> Trong < $SPOOF_TIME_WINDOW giây → phát hiện SPOOF"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 4] Xem log Controller..."
echo ""
echo "  tail -f /tmp/dynamic_acl.log | grep -E 'SPOOF|BLOCKING|PORT'"
echo ""
echo "Xem kết quả mong đợi:"
echo "  [Monitor] MAC SPOOFING! mac=$H1_MAC moved from dpid=.../port=1 to .../port=3 in 0.1s"
echo "  [ACLManager] DROP PORT: dpid=... in_port=3 hard_timeout=${BLOCK_DURATION}s"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 5] Xem flow table sau khi phát hiện Spoof..."
echo ""
echo "  sudo ovs-ofctl dump-flows $SWITCH -O OpenFlow13"
echo ""
echo ">>> Tìm flow DROP cho in_port=3:"
echo "  priority=10, in_port=3 actions=drop"
echo ""

echo "------------------------------------------------------------"
echo "[BƯỚC 6] Khôi phục MAC h3 về đúng..."
echo ""
echo "Trong Mininet CLI:"
echo "  mininet> h3 ip link set h3-eth0 address $H3_MAC"
echo ""
echo ">>> Sau $BLOCK_DURATION giây, flow DROP tự xóa (hard_timeout)"
echo ">>> h3 có thể giao tiếp bình thường trở lại"
echo ""

echo "------------------------------------------------------------"
echo "Ghi chú:"
echo "   SPOOF_TIME_WINDOW = 5 giây (trong config.py)"
echo "   Thay đổi xuống 10 giây nếu cần thêm thời gian test"
echo "------------------------------------------------------------"
