#!/bin/bash
# install.sh - Script cài đặt môi trường hoàn chỉnh cho Dynamic ACL SDN Project
# Chạy trên Ubuntu 20.04 / 22.04:
#   chmod +x install.sh
#   sudo bash install.sh

set -e  # Dừng nếu có lỗi

# Màu để in thông báo
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_step() { echo -e "\n${BLUE}[STEP]${NC} $1"; }
print_ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_err()  { echo -e "${RED}[ERROR]${NC} $1"; }

echo "  Dynamic ACL SDN - Cài đặt môi trường"
echo "  Ubuntu 20.04 / 22.04"

# BƯỚC 1: Cập nhật hệ thống
print_step "Cập nhật danh sách gói..."
apt-get update -qq
print_ok "apt-get update hoàn thành"
# BƯỚC 2: Cài đặt các gói hệ thống cần thiết
print_step "Cài đặt các gói hệ thống cơ bản..."
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-dev \
    git \
    curl \
    wget \
    net-tools \
    iputils-ping \
    iproute2 \
    tcpdump \
    wireshark-common \
    tshark \
    hping3 \
    nmap \
    iperf3 \
    openvswitch-switch \
    openvswitch-common \
    2>/dev/null
print_ok "Gói hệ thống đã cài đặt"

# BƯỚC 3: Cài đặt Mininet
print_step "Cài đặt Mininet..."
if command -v mn &> /dev/null; then
    print_warn "Mininet đã cài đặt: $(mn --version 2>&1 | head -1)"
else
    apt-get install -y -qq mininet
    print_ok "Mininet đã cài đặt: $(mn --version 2>&1 | head -1)"
fi

# BƯỚC 4: Cài đặt Python packages
print_step "Cài đặt Python packages (eventlet, ryu, requests)..."

# eventlet trước (phiên bản cụ thể để tránh lỗi tương thích)
pip3 install -q "eventlet==0.30.2"
print_ok "eventlet==0.30.2 đã cài đặt"

# Ryu Controller
pip3 install -q "ryu==4.34"
print_ok "ryu==4.34 đã cài đặt"

# Các thư viện phụ trợ
pip3 install -q requests netaddr msgpack six webob
print_ok "Thư viện phụ trợ đã cài đặt"

# BƯỚC 5: Cài đặt từ requirements.txt (nếu có)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    print_step "Cài đặt từ requirements.txt..."
    pip3 install -q -r "$SCRIPT_DIR/requirements.txt" || true
    print_ok "requirements.txt xử lý xong"
fi

# BƯỚC 6: Kiểm tra Open vSwitch
print_step "Kiểm tra và khởi động Open vSwitch..."
service openvswitch-switch start 2>/dev/null || true
ovs-vsctl show &>/dev/null && print_ok "Open vSwitch đang chạy" || \
    print_warn "Open vSwitch chưa khởi động - sẽ khởi động khi chạy Mininet"

# BƯỚC 7: Cấu hình Ryu với eventlet monkey-patching
print_step "Kiểm tra cấu hình Ryu..."
python3 -c "from ryu.base import app_manager; print('Ryu OK')" 2>/dev/null && \
    print_ok "Ryu import thành công" || \
    print_err "Ryu import thất bại - kiểm tra lại"

# BƯỚC 8: Tạo thư mục log
print_step "Tạo thư mục log..."
touch /tmp/dynamic_acl.log
chmod 666 /tmp/dynamic_acl.log
print_ok "Log file: /tmp/dynamic_acl.log"

# BƯỚC 9: Kiểm tra tổng quát
echo ""
echo "[KIỂM TRA MÔI TRƯỜNG]"

# Python
PY_VER=$(python3 --version 2>&1)
echo "  Python      : $PY_VER"

# Ryu
RYU_VER=$(python3 -c "import ryu; print(ryu.__version__)" 2>/dev/null || echo "NOT INSTALLED")
echo "  Ryu         : $RYU_VER"

# Mininet
MN_VER=$(mn --version 2>&1 | head -1 || echo "NOT INSTALLED")
echo "  Mininet     : $MN_VER"

# OVS
OVS_VER=$(ovs-vsctl --version 2>/dev/null | head -1 || echo "NOT INSTALLED")
echo "  OVS         : $OVS_VER"

# nmap
NMAP_VER=$(nmap --version 2>/dev/null | head -1 || echo "NOT INSTALLED")
echo "  nmap        : $NMAP_VER"

echo ""
echo -e "${GREEN}✓ Cài đặt hoàn thành!${NC}"
echo ""
echo "  Để chạy project:"
echo ""
echo "  Terminal 1 - Khởi động Controller:"
echo "    cd $SCRIPT_DIR/controller"
echo "    ryu-manager dynamic_acl_controller.py --verbose"
echo ""
echo "  Terminal 2 - Khởi động Mininet:"
echo "    cd $SCRIPT_DIR/topology"
echo "    sudo python3 topo_main.py"
echo ""
echo "  Kiểm tra REST API:"
echo "    curl http://127.0.0.1:8888/status | python3 -m json.tool"
echo ""
