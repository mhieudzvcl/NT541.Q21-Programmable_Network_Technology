#!/usr/bin/env python3
"""
auth_server.py - Giả lập Authentication Server cho Kịch bản 5 (NAC)

Server HTTP đơn giản chạy trên host 'authserver' trong Mininet.
Cung cấp REST API để:
  - Xác thực Host dựa trên MAC address và token
  - Danh sách MAC được phép (whitelist) hardcoded

API:
  POST /authenticate  - Xác thực MAC { "mac": "xx:xx:xx:xx:xx:xx", "token": "..." }
  GET  /status        - Xem danh sách MAC đã xác thực
  POST /revoke        - Thu hồi quyền { "mac": "xx:xx:xx:xx:xx:xx" }

Chạy:
  python3 auth_server.py
  python3 auth_server.py --port 8080
"""

import json
import argparse
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AuthServer] %(levelname)s: %(message)s"
)
logger = logging.getLogger("AuthServer")

# Cấu hình whitelist MAC được phép xác thực
# Trong thực tế, danh sách này lưu trong database
MAC_WHITELIST = {
    "00:00:00:00:00:01": {"name": "Host-1",   "token": "TOKEN_H1"},
    "00:00:00:00:00:02": {"name": "Host-2",   "token": "TOKEN_H2"},
    "00:00:00:00:00:03": {"name": "Guest-H3", "token": "TOKEN_H3"},
    "00:00:00:00:00:50": {"name": "NewHost",  "token": "TOKEN_NEW"},
}

# Danh sách MAC đã xác thực thành công
authenticated_macs = set()


# HTTP Request Handler
class AuthHandler(BaseHTTPRequestHandler):

    def log_message(self, format_str, *args):
        """Override để dùng logger thay vì stderr."""
        logger.info(f"{self.address_string()} - {format_str % args}")

    def _read_body(self):
        """Đọc JSON body từ request."""
        length = int(self.headers.get("Content-Length", 0))
        if length:
            return json.loads(self.rfile.read(length).decode())
        return {}

    def _send_json(self, data, status=200):
        """Gửi JSON response."""
        body = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # GET
    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/status":
            self._send_json({
                "service": "NAC Authentication Server",
                "authenticated_count": len(authenticated_macs),
                "authenticated_macs": list(authenticated_macs),
                "whitelist_count": len(MAC_WHITELIST),
            })

        elif path == "/whitelist":
            self._send_json({
                "whitelist": {
                    mac: info["name"]
                    for mac, info in MAC_WHITELIST.items()
                }
            })

        elif path == "/health":
            self._send_json({"status": "ok"})

        else:
            self._send_json({"error": "Not found"}, status=404)

    # POST
    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()

        # POST /authenticate - Xác thực Host
        if path == "/authenticate":
            mac   = body.get("mac", "").lower().strip()
            token = body.get("token", "").strip()

            if not mac:
                self._send_json({"error": "Missing 'mac' field"}, status=400)
                return

            # Kiểm tra MAC có trong whitelist không
            if mac not in MAC_WHITELIST:
                logger.warning(f"REJECT: mac={mac} not in whitelist")
                self._send_json({
                    "authenticated": False,
                    "mac": mac,
                    "message": "MAC address not registered. Contact network admin."
                }, status=403)
                return

            # Kiểm tra token (nếu có)
            expected_token = MAC_WHITELIST[mac].get("token", "")
            if token and expected_token and token != expected_token:
                logger.warning(f"REJECT: mac={mac} wrong token")
                self._send_json({
                    "authenticated": False,
                    "mac": mac,
                    "message": "Invalid authentication token."
                }, status=401)
                return

            # Xác thực thành công
            authenticated_macs.add(mac)
            name = MAC_WHITELIST[mac]["name"]
            logger.info(f"AUTHENTICATED: mac={mac} name={name}")

            # Thông báo cho Controller (Controller sẽ cấp quyền đầy đủ)
            self._notify_controller(mac)

            self._send_json({
                "authenticated": True,
                "mac": mac,
                "name": name,
                "message": f"Welcome, {name}! Full network access granted."
            })

        # POST /revoke - Thu hồi quyền
        elif path == "/revoke":
            mac = body.get("mac", "").lower().strip()
            if not mac:
                self._send_json({"error": "Missing 'mac' field"}, status=400)
                return

            if mac in authenticated_macs:
                authenticated_macs.discard(mac)
                logger.info(f"REVOKED: mac={mac}")
                self._send_json({
                    "revoked": True,
                    "mac": mac,
                    "message": "Access revoked successfully."
                })
            else:
                self._send_json({
                    "revoked": False,
                    "mac": mac,
                    "message": "MAC was not authenticated."
                }, status=404)

        # POST /register - Đăng ký MAC mới (dùng cho demo)
        elif path == "/register":
            mac   = body.get("mac", "").lower().strip()
            name  = body.get("name", "Unknown")
            token = body.get("token", "")
            if not mac:
                self._send_json({"error": "Missing 'mac' field"}, status=400)
                return
            MAC_WHITELIST[mac] = {"name": name, "token": token}
            logger.info(f"REGISTERED: mac={mac} name={name}")
            self._send_json({
                "registered": True,
                "mac": mac,
                "message": f"MAC {mac} registered as '{name}'."
            })

        else:
            self._send_json({"error": "Not found"}, status=404)

    def _notify_controller(self, mac):
        """
        Gửi thông báo đến Ryu Controller để cấp quyền đầy đủ cho Host.
        Controller REST API: POST http://<controller_ip>:8888/authenticate
        Lưu ý: Từ Mininet namespace, 127.0.0.1 là loopback của chính host đó,
        không phải Ubuntu. Cần dùng IP thật của Ubuntu.
        """
        import urllib.request
        import subprocess

        # Thử tìm IP Ubuntu qua default gateway
        controller_ips = []
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=2
            )
            # Output: "default via 10.0.0.1 dev h1-eth0"
            for part in result.stdout.split():
                if part.count('.') == 3 and part != '0.0.0.0':
                    controller_ips.append(part)
                    break
        except Exception:
            pass

        # Fallback: thử các IP phổ biến
        controller_ips += ['127.0.0.1', '10.0.0.1']

        data = json.dumps({"mac": mac}).encode()
        for ctrl_ip in controller_ips:
            try:
                controller_url = f"http://{ctrl_ip}:8888/authenticate"
                req = urllib.request.Request(
                    controller_url,
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    result = json.loads(resp.read())
                    logger.info(f"Controller notified for mac={mac} via {ctrl_ip}: {result}")
                    return  # Thành công, dừng
            except Exception as e:
                logger.debug(f"Cannot reach controller at {ctrl_ip}: {e}")
                continue

        logger.warning(f"Cannot notify controller for mac={mac} at any IP tried: {controller_ips}")
        logger.info("Hình thức thay thế: gọi trực tiếp: curl -X POST http://localhost:8888/authenticate -d '{{\"mac\": \"{mac}\"}}' (từ Ubuntu)")


# Main
def main():
    parser = argparse.ArgumentParser(description="NAC Authentication Server")
    parser.add_argument("--host", default="0.0.0.0", help="Listen host")
    parser.add_argument("--port", type=int, default=8080, help="Listen port")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), AuthHandler)
    logger.info(f"Authentication Server started at http://{args.host}:{args.port}")
    logger.info(f"Registered MACs: {len(MAC_WHITELIST)}")
    logger.info("Press Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped")
        server.server_close()


if __name__ == "__main__":
    main()
