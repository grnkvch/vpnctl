#!/usr/bin/env python3
import argparse
import ipaddress
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MAX_BODY_BYTES = 1024 * 1024


class WebhookHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    accepted_requests = 0
    accepted_requests_lock = threading.Lock()

    def log_message(self, format: str, *args: object) -> None:
        return

    def send_json(self, status: int, value: dict[str, object]) -> None:
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        if self.path != "/__vpnctl_probe/status" or self.client_address[0] != "127.0.0.1":
            self.send_json(404, {"ok": False})
            return
        with self.accepted_requests_lock:
            accepted_requests = self.accepted_requests
        self.send_json(200, {"accepted_requests": accepted_requests, "ok": True})

    def do_POST(self) -> None:
        if self.path != "/telegram/webhook":
            self.send_json(404, {"ok": False})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.send_json(400, {"ok": False})
            return
        if length < 2 or length > MAX_BODY_BYTES:
            self.send_json(413, {"ok": False})
            return
        body = self.rfile.read(length)
        try:
            update = json.loads(body)
            forwarded_for = self.headers["X-Forwarded-For"]
            real_ip = self.headers["X-Real-IP"]
            host = self.headers["Host"].split(":", 1)[0]
            ipaddress.ip_address(forwarded_for)
            ipaddress.ip_address(real_ip)
            ipaddress.ip_address(host)
            valid = (
                isinstance(update, dict)
                and isinstance(update.get("update_id"), int)
                and self.headers.get_content_type() == "application/json"
                and self.headers.get("X-Forwarded-Proto") == "https"
                and forwarded_for == real_ip
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            valid = False
        if not valid:
            self.send_json(400, {"ok": False})
            return
        with self.accepted_requests_lock:
            type(self).accepted_requests += 1
        self.send_json(
            200,
            {
                "body_valid": True,
                "forwarded_proto": "https",
                "host_is_ip": True,
                "ok": True,
            },
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="credential-free vpnctl v2 webhook ingress probe")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    with ThreadingHTTPServer((args.listen, args.port), WebhookHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
