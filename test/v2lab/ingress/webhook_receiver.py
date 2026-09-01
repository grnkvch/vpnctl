#!/usr/bin/env python3
import argparse
import ipaddress
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


MAX_BODY_BYTES = 16 * 1024 * 1024
READ_CHUNK_BYTES = 16 * 1024
LOAD_PATHS = {"/load/a", "/load/b"}
STREAM_PATHS = {"/stream/webhook", "/hard-limit/webhook"}


class ProbeServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128


class WebhookHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    accepted_requests = 0
    active_requests = 0
    max_active_requests = 0
    completed_requests = 0
    stream_started = 0
    stream_completed = 0
    bytes_received = 0
    state_lock = threading.Lock()

    def log_message(self, format: str, *args: object) -> None:
        return

    def send_json(self, status: int, value: dict[str, object]) -> None:
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    @classmethod
    def snapshot(cls) -> dict[str, object]:
        with cls.state_lock:
            return {
                "accepted_requests": cls.accepted_requests,
                "active_requests": cls.active_requests,
                "bytes_received": cls.bytes_received,
                "completed_requests": cls.completed_requests,
                "max_active_requests": cls.max_active_requests,
                "ok": True,
                "stream_completed": cls.stream_completed,
                "stream_started": cls.stream_started,
            }

    @classmethod
    def enter_request(cls) -> None:
        with cls.state_lock:
            cls.active_requests += 1
            cls.max_active_requests = max(cls.max_active_requests, cls.active_requests)

    @classmethod
    def leave_request(cls, received: int) -> None:
        with cls.state_lock:
            cls.active_requests -= 1
            cls.completed_requests += 1
            cls.bytes_received += received

    def do_GET(self) -> None:
        if self.path != "/__vpnctl_probe/status" or self.client_address[0] != "127.0.0.1":
            self.send_json(404, {"ok": False})
            return
        self.send_json(200, self.snapshot())

    def content_length(self) -> int | None:
        try:
            value = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return None
        if value < 0 or value > MAX_BODY_BYTES:
            return None
        return value

    def read_body(self, length: int, count_stream: bool, collect: bool) -> bytes:
        remaining = length
        received = 0
        body = bytearray()
        while remaining:
            chunk = self.rfile.read(min(READ_CHUNK_BYTES, remaining))
            if not chunk:
                break
            if received == 0 and count_stream:
                with self.state_lock:
                    type(self).stream_started += 1
            if collect:
                body.extend(chunk)
            received += len(chunk)
            remaining -= len(chunk)
        if remaining:
            raise ConnectionError("request body ended early")
        if count_stream:
            with self.state_lock:
                type(self).stream_completed += 1
        return bytes(body)

    def request_delay(self, query: str) -> float:
        values = parse_qs(query, keep_blank_values=False).get("delay_ms", ["0"])
        try:
            delay_ms = int(values[0])
        except ValueError:
            return -1
        if delay_ms < 0 or delay_ms > 10_000:
            return -1
        return delay_ms / 1000

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        allowed = {"/telegram/webhook", "/timeout"} | LOAD_PATHS | STREAM_PATHS
        if parsed.path not in allowed:
            self.send_json(404, {"ok": False})
            return
        length = self.content_length()
        if length is None:
            self.send_json(400, {"ok": False})
            return

        self.enter_request()
        received = 0
        try:
            body = self.read_body(
                length,
                count_stream=parsed.path in STREAM_PATHS,
                collect=parsed.path == "/telegram/webhook",
            )
            received = length
            delay = 2.0 if parsed.path == "/timeout" else self.request_delay(parsed.query)
            if delay < 0:
                self.send_json(400, {"ok": False})
                return
            if delay:
                time.sleep(delay)

            if parsed.path == "/telegram/webhook":
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
                with self.state_lock:
                    type(self).accepted_requests += 1
                self.send_json(
                    200,
                    {"body_valid": True, "forwarded_proto": "https", "host_is_ip": True, "ok": True},
                )
                return

            self.send_json(200, {"body_bytes": length, "ok": True, "streamed": parsed.path in STREAM_PATHS})
        except ConnectionError:
            self.send_json(400, {"ok": False})
        finally:
            self.leave_request(received)


def main() -> None:
    parser = argparse.ArgumentParser(description="credential-free vpnctl v2 ingress stress receiver")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    with ProbeServer((args.listen, args.port), WebhookHandler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
