#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import secrets
import stat
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


TELEGRAM_API_HOST = "api.telegram.org"
TOKEN_PATTERN = re.compile(r"^[0-9]{5,20}:[A-Za-z0-9_-]{20,}$")
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_WEBHOOK_BODY_BYTES = 1024 * 1024


def valid_webhook_update(content_type: str, supplied_secret: str, expected_secret: str, body: bytes) -> bool:
    if content_type != "application/json" or not hmac.compare_digest(supplied_secret, expected_secret):
        return False
    try:
        update = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(update, dict) and isinstance(update.get("update_id"), int)


class WebhookReceiverServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


class LocalWebhookReceiver:
    def __init__(self, port: int, provider_secret: str) -> None:
        if port != 0 and (port < 1024 or port > 65535):
            raise RuntimeError("receiver port must be between 1024 and 65535")
        self._accepted_requests = 0
        self._lock = threading.Lock()
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: object) -> None:
                return

            def send_empty(self, status: int) -> None:
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()

            def do_POST(self) -> None:
                if self.path != "/telegram/webhook":
                    self.send_empty(404)
                    return
                try:
                    length = int(self.headers.get("Content-Length", ""))
                except ValueError:
                    length = -1
                supplied_secret = self.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
                if (
                    length < 1
                    or length > MAX_WEBHOOK_BODY_BYTES
                    or self.headers.get_content_type() != "application/json"
                    or not hmac.compare_digest(supplied_secret, provider_secret)
                ):
                    self.send_empty(400)
                    return
                body = self.rfile.read(length)
                if len(body) != length:
                    self.send_empty(400)
                    return
                if not valid_webhook_update(
                    self.headers.get_content_type(), supplied_secret, provider_secret, body
                ):
                    self.send_empty(400)
                    return
                with receiver._lock:
                    receiver._accepted_requests += 1
                self.send_empty(200)

        try:
            self._server = WebhookReceiverServer(("127.0.0.1", port), Handler)
        except OSError as error:
            raise RuntimeError("local webhook receiver port is unavailable") from error
        self._thread = threading.Thread(target=self._server.serve_forever, name="vpnctl-telegram-gate", daemon=True)

    def __enter__(self) -> "LocalWebhookReceiver":
        self._thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)

    def count(self) -> int:
        with self._lock:
            return self._accepted_requests


def multipart_body(fields: dict[str, str], certificate: bytes | None) -> tuple[bytes, str]:
    boundary = f"vpnctl-v2-{secrets.token_hex(16)}"
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                value.encode(),
                b"\r\n",
            ]
        )
    if certificate is not None:
        chunks.extend(
            [
                f"--{boundary}\r\n".encode(),
                b'Content-Disposition: form-data; name="certificate"; filename="gateway.crt"\r\n',
                b"Content-Type: application/x-pem-file\r\n\r\n",
                certificate,
                b"\r\n",
            ]
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), boundary


def bot_api(token: str, method: str, fields: dict[str, str] | None = None, certificate: bytes | None = None) -> object:
    body, boundary = multipart_body(fields or {}, certificate)
    connection = http.client.HTTPSConnection(TELEGRAM_API_HOST, 443, timeout=15)
    try:
        connection.request(
            "POST",
            f"/bot{token}/{method}",
            body=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": str(len(body)),
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        payload = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, http.client.HTTPException) as error:
        raise RuntimeError("Telegram Bot API request failed") from error
    finally:
        connection.close()
    if response.status != 200 or len(payload) > MAX_RESPONSE_BYTES:
        raise RuntimeError("Telegram Bot API returned a bounded failure")
    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RuntimeError("Telegram Bot API returned invalid JSON") from error
    if not isinstance(decoded, dict) or decoded.get("ok") is not True:
        raise RuntimeError("Telegram Bot API rejected the request")
    return decoded.get("result")


def read_public_certificate(path: str) -> bytes:
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise RuntimeError("certificate path must be clean and absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1 or metadata.st_size > 64 * 1024:
            raise RuntimeError("certificate file is not a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as certificate_file:
            certificate = certificate_file.read(64 * 1024 + 1)
    finally:
        os.close(descriptor)
    stripped = certificate.strip()
    if (
        len(certificate) > 64 * 1024
        or stripped.count(b"-----BEGIN CERTIFICATE-----") != 1
        or stripped.count(b"-----END CERTIFICATE-----") != 1
        or not stripped.startswith(b"-----BEGIN CERTIFICATE-----")
        or not stripped.endswith(b"-----END CERTIFICATE-----")
        or b"PRIVATE KEY" in certificate
    ):
        raise RuntimeError("certificate file is not a bounded public PEM certificate")
    return certificate


def read_hidden_token() -> str:
    # getpass may fall back to visible stdin when /dev/tty is unavailable. Open
    # the controlling terminal explicitly so a non-interactive invocation
    # fails before a credential is accepted.
    with open("/dev/tty", "r+", encoding="utf-8", buffering=1) as terminal:
        return getpass.getpass("Telegram bot token: ", stream=terminal)


def cleanup_created_webhook(token: str, expected_url: str) -> bool:
    current = bot_api(token, "getWebhookInfo")
    if not isinstance(current, dict) or current.get("url") != expected_url:
        return False
    return bot_api(token, "deleteWebhook") is True


def run_gate(public_ip_text: str, certificate_path: str, timeout: int, receiver_port: int = 18081) -> dict[str, object]:
    public_ip = ipaddress.IPv4Address(public_ip_text)
    if not public_ip.is_global:
        raise RuntimeError("Telegram gate requires a global manually supplied IPv4 address")
    if receiver_port < 1024 or receiver_port > 65535:
        raise RuntimeError("receiver port must be between 1024 and 65535")
    token = read_hidden_token()
    if not TOKEN_PATTERN.fullmatch(token):
        raise RuntimeError("Telegram bot token format is invalid")
    certificate = read_public_certificate(certificate_path)
    existing = bot_api(token, "getWebhookInfo")
    if not isinstance(existing, dict) or existing.get("url"):
        raise RuntimeError("refusing to replace an existing Telegram webhook")

    url = f"https://{public_ip}/telegram/webhook"
    provider_secret = secrets.token_urlsafe(32)
    registered = False
    custom_certificate = False
    request_received = False
    cleanup_succeeded = False
    try:
        with LocalWebhookReceiver(receiver_port, provider_secret) as receiver:
            if bot_api(token, "setWebhook", {"url": url, "secret_token": provider_secret}, certificate) is not True:
                raise RuntimeError("Telegram setWebhook did not return true")
            registered = True
            info = bot_api(token, "getWebhookInfo")
            if not isinstance(info, dict) or info.get("url") != url or info.get("has_custom_certificate") is not True:
                raise RuntimeError("Telegram webhook state does not match the requested IP/certificate")
            custom_certificate = True
            print("Webhook registered; send one update to the bot while this gate is waiting.", file=sys.stderr)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if receiver.count() > 0:
                    request_received = True
                    break
                time.sleep(1)
            if not request_received:
                raise RuntimeError("no authenticated real Telegram webhook request arrived before the deadline")
    finally:
        if registered:
            try:
                cleanup_succeeded = cleanup_created_webhook(token, url)
            except RuntimeError:
                cleanup_succeeded = False
        token = ""
        provider_secret = ""
    if not cleanup_succeeded:
        raise RuntimeError("Telegram webhook cleanup failed; run deleteWebhook manually")
    return {
        "schema_version": 1,
        "status": "passed",
        "registered": registered,
        "custom_certificate": custom_certificate,
        "real_request_received": request_received,
        "provider_authenticated_request": request_received,
        "cleanup_succeeded": cleanup_succeeded,
        "public_certificate_sha256": hashlib.sha256(certificate).hexdigest(),
        "sensitive_values_emitted": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="test-only real Telegram webhook gate; token is read from a hidden TTY")
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--receiver-port", type=int, default=18081)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if args.timeout < 10 or args.timeout > 600:
        parser.error("timeout must be between 10 and 600 seconds")
    try:
        result = run_gate(args.public_ip, args.certificate, args.timeout, args.receiver_port)
    except (OSError, RuntimeError, ValueError):
        print("Telegram webhook gate failed without emitting credentials or webhook path.", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
