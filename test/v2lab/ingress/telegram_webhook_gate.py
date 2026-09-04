#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import http.client
import ipaddress
import json
import os
import re
import secrets
import stat
import sys
import time


TELEGRAM_API_HOST = "api.telegram.org"
TOKEN_PATTERN = re.compile(r"^[0-9]{5,20}:[A-Za-z0-9_-]{20,}$")
MAX_RESPONSE_BYTES = 1024 * 1024


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


def receiver_count() -> int:
    connection = http.client.HTTPConnection("127.0.0.1", 18081, timeout=2)
    try:
        connection.request("GET", "/__vpnctl_probe/status", headers={"Connection": "close"})
        response = connection.getresponse()
        payload = response.read(4096)
    except (OSError, http.client.HTTPException) as error:
        raise RuntimeError("local webhook receiver status is unavailable") from error
    finally:
        connection.close()
    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RuntimeError("local webhook receiver status is invalid") from error
    if response.status != 200 or decoded.get("ok") is not True or not isinstance(decoded.get("accepted_requests"), int):
        raise RuntimeError("local webhook receiver status is invalid")
    return decoded["accepted_requests"]


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


def run_gate(public_ip_text: str, certificate_path: str, timeout: int) -> dict[str, object]:
    public_ip = ipaddress.IPv4Address(public_ip_text)
    if not public_ip.is_global:
        raise RuntimeError("Telegram gate requires a global manually supplied IPv4 address")
    token = read_hidden_token()
    if not TOKEN_PATTERN.fullmatch(token):
        raise RuntimeError("Telegram bot token format is invalid")
    certificate = read_public_certificate(certificate_path)
    existing = bot_api(token, "getWebhookInfo")
    if not isinstance(existing, dict) or existing.get("url"):
        raise RuntimeError("refusing to replace an existing Telegram webhook")

    url = f"https://{public_ip}/telegram/webhook"
    baseline = receiver_count()
    registered = False
    custom_certificate = False
    request_received = False
    cleanup_succeeded = False
    try:
        if bot_api(token, "setWebhook", {"url": url}, certificate) is not True:
            raise RuntimeError("Telegram setWebhook did not return true")
        registered = True
        info = bot_api(token, "getWebhookInfo")
        if not isinstance(info, dict) or info.get("url") != url or info.get("has_custom_certificate") is not True:
            raise RuntimeError("Telegram webhook state does not match the requested IP/certificate")
        custom_certificate = True
        print("Webhook registered; send one update to the bot while this gate is waiting.", file=sys.stderr)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if receiver_count() > baseline:
                request_received = True
                break
            time.sleep(1)
        if not request_received:
            raise RuntimeError("no real Telegram webhook request arrived before the deadline")
    finally:
        if registered:
            try:
                cleanup_succeeded = cleanup_created_webhook(token, url)
            except RuntimeError:
                cleanup_succeeded = False
        token = ""
    if not cleanup_succeeded:
        raise RuntimeError("Telegram webhook cleanup failed; run deleteWebhook manually")
    return {
        "schema_version": 1,
        "status": "passed",
        "registered": registered,
        "custom_certificate": custom_certificate,
        "real_request_received": request_received,
        "cleanup_succeeded": cleanup_succeeded,
        "sensitive_values_emitted": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="test-only real Telegram webhook gate; token is read from a hidden TTY")
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--certificate", default="/etc/vpnctl-v2-spike/ingress/gateway.crt")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    if args.timeout < 10 or args.timeout > 600:
        parser.error("timeout must be between 10 and 600 seconds")
    try:
        result = run_gate(args.public_ip, args.certificate, args.timeout)
    except (OSError, RuntimeError, ValueError):
        print("Telegram webhook gate failed without emitting credentials or webhook path.", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
