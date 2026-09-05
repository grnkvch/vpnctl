#!/usr/bin/env python3
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import math
import socket
import ssl
import statistics
import time


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(len(ordered) * fraction) - 1)], 3)


def telegram_body(index: int, size: int) -> bytes:
    base = {"update_id": index + 1, "message": {"from": {"id": index % 300 + 1}, "text": "x"}}
    encoded = json.dumps(base, separators=(",", ":")).encode()
    if len(encoded) > size:
        raise ValueError("body size is too small for the Telegram-shaped payload")
    base["padding"] = "x" * max(0, size - len(encoded) - len(',"padding":""'))
    encoded = json.dumps(base, separators=(",", ":")).encode()
    if len(encoded) != size:
        raise ValueError(f"Telegram-shaped body is {len(encoded)} bytes, want {size}")
    return encoded


def webhook_request(args: argparse.Namespace, index: int, started: float) -> dict[str, object]:
    context = ssl.create_default_context(cafile=args.certificate)
    connection = http.client.HTTPSConnection(args.public_ip, 443, timeout=args.timeout, context=context)
    before = time.monotonic()
    try:
        body = telegram_body(index, args.body_bytes)
        connection.request(
            "POST",
            "/telegram/webhook",
            body=body,
            headers={"Content-Type": "application/json", "Connection": "close"},
        )
        response = connection.getresponse()
        payload = response.read(1024 * 1024)
        valid = False
        try:
            decoded = json.loads(payload)
            valid = decoded.get("ok") is True and decoded.get("body_valid") is True
        except (json.JSONDecodeError, AttributeError):
            pass
        return {
            "elapsed_ms": (time.monotonic() - before) * 1000,
            "offset_seconds": before - started,
            "ok": response.status == 200 and valid,
            "status": response.status,
            "error": "" if valid else "invalid_response",
        }
    except Exception as error:  # only the class is retained; requests contain no credentials
        return {
            "elapsed_ms": (time.monotonic() - before) * 1000,
            "offset_seconds": before - started,
            "ok": False,
            "status": 0,
            "error": type(error).__name__,
        }
    finally:
        connection.close()


def proxy_api_request(args: argparse.Namespace, _index: int, started: float) -> dict[str, object]:
    before = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection(("127.0.0.1", args.proxy_port), timeout=args.timeout)
        sock.settimeout(args.timeout)
        request = (
            f"GET {args.target} HTTP/1.1\r\nHost: 127.0.0.1:18080\r\n"
            "Connection: close\r\nAccept: application/json\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        chunks = []
        total = 0
        while total <= 1024 * 1024:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        response = b"".join(chunks)
        header, separator, body = response.partition(b"\r\n\r\n")
        first = header.split(b"\r\n", 1)[0].split()
        status = int(first[1]) if len(first) >= 2 and first[1].isdigit() else 0
        valid = separator != b"" and status == 200 and hashlib.sha256(body).hexdigest() == args.expected_sha256
        return {
            "elapsed_ms": (time.monotonic() - before) * 1000,
            "offset_seconds": before - started,
            "ok": valid,
            "status": status,
            "error": "" if valid else "invalid_response",
        }
    except Exception as error:
        return {
            "elapsed_ms": (time.monotonic() - before) * 1000,
            "offset_seconds": before - started,
            "ok": False,
            "status": 0,
            "error": type(error).__name__,
        }
    finally:
        if sock is not None:
            sock.close()


def run_scheduled(args: argparse.Namespace, operation) -> dict[str, object]:
    requests = args.duration * args.rate
    started = time.monotonic()
    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        for index in range(requests):
            due = started + index / args.rate
            remaining = due - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            futures.append(executor.submit(operation, args, index, started))
        results = [future.result(timeout=args.timeout + args.duration) for future in futures]
    wall = time.monotonic() - started
    successes = [result for result in results if result["ok"]]
    failures = [result for result in results if not result["ok"]]
    latencies = [float(result["elapsed_ms"]) for result in successes]
    status_counts: dict[str, int] = {}
    error_counts: dict[str, int] = {}
    for result in results:
        status = str(result["status"])
        status_counts[status] = status_counts.get(status, 0) + 1
        error = str(result["error"])
        if error:
            error_counts[error] = error_counts.get(error, 0) + 1
    outside = [
        result for result in failures
        if not args.failure_window_start <= float(result["offset_seconds"]) <= args.failure_window_end
    ]
    tail = [result for result in results if float(result["offset_seconds"]) >= args.duration - 30]
    return {
        "schema_version": 1,
        "status": "completed",
        "duration_seconds": args.duration,
        "rate_per_second": args.rate,
        "scheduled_requests": requests,
        "successful_requests": len(successes),
        "failed_requests": len(failures),
        "failures_outside_accepted_window": len(outside),
        "failure_offsets_seconds": [round(float(value["offset_seconds"]), 3) for value in failures[:200]],
        "tail_30_seconds_successful": len(tail) > 0 and all(bool(value["ok"]) for value in tail),
        "status_counts": status_counts,
        "error_counts": error_counts,
        "latency_ms": {
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "p99": percentile(latencies, 0.99),
            "max": round(max(latencies), 3) if latencies else 0.0,
        },
        "wall_seconds": round(wall, 3),
        "achieved_requests_per_second": round(requests / wall, 3),
    }


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--duration", type=int, required=True)
    parser.add_argument("--rate", type=int, required=True)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--failure-window-start", type=float, default=-1.0)
    parser.add_argument("--failure-window-end", type=float, default=-1.0)


def main() -> None:
    parser = argparse.ArgumentParser(description="vpnctl v2 sustained capacity workload")
    commands = parser.add_subparsers(dest="command", required=True)
    webhook = commands.add_parser("webhook")
    add_common(webhook)
    webhook.add_argument("--public-ip", required=True)
    webhook.add_argument("--certificate", required=True)
    webhook.add_argument("--body-bytes", type=int, required=True)
    webhook.set_defaults(operation=webhook_request)
    probe = commands.add_parser("probe")
    probe.add_argument("--public-ip", required=True)
    probe.add_argument("--certificate", required=True)
    probe.add_argument("--body-bytes", type=int, default=128)
    probe.add_argument("--timeout", type=float, default=5.0)
    api = commands.add_parser("api")
    add_common(api)
    api.add_argument("--proxy-port", type=int, default=17890)
    api.add_argument("--target", required=True)
    api.add_argument("--expected-sha256", required=True)
    api.set_defaults(operation=proxy_api_request)
    args = parser.parse_args()
    if args.command == "probe":
        print(json.dumps(webhook_request(args, 0, time.monotonic()), separators=(",", ":"), sort_keys=True))
        return
    if args.duration < 1 or args.rate < 1 or args.workers < 1:
        raise ValueError("duration, rate, and workers must be positive")
    print(json.dumps(run_scheduled(args, args.operation), separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
