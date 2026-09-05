#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import http.client
import json
import math
import pathlib
import socket
import ssl
import statistics
import sys
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


def webhook_request(
    args: argparse.Namespace,
    index: int,
    started: float,
    connection: http.client.HTTPSConnection | None = None,
) -> dict[str, object]:
    if connection is None:
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


def wait_for_trigger(
    trigger_file: pathlib.Path,
    timeout: float,
    clock=time.monotonic,
    sleeper=time.sleep,
) -> None:
    deadline = clock() + timeout
    while not trigger_file.exists():
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError("armed probe trigger was not created")
        sleeper(min(0.01, remaining))


def run_armed_probe(args: argparse.Namespace) -> dict[str, object]:
    trigger_file = pathlib.Path(args.trigger_file)
    ready_file = pathlib.Path(args.ready_file)
    if trigger_file.exists() or ready_file.exists():
        raise FileExistsError("armed probe synchronization file already exists")
    context = ssl.create_default_context(cafile=args.certificate)
    connection = http.client.HTTPSConnection(
        args.public_ip, 443, timeout=args.connect_timeout, context=context
    )
    try:
        connection.connect()
        if connection.sock is None:
            raise ConnectionError("armed probe TLS socket is unavailable")
        connection.timeout = args.timeout
        connection.sock.settimeout(args.timeout)
        ready_file.touch(mode=0o600, exist_ok=False)
        wait_for_trigger(trigger_file, args.trigger_timeout)
        return webhook_request(args, 0, time.monotonic(), connection)
    except Exception:
        connection.close()
        raise


def run_armed_recovery(args: argparse.Namespace) -> dict[str, object]:
    trigger_file = pathlib.Path(args.trigger_file)
    ready_file = pathlib.Path(args.ready_file)
    if trigger_file.exists() or ready_file.exists():
        raise FileExistsError("armed recovery synchronization file already exists")
    ready_file.touch(mode=0o600, exist_ok=False)
    started = read_trigger_timestamp(trigger_file, args.trigger_timeout)
    args.started_monotonic = started
    return run_recovery_probe(args)


def read_trigger_timestamp(
    trigger_file: pathlib.Path,
    timeout: float,
    clock=time.monotonic,
    sleeper=time.sleep,
) -> float:
    wait_for_trigger(trigger_file, timeout, clock, sleeper)
    started = float(trigger_file.read_text(encoding="ascii").strip())
    if not math.isfinite(started) or started <= 0:
        raise ValueError("armed recovery timestamp is invalid")
    return started


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


def run_recovery_probe(
    args: argparse.Namespace,
    operation=webhook_request,
    clock=time.monotonic,
    sleeper=time.sleep,
) -> dict[str, object]:
    started = args.started_monotonic
    deadline = started + args.recovery_limit_seconds
    stable = 0
    maximum_stable = 0
    attempts = 0
    successes = 0
    first_success = None
    last_success = None
    observed_at = started
    while clock() <= deadline:
        result = operation(args, attempts, started)
        attempts += 1
        observed_at = clock()
        successful = bool(result.get("ok")) and result.get("status") == 200 and observed_at <= deadline
        if successful:
            elapsed = observed_at - started
            if first_success is None:
                first_success = elapsed
            last_success = elapsed
            successes += 1
            stable += 1
            maximum_stable = max(maximum_stable, stable)
            if stable == args.stable_probes:
                return {
                    "status": "passed",
                    "recovery_seconds": round(elapsed, 3),
                    "first_recovery_seconds": round(first_success, 3),
                    "last_recovery_seconds": round(last_success, 3),
                    "maximum_stable_recovery_probes": maximum_stable,
                    "recovery_probe_attempts": attempts,
                    "successful_recovery_probes": successes,
                }
        else:
            stable = 0
        if observed_at >= deadline:
            break
        sleeper(min(args.probe_interval, deadline - observed_at))
    return {
        "status": "failed",
        "recovery_seconds": round(max(0.0, observed_at - started), 3),
        "first_recovery_seconds": None if first_success is None else round(first_success, 3),
        "last_recovery_seconds": None if last_success is None else round(last_success, 3),
        "maximum_stable_recovery_probes": maximum_stable,
        "recovery_probe_attempts": attempts,
        "successful_recovery_probes": successes,
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
    armed_probe = commands.add_parser("armed-probe")
    armed_probe.add_argument("--public-ip", required=True)
    armed_probe.add_argument("--certificate", required=True)
    armed_probe.add_argument("--body-bytes", type=int, default=128)
    armed_probe.add_argument("--timeout", type=float, default=2.0)
    armed_probe.add_argument("--trigger-file", required=True)
    armed_probe.add_argument("--ready-file", required=True)
    armed_probe.add_argument("--trigger-timeout", type=float, default=30.0)
    armed_probe.add_argument("--connect-timeout", type=float, default=5.0)
    recover = commands.add_parser("recover")
    recover.add_argument("--public-ip", required=True)
    recover.add_argument("--certificate", required=True)
    recover.add_argument("--body-bytes", type=int, default=128)
    recover.add_argument("--timeout", type=float, default=1.0)
    recover.add_argument("--started-monotonic", type=float, required=True)
    recover.add_argument("--recovery-limit-seconds", type=float, required=True)
    recover.add_argument("--stable-probes", type=int, default=5)
    recover.add_argument("--probe-interval", type=float, default=0.1)
    armed_recover = commands.add_parser("armed-recover")
    armed_recover.add_argument("--public-ip", required=True)
    armed_recover.add_argument("--certificate", required=True)
    armed_recover.add_argument("--body-bytes", type=int, default=128)
    armed_recover.add_argument("--timeout", type=float, default=1.0)
    armed_recover.add_argument("--recovery-limit-seconds", type=float, required=True)
    armed_recover.add_argument("--stable-probes", type=int, default=5)
    armed_recover.add_argument("--probe-interval", type=float, default=0.1)
    armed_recover.add_argument("--trigger-file", required=True)
    armed_recover.add_argument("--ready-file", required=True)
    armed_recover.add_argument("--trigger-timeout", type=float, default=30.0)
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
    if args.command == "armed-probe":
        if args.timeout <= 0 or args.trigger_timeout <= 0:
            raise ValueError("armed probe bounds are invalid")
        print(json.dumps(run_armed_probe(args), separators=(",", ":"), sort_keys=True))
        return
    if args.command == "recover":
        if args.started_monotonic <= 0 or args.recovery_limit_seconds <= 0 or args.stable_probes < 1 or args.probe_interval < 0:
            raise ValueError("recovery probe bounds are invalid")
        print(json.dumps(run_recovery_probe(args), separators=(",", ":"), sort_keys=True))
        return
    if args.command == "armed-recover":
        if args.recovery_limit_seconds <= 0 or args.stable_probes < 1 or args.probe_interval < 0 or args.trigger_timeout <= 0:
            raise ValueError("armed recovery bounds are invalid")
        print(json.dumps(run_armed_recovery(args), separators=(",", ":"), sort_keys=True))
        return
    if args.duration < 1 or args.rate < 1 or args.workers < 1:
        raise ValueError("duration, rate, and workers must be positive")
    print(json.dumps(run_scheduled(args, args.operation), separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
