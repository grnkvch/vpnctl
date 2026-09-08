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
import threading
import time


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(len(ordered) * fraction) - 1)], 3)


def numeric_summary(values: list[float]) -> dict[str, float]:
    return {
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": round(max(values), 3) if values else 0.0,
    }


def latency_summary(results: list[dict[str, object]]) -> dict[str, float]:
    return numeric_summary([float(result["elapsed_ms"]) for result in results])


def phase_summary(results: list[dict[str, object]]) -> dict[str, object]:
    successes = [result for result in results if bool(result["ok"])]
    failures = [result for result in results if not bool(result["ok"])]
    return {
        "requests": len(results),
        "successful_requests": len(successes),
        "failed_requests": len(failures),
        "latency_ms": latency_summary(successes),
        "end_to_end_ms": numeric_summary(
            [float(result["end_to_end_ms"]) for result in successes]
        ),
        "dispatch_lag_ms": numeric_summary(
            [float(result["dispatch_lag_ms"]) for result in results]
        ),
    }


class WorkerTracker:
    def __init__(self, workers: int):
        self.workers = workers
        self.active = 0
        self.maximum_active = 0
        self.lock = threading.Lock()

    def enter(self) -> int:
        with self.lock:
            self.active += 1
            self.maximum_active = max(self.maximum_active, self.active)
            return self.active

    def leave(self) -> None:
        with self.lock:
            self.active -= 1


def tracked_operation(
    operation,
    args: argparse.Namespace,
    index: int,
    started: float,
    tracker: WorkerTracker,
) -> dict[str, object]:
    worker_started = time.monotonic()
    active_workers = tracker.enter()
    try:
        result = operation(args, index, started)
        result["worker_started_offset_seconds"] = round(worker_started - started, 6)
        result["active_workers_at_start"] = active_workers
        return result
    finally:
        tracker.leave()


def latency_by_fault_window(
    successes: list[dict[str, object]], start: float, end: float
) -> dict[str, object]:
    inside = [result for result in successes if start <= float(result["offset_seconds"]) <= end]
    outside = [
        result for result in successes if not start <= float(result["offset_seconds"]) <= end
    ]
    return {
        "inside": {"successful_requests": len(inside), "latency_ms": latency_summary(inside)},
        "outside": {"successful_requests": len(outside), "latency_ms": latency_summary(outside)},
    }


def latency_by_start_bucket(
    successes: list[dict[str, object]], duration: int, bucket_seconds: int = 30
) -> list[dict[str, object]]:
    if bucket_seconds < 1:
        raise ValueError("latency bucket size must be positive")
    maximum_offset = max(
        [float(result["offset_seconds"]) for result in successes], default=0.0
    )
    covered_seconds = max(float(duration), maximum_offset + 0.001)
    bucket_count = max(1, math.ceil(covered_seconds / bucket_seconds))
    buckets = []
    for index in range(bucket_count):
        start = index * bucket_seconds
        end = (index + 1) * bucket_seconds
        values = [
            result
            for result in successes
            if start <= float(result["offset_seconds"]) < end
        ]
        buckets.append(
            {
                "start_seconds": start,
                "end_seconds": end,
                "successful_requests": len(values),
                "latency_ms": latency_summary(values),
            }
        )
    return buckets


def annotate_request_lifecycle(
    results: list[dict[str, object]], rate: int
) -> list[dict[str, object]]:
    for index, result in enumerate(results):
        scheduled_offset = index / rate
        started_offset = float(result["offset_seconds"])
        completed_offset = started_offset + float(result["elapsed_ms"]) / 1000
        result["request_index"] = index
        result["scheduled_offset_seconds"] = round(scheduled_offset, 6)
        result["started_offset_seconds"] = round(started_offset, 6)
        result["completed_offset_seconds"] = round(completed_offset, 6)
        result["dispatch_lag_ms"] = round(
            max(0.0, (started_offset - scheduled_offset) * 1000), 3
        )
        worker_started_offset = float(
            result.get("worker_started_offset_seconds", started_offset)
        )
        result["worker_queue_lag_ms"] = round(
            max(0.0, (worker_started_offset - scheduled_offset) * 1000), 3
        )
        result["end_to_end_ms"] = round(
            max(0.0, (completed_offset - scheduled_offset) * 1000), 3
        )
    return results


def classify_client_disruption(
    results: list[dict[str, object]],
    sanity_start: float,
    sanity_end: float,
    stable_recovery_probes: int,
    recovery_success_max_ms: float,
    maximum_disruption_seconds: float,
) -> dict[str, object]:
    if sanity_start < 0 or sanity_end <= sanity_start:
        raise ValueError("client disruption sanity bound is invalid")
    if stable_recovery_probes < 1 or recovery_success_max_ms <= 0:
        raise ValueError("client disruption recovery contract is invalid")
    if maximum_disruption_seconds <= 0:
        raise ValueError("client disruption duration bound is invalid")

    failures = [result for result in results if not bool(result["ok"])]
    if not failures:
        return {
            "status": "fault_not_observed",
            "sanity_window_start_seconds": sanity_start,
            "sanity_window_end_seconds": sanity_end,
            "start_offset_seconds": None,
            "end_offset_seconds": None,
            "duration_seconds": None,
            "maximum_duration_seconds": maximum_disruption_seconds,
            "stable_recovery_probes_required": stable_recovery_probes,
            "stable_recovery_observed": False,
            "failures_inside": 0,
            "failures_outside": 0,
            "affected_requests": 0,
            "latency_by_client_phase": None,
        }

    first_failure = min(
        failures, key=lambda result: float(result["started_offset_seconds"])
    )
    disruption_start = float(first_failure["started_offset_seconds"])
    start_inside_sanity = sanity_start <= disruption_start <= sanity_end
    first_failure_position = results.index(first_failure)
    first_failure_index = int(first_failure["request_index"])
    stable: list[dict[str, object]] = []
    recovery_cohort: list[dict[str, object]] | None = None
    for result in results[first_failure_position + 1 :]:
        timely_success = (
            bool(result["ok"])
            and int(result["status"]) == 200
            and float(result["end_to_end_ms"]) <= recovery_success_max_ms
        )
        if timely_success:
            stable.append(result)
            if len(stable) == stable_recovery_probes:
                recovery_cohort = list(stable)
                break
        else:
            stable.clear()

    if recovery_cohort is None:
        return {
            "status": "stable_recovery_not_observed",
            "sanity_window_start_seconds": sanity_start,
            "sanity_window_end_seconds": sanity_end,
            "first_impact_within_sanity_window": start_inside_sanity,
            "start_offset_seconds": round(disruption_start, 6),
            "end_offset_seconds": None,
            "duration_seconds": None,
            "maximum_duration_seconds": maximum_disruption_seconds,
            "stable_recovery_probes_required": stable_recovery_probes,
            "stable_recovery_observed": False,
            "failures_inside": len(failures),
            "failures_outside": 0,
            "affected_requests": len(results) - first_failure_index,
            "latency_by_client_phase": None,
        }

    disruption_end = max(
        float(result["completed_offset_seconds"]) for result in recovery_cohort
    )
    disruption_duration = max(0.0, disruption_end - disruption_start)
    affected = [
        result
        for result in results
        if float(result["scheduled_offset_seconds"]) < disruption_end
        and float(result["completed_offset_seconds"]) >= disruption_start
    ]
    affected_indexes = {int(result["request_index"]) for result in affected}
    outside_failures = [
        result
        for result in failures
        if int(result["request_index"]) not in affected_indexes
    ]
    pre = [
        result
        for result in results
        if float(result["completed_offset_seconds"]) < disruption_start
    ]
    post = [
        result
        for result in results
        if float(result["scheduled_offset_seconds"]) >= disruption_end
    ]
    status = "passed"
    if (
        not start_inside_sanity
        or disruption_duration > maximum_disruption_seconds
        or outside_failures
    ):
        status = "failed"
    return {
        "status": status,
        "sanity_window_start_seconds": sanity_start,
        "sanity_window_end_seconds": sanity_end,
        "first_impact_within_sanity_window": start_inside_sanity,
        "start_offset_seconds": round(disruption_start, 6),
        "end_offset_seconds": round(disruption_end, 6),
        "duration_seconds": round(disruption_duration, 6),
        "maximum_duration_seconds": maximum_disruption_seconds,
        "stable_recovery_probes_required": stable_recovery_probes,
        "stable_recovery_observed": True,
        "stable_recovery_request_indexes": [
            int(result["request_index"]) for result in recovery_cohort
        ],
        "recovery_success_max_ms": recovery_success_max_ms,
        "affected_requests": len(affected),
        "failures_inside": len(failures) - len(outside_failures),
        "failures_outside": len(outside_failures),
        "failure_indexes_outside": [
            int(result["request_index"]) for result in outside_failures
        ],
        "latency_by_client_phase": {
            "pre_disruption": phase_summary(pre),
            "disruption": phase_summary(affected),
            "post_recovery": phase_summary(post),
        },
    }


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


def send_keepalive_probe(connection: http.client.HTTPSConnection) -> None:
    connection.request("GET", "/", headers={"Connection": "keep-alive"})
    response = connection.getresponse()
    response.read(1024)
    if response.status != 404:
        raise ConnectionError("armed probe keepalive returned an unexpected status")
    if response.will_close:
        raise ConnectionError("armed probe keepalive connection was closed")


def wait_for_trigger_with_keepalive(
    trigger_file: pathlib.Path,
    timeout: float,
    connection: http.client.HTTPSConnection,
    keepalive_interval: float,
    clock=time.monotonic,
    sleeper=time.sleep,
) -> int:
    if keepalive_interval <= 0:
        raise ValueError("armed probe keepalive interval must be positive")
    deadline = clock() + timeout
    next_keepalive = clock() + keepalive_interval
    keepalive_requests = 0
    while not trigger_file.exists():
        now = clock()
        remaining = deadline - now
        if remaining <= 0:
            raise TimeoutError("armed probe trigger was not created")
        if now >= next_keepalive:
            send_keepalive_probe(connection)
            keepalive_requests += 1
            next_keepalive = clock() + keepalive_interval
            continue
        sleeper(min(0.01, remaining, next_keepalive - now))
    return keepalive_requests


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
        send_keepalive_probe(connection)
        ready_file.touch(mode=0o600, exist_ok=False)
        keepalive_requests = 1 + wait_for_trigger_with_keepalive(
            trigger_file,
            args.trigger_timeout,
            connection,
            args.keepalive_interval,
        )
        result = webhook_request(args, 0, time.monotonic(), connection)
        result["prearmed_keepalive_requests"] = keepalive_requests
        return result
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
    tracker = WorkerTracker(args.workers)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        for index in range(requests):
            due = started + index / args.rate
            remaining = due - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            futures.append(
                executor.submit(
                    tracked_operation, operation, args, index, started, tracker
                )
            )
        results = annotate_request_lifecycle(
            [future.result(timeout=args.timeout + args.duration) for future in futures],
            args.rate,
        )
    wall = time.monotonic() - started
    successes = [result for result in results if result["ok"]]
    failures = [result for result in results if not result["ok"]]
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
    tail = [
        result
        for result in results
        if float(result["scheduled_offset_seconds"]) >= args.duration - 30
    ]
    summary = {
        "schema_version": 2,
        "status": "completed",
        "duration_seconds": args.duration,
        "rate_per_second": args.rate,
        "scheduled_requests": requests,
        "submitted_requests": len(futures),
        "completed_requests": len(results),
        "successful_requests": len(successes),
        "failed_requests": len(failures),
        "failures_outside_accepted_window": len(outside),
        "failure_offsets_seconds": [round(float(value["offset_seconds"]), 3) for value in failures[:200]],
        "tail_30_seconds_successful": len(tail) > 0 and all(bool(value["ok"]) for value in tail),
        "status_counts": status_counts,
        "error_counts": error_counts,
        "latency_ms": latency_summary(successes),
        "latency_by_fault_window": latency_by_fault_window(
            successes, args.failure_window_start, args.failure_window_end
        ),
        "successful_latency_by_30_second_start_bucket": latency_by_start_bucket(
            successes, args.duration
        ),
        "dispatch_lag_ms": numeric_summary(
            [float(result["dispatch_lag_ms"]) for result in results]
        ),
        "tail_30_seconds": phase_summary(tail),
        "worker_pool": {
            "configured_workers": args.workers,
            "maximum_active_workers": tracker.maximum_active,
            "saturation_observed": tracker.maximum_active >= args.workers,
            "worker_queue_lag_ms": numeric_summary(
                [float(result["worker_queue_lag_ms"]) for result in results]
            ),
            "timeout_like_failures": sum(
                1
                for result in failures
                if int(result["status"]) == 0
                and float(result["elapsed_ms"]) >= args.timeout * 900
            ),
        },
        "wall_seconds": round(wall, 3),
        "achieved_requests_per_second": round(requests / wall, 3),
        "request_results": results,
    }
    if args.classify_disruption:
        summary["client_disruption"] = classify_client_disruption(
            results,
            args.failure_window_start,
            args.failure_window_end,
            args.stable_recovery_probes,
            args.recovery_success_max_ms,
            args.maximum_disruption_seconds,
        )
    return summary


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
    webhook.add_argument("--stable-recovery-probes", type=int, required=True)
    webhook.add_argument("--recovery-success-max-ms", type=float, required=True)
    webhook.add_argument("--maximum-disruption-seconds", type=float, required=True)
    webhook.set_defaults(operation=webhook_request, classify_disruption=True)
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
    armed_probe.add_argument("--keepalive-interval", type=float, default=5.0)
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
    api.set_defaults(operation=proxy_api_request, classify_disruption=False)
    args = parser.parse_args()
    if args.command == "probe":
        print(json.dumps(webhook_request(args, 0, time.monotonic()), separators=(",", ":"), sort_keys=True))
        return
    if args.command == "armed-probe":
        if args.timeout <= 0 or args.trigger_timeout <= 0 or args.keepalive_interval <= 0:
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
    if args.duration < 1 or args.rate < 1 or args.workers < 1 or args.timeout <= 0:
        raise ValueError("duration, rate, workers, and timeout must be positive")
    if args.failure_window_start < 0 or args.failure_window_end <= args.failure_window_start:
        raise ValueError("failure window bounds are invalid")
    if args.classify_disruption and (
        args.stable_recovery_probes < 1
        or args.recovery_success_max_ms <= 0
        or args.maximum_disruption_seconds <= 0
    ):
        raise ValueError("client disruption bounds are invalid")
    print(json.dumps(run_scheduled(args, args.operation), separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
