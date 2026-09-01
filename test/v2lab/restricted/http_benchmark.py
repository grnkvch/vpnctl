#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import math
import time
import urllib.parse


def parse_endpoint(value: str) -> tuple[str, int]:
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text:
        raise ValueError(f"invalid IPv4 endpoint: {value}")
    ipaddress.IPv4Address(host)
    port = int(port_text)
    if port < 1 or port > 65535:
        raise ValueError(f"invalid port: {port}")
    return host, port


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    rank = (len(ordered) - 1) * fraction
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (rank - lower)


def main() -> None:
    parser = argparse.ArgumentParser(description="benchmark small API-like HTTP requests through the restricted proxy")
    parser.add_argument("--profile", required=True)
    parser.add_argument("--proxy", default="127.0.0.1:17890")
    parser.add_argument("--target", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    if args.count < 1 or args.count > 10000:
        parser.error("count must be between 1 and 10000")
    if len(args.expected_sha256) != 64:
        parser.error("expected-sha256 must contain 64 hexadecimal characters")
    target = urllib.parse.urlsplit(args.target)
    if target.scheme != "http" or not target.hostname or target.port is None:
        parser.error("target must be an explicit HTTP URL with a port")

    proxy_host, proxy_port = parse_endpoint(args.proxy)
    latencies_ms: list[float] = []
    failures = 0
    response_bytes = None
    started_ns = time.monotonic_ns()
    for _ in range(args.count):
        request_started_ns = time.monotonic_ns()
        connection = http.client.HTTPConnection(proxy_host, proxy_port, timeout=args.timeout)
        try:
            connection.request("GET", args.target, headers={"Accept": "application/json", "Connection": "close"})
            response = connection.getresponse()
            body = response.read()
            if response.status != 200 or hashlib.sha256(body).hexdigest() != args.expected_sha256:
                failures += 1
                continue
            response_bytes = len(body)
            latencies_ms.append((time.monotonic_ns() - request_started_ns) / 1_000_000)
        except (OSError, http.client.HTTPException):
            failures += 1
        finally:
            connection.close()
    duration_seconds = (time.monotonic_ns() - started_ns) / 1_000_000_000
    success = len(latencies_ms)
    result = {
        "schema_version": 1,
        "profile": args.profile,
        "status": "passed" if failures == 0 else "observed-failure",
        "requests": args.count,
        "success": success,
        "failures": failures,
        "response_bytes": response_bytes,
        "duration_ms": round(duration_seconds * 1000, 3),
        "requests_per_second": round(success / duration_seconds, 3) if duration_seconds else None,
        "latency_ms": {
            "min": round(min(latencies_ms), 3) if latencies_ms else None,
            "p50": round(percentile(latencies_ms, 0.50), 3) if latencies_ms else None,
            "p95": round(percentile(latencies_ms, 0.95), 3) if latencies_ms else None,
            "p99": round(percentile(latencies_ms, 0.99), 3) if latencies_ms else None,
            "max": round(max(latencies_ms), 3) if latencies_ms else None,
        },
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
