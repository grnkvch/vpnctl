#!/usr/bin/env python3
import argparse
import concurrent.futures
import http.client
import json
import math
import ssl
import statistics
import threading
import time
from urllib.parse import urlencode


def body_of_size(size: int) -> bytes:
    if size < 0:
        raise ValueError("body size must not be negative")
    return b"x" * size


def one_request(
    public_ip: str,
    certificate: str,
    path: str,
    body: bytes,
    timeout: float,
    chunk_bytes: int,
    chunk_delay_ms: int,
) -> dict[str, object]:
    context = ssl.create_default_context(cafile=certificate)
    connection = http.client.HTTPSConnection(public_ip, 443, timeout=timeout, context=context)
    started = time.monotonic()
    send_error = ""
    try:
        connection.putrequest("POST", path)
        connection.putheader("Content-Type", "application/octet-stream")
        connection.putheader("Content-Length", str(len(body)))
        connection.putheader("Connection", "close")
        connection.endheaders()
        step = chunk_bytes if chunk_bytes > 0 else max(1, len(body))
        for offset in range(0, len(body), step):
            try:
                connection.send(body[offset : offset + step])
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError) as error:
                send_error = type(error).__name__
                break
            if chunk_delay_ms:
                time.sleep(chunk_delay_ms / 1000)
        response = connection.getresponse()
        response_body = response.read(1024 * 1024)
        elapsed_ms = (time.monotonic() - started) * 1000
        headers = {key.lower(): value for key, value in response.getheaders()}
        parsed_body: object
        try:
            parsed_body = json.loads(response_body)
        except json.JSONDecodeError:
            parsed_body = None
        return {
            "body": parsed_body,
            "elapsed_ms": round(elapsed_ms, 3),
            "generation": headers.get("x-vpnctl-spike-generation", ""),
            "send_error": send_error,
            "status": response.status,
        }
    finally:
        connection.close()


def percentile(values: list[float], percentile_value: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * percentile_value) - 1)
    return round(ordered[index], 3)


def run_request(args: argparse.Namespace) -> dict[str, object]:
    return one_request(
        args.public_ip,
        args.certificate,
        args.path,
        body_of_size(args.body_bytes),
        args.timeout,
        args.chunk_bytes,
        args.chunk_delay_ms,
    )


def run_load(args: argparse.Namespace) -> dict[str, object]:
    if args.requests < 1 or args.requests > 128:
        raise ValueError("requests must be between 1 and 128")
    paths = args.path
    if not paths:
        raise ValueError("at least one path is required")
    barrier = threading.Barrier(args.requests)
    body = body_of_size(args.body_bytes)

    def worker(index: int) -> dict[str, object]:
        path = paths[index % len(paths)]
        separator = "&" if "?" in path else "?"
        delayed_path = f"{path}{separator}{urlencode({'delay_ms': args.delay_ms})}"
        barrier.wait(timeout=10)
        return one_request(
            args.public_ip,
            args.certificate,
            delayed_path,
            body,
            args.timeout,
            0,
            0,
        )

    results: list[dict[str, object]] = []
    errors: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.requests) as executor:
        futures = [executor.submit(worker, index) for index in range(args.requests)]
        for future in futures:
            try:
                results.append(future.result(timeout=args.timeout + 15))
            except Exception as error:  # test harness records only error class, never request data
                errors.append(type(error).__name__)

    status_counts: dict[str, int] = {}
    for result in results:
        key = str(result["status"])
        status_counts[key] = status_counts.get(key, 0) + 1
    elapsed = [float(result["elapsed_ms"]) for result in results]
    generations = sorted({str(result["generation"]) for result in results if result["generation"]})
    return {
        "errors": errors,
        "generations": generations,
        "latency_ms": {
            "max": round(max(elapsed), 3) if elapsed else 0.0,
            "mean": round(statistics.fmean(elapsed), 3) if elapsed else 0.0,
            "p50": percentile(elapsed, 0.50),
            "p95": percentile(elapsed, 0.95),
        },
        "requests": args.requests,
        "responses": len(results),
        "status_counts": status_counts,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="credential-free vpnctl v2 HTTPS ingress load probe")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(target: argparse.ArgumentParser) -> None:
        target.add_argument("--public-ip", required=True)
        target.add_argument("--certificate", required=True)
        target.add_argument("--body-bytes", type=int, default=32)
        target.add_argument("--timeout", type=float, default=30.0)

    request_parser = subparsers.add_parser("request")
    common(request_parser)
    request_parser.add_argument("--path", required=True)
    request_parser.add_argument("--chunk-bytes", type=int, default=0)
    request_parser.add_argument("--chunk-delay-ms", type=int, default=0)
    request_parser.set_defaults(handler=run_request)

    load_parser = subparsers.add_parser("load")
    common(load_parser)
    load_parser.add_argument("--path", action="append", required=True)
    load_parser.add_argument("--requests", type=int, required=True)
    load_parser.add_argument("--delay-ms", type=int, default=1000)
    load_parser.set_defaults(handler=run_load)

    args = parser.parse_args()
    result = args.handler(args)
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
