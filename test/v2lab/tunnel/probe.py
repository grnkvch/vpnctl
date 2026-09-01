#!/usr/bin/env python3
import argparse
import json
import socket
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", action="append", required=True, metavar="HOST:PORT=LABEL")
    parser.add_argument("--streams-per-target", type=int, default=1)
    parser.add_argument("--hold-seconds", type=float, default=0)
    parser.add_argument("--timeout", type=float, default=3)
    args = parser.parse_args()
    if not 1 <= args.streams_per_target <= 128 or not 0 <= args.hold_seconds <= 30:
        raise SystemExit("probe bounds exceeded")

    sockets = []
    results = []
    try:
        for target in args.target:
            endpoint, expected_label = target.rsplit("=", 1)
            host, port_text = endpoint.rsplit(":", 1)
            for stream_index in range(args.streams_per_target):
                connection = socket.create_connection((host, int(port_text)), timeout=args.timeout)
                connection.settimeout(args.timeout)
                payload = f"stream-{stream_index}".encode("ascii")
                connection.sendall(payload + b"\n")
                response = b""
                while not response.endswith(b"\n") and len(response) <= 8192:
                    chunk = connection.recv(8192)
                    if not chunk:
                        break
                    response += chunk
                expected = expected_label.encode("ascii") + b":" + payload + b"\n"
                if response != expected:
                    raise RuntimeError("unexpected tunnel response")
                sockets.append(connection)
                results.append({"target": endpoint, "label": expected_label})
        if args.hold_seconds:
            time.sleep(args.hold_seconds)
    finally:
        for connection in sockets:
            connection.close()
    print(json.dumps({
        "schema_version": 1,
        "status": "passed",
        "streams": len(results),
        "targets": sorted({item["target"] for item in results}),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
