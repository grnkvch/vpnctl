#!/usr/bin/env python3
import argparse
import json
import os
import socket
import time
from pathlib import Path


def family_for(host):
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def open_socket(protocol, host, timeout, bind_host, mark):
    sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    connection = socket.socket(family_for(host), sock_type)
    connection.settimeout(timeout)
    if mark is not None:
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
    if bind_host:
        connection.bind((bind_host, 0))
    return connection


def request(protocol, host, port, payload, timeout, bind_host=None, mark=None):
    message = payload.encode("utf-8")
    with open_socket(protocol, host, timeout, bind_host, mark) as connection:
        if protocol == "tcp":
            connection.connect((host, port))
            connection.sendall(message + b"\n")
            reader = connection.makefile("rb")
            try:
                response = reader.readline(4097)
            finally:
                reader.close()
            if not response or len(response) > 4096:
                raise RuntimeError("invalid TCP response")
            return response.rstrip(b"\n").decode("utf-8")
        connection.sendto(message, (host, port))
        response, _ = connection.recvfrom(4096)
        return response.decode("utf-8")


def expected_response(label, payload):
    return f"{label}:{payload}"


def run_request(args):
    response = request(
        args.protocol,
        args.host,
        args.port,
        args.payload,
        args.timeout,
        args.bind,
        args.mark,
    )
    if response != expected_response(args.expect, args.payload):
        raise SystemExit(f"unexpected response label: {response.split(':', 1)[0]}")
    print(json.dumps({"status": "passed", "protocol": args.protocol, "label": args.expect}))


def run_blocked(args):
    try:
        response = request(
            args.protocol,
            args.host,
            args.port,
            args.payload,
            args.timeout,
            args.bind,
            args.mark,
        )
    except (OSError, RuntimeError):
        print(json.dumps({"status": "blocked", "protocol": args.protocol}))
        return
    raise SystemExit(f"traffic unexpectedly reached {response.split(':', 1)[0]}")


def write_json(path, value):
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def run_hold(args):
    result_path = Path(args.result)
    ready_path = Path(args.ready)
    signal_path = Path(args.signal)
    with open_socket("tcp", args.host, args.timeout, args.bind, args.mark) as connection:
        connection.connect((args.host, args.port))
        reader = connection.makefile("rb")
        try:
            responses = []
            for phase in ("before",):
                payload = f"{args.payload}-{phase}"
                connection.sendall(payload.encode("utf-8") + b"\n")
                responses.append(reader.readline(4097).rstrip(b"\n").decode("utf-8"))
            write_json(ready_path, {"status": "ready"})
            deadline = time.monotonic() + args.wait
            while not signal_path.exists():
                if time.monotonic() >= deadline:
                    raise TimeoutError("hold signal timed out")
                time.sleep(0.05)
            payload = f"{args.payload}-after"
            connection.sendall(payload.encode("utf-8") + b"\n")
            responses.append(reader.readline(4097).rstrip(b"\n").decode("utf-8"))
        finally:
            reader.close()
    expected = [
        expected_response(args.expect, f"{args.payload}-before"),
        expected_response(args.expect, f"{args.payload}-after"),
    ]
    value = {"status": "passed" if responses == expected else "failed", "responses": responses}
    write_json(result_path, value)
    if value["status"] != "passed":
        raise SystemExit("established flow did not retain its direct decision")


def run_storm(args):
    deadline = time.monotonic() + args.duration
    value = {"schema_version": 1, "allowed": 0, "blocked": 0, "forbidden": 0}
    sequence = 0
    while time.monotonic() < deadline:
        sequence += 1
        payload = f"{args.payload}-{sequence}"
        try:
            response = request(
                args.protocol,
                args.host,
                args.port,
                payload,
                args.timeout,
                args.bind,
                args.mark,
            )
        except (OSError, RuntimeError):
            value["blocked"] += 1
            continue
        label = response.split(":", 1)[0]
        if label == args.expect:
            value["allowed"] += 1
        else:
            value["forbidden"] += 1
    value["status"] = "passed" if value["forbidden"] == 0 else "failed"
    print(json.dumps(value, sort_keys=True))
    if value["status"] != "passed":
        raise SystemExit("restart storm observed a forbidden direct response")


def add_common(parser, include_expect=True):
    parser.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--payload", default="vpnctl-routing-spike")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--bind")
    parser.add_argument("--mark", type=lambda value: int(value, 0))
    if include_expect:
        parser.add_argument("--expect", required=True)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    request_parser = subparsers.add_parser("request")
    add_common(request_parser)
    request_parser.set_defaults(function=run_request)

    blocked_parser = subparsers.add_parser("blocked")
    add_common(blocked_parser, include_expect=False)
    blocked_parser.set_defaults(function=run_blocked)

    hold_parser = subparsers.add_parser("hold")
    hold_parser.add_argument("--host", required=True)
    hold_parser.add_argument("--port", type=int, required=True)
    hold_parser.add_argument("--expect", required=True)
    hold_parser.add_argument("--payload", default="vpnctl-routing-hold")
    hold_parser.add_argument("--timeout", type=float, default=3.0)
    hold_parser.add_argument("--wait", type=float, default=30.0)
    hold_parser.add_argument("--bind")
    hold_parser.add_argument("--mark", type=lambda value: int(value, 0))
    hold_parser.add_argument("--ready", required=True)
    hold_parser.add_argument("--signal", required=True)
    hold_parser.add_argument("--result", required=True)
    hold_parser.set_defaults(function=run_hold)

    storm_parser = subparsers.add_parser("storm")
    add_common(storm_parser)
    storm_parser.add_argument("--duration", type=float, default=4.0)
    storm_parser.set_defaults(function=run_storm)

    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
