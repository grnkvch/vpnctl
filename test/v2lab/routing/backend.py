#!/usr/bin/env python3
import argparse
import json
import os
import signal
import socket
import threading
from pathlib import Path


STATE_LOCK = threading.Lock()
STOP = threading.Event()


def split_endpoint(value):
    endpoint, label = value.rsplit("=", 1)
    host, port_text = endpoint.rsplit(":", 1)
    return host.strip("[]"), int(port_text), label


def socket_family(host):
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def increment(state_path, protocol, label):
    with STATE_LOCK:
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            state = {"schema_version": 1, "requests": {}}
        key = f"{protocol}:{label}"
        state["requests"][key] = int(state["requests"].get(key, 0)) + 1
        temporary = state_path.with_name(f".{state_path.name}.tmp.{os.getpid()}")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(state, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, state_path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def handle_tcp(connection, label, state_path):
    with connection:
        connection.settimeout(30)
        reader = connection.makefile("rb")
        writer = connection.makefile("wb")
        try:
            while not STOP.is_set():
                payload = reader.readline(4097)
                if not payload or len(payload) > 4096:
                    return
                increment(state_path, "tcp", label)
                writer.write(label.encode("utf-8") + b":" + payload)
                writer.flush()
        finally:
            reader.close()
            writer.close()


def serve_tcp(host, port, label, state_path):
    family = socket_family(host)
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(64)
        listener.settimeout(0.25)
        while not STOP.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            threading.Thread(
                target=handle_tcp,
                args=(connection, label, state_path),
                daemon=True,
            ).start()


def serve_udp(host, port, label, state_path):
    family = socket_family(host)
    with socket.socket(family, socket.SOCK_DGRAM) as listener:
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind((host, port))
        listener.settimeout(0.25)
        while not STOP.is_set():
            try:
                payload, peer = listener.recvfrom(4096)
            except socket.timeout:
                continue
            increment(state_path, "udp", label)
            listener.sendto(label.encode("utf-8") + b":" + payload, peer)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--tcp", action="append", default=[])
    parser.add_argument("--udp", action="append", default=[])
    args = parser.parse_args()
    if not args.tcp and not args.udp:
        raise SystemExit("at least one listener is required")

    state_path = Path(args.state)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    if not state_path.exists():
        state_path.write_text('{"requests":{},"schema_version":1}\n', encoding="utf-8")
        state_path.chmod(0o600)

    def stop(_signum, _frame):
        STOP.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    threads = []
    for value in args.tcp:
        thread = threading.Thread(
            target=serve_tcp,
            args=(*split_endpoint(value), state_path),
            daemon=True,
        )
        thread.start()
        threads.append(thread)
    for value in args.udp:
        thread = threading.Thread(
            target=serve_udp,
            args=(*split_endpoint(value), state_path),
            daemon=True,
        )
        thread.start()
        threads.append(thread)

    while not STOP.wait(0.25):
        if any(not thread.is_alive() for thread in threads):
            raise SystemExit("listener stopped unexpectedly")


if __name__ == "__main__":
    main()
