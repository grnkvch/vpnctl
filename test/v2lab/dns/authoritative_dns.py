#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import signal
import socket
import struct
import threading
from pathlib import Path


STOP = threading.Event()
STATE_LOCK = threading.Lock()


def read_exact(connection, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise EOFError("short DNS-over-TCP frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def parse_question(packet):
    if len(packet) < 12:
        raise ValueError("short DNS header")
    question_count = struct.unpack_from("!H", packet, 4)[0]
    if question_count != 1:
        raise ValueError("fixture accepts exactly one DNS question")
    labels = []
    offset = 12
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise ValueError("compressed query names are not accepted")
        if length > 63 or offset + length > len(packet):
            raise ValueError("invalid DNS label")
        labels.append(packet[offset : offset + length].decode("ascii").lower())
        offset += length
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question")
    query_type, query_class = struct.unpack_from("!HH", packet, offset)
    question_end = offset + 4
    return ".".join(labels), query_type, query_class, question_end


def build_response(packet, answer, ttl):
    query_name, query_type, query_class, question_end = parse_question(packet)
    transaction_id = packet[:2]
    flags = struct.pack("!H", 0x8180)
    answer_count = 1 if query_type == 1 and query_class == 1 else 0
    header = transaction_id + flags + struct.pack("!HHHH", 1, answer_count, 0, 0)
    question = packet[12:question_end]
    if answer_count == 0:
        return query_name, query_type, header + question
    record = (
        b"\xc0\x0c"
        + struct.pack("!HHI", 1, 1, ttl)
        + struct.pack("!H", 4)
        + ipaddress.IPv4Address(answer).packed
    )
    return query_name, query_type, header + question + record


def update_state(path, protocol, query_name, query_type):
    key = f"{protocol}:{query_type}:{query_name}"
    with STATE_LOCK:
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            state = {"schema_version": 1, "queries": {}, "total": 0}
        state["queries"][key] = int(state["queries"].get(key, 0)) + 1
        state["total"] = int(state.get("total", 0)) + 1
        temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(state, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def process_query(packet, protocol, answer, ttl, state_path):
    query_name, query_type, response = build_response(packet, answer, ttl)
    update_state(state_path, protocol, query_name, query_type)
    return response


def serve_udp(address, port, answer, ttl, state_path):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind((address, port))
        listener.settimeout(0.25)
        while not STOP.is_set():
            try:
                packet, peer = listener.recvfrom(65535)
            except socket.timeout:
                continue
            try:
                response = process_query(packet, "udp", answer, ttl, state_path)
            except (UnicodeDecodeError, ValueError):
                continue
            listener.sendto(response, peer)


def handle_tcp(connection, answer, ttl, state_path):
    with connection:
        connection.settimeout(5)
        try:
            frame_size = struct.unpack("!H", read_exact(connection, 2))[0]
            packet = read_exact(connection, frame_size)
            response = process_query(packet, "tcp", answer, ttl, state_path)
            connection.sendall(struct.pack("!H", len(response)) + response)
        except (EOFError, OSError, UnicodeDecodeError, ValueError):
            return


def serve_tcp(address, port, answer, ttl, state_path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((address, port))
        listener.listen(64)
        listener.settimeout(0.25)
        while not STOP.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            threading.Thread(
                target=handle_tcp,
                args=(connection, answer, ttl, state_path),
                daemon=True,
            ).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", required=True)
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--answer", required=True)
    parser.add_argument("--ttl", type=int, required=True)
    parser.add_argument("--state", required=True)
    args = parser.parse_args()
    ipaddress.IPv4Address(args.address)
    ipaddress.IPv4Address(args.answer)
    if not 1 <= args.port <= 65535 or not 1 <= args.ttl <= 3600:
        raise SystemExit("invalid port or TTL")

    state_path = Path(args.state)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text('{"queries":{},"schema_version":1,"total":0}\n', encoding="utf-8")
    state_path.chmod(0o600)

    def stop(_signum, _frame):
        STOP.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    threads = [
        threading.Thread(
            target=serve_udp,
            args=(args.address, args.port, args.answer, args.ttl, state_path),
            daemon=True,
        ),
        threading.Thread(
            target=serve_tcp,
            args=(args.address, args.port, args.answer, args.ttl, state_path),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()
    while not STOP.wait(0.25):
        if any(not thread.is_alive() for thread in threads):
            raise SystemExit("DNS fixture listener stopped")


if __name__ == "__main__":
    main()
