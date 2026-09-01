#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import socket
import struct
import time


SOCKS_VERSION = 5
ADDRESS_IPV4 = 1
ADDRESS_DOMAIN = 3
ADDRESS_IPV6 = 4
PAYLOAD_HEADER = struct.Struct("!8sIQ")
PAYLOAD_MAGIC = b"VPN2UOT\0"


def receive_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError("SOCKS5 control connection closed")
        chunks.extend(chunk)
    return bytes(chunks)


def receive_address(connection: socket.socket, address_type: int) -> str:
    if address_type == ADDRESS_IPV4:
        return socket.inet_ntop(socket.AF_INET, receive_exact(connection, 4))
    if address_type == ADDRESS_IPV6:
        return socket.inet_ntop(socket.AF_INET6, receive_exact(connection, 16))
    if address_type == ADDRESS_DOMAIN:
        length = receive_exact(connection, 1)[0]
        return receive_exact(connection, length).decode("ascii")
    raise RuntimeError(f"unsupported SOCKS5 address type: {address_type}")


def parse_endpoint(value: str) -> tuple[str, int]:
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text:
        raise ValueError(f"invalid IPv4 endpoint: {value}")
    ipaddress.IPv4Address(host)
    port = int(port_text)
    if port < 1 or port > 65535:
        raise ValueError(f"invalid port: {port}")
    return host, port


def parse_udp_response(packet: bytes) -> bytes:
    if len(packet) < 4 or packet[:2] != b"\x00\x00" or packet[2] != 0:
        raise RuntimeError("invalid SOCKS5 UDP response header")
    address_type = packet[3]
    offset = 4
    if address_type == ADDRESS_IPV4:
        offset += 4
    elif address_type == ADDRESS_IPV6:
        offset += 16
    elif address_type == ADDRESS_DOMAIN:
        if len(packet) < 5:
            raise RuntimeError("truncated SOCKS5 UDP domain header")
        offset += 1 + packet[4]
    else:
        raise RuntimeError(f"unsupported SOCKS5 UDP response address type: {address_type}")
    offset += 2
    if len(packet) < offset:
        raise RuntimeError("truncated SOCKS5 UDP response")
    return packet[offset:]


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = (len(ordered) - 1) * fraction
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (rank - lower)


def rounded(value: float | None) -> float | None:
    return None if value is None else round(value, 3)


def payload_for(sequence: int, sent_ns: int, size: int) -> bytes:
    header = PAYLOAD_HEADER.pack(PAYLOAD_MAGIC, sequence, sent_ns)
    padding = bytes((sequence + index) % 251 for index in range(size - len(header)))
    return header + padding


def open_udp_associate(proxy: tuple[str, int], timeout: float) -> tuple[socket.socket, str, int]:
    control = socket.create_connection(proxy, timeout=timeout)
    control.settimeout(timeout)
    control.sendall(bytes((SOCKS_VERSION, 1, 0)))
    if receive_exact(control, 2) != bytes((SOCKS_VERSION, 0)):
        control.close()
        raise RuntimeError("SOCKS5 proxy rejected no-auth method")
    control.sendall(bytes((SOCKS_VERSION, 3, 0, ADDRESS_IPV4)) + b"\x00" * 6)
    version, reply, reserved, address_type = receive_exact(control, 4)
    if version != SOCKS_VERSION or reply != 0 or reserved != 0:
        control.close()
        raise RuntimeError(f"SOCKS5 UDP associate failed with reply {reply}")
    relay_host = receive_address(control, address_type)
    relay_port = struct.unpack("!H", receive_exact(control, 2))[0]
    if relay_host == "0.0.0.0":
        relay_host = proxy[0]
    return control, relay_host, relay_port


def main() -> None:
    parser = argparse.ArgumentParser(description="benchmark one UoT flow through SOCKS5 UDP associate")
    parser.add_argument("--profile", required=True)
    parser.add_argument("--proxy", default="127.0.0.1:17890")
    parser.add_argument("--target", required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--payload-bytes", type=int, required=True)
    parser.add_argument("--interval-ms", type=float, required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    if args.count < 1 or args.count > 100000:
        parser.error("count must be between 1 and 100000")
    if args.payload_bytes < PAYLOAD_HEADER.size or args.payload_bytes > 1400:
        parser.error(f"payload-bytes must be between {PAYLOAD_HEADER.size} and 1400")
    if args.interval_ms < 0 or args.interval_ms > 60000:
        parser.error("interval-ms must be between 0 and 60000")
    if args.timeout <= 0 or args.timeout > 60:
        parser.error("timeout must be greater than 0 and at most 60")

    proxy = parse_endpoint(args.proxy)
    target_host, target_port = parse_endpoint(args.target)
    interval_ns = int(args.interval_ms * 1_000_000)
    sent_payloads: dict[int, bytes] = {}
    latencies_ms: list[float] = []
    received_sequences: list[int] = []
    duplicates = 0
    invalid = 0
    started_ns = time.monotonic_ns()
    last_send_ns = started_ns

    control, relay_host, relay_port = open_udp_associate(proxy, args.timeout)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            next_sequence = 0
            final_deadline_ns = 0
            while True:
                now_ns = time.monotonic_ns()
                while next_sequence < args.count and now_ns >= started_ns + next_sequence * interval_ns:
                    sent_ns = time.monotonic_ns()
                    payload = payload_for(next_sequence, sent_ns, args.payload_bytes)
                    request = (
                        b"\x00\x00\x00"
                        + bytes((ADDRESS_IPV4,))
                        + socket.inet_aton(target_host)
                        + struct.pack("!H", target_port)
                        + payload
                    )
                    client.sendto(request, (relay_host, relay_port))
                    sent_payloads[next_sequence] = payload
                    last_send_ns = sent_ns
                    next_sequence += 1
                    now_ns = time.monotonic_ns()
                if next_sequence == args.count and final_deadline_ns == 0:
                    final_deadline_ns = last_send_ns + int(args.timeout * 1_000_000_000)
                if len(received_sequences) == args.count:
                    break
                now_ns = time.monotonic_ns()
                if final_deadline_ns and now_ns >= final_deadline_ns:
                    break
                next_event_ns = final_deadline_ns if final_deadline_ns else started_ns + next_sequence * interval_ns
                wait_seconds = max(0.001, min(0.1, (next_event_ns - now_ns) / 1_000_000_000))
                client.settimeout(wait_seconds)
                try:
                    packet, _ = client.recvfrom(65535)
                except socket.timeout:
                    continue
                received_ns = time.monotonic_ns()
                try:
                    payload = parse_udp_response(packet)
                    magic, sequence, sent_ns = PAYLOAD_HEADER.unpack(payload[: PAYLOAD_HEADER.size])
                except (RuntimeError, struct.error):
                    invalid += 1
                    continue
                expected = sent_payloads.get(sequence)
                if magic != PAYLOAD_MAGIC or expected is None or payload != expected:
                    invalid += 1
                    continue
                if sequence in received_sequences:
                    duplicates += 1
                    continue
                received_sequences.append(sequence)
                latencies_ms.append((received_ns - sent_ns) / 1_000_000)
    finally:
        control.close()

    finished_ns = time.monotonic_ns()
    out_of_order = 0
    highest = -1
    for sequence in received_sequences:
        if sequence < highest:
            out_of_order += 1
        highest = max(highest, sequence)
    lost = args.count - len(received_sequences)
    result = {
        "schema_version": 1,
        "profile": args.profile,
        "status": "passed" if lost == 0 and invalid == 0 else "observed-loss",
        "payload_bytes": args.payload_bytes,
        "interval_ms": args.interval_ms,
        "sent": args.count,
        "received": len(received_sequences),
        "lost": lost,
        "loss_percent": round(lost * 100 / args.count, 3),
        "duplicates": duplicates,
        "invalid": invalid,
        "out_of_order": out_of_order,
        "duration_ms": round((finished_ns - started_ns) / 1_000_000, 3),
        "responses_over_100ms": sum(value > 100 for value in latencies_ms),
        "rtt_ms": {
            "min": rounded(min(latencies_ms) if latencies_ms else None),
            "p50": rounded(percentile(latencies_ms, 0.50)),
            "p95": rounded(percentile(latencies_ms, 0.95)),
            "p99": rounded(percentile(latencies_ms, 0.99)),
            "max": rounded(max(latencies_ms) if latencies_ms else None),
        },
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
