#!/usr/bin/env python3
import argparse
import ipaddress
import socket
import struct


SOCKS_VERSION = 5
ADDRESS_IPV4 = 1
ADDRESS_DOMAIN = 3
ADDRESS_IPV6 = 4


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
    offset = 4
    address_type = packet[3]
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


def main() -> None:
    parser = argparse.ArgumentParser(description="send one IPv4 UDP payload through a SOCKS5 UDP associate")
    parser.add_argument("--proxy", default="127.0.0.1:17890")
    parser.add_argument("--target", required=True)
    parser.add_argument("--payload", default="vpnctl-v2-uot-ok")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    proxy_host, proxy_port = parse_endpoint(args.proxy)
    target_host, target_port = parse_endpoint(args.target)
    expected = args.payload.encode("utf-8")

    with socket.create_connection((proxy_host, proxy_port), timeout=args.timeout) as control:
        control.settimeout(args.timeout)
        control.sendall(bytes((SOCKS_VERSION, 1, 0)))
        if receive_exact(control, 2) != bytes((SOCKS_VERSION, 0)):
            raise RuntimeError("SOCKS5 proxy rejected no-auth method")

        control.sendall(bytes((SOCKS_VERSION, 3, 0, ADDRESS_IPV4)) + b"\x00" * 6)
        version, reply, reserved, address_type = receive_exact(control, 4)
        if version != SOCKS_VERSION or reply != 0 or reserved != 0:
            raise RuntimeError(f"SOCKS5 UDP associate failed with reply {reply}")
        relay_host = receive_address(control, address_type)
        relay_port = struct.unpack("!H", receive_exact(control, 2))[0]
        if relay_host == "0.0.0.0":
            relay_host = proxy_host

        request = (
            b"\x00\x00\x00"
            + bytes((ADDRESS_IPV4,))
            + socket.inet_aton(target_host)
            + struct.pack("!H", target_port)
            + expected
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(args.timeout)
            client.sendto(request, (relay_host, relay_port))
            response, _ = client.recvfrom(65535)

    payload = parse_udp_response(response)
    if payload != expected:
        raise RuntimeError(f"unexpected UDP echo payload: {payload!r}")
    print(payload.decode("utf-8"))


if __name__ == "__main__":
    main()
