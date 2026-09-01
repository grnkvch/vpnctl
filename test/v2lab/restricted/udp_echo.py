#!/usr/bin/env python3
import argparse
import socket


def main() -> None:
    parser = argparse.ArgumentParser(description="vpnctl v2 restricted-spike UDP echo")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((args.listen, args.port))
        while True:
            payload, peer = server.recvfrom(65535)
            server.sendto(payload, peer)


if __name__ == "__main__":
    main()
