#!/usr/bin/env python3
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread


class Handler(BaseHTTPRequestHandler):
    destination = ""

    def do_GET(self):
        body = json.dumps(
            {
                "destination": self.destination,
                "source": self.client_address[0],
                "path": self.path,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def parse_listener(value):
    address, destination = value.split("=", 1)
    host, port = address.rsplit(":", 1)
    return host, int(port), destination


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", action="append", required=True)
    args = parser.parse_args()
    servers = []
    for raw in args.listen:
        host, port, destination = parse_listener(raw)
        handler = type(f"Handler_{destination}", (Handler,), {"destination": destination})
        server = ThreadingHTTPServer((host, port), handler)
        servers.append(server)
        Thread(target=server.serve_forever, daemon=True).start()
    Event().wait()


if __name__ == "__main__":
    main()
