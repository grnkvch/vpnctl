#!/usr/bin/env python3
import argparse
import socketserver
import threading


class BackendHandler(socketserver.StreamRequestHandler):
    def handle(self):
        for raw_line in self.rfile:
            if len(raw_line) > 4096:
                return
            payload = raw_line.rstrip(b"\r\n")
            self.wfile.write(self.server.label.encode("ascii") + b":" + payload + b"\n")
            self.wfile.flush()


class BackendServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def run_server(address, label):
    server = BackendServer(address, BackendHandler)
    server.label = label
    server.serve_forever(poll_interval=0.25)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--backend", action="append", required=True, metavar="PORT=LABEL")
    args = parser.parse_args()
    threads = []
    for value in args.backend:
        port_text, label = value.split("=", 1)
        thread = threading.Thread(
            target=run_server,
            args=((args.listen, int(port_text)), label),
            daemon=True,
        )
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
