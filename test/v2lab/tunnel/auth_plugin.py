#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import os
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

MAX_REQUEST_BYTES = 64 * 1024
STATE_LOCK = threading.Lock()


def read_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def atomic_json(path: Path, value):
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def verify_state_file(path: Path):
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise ValueError("authorization state must not be group/world accessible")
    state = read_json(path)
    if state.get("schema_version") != 1 or not isinstance(state.get("nodes"), dict):
        raise ValueError("unsupported authorization state")
    return state


def empty_metrics():
    return {
        "schema_version": 1,
        "requests": {
            operation: {"allowed": 0, "rejected": 0}
            for operation in ("Login", "NewProxy", "Ping")
        },
        "last_event": None,
        "last_by_operation": {},
    }


def record_metric(path: Path, operation: str, allowed: bool, reason: str):
    with STATE_LOCK:
        try:
            metrics = read_json(path)
        except (FileNotFoundError, json.JSONDecodeError):
            metrics = empty_metrics()
        if operation not in metrics["requests"]:
            metrics["requests"][operation] = {"allowed": 0, "rejected": 0}
        outcome = "allowed" if allowed else "rejected"
        metrics["requests"][operation][outcome] += 1
        event = {
            "operation": operation,
            "outcome": outcome,
            "reason": reason,
        }
        metrics["last_event"] = event
        metrics.setdefault("last_by_operation", {})[operation] = event
        atomic_json(path, metrics)


def identity_metadata(operation: str, content):
    if operation == "Login":
        return content.get("metas") or {}
    return (content.get("user") or {}).get("metas") or {}


def authorize_identity(state, operation: str, content):
    metadata = identity_metadata(operation, content)
    node_id = metadata.get("node_id")
    generation = metadata.get("generation")
    token = metadata.get("tunnel_token")
    if not all(isinstance(value, str) and value for value in (node_id, generation, token)):
        return None, "missing_identity"
    node = state["nodes"].get(node_id)
    if not isinstance(node, dict):
        return None, "unknown_node"
    if node.get("active") is not True:
        return None, "revoked"
    if generation != str(node.get("generation")):
        return None, "generation_mismatch"
    candidate = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expected = str(node.get("token_sha256", ""))
    if not hmac.compare_digest(candidate, expected):
        return None, "token_mismatch"
    # frpc v0.69.0 normalizes a declared zero to one before Login. Accept only
    # that pinned input; the response handler rewrites it to the effective zero
    # before frps creates the control session.
    if operation == "Login" and content.get("pool_count") != 1:
        return None, "pool_input_not_one"
    return node, "identity_valid"


def authorize(state, operation: str, content):
    if operation not in ("Login", "NewProxy", "Ping"):
        return False, "unsupported_operation"
    node, reason = authorize_identity(state, operation, content)
    if node is None:
        return False, reason
    if operation != "NewProxy":
        return True, reason

    proxy_metadata = content.get("metas") or {}
    announced = {
        "name": content.get("proxy_name"),
        "type": content.get("proxy_type"),
        "remote_port": content.get("remote_port"),
        "generation": proxy_metadata.get("generation"),
    }
    for allowed in node.get("allowed_proxies", []):
        expected = {
            "name": allowed.get("name"),
            "type": allowed.get("type"),
            "remote_port": allowed.get("remote_port"),
            "generation": str(allowed.get("generation")),
        }
        if announced == expected:
            return True, "mapping_valid"
    return False, "mapping_mismatch"


class AuthorizationHandler(BaseHTTPRequestHandler):
    server_version = "vpnctl-tunnel-authorizer"
    sys_version = ""

    def log_message(self, _format, *_args):
        return

    def send_json(self, payload, status=200):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/handler":
            self.send_json({"reject": True, "reject_reason": "not found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_REQUEST_BYTES:
            self.send_json({"reject": True, "reject_reason": "invalid request"}, 400)
            return
        try:
            request = json.loads(self.rfile.read(length))
            query_operation = (parse_qs(parsed.query).get("op") or [None])[0]
            operation = request.get("op")
            if operation != query_operation or not isinstance(request.get("content"), dict):
                raise ValueError("operation mismatch")
            state = verify_state_file(self.server.state_path)
            allowed, reason = authorize(state, operation, request["content"])
        except Exception:
            operation = operation if isinstance(locals().get("operation"), str) else "Unknown"
            record_metric(self.server.metrics_path, operation, False, "controller_error")
            self.send_json({"reject": True, "reject_reason": "vpnctl authorization unavailable"})
            return
        record_metric(self.server.metrics_path, operation, allowed, reason)
        if allowed and operation == "Login":
            normalized = dict(request["content"])
            normalized["pool_count"] = 0
            self.send_json({"reject": False, "unchange": False, "content": normalized})
        elif allowed:
            self.send_json({"reject": False, "unchange": True})
        else:
            self.send_json({"reject": True, "reject_reason": "vpnctl authorization denied"})


def serve(args):
    state_path = Path(args.state)
    metrics_path = Path(args.metrics)
    verify_state_file(state_path)
    if not metrics_path.exists():
        atomic_json(metrics_path, empty_metrics())
    server = ThreadingHTTPServer((args.listen, args.port), AuthorizationHandler)
    server.daemon_threads = True
    server.state_path = state_path
    server.metrics_path = metrics_path
    server.serve_forever(poll_interval=0.25)


def set_active(args):
    path = Path(args.state)
    with STATE_LOCK:
        state = verify_state_file(path)
        node = state["nodes"].get(args.node)
        if not isinstance(node, dict):
            raise SystemExit("unknown node")
        node["active"] = args.active == "true"
        atomic_json(path, state)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--state", required=True)
    serve_parser.add_argument("--metrics", required=True)
    serve_parser.add_argument("--listen", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=19091)
    serve_parser.set_defaults(function=serve)

    active_parser = subparsers.add_parser("set-active")
    active_parser.add_argument("--state", required=True)
    active_parser.add_argument("--node", required=True)
    active_parser.add_argument("--active", choices=("true", "false"), required=True)
    active_parser.set_defaults(function=set_active)

    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
