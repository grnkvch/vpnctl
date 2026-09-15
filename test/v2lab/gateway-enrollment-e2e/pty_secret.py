#!/usr/bin/env python3
"""Guest-only PTY adapter for one-time enrollment input and typed purge.

The helper never writes a PTY transcript. Invite material exists only in this
process and one explicitly supplied mode-0600 runtime file.
"""

from __future__ import annotations

import fcntl
import json
import os
import pathlib
import pty
import re
import select
import stat
import subprocess
import sys
import termios
import time
from typing import Sequence


TOKEN_PATTERN = re.compile(
    rb"(?<![A-Za-z0-9_-])vpnctl-invite-v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![A-Za-z0-9_-])"
)
MAXIMUM_TTY_BYTES = 65536
MAXIMUM_RESULT_BYTES = 262144


class HelperError(RuntimeError):
    pass


def extract_single_token(payload: bytes) -> bytes:
    matches = TOKEN_PATTERN.findall(payload)
    if len(matches) != 1:
        raise HelperError("invite PTY output did not contain exactly one token")
    return matches[0]


def private_write(path: pathlib.Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise HelperError("private runtime write did not complete")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise HelperError("private runtime file mode changed")


def read_bounded(path: pathlib.Path, maximum: int) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise HelperError("result path is not a regular file")
    if info.st_size <= 0 or info.st_size > maximum:
        raise HelperError("result path has invalid size")
    return path.read_bytes()


def safe_projection(document: object, operation: str) -> dict[str, object]:
    if not isinstance(document, dict):
        raise HelperError("vpnctl result is not an object")
    if document.get("schema_version") != 1 or document.get("status") != "ok":
        raise HelperError("vpnctl operation did not return success")
    resource_ids = document.get("resource_ids")
    data = document.get("data")
    if not isinstance(resource_ids, dict) or not isinstance(data, dict):
        raise HelperError("vpnctl result has invalid public fields")
    if operation == "invite":
        invite_id = resource_ids.get("invite_id")
        expires_at = data.get("expires_at")
        if (
            not isinstance(invite_id, str)
            or not invite_id
            or not isinstance(expires_at, str)
            or data.get("displayed_to_tty") is not True
        ):
            raise HelperError("invite result lacks public identity")
        return {
            "schema_version": 1,
            "operation": "invite",
            "status": "ok",
            "resource_ids": {"invite_id": invite_id},
            "data": {"expires_at": expires_at, "displayed_to_tty": True},
        }
    if operation == "join":
        node_id = resource_ids.get("node_id")
        generation = data.get("generation")
        if (
            not isinstance(node_id, str)
            or not node_id
            or not isinstance(generation, int)
            or data.get("active_transport") != "standard"
            or data.get("presets") != ["telegram"]
        ):
            raise HelperError("join result lacks public identity")
        return {
            "schema_version": 1,
            "operation": "join",
            "status": "ok",
            "resource_ids": {"node_id": node_id},
            "data": {
                "generation": generation,
                "active_transport": data.get("active_transport"),
                "presets": data.get("presets"),
            },
        }
    if operation in {"purge-node", "purge-gateway"}:
        return {
            "schema_version": 1,
            "operation": operation,
            "status": "ok",
            "data": {
                "changed": data.get("changed"),
                "role": data.get("role"),
                "data_purged": data.get("data_purged"),
                "binary_removed": data.get("binary_removed"),
            },
        }
    raise HelperError("unsupported result projection")


def run_with_controlling_tty(
    command: Sequence[str],
    result_path: pathlib.Path,
    tty_input: bytes = b"",
    maximum_seconds: float = 180.0,
) -> bytes:
    master, slave = pty.openpty()
    attributes = termios.tcgetattr(slave)
    attributes[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, attributes)

    def prepare_child() -> None:
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    with result_path.open("xb") as output:
        os.chmod(result_path, 0o600)
        process = subprocess.Popen(
            list(command),
            stdin=slave,
            stdout=output,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            preexec_fn=prepare_child,
        )
    os.close(slave)
    if tty_input:
        os.write(master, tty_input + b"\n")
    captured = bytearray()
    deadline = time.monotonic() + maximum_seconds
    try:
        while process.poll() is None:
            if time.monotonic() >= deadline:
                process.kill()
                raise HelperError("vpnctl PTY operation timed out")
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                captured.extend(chunk)
                if len(captured) > MAXIMUM_TTY_BYTES:
                    process.kill()
                    raise HelperError("vpnctl PTY output exceeded its bound")
        return_code = process.wait(timeout=5)
        while True:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            captured.extend(chunk)
            if len(captured) > MAXIMUM_TTY_BYTES:
                raise HelperError("vpnctl PTY output exceeded its bound")
    finally:
        os.close(master)
    if return_code != 0:
        raise HelperError("vpnctl PTY operation failed")
    return bytes(captured)


def require_runtime_root(raw: str, operation: str) -> pathlib.Path:
    root = pathlib.Path(raw)
    expected = (
        pathlib.Path("/run/vpnctl/gateway-enrollment-e2e")
        if operation in {"invite", "join"}
        else pathlib.Path("/var/lib/vpnctl-v2-gateway-enrollment-e2e/runtime")
    )
    if root != expected:
        raise HelperError("unexpected runtime root")
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise HelperError("runtime root is unsafe")
    return root


def load_result(path: pathlib.Path) -> object:
    try:
        return json.loads(read_bounded(path, MAXIMUM_RESULT_BYTES))
    except (OSError, ValueError) as error:
        raise HelperError("vpnctl result is invalid") from error


def execute(operation: str, runtime_raw: str) -> dict[str, object]:
    if os.geteuid() != 0:
        raise HelperError("PTY helper must run as root")
    root = require_runtime_root(runtime_raw, operation)
    result_path = root / f"{operation}.result.json"
    token_path = root / "invite.token"
    completed = False
    if result_path.exists() or result_path.is_symlink():
        raise HelperError("runtime result already exists")
    try:
        if operation == "invite":
            tty_output = run_with_controlling_tty(
                ["/usr/local/bin/vpnctl", "invite", "e2e-node", "--json"], result_path
            )
            token = extract_single_token(tty_output)
            if token_path.exists() or token_path.is_symlink():
                raise HelperError("runtime token already exists")
            private_write(token_path, token + b"\n")
        elif operation == "join":
            token = read_bounded(token_path, 4096).strip()
            if not TOKEN_PATTERN.fullmatch(token):
                raise HelperError("runtime token is invalid")
            run_with_controlling_tty(
                ["/usr/local/bin/vpnctl", "join", "standard", "telegram", "--yes", "--json"],
                result_path,
                token,
            )
        elif operation == "purge-node":
            run_with_controlling_tty(
                ["/usr/local/bin/vpnctl", "purge", "--local-only", "--json"],
                result_path,
                b"purge node",
            )
        elif operation == "purge-gateway":
            run_with_controlling_tty(
                ["/usr/local/bin/vpnctl", "purge", "--force", "--json"],
                result_path,
                b"purge gateway",
            )
        else:
            raise HelperError("unsupported operation")
        projected = safe_projection(load_result(result_path), operation)
        completed = True
        return projected
    finally:
        try:
            result_path.unlink()
        except FileNotFoundError:
            pass
        if operation != "invite" or not completed:
            try:
                token_path.unlink()
            except FileNotFoundError:
                pass


def main(arguments: Sequence[str]) -> int:
    if len(arguments) != 2:
        print("guest PTY helper failed", file=sys.stderr)
        return 2
    try:
        projected = execute(arguments[0], arguments[1])
        print(json.dumps(projected, sort_keys=True, separators=(",", ":")))
        return 0
    except (HelperError, OSError, subprocess.SubprocessError):
        print("guest PTY helper failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
