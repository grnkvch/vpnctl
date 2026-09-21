#!/usr/bin/env python3
"""Capture development inputs, not Git objects or a reusable release receipt."""

import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tarfile


def capture(repository, output, archive=None):
    roots = ["cmd", "internal", "scripts", "test", "openspec", "docs",
             "go.mod", "go.sum", "README.md", "AGENTS.md"]
    names = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
         "--", *roots], cwd=repository
    )
    records = []
    snapshot = tarfile.open(archive, "w") if archive else None
    try:
        for raw in sorted(set(names.split(b"\0")) - {b""}):
            name = raw.decode("utf-8")
            path = repository / name
            if any(part in {"__pycache__", ".pytest_cache"} for part in path.parts):
                continue
            if path.is_symlink():
                raise ValueError(f"development input is a symlink: {name}")
            if not path.exists():
                continue  # A tracked deletion is valid uncommitted source.
            if not path.is_file():
                raise ValueError(f"development input is not a regular file: {name}")
            data = path.read_bytes()
            mode = stat.S_IMODE(path.stat().st_mode)
            records.append({"path": name, "mode": mode,
                            "sha256": hashlib.sha256(data).hexdigest()})
            if snapshot:
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                entry.mode = mode
                snapshot.addfile(entry, io.BytesIO(data))
        output.write_text(json.dumps({"schema_version": 1, "files": records},
                                     sort_keys=True, indent=2) + "\n")
    finally:
        if snapshot:
            snapshot.close()


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        sys.exit("usage: v2-dev-inputs.py <repository> <manifest> [snapshot.tar]")
    try:
        capture(Path(sys.argv[1]), Path(sys.argv[2]),
                Path(sys.argv[3]) if len(sys.argv) == 4 else None)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f"development input capture failed: {error}")
