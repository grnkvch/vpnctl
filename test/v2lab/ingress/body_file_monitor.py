#!/usr/bin/env python3
import argparse
import json
import os
import stat
import time


def regular_file_count(paths: list[str]) -> int:
    count = 0
    for root_path in paths:
        if not os.path.isdir(root_path):
            continue
        for directory, _, names in os.walk(root_path):
            for name in names:
                try:
                    mode = os.stat(os.path.join(directory, name), follow_symlinks=False).st_mode
                except FileNotFoundError:
                    continue
                if stat.S_ISREG(mode):
                    count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="observe nginx request/response temp directories without logging bodies")
    parser.add_argument("--directory", action="append", required=True)
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.duration <= 0 or args.duration > 60:
        raise ValueError("duration must be between 0 and 60 seconds")

    deadline = time.monotonic() + args.duration
    samples = 0
    maximum = 0
    while time.monotonic() < deadline:
        maximum = max(maximum, regular_file_count(args.directory))
        samples += 1
        time.sleep(0.002)
    maximum = max(maximum, regular_file_count(args.directory))
    result = {
        "directories": len(args.directory),
        "max_regular_files": maximum,
        "samples": samples,
        "status": "passed" if maximum == 0 else "failed",
    }
    temporary = f"{args.output}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(result, output, separators=(",", ":"), sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, args.output)


if __name__ == "__main__":
    main()
