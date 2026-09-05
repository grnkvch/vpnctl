#!/usr/bin/env python3
import argparse
import json
import re
import subprocess


SUMMARY = re.compile(r"(\d+) packets transmitted, (\d+) received, .*?([0-9.]+)% packet loss")
RTT = re.compile(r"= ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms")


def main() -> None:
    parser = argparse.ArgumentParser(description="five-client WireGuard capacity workload")
    parser.add_argument("--duration", type=int, required=True)
    args = parser.parse_args()
    if args.duration < 1:
        raise ValueError("duration must be positive")
    processes = []
    for index in range(1, 6):
        command = [
            "ip", "netns", "exec", f"v2capc{index}",
            "ping", "-n", "-q", "-i", "1", "-c", str(args.duration), "-W", "2", "10.66.0.1",
        ]
        processes.append((index, subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)))
    clients = []
    for index, process in processes:
        stdout, stderr = process.communicate(timeout=args.duration + 30)
        summary = SUMMARY.search(stdout)
        rtt = RTT.search(stdout)
        if summary is None:
            raise RuntimeError(f"client {index} ping did not emit a summary: {stderr.strip()}")
        transmitted, received, loss = summary.groups()
        clients.append({
            "client": index,
            "transmitted": int(transmitted),
            "received": int(received),
            "packet_loss_percent": float(loss),
            "rtt_ms": {
                "minimum": float(rtt.group(1)) if rtt else 0.0,
                "average": float(rtt.group(2)) if rtt else 0.0,
                "maximum": float(rtt.group(3)) if rtt else 0.0,
            },
            "exit_code": process.returncode,
        })
    passed = all(item["exit_code"] == 0 and item["packet_loss_percent"] == 0 for item in clients)
    print(json.dumps({
        "schema_version": 1,
        "status": "passed" if passed else "failed",
        "duration_seconds": args.duration,
        "clients": clients,
    }, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
