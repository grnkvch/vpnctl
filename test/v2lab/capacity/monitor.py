#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import time
import urllib.request


def read_pairs(path: str) -> dict[str, int]:
    result = {}
    try:
        with open(path, encoding="ascii") as source:
            for line in source:
                key, value, *_ = line.split()
                result[key.rstrip(":")] = int(value)
    except FileNotFoundError:
        pass
    return result


def cpu_sample() -> dict[str, int]:
    with open("/proc/stat", encoding="ascii") as source:
        fields = source.readline().split()[1:]
    values = [int(value) for value in fields]
    names = ["user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"]
    counters = {
        name: values[index] if index < len(values) else 0
        for index, name in enumerate(names)
    }
    counters["total"] = sum(values)
    return counters


def cpu_delta(before: dict[str, int], after: dict[str, int]) -> dict[str, float]:
    total = after["total"] - before["total"]
    if total <= 0:
        return {"busy": 0.0, "iowait": 0.0, "steal": 0.0}
    idle = after["idle"] - before["idle"]
    iowait = after["iowait"] - before["iowait"]
    steal = after["steal"] - before["steal"]
    return {
        "busy": 100.0 * (total - idle - iowait) / total,
        "iowait": 100.0 * iowait / total,
        "steal": 100.0 * steal / total,
    }


def load_sample() -> dict[str, float | int]:
    with open("/proc/loadavg", encoding="ascii") as source:
        load1, load5, load15, processes, _last_pid = source.read().split()
    running, total = processes.split("/", 1)
    return {
        "load1": float(load1),
        "load5": float(load5),
        "load15": float(load15),
        "run_queue": int(running),
        "processes": int(total),
    }


def cgroup_for(unit: str) -> str:
    value = os.popen(f"systemctl show --value -p ControlGroup {unit}").read().strip()
    if not value or not value.startswith("/"):
        raise RuntimeError(f"unit has no cgroup: {unit}")
    return "/sys/fs/cgroup" + value


def unit_integer(unit: str, property_name: str) -> int:
    value = os.popen(
        f"systemctl show --value -p {property_name} {unit}"
    ).read().strip()
    return int(value)


def unit_state(unit: str, cgroup_root: str) -> dict[str, object]:
    process = subprocess.run(
        [
            "systemctl",
            "show",
            "--no-pager",
            "-p",
            "ActiveState",
            "-p",
            "SubState",
            "-p",
            "MainPID",
            "-p",
            "NRestarts",
            unit,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=1,
    )
    properties = {}
    for line in process.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            properties[key] = value
    processes = []
    try:
        with open(os.path.join(cgroup_root, "cgroup.procs"), encoding="ascii") as source:
            pids = source.read().split()
    except FileNotFoundError:
        pids = []
    for pid in pids[:64]:
        try:
            with open(f"/proc/{pid}/comm", encoding="ascii") as source:
                command = source.read().strip()
        except FileNotFoundError:
            continue
        processes.append({"pid": int(pid), "command": command})
    return {
        "active_state": properties.get("ActiveState", "unknown"),
        "sub_state": properties.get("SubState", "unknown"),
        "main_pid": int(properties.get("MainPID", "0") or 0),
        "restarts": int(properties.get("NRestarts", "0") or 0),
        "cgroup_processes": processes,
    }


def tcp_state_counts() -> dict[str, int]:
    counts = {"listen": 0, "established": 0}
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, encoding="ascii") as source:
                lines = source.readlines()[1:]
        except FileNotFoundError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 4:
                continue
            if fields[3] == "0A":
                counts["listen"] += 1
            elif fields[3] == "01":
                counts["established"] += 1
    return counts


def frpc_status(url: str, user: str, password: str) -> dict[str, object]:
    request = urllib.request.Request(url)
    credential = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
    request.add_header("Authorization", f"Basic {credential}")
    try:
        with urllib.request.urlopen(request, timeout=0.5) as response:
            body = response.read(1024 * 1024)
            return {"status": response.status, "response_bytes": len(body), "error": ""}
    except Exception as error:
        return {"status": 0, "response_bytes": 0, "error": type(error).__name__}


def cgroup_value(root: str, name: str) -> int:
    try:
        with open(os.path.join(root, name), encoding="ascii") as source:
            value = source.read().strip()
    except FileNotFoundError:
        return 0
    return 0 if value == "max" else int(value)


def main() -> None:
    parser = argparse.ArgumentParser(description="minimum-gateway resource sampler")
    parser.add_argument("--duration", type=int, required=True)
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--unit", action="append", required=True)
    parser.add_argument("--diagnostic-start", type=float, required=True)
    parser.add_argument("--diagnostic-end", type=float, required=True)
    parser.add_argument("--frpc-url")
    parser.add_argument("--frpc-user", default="vpnctl")
    args = parser.parse_args()
    if args.diagnostic_start < 0 or args.diagnostic_end <= args.diagnostic_start:
        raise ValueError("runtime diagnostic window is invalid")
    frpc_password = os.environ.get("VPNCTL_CAPACITY_FRPC_PASSWORD", "")
    if args.frpc_url and not frpc_password:
        raise ValueError("FRPC diagnostic password is absent")
    groups = {unit: cgroup_for(unit) for unit in args.unit}
    service_peaks = {unit: 0 for unit in args.unit}
    service_oom_before = {
        unit: read_pairs(os.path.join(root, "memory.events")).get("oom_kill", 0)
        for unit, root in groups.items()
    }
    service_restarts_before = {unit: unit_integer(unit, "NRestarts") for unit in args.unit}
    host_oom_before = read_pairs("/proc/vmstat").get("oom_kill", 0)
    cpu_before = cpu_sample()
    cpu_previous = cpu_before
    interval_cpu = []
    timeline = []
    minimum_available = 1 << 62
    maximum_resident = 0
    maximum_swap_used = 0
    swap_total_bytes = 0
    minimum_disk_free = 1 << 62
    disk_free_before = shutil.disk_usage("/").free
    samples = 0
    started = time.monotonic()
    while True:
        memory = read_pairs("/proc/meminfo")
        available = memory["MemAvailable"] * 1024
        resident = (memory["MemTotal"] - memory["MemAvailable"]) * 1024
        swap_used = (memory["SwapTotal"] - memory["SwapFree"]) * 1024
        swap_total_bytes = memory["SwapTotal"] * 1024
        minimum_available = min(minimum_available, available)
        maximum_resident = max(maximum_resident, resident)
        maximum_swap_used = max(maximum_swap_used, swap_used)
        minimum_disk_free = min(minimum_disk_free, shutil.disk_usage("/").free)
        for unit, root in groups.items():
            service_peaks[unit] = max(service_peaks[unit], cgroup_value(root, "memory.current"))
        cpu = cpu_sample()
        interval = cpu_delta(cpu_previous, cpu)
        current_load = load_sample()
        interval_cpu.append(interval["busy"])
        offset = time.monotonic() - started
        sample = {
            "offset_seconds": round(offset, 3),
            "cpu_percent": {key: round(value, 3) for key, value in interval.items()},
            "load": current_load,
        }
        if args.diagnostic_start <= offset <= args.diagnostic_end:
            sample["runtime"] = {
                "units": {
                    unit: unit_state(unit, groups[unit]) for unit in args.unit
                },
                "tcp": tcp_state_counts(),
                "frpc_status": (
                    frpc_status(args.frpc_url, args.frpc_user, frpc_password)
                    if args.frpc_url
                    else None
                ),
            }
        timeline.append(sample)
        cpu_previous = cpu
        samples += 1
        remaining = args.duration - (time.monotonic() - started)
        if remaining <= 0:
            break
        time.sleep(min(args.interval, remaining))
    cpu_after = cpu_sample()
    average_cpu = cpu_delta(cpu_before, cpu_after)
    service_oom = {
        unit: read_pairs(os.path.join(root, "memory.events")).get("oom_kill", 0) - service_oom_before[unit]
        for unit, root in groups.items()
    }
    service_restarts = {
        unit: unit_integer(unit, "NRestarts") - service_restarts_before[unit]
        for unit in args.unit
    }
    host_oom_kills = read_pairs("/proc/vmstat").get("oom_kill", 0) - host_oom_before
    disk_free_after = shutil.disk_usage("/").free
    print(json.dumps({
        "schema_version": 2,
        "status": "completed",
        "samples": samples,
        "duration_seconds": round(time.monotonic() - started, 3),
        "cpu_percent": {
            "average": round(average_cpu["busy"], 3),
            "maximum_interval": round(max(interval_cpu), 3) if interval_cpu else 0.0,
            "average_iowait": round(average_cpu["iowait"], 3),
            "average_steal": round(average_cpu["steal"], 3),
        },
        "scheduler": {
            "logical_cpus": os.cpu_count(),
            "maximum_load1": round(max((item["load"]["load1"] for item in timeline), default=0.0), 3),
            "maximum_run_queue": max((item["load"]["run_queue"] for item in timeline), default=0),
        },
        "timeline": timeline,
        "memory": {
            "minimum_available_bytes": minimum_available,
            "maximum_resident_estimate_bytes": maximum_resident,
            "swap_total_bytes": swap_total_bytes,
            "maximum_swap_used_bytes": maximum_swap_used,
        },
        "disk": {
            "free_before_bytes": disk_free_before,
            "minimum_free_bytes": minimum_disk_free,
            "free_after_bytes": disk_free_after,
            "growth_bytes": max(0, disk_free_before - disk_free_after),
        },
        "services": {
            unit: {
                "maximum_memory_current_bytes": service_peaks[unit],
                "oom_kills": service_oom[unit],
                "restarts": service_restarts[unit],
            }
            for unit in args.unit
        },
        "host_oom_kills": host_oom_kills,
        "monitor_overhead_included_in_host_totals": True,
    }, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
