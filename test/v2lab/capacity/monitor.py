#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import time


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


def cpu_sample() -> tuple[int, int]:
    with open("/proc/stat", encoding="ascii") as source:
        fields = source.readline().split()[1:]
    values = [int(value) for value in fields]
    return sum(values), values[3] + values[4]


def cgroup_for(unit: str) -> str:
    value = os.popen(f"systemctl show --value -p ControlGroup {unit}").read().strip()
    if not value or not value.startswith("/"):
        raise RuntimeError(f"unit has no cgroup: {unit}")
    return "/sys/fs/cgroup" + value


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
    args = parser.parse_args()
    groups = {unit: cgroup_for(unit) for unit in args.unit}
    service_peaks = {unit: 0 for unit in args.unit}
    service_oom_before = {
        unit: read_pairs(os.path.join(root, "memory.events")).get("oom_kill", 0)
        for unit, root in groups.items()
    }
    total_before, idle_before = cpu_sample()
    total_previous, idle_previous = total_before, idle_before
    interval_cpu = []
    minimum_available = 1 << 62
    maximum_resident = 0
    maximum_swap_used = 0
    minimum_disk_free = 1 << 62
    disk_free_before = shutil.disk_usage("/").free
    samples = 0
    started = time.monotonic()
    while True:
        memory = read_pairs("/proc/meminfo")
        available = memory["MemAvailable"] * 1024
        resident = (memory["MemTotal"] - memory["MemAvailable"]) * 1024
        swap_used = (memory["SwapTotal"] - memory["SwapFree"]) * 1024
        minimum_available = min(minimum_available, available)
        maximum_resident = max(maximum_resident, resident)
        maximum_swap_used = max(maximum_swap_used, swap_used)
        minimum_disk_free = min(minimum_disk_free, shutil.disk_usage("/").free)
        for unit, root in groups.items():
            service_peaks[unit] = max(service_peaks[unit], cgroup_value(root, "memory.current"))
        total, idle = cpu_sample()
        delta_total = total - total_previous
        delta_idle = idle - idle_previous
        if delta_total > 0:
            interval_cpu.append(100.0 * (delta_total - delta_idle) / delta_total)
        total_previous, idle_previous = total, idle
        samples += 1
        remaining = args.duration - (time.monotonic() - started)
        if remaining <= 0:
            break
        time.sleep(min(args.interval, remaining))
    total_after, idle_after = cpu_sample()
    delta_total = total_after - total_before
    delta_idle = idle_after - idle_before
    average_cpu = 100.0 * (delta_total - delta_idle) / delta_total if delta_total else 0.0
    service_oom = {
        unit: read_pairs(os.path.join(root, "memory.events")).get("oom_kill", 0) - service_oom_before[unit]
        for unit, root in groups.items()
    }
    disk_free_after = shutil.disk_usage("/").free
    print(json.dumps({
        "schema_version": 1,
        "status": "completed",
        "samples": samples,
        "duration_seconds": round(time.monotonic() - started, 3),
        "cpu_percent": {
            "average": round(average_cpu, 3),
            "maximum_interval": round(max(interval_cpu), 3) if interval_cpu else 0.0,
        },
        "memory": {
            "minimum_available_bytes": minimum_available,
            "maximum_resident_estimate_bytes": maximum_resident,
            "maximum_swap_used_bytes": maximum_swap_used,
        },
        "disk": {
            "free_before_bytes": disk_free_before,
            "minimum_free_bytes": minimum_disk_free,
            "free_after_bytes": disk_free_after,
            "growth_bytes": max(0, disk_free_before - disk_free_after),
        },
        "services": {
            unit: {"maximum_memory_current_bytes": service_peaks[unit], "oom_kills": service_oom[unit]}
            for unit in args.unit
        },
        "monitor_overhead_included_in_host_totals": True,
    }, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
