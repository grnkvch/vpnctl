#!/bin/bash
set -euo pipefail

role=${1:?role is required}
peer_ip=${2:-}

timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
hostname_value=$(hostname)
os_id=$(awk -F= '$1 == "ID" {gsub(/"/, "", $2); print $2}' /etc/os-release)
os_version=$(awk -F= '$1 == "VERSION_ID" {gsub(/"/, "", $2); print $2}' /etc/os-release)
architecture=$(dpkg --print-architecture)
vcpus=$(nproc)
memory_bytes=$(awk '$1 == "MemTotal:" {printf "%.0f\n", $2 * 1024}' /proc/meminfo)
swap_bytes=$(awk '$1 == "SwapTotal:" {printf "%.0f\n", $2 * 1024}' /proc/meminfo)
read -r disk_bytes disk_available_bytes < <(df -B1 --output=size,avail / | tail -n 1)
load_1m=$(awk '{print $1}' /proc/loadavg)
read -r cpu_user cpu_system cpu_idle cpu_wait < <(vmstat 1 2 | awk '
  NR == 2 {
    for (i = 1; i <= NF; i++) {
      column[$i] = i
    }
  }
  END {print $(column["us"]), $(column["sy"]), $(column["id"]), $(column["wa"])}')
total_rss_kib=$(ps -e -o rss= | awk '{sum += $1} END {print sum + 0}')
processes=$(ps -e -o pid=,comm=,rss= --sort=-rss | awk 'NR <= 20' | jq -R -s '
  [splits("\\n")
   | select(length > 0)
   | capture("^\\s*(?<pid>[0-9]+)\\s+(?<command>\\S+)\\s+(?<rss>[0-9]+)\\s*$")
   | {pid: (.pid | tonumber), command: .command, rss_kib: (.rss | tonumber)}]')
sockets=$(ss -H -tunlp | jq -R -s '[splits("\\n") | select(length > 0)]')
addresses=$(ip -4 -j address show scope global | jq '[.[].addr_info[] | select(.family == "inet") | .local]')

latency_ms=null
packet_loss_percent=null
if [ -n "$peer_ip" ]; then
  ping_output=$(ping -n -c 3 -W 2 "$peer_ip" 2>&1 || true)
  measured_latency=$(awk -F'/' '/^(rtt|round-trip)/ {print $5}' <<<"$ping_output")
  measured_loss=$(awk -F', ' '/packet loss/ {gsub(/% packet loss/, "", $3); print $3}' <<<"$ping_output")
  if [ -n "$measured_latency" ]; then
    latency_ms=$measured_latency
  fi
  if [[ "$measured_loss" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    packet_loss_percent=$measured_loss
  fi
fi

jq -n \
  --arg timestamp "$timestamp" \
  --arg role "$role" \
  --arg hostname "$hostname_value" \
  --arg os_id "$os_id" \
  --arg os_version "$os_version" \
  --arg architecture "$architecture" \
  --arg peer_ip "$peer_ip" \
  --argjson vcpus "$vcpus" \
  --argjson memory_bytes "$memory_bytes" \
  --argjson swap_bytes "$swap_bytes" \
  --argjson disk_bytes "$disk_bytes" \
  --argjson disk_available_bytes "$disk_available_bytes" \
  --argjson load_1m "$load_1m" \
  --argjson cpu_user_percent "$cpu_user" \
  --argjson cpu_system_percent "$cpu_system" \
  --argjson cpu_idle_percent "$cpu_idle" \
  --argjson cpu_wait_percent "$cpu_wait" \
  --argjson total_rss_kib "$total_rss_kib" \
  --argjson processes "$processes" \
  --argjson sockets "$sockets" \
  --argjson addresses "$addresses" \
  --argjson latency_ms "$latency_ms" \
  --argjson packet_loss_percent "$packet_loss_percent" \
  '{
    schema_version: 1,
    timestamp: $timestamp,
    role: $role,
    host: {
      hostname: $hostname,
      os: $os_id,
      os_version: $os_version,
      architecture: $architecture,
      vcpus: $vcpus,
      memory_bytes: $memory_bytes,
      swap_bytes: $swap_bytes,
      disk_bytes: $disk_bytes,
      disk_available_bytes: $disk_available_bytes,
      addresses: $addresses
    },
    cpu: {
      load_1m: $load_1m,
      user_percent: $cpu_user_percent,
      system_percent: $cpu_system_percent,
      idle_percent: $cpu_idle_percent,
      wait_percent: $cpu_wait_percent
    },
    rss: {
      total_kib: $total_rss_kib,
      top_processes: $processes
    },
    sockets: $sockets,
    peer: {
      address: (if $peer_ip == "" then null else $peer_ip end),
      latency_ms: $latency_ms,
      packet_loss_percent: $packet_loss_percent
    }
  }'
