#!/bin/bash
set -euo pipefail

node_ns=vpnctl-v2-rnode
engine_unit=vpnctl-v2-spike-routing-engine.service
runtime_root=/run/vpnctl-v2-spike-routing
probe=/usr/local/libexec/vpnctl-v2-spike-routing/probe
policy=/usr/local/libexec/vpnctl-v2-spike-routing/policy

node_exec() {
  ip netns exec "$node_ns" "$@"
}

wait_file() {
  local path=$1 attempt
  for attempt in $(seq 1 80); do
    [ -e "$path" ] && return
    sleep 0.1
  done
  echo "timed out waiting for $path" >&2
  exit 1
}

wait_readiness() {
  local expected=$1 attempt current
  for attempt in $(seq 1 200); do
    current=$(node_exec "$policy" status | jq -r '.readiness')
    [ "$current" = "$expected" ] && return
    sleep 0.1
  done
  echo "timed out waiting for routing readiness $expected" >&2
  exit 1
}

blocked() {
  node_exec "$probe" blocked --protocol "$1" --host "$2" --port 18080 --timeout 0.4 >/dev/null
}

request() {
  node_exec "$probe" request --protocol "$1" --host "$2" --port "$3" --expect "$4" --timeout 1 >/dev/null
}

crash_case() {
  local output=$1 hold_pid
  local ready="$runtime_root/hold-ready.json"
  local signal_path="$runtime_root/hold-signal"
  local result="$runtime_root/hold-result.json"
  rm -f "$ready" "$signal_path" "$result"

  node_exec "$probe" hold \
    --host 203.0.113.20 --port 18080 --expect direct-unmatched \
    --ready "$ready" --signal "$signal_path" --result "$result" &
  hold_pid=$!
  wait_file "$ready"

  systemctl kill --kill-who=main --signal=KILL "$engine_unit"
  wait_readiness not-ready

  blocked tcp 203.0.113.10
  blocked udp 203.0.113.10
  blocked tcp 203.0.113.20
  blocked udp 203.0.113.20
  blocked tcp 2001:db8:1::10
  blocked udp 2001:db8:1::10
  blocked tcp 2001:db8:1::20
  blocked udp 2001:db8:1::20
  request tcp 10.202.0.1 19000 recovery

  install -m 0600 /dev/null "$signal_path"
  wait "$hold_pid"
  jq -e '.status == "passed"' "$result" >/dev/null

  wait_readiness ready
  request tcp 203.0.113.10 18080 gateway-selected
  jq -n \
    --arg status passed \
    --slurpfile retained "$result" \
    '{schema_version: 1, status: $status, guard_after_crash: "not-ready", established_direct_retained: ($retained[0].status == "passed"), new_selected_blocked: true, new_direct_blocked: true, recovery_allowed: true, automatic_restart_ready: true}' \
    > "$output"
}

restart_case() {
  local output=$1 tcp_pid udp_pid ipv6_pid
  local tcp_storm="$runtime_root/restart-tcp.json"
  local udp_storm="$runtime_root/restart-udp.json"
  local ipv6_storm="$runtime_root/restart-ipv6.json"
  rm -f "$tcp_storm" "$udp_storm" "$ipv6_storm"
  node_exec "$probe" storm \
    --protocol tcp --host 203.0.113.10 --port 18080 \
    --expect gateway-selected --timeout 0.25 --duration 15 > "$tcp_storm" &
  tcp_pid=$!
  node_exec "$probe" storm \
    --protocol udp --host 203.0.113.10 --port 18080 \
    --expect gateway-selected --timeout 0.25 --duration 15 > "$udp_storm" &
  udp_pid=$!
  node_exec "$probe" storm \
    --protocol udp --host 2001:db8:1::10 --port 18080 \
    --expect never-direct --timeout 0.25 --duration 15 > "$ipv6_storm" &
  ipv6_pid=$!
  sleep 0.5
  systemctl restart "$engine_unit"
  wait "$tcp_pid"
  wait "$udp_pid"
  wait "$ipv6_pid"
  wait_readiness ready
  jq -e '.status == "passed" and .forbidden == 0 and (.allowed + .blocked) > 0' \
    "$tcp_storm" "$udp_storm" "$ipv6_storm" >/dev/null
  jq -n \
    --slurpfile tcp "$tcp_storm" \
    --slurpfile udp "$udp_storm" \
    --slurpfile ipv6 "$ipv6_storm" \
    '{schema_version: 1, status: "passed", tcp: $tcp[0], udp: $udp[0], ipv6: $ipv6[0]}' \
    > "$output"
}

case "${1:-}" in
  crash)
    [ -n "${2:-}" ] || { echo "missing crash evidence path" >&2; exit 2; }
    crash_case "$2"
    ;;
  restart)
    [ -n "${2:-}" ] || { echo "missing restart evidence path" >&2; exit 2; }
    restart_case "$2"
    ;;
  *) echo "usage: fault.sh <crash|restart> <evidence-path>" >&2; exit 2 ;;
esac
