#!/bin/bash
set -euo pipefail

unit=
public_ip=
certificate=
down_seconds=
recovery_limit_seconds=
restart_pid=
restart_timing_file=
restore_required=false

usage() {
  echo 'usage: fault.sh --unit UNIT --public-ip IP --certificate FILE --down-seconds N --recovery-limit-seconds N'
}

monotonic() {
  python3 -c 'import time; print(time.monotonic())'
}

delta() {
  awk -v start="$1" -v finish="$2" 'BEGIN {value=finish-start; if (value < 0) value=0; printf "%.3f", value}'
}

probe() {
  python3 /usr/local/libexec/vpnctl-v2-capacity/load probe \
    --public-ip "$public_ip" --certificate "$certificate" --body-bytes 128 --timeout 1
}

cleanup() {
  local status=$?
  if [ -n "$restart_pid" ]; then
    wait "$restart_pid" >/dev/null 2>&1 || true
  fi
  if [ "$restore_required" = true ]; then
    systemctl start "$unit" >/dev/null 2>&1 || true
  fi
  if [ -n "$restart_timing_file" ]; then
    rm -f -- "$restart_timing_file"
  fi
  exit "$status"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --unit) unit=${2:-}; shift 2 ;;
    --public-ip) public_ip=${2:-}; shift 2 ;;
    --certificate) certificate=${2:-}; shift 2 ;;
    --down-seconds) down_seconds=${2:-}; shift 2 ;;
    --recovery-limit-seconds) recovery_limit_seconds=${2:-}; shift 2 ;;
    *) usage >&2; exit 2 ;;
  esac
done

[ "$unit" = vpnctl-v2-spike-tunnel-server.service ] || { echo 'unexpected fault target unit' >&2; exit 2; }
[ -n "$public_ip" ] && [ -f "$certificate" ] || { usage >&2; exit 2; }
awk -v value="$down_seconds" 'BEGIN {exit !(value > 0)}'
awk -v value="$recovery_limit_seconds" 'BEGIN {exit !(value > 0)}'

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

stop_started=$(monotonic)
systemctl stop --no-block "$unit"
restore_required=true
sleep 0.25
systemctl kill --kill-who=main --signal=KILL "$unit" >/dev/null 2>&1 || true
stop_state=
for _attempt in $(seq 1 20); do
  stop_state=$(systemctl show --value -p ActiveState "$unit")
  if [ "$stop_state" = inactive ] || [ "$stop_state" = failed ]; then
    break
  fi
  sleep 0.1
done
if [ "$stop_state" != inactive ] && [ "$stop_state" != failed ]; then
  echo 'FRP server did not stop within the bounded fault-injection window' >&2
  exit 1
fi
stop_finished=$(monotonic)

restart_timing_file=$(mktemp /run/vpnctl-v2-capacity-restart.XXXXXX)
down_started=$(monotonic)
(
  sleep "$down_seconds"
  restart_started=$(monotonic)
  systemctl start "$unit"
  restart_finished=$(monotonic)
  printf '%s %s\n' "$restart_started" "$restart_finished" > "$restart_timing_file"
) &
restart_pid=$!

unavailable_probe=$(probe 2>/dev/null || true)
unavailable_status=$(printf '%s\n' "$unavailable_probe" | jq -r '.status' 2>/dev/null || true)

wait "$restart_pid"
restart_pid=
restore_required=false
read -r restart_started restart_finished < "$restart_timing_file"
[ "$unavailable_status" = 503 ] || { echo 'ingress did not return 503 while frps was stopped' >&2; exit 1; }

stable=0
recovered=false
probe_output=
recovery_finished=$restart_finished
deadline=$(awk -v start="$restart_started" -v limit="$recovery_limit_seconds" 'BEGIN {printf "%.9f", start+limit}')
while awk -v now="$(monotonic)" -v deadline="$deadline" 'BEGIN {exit !(now <= deadline)}'; do
  probe_output=$(probe 2>/dev/null || true)
  if printf '%s\n' "$probe_output" | jq -e '.status == 200 and .ok == true' >/dev/null 2>&1; then
    stable=$((stable + 1))
    if [ "$stable" -eq 5 ]; then
      recovered=true
      recovery_finished=$(monotonic)
      break
    fi
  else
    stable=0
  fi
  sleep 0.1
done
[ "$recovered" = true ] || { echo 'FRP did not reconnect within the bounded recovery window' >&2; exit 1; }

jq -n \
  --argjson unavailable_probe "$unavailable_probe" \
  --argjson stop_seconds "$(delta "$stop_started" "$stop_finished")" \
  --argjson requested_down_seconds "$down_seconds" \
  --argjson down_seconds "$(delta "$down_started" "$restart_started")" \
  --argjson recovery_seconds "$(delta "$restart_started" "$recovery_finished")" \
  '{
    unavailable_status: $unavailable_probe.status,
    unavailable_probe: $unavailable_probe,
    stop_seconds: $stop_seconds,
    requested_down_seconds: $requested_down_seconds,
    down_seconds: $down_seconds,
    recovery_seconds: $recovery_seconds,
    stable_recovery_probes: 5,
    recovered_without_client_restart: true
  }'
