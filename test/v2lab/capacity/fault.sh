#!/bin/bash
set -euo pipefail

unit=
public_ip=
certificate=
down_seconds=
recovery_limit_seconds=
restart_job=vpnctl-v2-capacity-frps-restart
restart_job_armed=false
restore_required=false
restart_advance_seconds=0.1
first_recovery_seconds=null
last_recovery_seconds=null
maximum_stable_recovery_probes=0
recovery_probe_attempts=0
successful_recovery_probes=0
recovery_seconds=0

usage() {
  echo 'usage: fault.sh --unit UNIT --public-ip IP --certificate FILE --down-seconds N --recovery-limit-seconds N'
}

monotonic() {
  python3 -c 'import time; print(time.monotonic())'
}

delta() {
  awk -v start="$1" -v finish="$2" 'BEGIN {value=finish-start; if (value < 0) value=0; printf "%.3f", value}'
}

emit_result() {
  local result_status=$1 stable_recovery=$2
  jq -n \
    --arg status "$result_status" \
    --argjson unavailable_probe "$unavailable_probe" \
    --argjson stop_seconds "$(delta "$stop_started" "$stop_finished")" \
    --argjson requested_down_seconds "$down_seconds" \
    --argjson scheduled_down_seconds "$scheduled_down_seconds" \
    --argjson down_seconds "$(delta "$down_started" "$restart_started")" \
    --argjson recovery_seconds "$recovery_seconds" \
    --argjson first_recovery_seconds "$first_recovery_seconds" \
    --argjson last_recovery_seconds "$last_recovery_seconds" \
    --argjson maximum_stable_recovery_probes "$maximum_stable_recovery_probes" \
    --argjson recovery_probe_attempts "$recovery_probe_attempts" \
    --argjson successful_recovery_probes "$successful_recovery_probes" \
    --argjson stable_recovery "$stable_recovery" \
    '{
      status: $status,
      unavailable_status: $unavailable_probe.status,
      unavailable_probe: $unavailable_probe,
      stop_seconds: $stop_seconds,
      requested_down_seconds: $requested_down_seconds,
      scheduled_down_seconds: $scheduled_down_seconds,
      down_seconds: $down_seconds,
      recovery_seconds: $recovery_seconds,
      first_recovery_seconds: $first_recovery_seconds,
      last_recovery_seconds: $last_recovery_seconds,
      maximum_stable_recovery_probes: $maximum_stable_recovery_probes,
      recovery_probe_attempts: $recovery_probe_attempts,
      successful_recovery_probes: $successful_recovery_probes,
      stable_recovery_probes: 5,
      stable_recovery_observed: $stable_recovery
    }'
}

probe() {
  python3 /usr/local/libexec/vpnctl-v2-capacity/load probe \
    --public-ip "$public_ip" --certificate "$certificate" --body-bytes 128 --timeout 1
}

recover() {
  python3 /usr/local/libexec/vpnctl-v2-capacity/load recover \
    --public-ip "$public_ip" --certificate "$certificate" --body-bytes 128 --timeout 1 \
    --started-monotonic "$restart_started" --recovery-limit-seconds "$recovery_limit_seconds" \
    --stable-probes 5 --probe-interval 0.1
}

cleanup() {
  local status=$?
  if [ "$restart_job_armed" = true ]; then
    systemctl stop "$restart_job.timer" "$restart_job.service" >/dev/null 2>&1 || true
    systemctl reset-failed "$restart_job.timer" "$restart_job.service" >/dev/null 2>&1 || true
    restart_job_armed=false
  fi
  if [ "$restore_required" = true ]; then
    systemctl start "$unit" >/dev/null 2>&1 || true
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
scheduled_down_seconds=$(awk -v value="$down_seconds" -v advance="$restart_advance_seconds" '
  BEGIN {value -= advance; if (value <= 0) exit 1; printf "%.3f", value}
')

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

stop_started=$(monotonic)
systemctl stop --no-block "$unit"
restore_required=true
sleep 0.25
down_started=$(monotonic)
fault_active_state=$(systemctl show --value -p ActiveState "$unit")
if [ "$fault_active_state" != inactive ] && [ "$fault_active_state" != failed ]; then
  systemctl kill --kill-whom=all --signal=KILL "$unit" >/dev/null
fi
systemd-run --quiet --collect --unit="$restart_job" \
  --on-active="${scheduled_down_seconds}s" --timer-property=AccuracySec=10ms \
  /bin/systemctl start "$unit"
restart_job_armed=true

unavailable_probe=$(probe 2>/dev/null || true)
unavailable_status=$(printf '%s\n' "$unavailable_probe" | jq -r '.status' 2>/dev/null || true)
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
restart_state=
for _attempt in $(seq 1 120); do
  restart_state=$(systemctl show --value -p ActiveState "$unit")
  if [ "$restart_state" = active ]; then
    break
  fi
  sleep 0.1
done
if [ "$restart_state" != active ]; then
  echo 'FRP server did not restart within the bounded fault-injection window' >&2
  exit 1
fi
restart_started_microseconds=$(systemctl show --value -p ActiveEnterTimestampMonotonic "$unit")
if ! [[ "$restart_started_microseconds" =~ ^[1-9][0-9]*$ ]]; then
  echo 'FRP server restart timestamp is invalid' >&2
  exit 1
fi
restart_started=$(awk -v value="$restart_started_microseconds" 'BEGIN {printf "%.9f", value/1000000}')
systemctl stop "$restart_job.timer" "$restart_job.service" >/dev/null 2>&1 || true
systemctl reset-failed "$restart_job.timer" "$restart_job.service" >/dev/null 2>&1 || true
restart_job_armed=false
restore_required=false
if [ "$unavailable_status" != 503 ]; then
  emit_result failed false
  echo 'ingress did not return 503 while frps was stopped' >&2
  exit 1
fi

recovery_result=$(recover 2>/dev/null || true)
if ! printf '%s\n' "$recovery_result" | jq -e '
  (.status == "passed" or .status == "failed") and
  (.recovery_seconds | type == "number" and . >= 0) and
  ((.first_recovery_seconds == null) or (.first_recovery_seconds | type == "number" and . >= 0)) and
  ((.last_recovery_seconds == null) or (.last_recovery_seconds | type == "number" and . >= 0)) and
  (.maximum_stable_recovery_probes | type == "number" and . >= 0 and . <= 5 and floor == .) and
  (.recovery_probe_attempts | type == "number" and . > 0 and floor == .) and
  (.successful_recovery_probes | type == "number" and . >= 0 and floor == .) and
  (.successful_recovery_probes <= .recovery_probe_attempts)
' >/dev/null 2>&1; then
  emit_result failed false
  echo 'FRP recovery probe returned invalid evidence' >&2
  exit 1
fi
recovery_status=$(printf '%s\n' "$recovery_result" | jq -r '.status')
recovery_seconds=$(printf '%s\n' "$recovery_result" | jq -c '.recovery_seconds')
first_recovery_seconds=$(printf '%s\n' "$recovery_result" | jq -c '.first_recovery_seconds')
last_recovery_seconds=$(printf '%s\n' "$recovery_result" | jq -c '.last_recovery_seconds')
maximum_stable_recovery_probes=$(printf '%s\n' "$recovery_result" | jq -c '.maximum_stable_recovery_probes')
recovery_probe_attempts=$(printf '%s\n' "$recovery_result" | jq -c '.recovery_probe_attempts')
successful_recovery_probes=$(printf '%s\n' "$recovery_result" | jq -c '.successful_recovery_probes')
if [ "$recovery_status" != passed ]; then
  emit_result failed false
  echo 'FRP did not reconnect within the bounded recovery window' >&2
  exit 1
fi

emit_result passed true
