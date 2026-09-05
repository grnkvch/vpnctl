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
restart_advance_seconds=0.2
runtime_dropin_directory=/run/systemd/system/vpnctl-v2-spike-tunnel-server.service.d
runtime_dropin=$runtime_dropin_directory/vpnctl-v2-capacity-fault.conf
runtime_dropin_installed=false
runtime_dropin_directory_created=false
runtime_dropin_sha256=9b6943ff77b31e063152214a3aa57a6f73782b14434700170a0f30ca70ef2524
original_restart=
first_recovery_seconds=null
last_recovery_seconds=null
maximum_stable_recovery_probes=0
recovery_probe_attempts=0
successful_recovery_probes=0
recovery_seconds=0
unavailable_probe='{"status":null,"ok":false,"error":"fault_incomplete"}'
stop_started=0
stop_finished=0
down_started=0
restart_started=0
result_emitted=false
fault_stage=preflight
armed_probe_root=/var/lib/vpnctl-v2-capacity/fault-probe
armed_probe_pid=
armed_probe_root_created=false

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
  result_emitted=true
  jq -n \
    --arg status "$result_status" \
    --arg fault_stage "$fault_stage" \
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
      fault_stage: $fault_stage,
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

prepare_armed_probe() {
  local armed_ready=false
  if [ -e "$armed_probe_root" ] || [ -L "$armed_probe_root" ]; then
    echo 'refusing existing armed probe runtime' >&2
    return 3
  fi
  mkdir -m 0700 -- "$armed_probe_root"
  armed_probe_root_created=true
  python3 /usr/local/libexec/vpnctl-v2-capacity/load armed-probe \
    --public-ip "$public_ip" --certificate "$certificate" --body-bytes 128 --timeout 2 \
    --trigger-file "$armed_probe_root/trigger" --ready-file "$armed_probe_root/ready" \
    --trigger-timeout 30 > "$armed_probe_root/result.json" &
  armed_probe_pid=$!
  for _attempt in $(seq 1 200); do
    if [ -f "$armed_probe_root/ready" ] && [ ! -L "$armed_probe_root/ready" ]; then
      armed_ready=true
      break
    fi
    if ! kill -0 "$armed_probe_pid" 2>/dev/null; then
      wait "$armed_probe_pid" || true
      armed_probe_pid=
      echo 'armed HTTPS probe exited before readiness' >&2
      return 1
    fi
    sleep 0.05
  done
  if [ "$armed_ready" != true ]; then
    echo 'armed HTTPS probe did not become ready' >&2
    return 1
  fi
}

run_armed_probe() {
  : > "$armed_probe_root/trigger"
  if ! wait "$armed_probe_pid"; then
    armed_probe_pid=
    echo 'armed HTTPS probe failed' >&2
    return 1
  fi
  armed_probe_pid=
  unavailable_probe=$(cat "$armed_probe_root/result.json")
}

cleanup_armed_probe() {
  local cleanup_status=0
  if [ -n "$armed_probe_pid" ]; then
    kill "$armed_probe_pid" >/dev/null 2>&1 || true
    wait "$armed_probe_pid" >/dev/null 2>&1 || true
    armed_probe_pid=
  fi
  if [ "$armed_probe_root_created" = true ]; then
    if [ ! -d "$armed_probe_root" ] || [ -L "$armed_probe_root" ]; then
      echo 'refusing cleanup of changed armed probe runtime type' >&2
      return 3
    fi
    rm -f -- "$armed_probe_root/trigger" "$armed_probe_root/ready" "$armed_probe_root/result.json" || cleanup_status=$?
    rmdir "$armed_probe_root" || cleanup_status=$?
    armed_probe_root_created=false
  fi
  return "$cleanup_status"
}

recover() {
  python3 /usr/local/libexec/vpnctl-v2-capacity/load recover \
    --public-ip "$public_ip" --certificate "$certificate" --body-bytes 128 --timeout 1 \
    --started-monotonic "$restart_started" --recovery-limit-seconds "$recovery_limit_seconds" \
    --stable-probes 5 --probe-interval 0.1
}

restore_restart_policy() {
  local actual_sha256 current_restart
  if [ "$runtime_dropin_installed" != true ]; then
    return
  fi
  if [ ! -f "$runtime_dropin" ] || [ -L "$runtime_dropin" ]; then
    echo 'refusing to remove changed FRPS fault drop-in type' >&2
    return 3
  fi
  actual_sha256=$(sha256sum "$runtime_dropin" | awk '{print $1}')
  if [ "$actual_sha256" != "$runtime_dropin_sha256" ]; then
    echo 'refusing to remove changed FRPS fault drop-in contents' >&2
    return 3
  fi
  rm -f -- "$runtime_dropin"
  runtime_dropin_installed=false
  if [ "$runtime_dropin_directory_created" = true ]; then
    rmdir "$runtime_dropin_directory" 2>/dev/null || true
    runtime_dropin_directory_created=false
  fi
  systemctl daemon-reload
  current_restart=$(systemctl show --value -p Restart "$unit")
  if [ "$current_restart" != "$original_restart" ]; then
    echo 'FRPS restart policy was not restored' >&2
    return 3
  fi
}

cleanup() {
  local status=$? cleanup_status=0
  trap - EXIT INT TERM
  set +e
  if [ "$restart_job_armed" = true ]; then
    systemctl stop "$restart_job.timer" "$restart_job.service" >/dev/null 2>&1 || true
    systemctl reset-failed "$restart_job.timer" "$restart_job.service" >/dev/null 2>&1 || true
    restart_job_armed=false
  fi
  cleanup_armed_probe || cleanup_status=$?
  restore_restart_policy || cleanup_status=$?
  if [ "$restore_required" = true ]; then
    systemctl start "$unit" >/dev/null 2>&1 || cleanup_status=$?
  fi
  if [ "$status" -eq 0 ] && [ "$cleanup_status" -ne 0 ]; then
    status=$cleanup_status
  fi
  if [ "$status" -ne 0 ] && [ "$result_emitted" != true ]; then
    emit_result failed false || true
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

original_restart=$(systemctl show --value -p Restart "$unit")
if [ "$original_restart" != on-failure ]; then
  echo 'unexpected FRPS restart policy' >&2
  exit 3
fi
prepare_armed_probe
if [ -L "$runtime_dropin_directory" ] || { [ -e "$runtime_dropin_directory" ] && [ ! -d "$runtime_dropin_directory" ]; }; then
  echo 'refusing unsafe FRPS runtime drop-in directory' >&2
  exit 3
fi
if [ -e "$runtime_dropin" ] || [ -L "$runtime_dropin" ]; then
  echo 'refusing existing FRPS capacity fault drop-in' >&2
  exit 3
fi
if [ ! -d "$runtime_dropin_directory" ]; then
  mkdir -- "$runtime_dropin_directory"
  runtime_dropin_directory_created=true
fi
(
  umask 022
  set -o noclobber
  printf '[Service]\nRestart=no\n' > "$runtime_dropin"
)
runtime_dropin_installed=true
systemctl daemon-reload
[ "$(systemctl show --value -p Restart "$unit")" = no ] || {
  echo 'FRPS temporary restart policy was not applied' >&2
  exit 3
}
fault_stage=armed
systemd-run --quiet --collect --unit="$restart_job" \
  --on-active="${scheduled_down_seconds}s" --timer-property=AccuracySec=10ms \
  /bin/systemctl start "$unit"
restart_job_armed=true
restore_required=true
down_started=$(monotonic)
stop_started=$down_started
restart_started=$down_started
systemctl kill --kill-whom=main --signal=KILL "$unit" >/dev/null
fault_stage=killed

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
fault_stage=stopped
run_armed_probe
unavailable_status=$(printf '%s\n' "$unavailable_probe" | jq -r '.status' 2>/dev/null || true)
cleanup_armed_probe
fault_stage=unavailable_probed
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
fault_stage=restarted
systemctl stop "$restart_job.timer" "$restart_job.service" >/dev/null 2>&1 || true
systemctl reset-failed "$restart_job.timer" "$restart_job.service" >/dev/null 2>&1 || true
restart_job_armed=false
restore_restart_policy
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

fault_stage=recovered
emit_result passed true
