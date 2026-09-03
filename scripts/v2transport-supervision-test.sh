#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
fixture_root="$repository_root/test/v2lab/transport-supervision"
gateway_instance=vpnctl-v2-gateway
runtime_root=/opt/vpnctl-v2-task86
owner_value=vpnctl-v2-task86-v1
owner_path="$runtime_root/.owner"
standard_unit=vpnctl-v2-task86-standard.service
restricted_unit=vpnctl-v2-task86-restricted.service
standard_unit_path="/etc/systemd/system/$standard_unit"
restricted_unit_path="/etc/systemd/system/$restricted_unit"
standard_test_port=19091
restricted_test_port=8443
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
local_binary=
local_standard_unit=
local_restricted_unit=

usage() {
  cat <<'EOF'
Usage:
  scripts/v2transport-supervision-test.sh verify
  scripts/v2transport-supervision-test.sh status
  scripts/v2transport-supervision-test.sh cleanup
EOF
}

instance_json() {
  limactl list --json | jq -ce --arg name "$1" 'select(.name == $name)'
}

assert_lab_instance() {
  if ! instance_json "$gateway_instance" | jq -e --arg digest "$lab_image_digest" '
    .status == "Running" and
    .vmType == "qemu" and
    .arch == "x86_64" and
    .cpus == 1 and
    .memory == 536870912 and
    .disk == 10737418240 and
    .config.images[0].digest == $digest and
    any(.network[]?; .lima == "user-v2")
  ' >/dev/null; then
    echo "required contract-matching lab instance is not running: $gateway_instance" >&2
    exit 4
  fi
}

ensure_instance_running() {
  local status
  status=$(instance_json "$gateway_instance" | jq -r '.status')
  if [ "$status" != Running ]; then
    limactl start "$gateway_instance"
  fi
  assert_lab_instance
}

guest() {
  limactl shell --tty=false "$gateway_instance" -- "$@"
}

assert_spikes_inactive() {
  local unit
  for unit in \
    vpnctl-v2-spike-restricted-gateway.service \
    vpnctl-v2-spike-restricted-echo.service \
    vpnctl-v2-spike-tunnel-server.service \
    vpnctl-v2-spike-ingress.service; do
    if guest systemctl is-active --quiet "$unit"; then
      echo "refusing supervision test while another gateway spike is active: $unit" >&2
      exit 3
    fi
  done
}

assert_host_ports_free() {
  local port
  for port in "$standard_test_port" "$restricted_test_port"; do
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | grep -q . || lsof -nP -iUDP:"$port" 2>/dev/null | grep -q .; then
      echo "refusing supervision test while development-host port $port is in use" >&2
      exit 3
    fi
  done
}

assert_fresh_scope() {
  local path
  for path in "$runtime_root" "$standard_unit_path" "$restricted_unit_path"; do
    if guest sudo test -e "$path"; then
      echo "refusing to adopt existing supervision test resource: $path" >&2
      exit 3
    fi
  done
  if guest sudo ss -H -lunp "sport = :$standard_test_port" | grep -q . || guest sudo ss -H -ltnp "sport = :$restricted_test_port" | grep -q .; then
    echo "refusing supervision test while a required guest port is in use" >&2
    exit 3
  fi
}

assert_owned_scope() {
  if ! guest sudo test -f "$owner_path" || ! guest sudo grep -Fxq "$owner_value" "$owner_path"; then
    echo "refusing to operate on unowned supervision runtime: $runtime_root" >&2
    return 3
  fi
  local path
  for path in "$standard_unit_path" "$restricted_unit_path"; do
    if guest sudo test -e "$path" && ! guest sudo grep -Fq "$runtime_root/listener" "$path"; then
      echo "refusing to operate on unexpected unit content: $path" >&2
      return 3
    fi
  done
}

build_inputs() {
  local_binary=$(mktemp -t vpnctl-v2-task86-listener)
  local_standard_unit=$(mktemp -t vpnctl-v2-task86-standard)
  local_restricted_unit=$(mktemp -t vpnctl-v2-task86-restricted)
  env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOCACHE=/private/tmp/vpnctl-go-cache \
    go build -trimpath -o "$local_binary" ./test/v2lab/transport-supervision
  sed "s|@RUNTIME_ROOT@|$runtime_root|g" "$fixture_root/standard.service" > "$local_standard_unit"
  sed "s|@RUNTIME_ROOT@|$runtime_root|g" "$fixture_root/restricted.service" > "$local_restricted_unit"
}

copy_input() {
  local source=$1 name=$2
  limactl copy --backend=scp "$source" "$gateway_instance:/tmp/$name"
}

install_scope() {
  guest sudo install -d -m 0700 "$runtime_root"
  guest sudo sh -c "printf '%s\\n' '$owner_value' > '$owner_path'"
  guest sudo chmod 0600 "$owner_path"
  copy_input "$local_binary" vpnctl-v2-task86-listener
  copy_input "$local_standard_unit" "$standard_unit"
  copy_input "$local_restricted_unit" "$restricted_unit"
  guest sudo install -o root -g root -m 0755 /tmp/vpnctl-v2-task86-listener "$runtime_root/listener"
  guest sudo install -o root -g root -m 0644 "/tmp/$standard_unit" "$standard_unit_path"
  guest sudo install -o root -g root -m 0644 "/tmp/$restricted_unit" "$restricted_unit_path"
  guest sudo rm -f -- /tmp/vpnctl-v2-task86-listener "/tmp/$standard_unit" "/tmp/$restricted_unit"
  local self_test_status=0
  guest sudo timeout 1 "$runtime_root/listener" --network tcp4 --address 127.0.0.1:0 || self_test_status=$?
  if [ "$self_test_status" -ne 124 ]; then
    echo "listener helper failed its isolated pre-systemd bind check: $self_test_status" >&2
    return 1
  fi
  guest sudo systemctl daemon-reload
  guest sudo systemctl enable --now "$standard_unit" "$restricted_unit"
}

wait_ready() {
  local attempt standard_pid restricted_pid standard_exe restricted_exe
  for attempt in $(seq 1 60); do
    if guest systemctl is-active --quiet "$standard_unit" && guest systemctl is-active --quiet "$restricted_unit"; then
      standard_pid=$(guest systemctl show --property MainPID --value "$standard_unit")
      restricted_pid=$(guest systemctl show --property MainPID --value "$restricted_unit")
      standard_exe=$(guest sudo readlink -f "/proc/$standard_pid/exe" 2>/dev/null || true)
      restricted_exe=$(guest sudo readlink -f "/proc/$restricted_pid/exe" 2>/dev/null || true)
      if [ "$standard_exe" = "$runtime_root/listener" ] && [ "$restricted_exe" = "$runtime_root/listener" ] && \
        guest sudo ss -H -lunp "sport = :$standard_test_port" | grep -Fq "pid=$standard_pid," && \
        guest sudo ss -H -ltnp "sport = :$restricted_test_port" | grep -Fq "pid=$restricted_pid," && \
        ! guest sudo ss -H -lunp "sport = :$restricted_test_port" | grep -q .; then
        return
      fi
    fi
    sleep 1
  done
  echo "supervised gateway listener pair did not become ready" >&2
  guest systemctl show --property ActiveState --property SubState --property MainPID --property NRestarts --property Result --property ExecMainCode --property ExecMainStatus "$standard_unit" "$restricted_unit" >&2 || true
  standard_pid=$(guest systemctl show --property MainPID --value "$standard_unit" 2>/dev/null || true)
  restricted_pid=$(guest systemctl show --property MainPID --value "$restricted_unit" 2>/dev/null || true)
  if [ -n "$standard_pid" ]; then
    guest sudo readlink -f "/proc/$standard_pid/exe" >&2 || true
  fi
  if [ -n "$restricted_pid" ]; then
    guest sudo readlink -f "/proc/$restricted_pid/exe" >&2 || true
  fi
  guest sudo ss -H -lunp "sport = :$standard_test_port" >&2 || true
  guest sudo ss -H -ltnp "sport = :$restricted_test_port" >&2 || true
  guest sudo ss -H -lunp "sport = :$restricted_test_port" >&2 || true
  return 1
}

verify_failure_restart() {
  local standard_before restricted_before standard_restarts restricted_restarts
  standard_before=$(guest systemctl show --property MainPID --value "$standard_unit")
  restricted_before=$(guest systemctl show --property MainPID --value "$restricted_unit")
  guest sudo kill -KILL "$standard_before" "$restricted_before"
  wait_ready
  if [ "$(guest systemctl show --property MainPID --value "$standard_unit")" = "$standard_before" ] || \
    [ "$(guest systemctl show --property MainPID --value "$restricted_unit")" = "$restricted_before" ]; then
    echo "systemd did not replace a failed listener process" >&2
    return 1
  fi
  standard_restarts=$(guest systemctl show --property NRestarts --value "$standard_unit")
  restricted_restarts=$(guest systemctl show --property NRestarts --value "$restricted_unit")
  if [ "$standard_restarts" -lt 1 ] || [ "$restricted_restarts" -lt 1 ]; then
    echo "systemd restart counters did not record both listener failures" >&2
    return 1
  fi
}

verify_boot_restore() {
  limactl stop "$gateway_instance"
  limactl start "$gateway_instance"
  assert_lab_instance
  wait_ready
  if [ "$(guest systemctl is-enabled "$standard_unit")" != enabled ] || [ "$(guest systemctl is-enabled "$restricted_unit")" != enabled ]; then
    echo "gateway boot did not retain both enabled listener units" >&2
    return 1
  fi
}

cleanup_local() {
  local path
  for path in "$local_binary" "$local_standard_unit" "$local_restricted_unit"; do
    if [ -n "$path" ] && [ -f "$path" ]; then
      rm -f -- "$path"
    fi
  done
  local_binary=
  local_standard_unit=
  local_restricted_unit=
}

cleanup_guest() {
  ensure_instance_running
  if guest sudo test -e "$runtime_root"; then
    assert_owned_scope
  elif guest sudo test -e "$standard_unit_path" || guest sudo test -e "$restricted_unit_path"; then
    echo "refusing to remove task units without their owned runtime marker" >&2
    return 3
  else
    return
  fi
  guest sudo systemctl disable --now "$standard_unit" "$restricted_unit" >/dev/null 2>&1 || true
  guest sudo rm -f -- "$standard_unit_path" "$restricted_unit_path"
  guest sudo systemctl daemon-reload
  guest sudo rm -rf -- "$runtime_root"
}

cleanup_all() {
  cleanup_guest
  cleanup_local
}

verify() {
  assert_lab_instance
  assert_spikes_inactive
  assert_host_ports_free
  assert_fresh_scope
  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/transport ./internal/platform/linux ./internal/lifecycle -run 'Gateway|Transport|Standard|Restricted' -count=1
  trap cleanup_local EXIT INT TERM
  build_inputs
  trap cleanup_all EXIT INT TERM
  install_scope
  wait_ready
  verify_failure_restart
  verify_boot_restore
  assert_host_ports_free
  trap - EXIT INT TERM
  cleanup_all
}

status() {
  local instance_status
  instance_status=$(instance_json "$gateway_instance" | jq -r '.status')
  printf 'instance=%s\n' "$instance_status"
  if [ "$instance_status" != Running ]; then
    return
  fi
  if guest sudo test -e "$runtime_root"; then
    if guest sudo test -f "$owner_path" && guest sudo grep -Fxq "$owner_value" "$owner_path"; then
      printf 'runtime=owned\n'
    else
      printf 'runtime=foreign\n'
    fi
  else
    printf 'runtime=absent\n'
  fi
  printf 'standard_unit=%s\n' "$(guest systemctl is-active "$standard_unit" 2>/dev/null || true)"
  printf 'restricted_unit=%s\n' "$(guest systemctl is-active "$restricted_unit" 2>/dev/null || true)"
}

case "${1:-}" in
  verify) verify ;;
  status) status ;;
  cleanup) cleanup_all ;;
  *) usage; exit 2 ;;
esac
