#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
. "$repository_root/scripts/lib/v2-stage-timing.sh"
fixture_root=$repository_root/test/v2lab/capacity
manifest=$fixture_root/manifest.json
fixture_contract=$repository_root/test/v2lab/fixtures.json
artifact_root=$repository_root/artifacts/v2lab/capacity-e2e
cache_root=$repository_root/artifacts/v2lab/cache
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
fixture_start_timeout=20m
degraded_boot_attempts=120
degraded_boot_interval_seconds=5
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
capacity_owner=vpnctl-v2-capacity-v1
capacity_root=/etc/vpnctl-v2-capacity
capacity_owner_path=$capacity_root/.owner
controller_unit=vpnctl-v2-capacity-controller.service
capacity_backend_dropin=vpnctl-v2-capacity-backend.conf
capacity_client_dropin=vpnctl-v2-capacity-client.conf
capacity_admin_password=b29cf595a13d39c8445e2d42b6a5d8e7a50772b7703b26f9f7d8da9f45f4c485
tunnel_server_unit=vpnctl-v2-spike-tunnel-server.service
tunnel_backend_unit=vpnctl-v2-spike-tunnel-backend.service
tunnel_client_unit=vpnctl-v2-spike-tunnel-client.service
ingress_unit=vpnctl-v2-spike-ingress.service
ingress_webhook_unit=vpnctl-v2-spike-webhook.service
restricted_gateway_unit=vpnctl-v2-spike-restricted-gateway.service
restricted_node_unit=vpnctl-v2-spike-restricted-node.service
restricted_echo_unit=vpnctl-v2-spike-echo.service
restricted_udp_unit=vpnctl-v2-spike-udp-echo.service
tunnel_auth_unit=vpnctl-v2-spike-tunnel-auth.service
capacity_fault_restart_job=vpnctl-v2-capacity-frps-restart
capacity_fault_dropin_dir=/run/systemd/system/$tunnel_server_unit.d
capacity_fault_dropin=$capacity_fault_dropin_dir/vpnctl-v2-capacity-fault.conf
capacity_fault_dropin_sha256=9b6943ff77b31e063152214a3aa57a6f73782b14434700170a0f30ca70ef2524
capacity_fault_start_ready=/var/lib/vpnctl-v2-capacity/fault-start.ready
capacity_fault_start_trigger=/var/lib/vpnctl-v2-capacity/fault-start.trigger
gateway_initial=
node_initial=
gateway_started=false
node_started=false
temporary_root=
run_root=
background_pids=()
background_labels=()
reconnect_pid=
tunnel_service_pid_before=
tunnel_service_restarts_before=
tunnel_frpc_pid_before=
reconnect_finalized=false

usage() {
  cat <<'EOF'
Usage:
  scripts/v2capacity-e2e.sh verify
  scripts/v2capacity-e2e.sh status

The verify command runs the fixed five-minute 300-user profile against the
minimum Gateway. The larger Node fixture supplies the private services and
load generators; it is not a normative product capacity target. The command
never contacts Telegram or a public VPS.
EOF
}

value() {
  jq -er "$1" "$manifest"
}

fixture_topology_sha256() {
  {
    printf '%s\0' vpnctl-v2-fixture-topology-v1
    for file in "$fixture_contract" "$repository_root/test/v2lab/lima.yaml" \
      "$repository_root/test/v2lab/lima-node.yaml" "$repository_root/test/v2lab/provision.sh" \
      "$manifest" "$fixture_root/load.py" "$fixture_root/client_load.py" "$fixture_root/monitor.py" \
      "$fixture_root/fault.sh" "$fixture_root/evaluate.py"; do
      printf '%s\0%s\0' "${file#"$repository_root/"}" "$(shasum -a 256 "$file" | awk '{print $1}')"
    done
  } | shasum -a 256 | awk '{print $1}'
}

instance_json() {
  limactl list --json | jq -ce --arg name "$1" 'select(.name == $name)'
}

instance_status() {
  instance_json "$1" | jq -er '.status'
}

instance_running() {
  [ "$(instance_status "$1")" = Running ]
}

assert_instance_contract() {
  local instance=$1
  if ! instance_json "$instance" | jq -e --arg digest "$lab_image_digest" --arg instance "$instance" '
    (.status == "Running" or .status == "Stopped") and
    .vmType == "qemu" and .arch == "x86_64" and
    .cpus == (if $instance == "vpnctl-v2-node" then 4 else 1 end) and
    .memory == (if $instance == "vpnctl-v2-node" then 2147483648 else 536870912 end) and
    .disk == 10737418240 and
    .config.images[0].digest == $digest and
    any(.network[]?; .lima == "user-v2")
  ' >/dev/null; then
    echo "refusing non-lab, transitioning, or drifted instance: $instance" >&2
    exit 3
  fi
}

guest() {
  local instance=$1
  shift
  limactl shell --tty=false "$instance" -- "$@"
}

lab_ip() {
  guest "$1" ip -4 -o address show scope global |
    awk '$4 ~ /^192[.]168[.]104[.]/ {sub(/\/.*/, "", $4); print $4; exit}'
}

start_fixture() {
  local instance=$1 marker=$2 start_attempt
  assert_instance_contract "$instance"
  if instance_running "$instance"; then
    return
  fi
  printf -v "$marker" '%s' true
  for start_attempt in 1 2; do
    if limactl start --tty=false --timeout "$fixture_start_timeout" "$instance"; then
      break
    fi
    if instance_running "$instance"; then
      echo "fixture entered running/degraded state; waiting for exact boot completion: $instance" >&2
      wait_for_degraded_boot "$instance"
      break
    fi
    if [ "$start_attempt" -eq 2 ] || [ "$(instance_status "$instance")" != Stopped ]; then
      echo "fixture start failed before reaching a stable running state: $instance" >&2
      return 4
    fi
    echo "fixture driver stopped during startup; retrying once: $instance" >&2
  done
  assert_instance_contract "$instance"
  instance_running "$instance" || { echo "fixture did not become ready: $instance" >&2; exit 4; }
}

wait_for_degraded_boot() {
  local instance=$1 attempt command
  for attempt in $(seq 1 "$degraded_boot_attempts"); do
    if guest "$instance" sudo test -s /run/lima-boot-done; then
      [ "$(guest "$instance" dpkg --print-architecture)" = amd64 ]
      if [ "$instance" = "$node_instance" ]; then
        [ "$(guest "$instance" nproc)" -eq 4 ]
      else
        [ "$(guest "$instance" nproc)" -eq 1 ]
      fi
      guest "$instance" grep -q '^VERSION_ID="24.04"$' /etc/os-release
      for command in jq nft ss tc vmstat; do
        guest "$instance" command -v "$command" >/dev/null
      done
      return
    fi
    sleep "$degraded_boot_interval_seconds"
  done
  echo "fixture provisioning did not complete after degraded start: $instance" >&2
  return 4
}

assert_cached_archive() {
  local child_manifest=$1 section=$2 archive expected actual
  archive=$cache_root/$(jq -er "$section.asset" "$child_manifest")
  expected=$(jq -er "$section.sha256" "$child_manifest")
  [ -f "$archive" ] || { echo "required pinned archive is not cached: $archive" >&2; exit 4; }
  actual=$(shasum -a 256 "$archive" | awk '{print $1}')
  [ "$actual" = "$expected" ] || { echo "cached archive checksum mismatch: $archive" >&2; exit 3; }
}

path_owned() {
  local instance=$1 path=$2 owner_path=$3 owner=$4
  guest "$instance" sudo test -e "$path" &&
    guest "$instance" sudo test -f "$owner_path" &&
    guest "$instance" sudo grep -Fxq "$owner" "$owner_path"
}

cleanup_capacity_fault() {
  local actual_sha256
  guest "$gateway_instance" sudo systemctl stop \
    "$capacity_fault_restart_job.timer" "$capacity_fault_restart_job.service" >/dev/null 2>&1 || true
  guest "$gateway_instance" sudo systemctl reset-failed \
    "$capacity_fault_restart_job.timer" "$capacity_fault_restart_job.service" >/dev/null 2>&1 || true
  if guest "$gateway_instance" sudo test -e "$capacity_fault_dropin" ||
     guest "$gateway_instance" sudo test -L "$capacity_fault_dropin"; then
    if ! guest "$gateway_instance" sudo test -f "$capacity_fault_dropin" ||
       guest "$gateway_instance" sudo test -L "$capacity_fault_dropin"; then
      echo "refusing cleanup of unsafe capacity fault drop-in" >&2
      return 3
    fi
    actual_sha256=$(guest "$gateway_instance" sudo sha256sum "$capacity_fault_dropin" | awk '{print $1}')
    if [ "$actual_sha256" != "$capacity_fault_dropin_sha256" ]; then
      echo "refusing cleanup of changed capacity fault drop-in" >&2
      return 3
    fi
    guest "$gateway_instance" sudo rm -f -- "$capacity_fault_dropin"
    guest "$gateway_instance" sudo rmdir "$capacity_fault_dropin_dir" >/dev/null 2>&1 || true
  fi
  guest "$gateway_instance" sudo systemctl daemon-reload
}

cleanup_pair_if_fully_owned() {
  local script=$1 path=$2 owner_path=$3 owner=$4
  local gateway_owned=false node_owned=false
  path_owned "$gateway_instance" "$path" "$owner_path" "$owner" && gateway_owned=true
  path_owned "$node_instance" "$path" "$owner_path" "$owner" && node_owned=true
  if [ "$gateway_owned" = true ] && [ "$node_owned" = true ]; then
    "$repository_root/scripts/$script" uninstall >/dev/null 2>&1
  elif [ "$gateway_owned" != "$node_owned" ]; then
    echo "refusing cleanup of partial $owner fixture" >&2
    return 3
  fi
}

cleanup_capacity_instance() {
  local instance=$1 role=$2
  if ! guest "$instance" sudo test -e "$capacity_root"; then
    return
  fi
  if ! path_owned "$instance" "$capacity_root" "$capacity_owner_path" "$capacity_owner"; then
    echo "refusing cleanup of unowned capacity root on $instance" >&2
    return 3
  fi
  case "$role" in
    gateway)
      cleanup_capacity_fault || return
      guest "$instance" sudo systemctl stop "$controller_unit" >/dev/null 2>&1 || true
      if guest "$instance" sudo test -x /usr/local/libexec/vpnctl-v2-capacity/clients; then
        guest "$instance" sudo /usr/local/libexec/vpnctl-v2-capacity/clients cleanup-gateway
      else
        guest "$instance" sudo ip link delete v2capwg >/dev/null 2>&1 || true
      fi
      ;;
    node)
      guest "$instance" sudo systemctl stop "$tunnel_client_unit" >/dev/null 2>&1 || true
      if guest "$instance" sudo test -x /usr/local/libexec/vpnctl-v2-capacity/clients; then
        guest "$instance" sudo /usr/local/libexec/vpnctl-v2-capacity/clients cleanup-node
      else
        echo "capacity node cleanup helper is absent" >&2
        return 3
      fi
      guest "$instance" sudo rm -f \
        "/etc/systemd/system/$tunnel_backend_unit.d/$capacity_backend_dropin" \
        "/etc/systemd/system/$tunnel_client_unit.d/$capacity_client_dropin"
      guest "$instance" sudo rmdir "/etc/systemd/system/$tunnel_backend_unit.d" >/dev/null 2>&1 || true
      guest "$instance" sudo rmdir "/etc/systemd/system/$tunnel_client_unit.d" >/dev/null 2>&1 || true
      ;;
    *) return 2 ;;
  esac
  guest "$instance" sudo rm -f "/etc/systemd/system/$controller_unit"
  guest "$instance" sudo rm -rf -- /usr/local/libexec/vpnctl-v2-capacity /var/lib/vpnctl-v2-capacity
  guest "$instance" sudo systemctl daemon-reload
  guest "$instance" sudo systemctl reset-failed "$controller_unit" >/dev/null 2>&1 || true
}

cleanup_capacity() {
  local result=0
  cleanup_capacity_instance "$node_instance" node || result=$?
  cleanup_capacity_instance "$gateway_instance" gateway || result=$?
  return "$result"
}

cleanup_capacity_ingress_backup() {
  local directory=/etc/vpnctl-v2-spike/ingress
  local backup=$directory/nginx.conf.capacity-before
  local expected actual entries
  if ! guest "$gateway_instance" sudo test -e "$backup"; then
    return
  fi
  if path_owned "$gateway_instance" "$directory" "$directory/.owner" vpnctl-v2-ingress-spike-v1; then
    guest "$gateway_instance" sudo rm -f "$backup"
    return
  fi
  if ! guest "$gateway_instance" sudo test -d "$directory" ||
     guest "$gateway_instance" sudo test -L "$directory" ||
     ! guest "$gateway_instance" sudo test -f "$backup" ||
     guest "$gateway_instance" sudo test -L "$backup"; then
    echo "refusing unsafe unmarked ingress residue type" >&2
    return 3
  fi
  expected=$(shasum -a 256 "$repository_root/test/v2lab/ingress/nginx.conf" | awk '{print $1}')
  actual=$(guest "$gateway_instance" sudo sha256sum "$backup" | awk '{print $1}')
  entries=$(guest "$gateway_instance" sudo find "$directory" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
  if [ "$actual" != "$expected" ] || [ "$entries" != nginx.conf.capacity-before ]; then
    echo "refusing to remove non-exact unmarked ingress residue" >&2
    return 3
  fi
  guest "$gateway_instance" sudo rm -f "$backup"
  guest "$gateway_instance" sudo rmdir "$directory" /etc/vpnctl-v2-spike >/dev/null 2>&1 || true
}

cleanup_guest_temporary() {
  guest "$gateway_instance" sudo rm -f \
    /tmp/clients.sh /tmp/fault.sh /tmp/load.py /tmp/monitor.py /tmp/controller "/tmp/$controller_unit" \
    /tmp/vpnctl-v2-capacity-peers.conf >/dev/null 2>&1 || true
  guest "$node_instance" sudo rm -f \
    /tmp/clients.sh /tmp/client_load.py /tmp/load.py /tmp/monitor.py /tmp/tunnel-client "/tmp/$capacity_backend_dropin" "/tmp/$capacity_client_dropin" \
    /tmp/webhook_receiver.py /tmp/ingress_load.py /tmp/vpnctl-v2-capacity-gateway.crt \
    >/dev/null 2>&1 || true
}

cleanup_owned() {
  local result=0
  if ! instance_running "$gateway_instance" || ! instance_running "$node_instance"; then
    return
  fi
  cleanup_capacity || result=$?
  cleanup_capacity_ingress_backup || result=$?
  if path_owned "$gateway_instance" /etc/vpnctl-v2-spike/ingress \
    /etc/vpnctl-v2-spike/ingress/.owner vpnctl-v2-ingress-spike-v1; then
    "$repository_root/scripts/v2ingress-spike.sh" uninstall >/dev/null 2>&1 || result=$?
  fi
  cleanup_pair_if_fully_owned v2tunnel-spike.sh /etc/vpnctl-v2-spike/tunnel \
    /etc/vpnctl-v2-spike/tunnel/.owner vpnctl-v2-tunnel-spike-v1 || result=$?
  cleanup_pair_if_fully_owned v2restricted-spike.sh /etc/vpnctl-v2-spike/restricted \
    /etc/vpnctl-v2-spike/restricted/.owner vpnctl-v2-restricted-spike-v1 || result=$?
  cleanup_guest_temporary
  return "$result"
}

stop_background() {
  local pid
  if [ -n "$reconnect_pid" ]; then
    kill "$reconnect_pid" >/dev/null 2>&1 || true
  fi
  for pid in "${background_pids[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  if [ -n "$reconnect_pid" ]; then
    wait "$reconnect_pid" >/dev/null 2>&1 || true
    reconnect_pid=
  fi
  for pid in "${background_pids[@]:-}"; do
    wait "$pid" >/dev/null 2>&1 || true
  done
  background_pids=()
  background_labels=()
}

restore_fixture_states() {
  local result=0
  if [ "$node_started" = true ] && [ "$(instance_status "$node_instance")" != Stopped ]; then
    limactl stop "$node_instance" >/dev/null || result=$?
  fi
  if [ "$gateway_started" = true ] && [ "$(instance_status "$gateway_instance")" != Stopped ]; then
    limactl stop "$gateway_instance" >/dev/null || result=$?
  fi
  return "$result"
}

cleanup_on_exit() {
  local status=$? cleanup_status=0
  trap - EXIT INT TERM
  set +e
  stop_background
  cleanup_owned
  cleanup_status=$?
  restore_fixture_states
  if [ -n "$temporary_root" ] && [ -d "$temporary_root" ]; then
    rm -rf -- "$temporary_root"
  fi
  if [ "$status" -eq 0 ] && [ "$cleanup_status" -ne 0 ]; then
    status=$cleanup_status
  fi
  exit "$status"
}

assert_path_absent() {
  if guest "$1" sudo test -e "$2" || guest "$1" sudo test -L "$2"; then
    echo "capacity path remains on $1: $2" >&2
    exit 3
  fi
}

assert_transient_unit_absent() {
  local load_state
  load_state=$(guest "$gateway_instance" systemctl show --value -p LoadState "$1")
  if [ "$load_state" != not-found ]; then
    echo "capacity transient unit remains: $1 ($load_state)" >&2
    exit 3
  fi
}

assert_clean() {
  local instance namespace unit package
  for instance in "$gateway_instance" "$node_instance"; do
    assert_path_absent "$instance" "$capacity_root"
    assert_path_absent "$instance" /usr/local/libexec/vpnctl-v2-capacity
    assert_path_absent "$instance" /var/lib/vpnctl-v2-capacity
    assert_path_absent "$instance" /etc/vpnctl-v2-spike/tunnel
    assert_path_absent "$instance" /etc/vpnctl-v2-spike/restricted
  done
  assert_path_absent "$gateway_instance" /etc/vpnctl-v2-spike/ingress
  if guest "$gateway_instance" sudo ip link show v2capwg >/dev/null 2>&1; then
    echo "capacity WireGuard interface remains on gateway" >&2
    exit 3
  fi
  if guest "$node_instance" sudo nft list table ip vpnctl_v2_capacity_clients >/dev/null 2>&1; then
    echo "capacity client nftables table remains on node" >&2
    exit 3
  fi
  for namespace in v2capc1 v2capc2 v2capc3 v2capc4 v2capc5; do
    if guest "$node_instance" sudo ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
      echo "capacity client namespace remains: $namespace" >&2
      exit 3
    fi
  done
  if guest "$gateway_instance" systemctl is-active --quiet "$controller_unit"; then
    echo "capacity controller remains active" >&2
    exit 3
  fi
  assert_path_absent "$node_instance" "/etc/systemd/system/$tunnel_backend_unit.d/$capacity_backend_dropin"
  assert_path_absent "$node_instance" "/etc/systemd/system/$tunnel_client_unit.d/$capacity_client_dropin"
  assert_path_absent "$gateway_instance" "$capacity_fault_dropin"
  assert_transient_unit_absent "$capacity_fault_restart_job.timer"
  assert_transient_unit_absent "$capacity_fault_restart_job.service"
  for package in nginx nginx-common; do
    if guest "$gateway_instance" dpkg-query -W "$package" >/dev/null 2>&1; then
      echo "owned capacity nginx package remains: $package" >&2
      exit 3
    fi
  done
}

assert_capacity_temporary_absent() {
  local instance path
  for path in /tmp/clients.sh /tmp/fault.sh /tmp/load.py /tmp/monitor.py /tmp/controller \
    "/tmp/$controller_unit" /tmp/vpnctl-v2-capacity-peers.conf; do
    assert_path_absent "$gateway_instance" "$path"
  done
  for path in /tmp/clients.sh /tmp/client_load.py /tmp/load.py /tmp/monitor.py /tmp/tunnel-client "/tmp/$capacity_backend_dropin" "/tmp/$capacity_client_dropin" \
    /tmp/webhook_receiver.py /tmp/ingress_load.py /tmp/vpnctl-v2-capacity-gateway.crt; do
    assert_path_absent "$node_instance" "$path"
  done
  for instance in "$gateway_instance" "$node_instance"; do
    if guest "$instance" sudo ss -H -lun 'sport = :51820' | grep -q .; then
      echo "capacity UDP/51820 is already occupied on $instance" >&2
      exit 3
    fi
  done
}

record_fixture() {
  instance_json "$1" | jq '{
    name, status, vmType, arch, cpus, memory, disk,
    image_digest: .config.images[0].digest,
    network: [.network[]? | {lima, interface}]
  }' > "$2"
}

prepare_capacity_binaries() {
  temporary_root=$(mktemp -d /private/tmp/vpnctl-v2-capacity.XXXXXX)
  env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOCACHE=/private/tmp/vpnctl-go-cache \
    go build -trimpath -ldflags '-s -w' -o "$temporary_root/controller" ./test/v2lab/capacity/controller
  env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOCACHE=/private/tmp/vpnctl-go-cache \
    go build -trimpath -ldflags '-s -w' -o "$temporary_root/tunnel-client" ./test/v2lab/capacity/tunnel_client
  shasum -a 256 "$temporary_root/controller" > "$run_root/controller.sha256"
  shasum -a 256 "$temporary_root/tunnel-client" > "$run_root/tunnel-client.sha256"
}

copy_capacity_files() {
  limactl copy --backend=scp \
    "$fixture_root/clients.sh" "$fixture_root/fault.sh" "$fixture_root/load.py" \
    "$fixture_root/monitor.py" "$fixture_root/$controller_unit" \
    "$temporary_root/controller" "$gateway_instance:/tmp/"
  limactl copy --backend=scp \
    "$fixture_root/clients.sh" "$fixture_root/client_load.py" "$fixture_root/load.py" "$fixture_root/monitor.py" \
    "$fixture_root/$capacity_backend_dropin" "$repository_root/test/v2lab/ingress/webhook_receiver.py" \
    "$repository_root/test/v2lab/ingress/ingress_load.py" "$temporary_root/tunnel-client" "$node_instance:/tmp/"
}

setup_clients() {
  local gateway_ip gateway_public
  gateway_ip=$(lab_ip "$gateway_instance")
  guest "$gateway_instance" sudo install -d -m 0755 /usr/local/libexec/vpnctl-v2-capacity
  guest "$gateway_instance" sudo install -m 0755 /tmp/clients.sh /usr/local/libexec/vpnctl-v2-capacity/clients
  gateway_public=$(guest "$gateway_instance" sudo /usr/local/libexec/vpnctl-v2-capacity/clients gateway-prepare)
  guest "$node_instance" sudo install -d -m 0755 /usr/local/libexec/vpnctl-v2-capacity
  guest "$node_instance" sudo install -m 0755 /tmp/clients.sh /usr/local/libexec/vpnctl-v2-capacity/clients
  guest "$node_instance" sudo /usr/local/libexec/vpnctl-v2-capacity/clients node-prepare \
    "$gateway_ip" "$gateway_public" > "$run_root/client-peers.conf"
  limactl copy --backend=scp "$run_root/client-peers.conf" "$gateway_instance:/tmp/vpnctl-v2-capacity-peers.conf"
  guest "$gateway_instance" sudo /usr/local/libexec/vpnctl-v2-capacity/clients \
    gateway-install-peers /tmp/vpnctl-v2-capacity-peers.conf
  guest "$gateway_instance" sudo rm -f /tmp/vpnctl-v2-capacity-peers.conf
  guest "$node_instance" sudo /usr/local/libexec/vpnctl-v2-capacity/clients node-verify
  guest "$gateway_instance" sudo wg show v2capwg > "$run_root/gateway-wireguard.txt"
  if [ "$(grep -c '^peer:' "$run_root/gateway-wireguard.txt")" -ne 5 ]; then
    echo "capacity gateway does not have five WireGuard peers" >&2
    exit 1
  fi
}

setup_controller() {
  local attempt pid rss
  guest "$gateway_instance" sudo install -m 0755 /tmp/controller /usr/local/libexec/vpnctl-v2-capacity/controller
  guest "$gateway_instance" sudo install -m 0755 /tmp/fault.sh /usr/local/libexec/vpnctl-v2-capacity/fault
  guest "$gateway_instance" sudo install -m 0755 /tmp/load.py /usr/local/libexec/vpnctl-v2-capacity/load
  guest "$gateway_instance" sudo install -m 0644 "/tmp/$controller_unit" "/etc/systemd/system/$controller_unit"
  guest "$gateway_instance" sudo install -m 0755 /tmp/monitor.py /usr/local/libexec/vpnctl-v2-capacity/monitor
  guest "$gateway_instance" sudo install -d -m 0700 /var/lib/vpnctl-v2-capacity
  guest "$gateway_instance" sudo /usr/local/libexec/vpnctl-v2-capacity/controller \
    --root /var/lib/vpnctl-v2-capacity/controller-root init
  guest "$gateway_instance" sudo systemctl daemon-reload
  guest "$gateway_instance" sudo systemctl start "$controller_unit"
  for attempt in $(seq 1 40); do
    if guest "$gateway_instance" systemctl is-active --quiet "$controller_unit" &&
       guest "$gateway_instance" sudo test -S /var/lib/vpnctl-v2-capacity/controller-root/run/vpnctl/control.sock &&
       [ -n "$(guest "$gateway_instance" sudo ss -H -ltn 'sport = :9443')" ]; then
      break
    fi
    sleep 0.25
  done
  guest "$gateway_instance" systemctl is-active --quiet "$controller_unit"
  pid=$(guest "$gateway_instance" systemctl show --value -p MainPID "$controller_unit")
  rss=$(guest "$gateway_instance" sudo awk '$1 == "VmRSS:" {print $2 * 1024}' "/proc/$pid/status")
  jq -n --argjson pid "$pid" --argjson rss_bytes "$rss" \
    --argjson limit_bytes "$(value '.bounds.controller_idle_rss_bytes')" \
    '{pid: $pid, rss_bytes: $rss_bytes, limit_bytes: $limit_bytes, within_target: ($rss_bytes <= $limit_bytes)}' \
    > "$run_root/controller-idle.json"
  jq -e '.within_target' "$run_root/controller-idle.json" >/dev/null
}

compose_ingress_tunnel() {
  local gateway_ip attempt probe_output client_dropin_path
  gateway_ip=$(lab_ip "$gateway_instance")
  "$repository_root/scripts/v2restricted-spike.sh" prepare > "$run_root/restricted-prepare.log" 2>&1
  "$repository_root/scripts/v2tunnel-spike.sh" prepare > "$run_root/tunnel-prepare.log" 2>&1
  "$repository_root/scripts/v2ingress-spike.sh" prepare "$gateway_ip" > "$run_root/ingress-prepare.log" 2>&1

  [ "$(guest "$gateway_instance" sudo grep -Fxc 'log-level: info' /etc/vpnctl-v2-spike/restricted/gateway.yaml)" -eq 1 ]
  [ "$(guest "$node_instance" sudo grep -Fxc 'log-level: info' /etc/vpnctl-v2-spike/restricted/node.yaml)" -eq 1 ]
  [ "$(guest "$gateway_instance" sudo grep -Fxc 'log.level = "info"' /etc/vpnctl-v2-spike/tunnel/frps.toml)" -eq 1 ]
  [ "$(guest "$node_instance" sudo grep -Fxc 'log.level = "info"' /etc/vpnctl-v2-spike/tunnel/frpc.toml)" -eq 1 ]
  guest "$gateway_instance" sudo sed -i 's/^log-level: info$/log-level: silent/' \
    /etc/vpnctl-v2-spike/restricted/gateway.yaml
  guest "$node_instance" sudo sed -i 's/^log-level: info$/log-level: silent/' \
    /etc/vpnctl-v2-spike/restricted/node.yaml
  guest "$gateway_instance" sudo sed -i 's/^log.level = "info"$/log.level = "error"/' \
    /etc/vpnctl-v2-spike/tunnel/frps.toml
  guest "$node_instance" sudo sed -i 's/^log.level = "info"$/log.level = "error"/' \
    /etc/vpnctl-v2-spike/tunnel/frpc.toml
  guest "$node_instance" sudo sed -i \
    -e 's/^webServer.user = "vpnctl-spike"$/webServer.user = "vpnctl"/' \
    -e "s/^webServer.password = .*$/webServer.password = \"$capacity_admin_password\"/" \
    /etc/vpnctl-v2-spike/tunnel/frpc.toml
  guest "$gateway_instance" sudo /usr/local/libexec/vpnctl-v2-spike/mihomo -t \
    -d /var/lib/vpnctl-v2-spike-gateway -f /etc/vpnctl-v2-spike/restricted/gateway.yaml \
    > "$run_root/restricted-gateway-production-log-validation.txt" 2>&1
  guest "$node_instance" sudo /usr/local/libexec/vpnctl-v2-spike/mihomo -t \
    -d /var/lib/vpnctl-v2-spike-node -f /etc/vpnctl-v2-spike/restricted/node.yaml \
    > "$run_root/restricted-node-production-log-validation.txt" 2>&1
  guest "$gateway_instance" sudo /usr/local/libexec/vpnctl-v2-spike/frps verify \
    -c /etc/vpnctl-v2-spike/tunnel/frps.toml \
    > "$run_root/frps-production-log-validation.txt" 2>&1
  guest "$node_instance" sudo /usr/local/libexec/vpnctl-v2-spike/frpc verify \
    -c /etc/vpnctl-v2-spike/tunnel/frpc.toml \
    > "$run_root/frpc-production-log-validation.txt" 2>&1
  guest "$gateway_instance" sudo systemctl restart "$restricted_gateway_unit" "$tunnel_server_unit"
  guest "$node_instance" sudo systemctl restart "$restricted_node_unit"

  guest "$node_instance" sudo install -m 0755 /tmp/webhook_receiver.py \
    /usr/local/libexec/vpnctl-v2-capacity/webhook-receiver
  guest "$node_instance" sudo install -m 0755 /tmp/load.py /usr/local/libexec/vpnctl-v2-capacity/load
  guest "$node_instance" sudo install -m 0755 /tmp/client_load.py /usr/local/libexec/vpnctl-v2-capacity/client-load
  guest "$node_instance" sudo install -m 0755 /tmp/ingress_load.py /usr/local/libexec/vpnctl-v2-capacity/ingress-load
  guest "$node_instance" sudo install -m 0755 /tmp/tunnel-client /usr/local/libexec/vpnctl-v2-capacity/tunnel-client
  guest "$node_instance" sudo install -d -m 0755 "/etc/systemd/system/$tunnel_backend_unit.d"
  guest "$node_instance" sudo install -m 0644 "/tmp/$capacity_backend_dropin" \
    "/etc/systemd/system/$tunnel_backend_unit.d/$capacity_backend_dropin"
  client_dropin_path="$run_root/$capacity_client_dropin"
  sed "s|@GATEWAY_IP@|$gateway_ip|g" "$fixture_root/$capacity_client_dropin" > "$client_dropin_path"
  limactl copy --backend=scp "$client_dropin_path" "$node_instance:/tmp/$capacity_client_dropin"
  guest "$node_instance" sudo install -d -m 0755 "/etc/systemd/system/$tunnel_client_unit.d"
  guest "$node_instance" sudo install -m 0644 "/tmp/$capacity_client_dropin" \
    "/etc/systemd/system/$tunnel_client_unit.d/$capacity_client_dropin"
  guest "$node_instance" sudo systemctl daemon-reload
  guest "$node_instance" sudo systemctl restart "$tunnel_backend_unit"
  guest "$node_instance" sudo systemctl restart "$tunnel_client_unit"

  guest "$gateway_instance" sudo sed -i \
    's|127.0.0.1:18081|127.0.0.1:18111|g' /etc/vpnctl-v2-spike/ingress/nginx.conf
  guest "$gateway_instance" sudo /usr/sbin/nginx -t \
    -p /etc/vpnctl-v2-spike/ingress/ -c nginx.conf > "$run_root/nginx-composed-validation.txt" 2>&1
  guest "$gateway_instance" sudo systemctl reload "$ingress_unit"
  guest "$gateway_instance" sudo systemctl stop "$ingress_webhook_unit"
  guest "$gateway_instance" sudo cat /etc/vpnctl-v2-spike/ingress/gateway.crt > "$run_root/gateway.crt"
  chmod 0644 "$run_root/gateway.crt"
  limactl copy --backend=scp "$run_root/gateway.crt" "$node_instance:/tmp/vpnctl-v2-capacity-gateway.crt"
  for attempt in $(seq 1 40); do
    probe_output=$(probe_webhook 2>&1 || true)
    printf '%s\n' "$probe_output" > "$run_root/composition-probe-last.json"
    if printf '%s\n' "$probe_output" | jq -e '.status == 200 and .ok == true' >/dev/null 2>&1; then
      return
    fi
    sleep 0.25
  done
  capture_composition_failure
  echo "composed ingress-to-node tunnel did not become ready" >&2
  exit 1
}

capture_composition_failure() {
  guest "$gateway_instance" systemctl show --no-pager \
    "$ingress_unit" "$tunnel_auth_unit" "$tunnel_server_unit" \
    -p Id -p ActiveState -p SubState -p MainPID -p NRestarts \
    > "$run_root/composition-gateway-units.txt" 2>&1 || true
  guest "$node_instance" systemctl show --no-pager \
    "$tunnel_backend_unit" "$tunnel_client_unit" \
    -p Id -p ActiveState -p SubState -p MainPID -p NRestarts \
    > "$run_root/composition-node-units.txt" 2>&1 || true
  guest "$gateway_instance" sudo ss -H -ltnp \
    > "$run_root/composition-gateway-listeners.txt" 2>&1 || true
  guest "$node_instance" sudo ss -H -ltnp \
    > "$run_root/composition-node-listeners.txt" 2>&1 || true
  guest "$gateway_instance" sudo journalctl --no-pager -n 80 \
    -u "$ingress_unit" -u "$tunnel_auth_unit" -u "$tunnel_server_unit" \
    > "$run_root/composition-gateway-journal.txt" 2>&1 || true
  guest "$node_instance" sudo journalctl --no-pager -n 80 \
    -u "$tunnel_backend_unit" -u "$tunnel_client_unit" \
    > "$run_root/composition-node-journal.txt" 2>&1 || true
  guest "$gateway_instance" sudo cat /var/lib/vpnctl-v2-spike-tunnel-auth/metrics.json \
    > "$run_root/composition-tunnel-metrics.json" 2>/dev/null || true
}

probe_webhook() {
  local gateway_ip
  gateway_ip=$(lab_ip "$gateway_instance")
  guest "$node_instance" python3 /usr/local/libexec/vpnctl-v2-capacity/load probe \
    --public-ip "$gateway_ip" --certificate /tmp/vpnctl-v2-capacity-gateway.crt \
    --body-bytes 128 --timeout 5
}

tunnel_client_process_state() {
  guest "$node_instance" sudo bash -c '
    set -euo pipefail
    unit=$1
    for _attempt in $(seq 1 20); do
      service_pid=$(systemctl show --value -p MainPID "$unit")
      service_restarts=$(systemctl show --value -p NRestarts "$unit")
      case "$service_pid:$service_restarts" in
        :*|*:|*[!0-9:]*) ;;
        *)
          frpc_pid=$(pgrep -P "$service_pid" -x frpc || true)
          case "$frpc_pid" in
            ""|*[!0-9]*) ;;
            *) printf "%s %s %s\n" "$service_pid" "$service_restarts" "$frpc_pid"; exit 0 ;;
          esac
          ;;
      esac
      sleep 0.1
    done
    echo "expected one active tunnel client service and supervised frpc child" >&2
    exit 1
  ' vpnctl-capacity-state "$tunnel_client_unit"
}

capture_tunnel_client_process_state_before() {
  read -r tunnel_service_pid_before tunnel_service_restarts_before tunnel_frpc_pid_before \
    < <(tunnel_client_process_state)
}

finalize_reconnect_process_state() {
  local service_pid_after=null service_restarts_after=null frpc_pid_after=null process_state_observed=false
  if read -r service_pid_after service_restarts_after frpc_pid_after < <(tunnel_client_process_state); then
    process_state_observed=true
  fi
  jq \
    --argjson service_pid_before "$tunnel_service_pid_before" \
    --argjson service_restarts_before "$tunnel_service_restarts_before" \
    --argjson frpc_pid_before "$tunnel_frpc_pid_before" \
    --argjson service_pid_after "$service_pid_after" \
    --argjson service_restarts_after "$service_restarts_after" \
    --argjson frpc_pid_after "$frpc_pid_after" \
    --argjson process_state_observed "$process_state_observed" '
    . + {
      client_process_state_observed_after_fault: $process_state_observed,
      client_service_pid_before: $service_pid_before,
      client_service_pid_after: $service_pid_after,
      client_service_restarts_before: $service_restarts_before,
      client_service_restarts_after: $service_restarts_after,
      frpc_child_pid_before: $frpc_pid_before,
      frpc_child_pid_after: $frpc_pid_after,
      frpc_child_recycled: ($process_state_observed and $frpc_pid_before != $frpc_pid_after),
      recovered_without_client_service_restart:
        ($process_state_observed and $service_pid_before == $service_pid_after and $service_restarts_before == $service_restarts_after)
    }' "$run_root/reconnect.base.json" > "$run_root/reconnect.json"
  rm -f -- "$run_root/reconnect.base.json"
  reconnect_finalized=true
}

capture_node_health() {
  local restricted=false backend=false client=false frpc_api=false
  guest "$node_instance" systemctl is-active --quiet "$restricted_node_unit" && restricted=true
  guest "$node_instance" systemctl is-active --quiet "$tunnel_backend_unit" && backend=true
  guest "$node_instance" systemctl is-active --quiet "$tunnel_client_unit" && client=true
  guest "$node_instance" curl -fsS --max-time 2 -u "vpnctl:$capacity_admin_password" \
    http://127.0.0.1:17400/api/status > "$run_root/node-health-frpc-status.json" 2>&1 && frpc_api=true
  jq -n --argjson restricted "$restricted" --argjson backend "$backend" \
    --argjson client "$client" --argjson frpc_api "$frpc_api" '{
      schema_version:1,
      status:(if $restricted and $backend and $client and $frpc_api then "passed" else "failed" end),
      checks:{mihomo_active:$restricted,webhook_backend_active:$backend,watchdog_frpc_unit_active:$client,frpc_api_reachable:$frpc_api}
    }' > "$run_root/node-health.json"
}

run_connection_limits() {
  local gateway_ip attempt active connection_count limit_pid
  gateway_ip=$(lab_ip "$gateway_instance")
  guest "$node_instance" python3 /usr/local/libexec/vpnctl-v2-capacity/ingress-load load \
    --public-ip "$gateway_ip" --certificate /tmp/vpnctl-v2-capacity-gateway.crt \
    --requests 45 --delay-ms 3000 --body-bytes 32 --timeout 20 --path /load/a \
    > "$run_root/per-expose-limit.json"
  jq -e '.responses == 45 and (.errors | length) == 0 and .status_counts["200"] == 40 and .status_counts["503"] == 5' \
    "$run_root/per-expose-limit.json" >/dev/null
  for attempt in $(seq 1 40); do
    active=$(guest "$node_instance" curl -fsS http://127.0.0.1:18121/__vpnctl_probe/status | jq -er '.active_requests')
    if [ "$active" -eq 0 ]; then
      break
    fi
    sleep 0.25
  done
  [ "$active" -eq 0 ] || { echo "capacity backend did not become idle between limit cases" >&2; exit 1; }
  connection_count=0
  for attempt in $(seq 1 80); do
    connection_count=$(guest "$gateway_instance" sudo ss -H -tan state established 'sport = :443' | wc -l | tr -d ' ')
    if [ "$connection_count" -eq 0 ]; then
      break
    fi
    sleep 0.25
  done
  guest "$gateway_instance" sudo ss -H -tan state established 'sport = :443' \
    > "$run_root/gateway-limit-before-connections.txt"
  [ "$connection_count" -eq 0 ] || { echo "HTTPS ingress did not become quiescent between limit cases" >&2; exit 1; }
  guest "$node_instance" python3 /usr/local/libexec/vpnctl-v2-capacity/ingress-load load \
    --public-ip "$gateway_ip" --certificate /tmp/vpnctl-v2-capacity-gateway.crt \
    --requests 72 --delay-ms 5000 --body-bytes 32 --timeout 20 --path /load/a --path /load/b \
    > "$run_root/gateway-limit.json" &
  limit_pid=$!
  background_pids+=("$limit_pid")
  connection_count=0
  for attempt in $(seq 1 100); do
    connection_count=$(guest "$gateway_instance" sudo ss -H -tan state established 'sport = :443' | wc -l | tr -d ' ')
    if [ "$connection_count" -ge 60 ]; then
      break
    fi
    sleep 0.05
  done
  guest "$gateway_instance" sudo ss -H -tan state established 'sport = :443' \
    > "$run_root/gateway-limit-during-connections.txt"
  [ "$connection_count" -ge 60 ] || { echo "global limit case did not reach concurrent ingress load" >&2; exit 1; }
  wait "$limit_pid"
  background_pids=()
  background_labels=()
  guest "$node_instance" curl -fsS http://127.0.0.1:18121/__vpnctl_probe/status \
    > "$run_root/gateway-limit-backend.json"
  jq -e '.responses == 72 and (.errors | length) == 0 and .status_counts["200"] == 64 and .status_counts["503"] == 8' \
    "$run_root/gateway-limit.json" >/dev/null
  jq -e '.ok and .active_requests == 0 and .max_active_requests == 64' \
    "$run_root/gateway-limit-backend.json" >/dev/null
}

wait_background_group() {
  local context=$1 index pid status result=0
  for index in "${!background_pids[@]}"; do
    pid=${background_pids[$index]}
    status=0
    wait "$pid" || status=$?
    if [ "$status" -ne 0 ]; then
      printf '%s process failed: %s (exit %s)\n' "$context" "${background_labels[$index]}" "$status" >&2
      result=1
    fi
  done
  background_pids=()
  background_labels=()
  return "$result"
}

run_warmup() {
  local gateway_ip duration webhook_rate api_rate body expected_sha timeout webhook_workers api_workers
  local failure_start failure_end stable_recovery recovery_success maximum_disruption
  gateway_ip=$(lab_ip "$gateway_instance")
  duration=$(value '.load_generator.warmup_seconds')
  webhook_rate=$(value '.profile.webhook_requests_per_second')
  api_rate=$(value '.profile.bot_api_requests_per_second')
  body=$(value '.profile.webhook_body_bytes')
  timeout=$(value '.load_generator.request_timeout_seconds')
  webhook_workers=$(value '.load_generator.webhook_workers')
  api_workers=$(value '.load_generator.bot_api_workers')
  stable_recovery=$(value '.bounds.client_disruption_stable_recovery_probes')
  recovery_success=$(value '.bounds.webhook_steady_state_success_p99_ms')
  maximum_disruption=$(value '.bounds.maximum_client_disruption_seconds')
  failure_start=$((duration + 1))
  failure_end=$((duration + 2))
  expected_sha=$(shasum -a 256 "$repository_root/test/v2lab/restricted/telegram-api.json" | awk '{print $1}')

  guest "$node_instance" python3 /usr/local/libexec/vpnctl-v2-capacity/load webhook \
    --duration "$duration" --rate "$webhook_rate" --workers "$webhook_workers" --timeout "$timeout" \
    --failure-window-start "$failure_start" --failure-window-end "$failure_end" \
    --stable-recovery-probes "$stable_recovery" --recovery-success-max-ms "$recovery_success" \
    --maximum-disruption-seconds "$maximum_disruption" \
    --public-ip "$gateway_ip" --certificate /tmp/vpnctl-v2-capacity-gateway.crt --body-bytes "$body" \
    > "$run_root/webhook-warmup.json" &
  background_pids+=("$!")
  background_labels+=("webhook-warmup")
  guest "$node_instance" python3 /usr/local/libexec/vpnctl-v2-capacity/load api \
    --duration "$duration" --rate "$api_rate" --workers "$api_workers" --timeout "$timeout" \
    --failure-window-start "$failure_start" --failure-window-end "$failure_end" \
    --target http://127.0.0.1:18080/telegram-api.json --expected-sha256 "$expected_sha" \
    > "$run_root/api-warmup.json" &
  background_pids+=("$!")
  background_labels+=("bot-api-warmup")
  wait_background_group "capacity warm-up"
  jq -e --argjson expected "$((duration * webhook_rate))" '
    .status == "completed" and .scheduled_requests == $expected and
    .submitted_requests == $expected and .completed_requests == $expected and
    .successful_requests == $expected and .failed_requests == 0
  ' "$run_root/webhook-warmup.json" >/dev/null
  jq -e --argjson expected "$((duration * api_rate))" '
    .status == "completed" and .scheduled_requests == $expected and
    .submitted_requests == $expected and .completed_requests == $expected and
    .successful_requests == $expected and .failed_requests == 0
  ' "$run_root/api-warmup.json" >/dev/null
}

start_loads() {
  local gateway_ip duration webhook_rate api_rate body fault_start fault_end expected_sha monitor_duration
  local stable_recovery recovery_success maximum_disruption timeout webhook_workers api_workers
  gateway_ip=$(lab_ip "$gateway_instance")
  duration=$(value '.profile.duration_seconds')
  webhook_rate=$(value '.profile.webhook_requests_per_second')
  api_rate=$(value '.profile.bot_api_requests_per_second')
  body=$(value '.profile.webhook_body_bytes')
  fault_start=$(value '.fault.accepted_failure_window_start_seconds')
  fault_end=$(value '.fault.accepted_failure_window_end_seconds')
  stable_recovery=$(value '.bounds.client_disruption_stable_recovery_probes')
  recovery_success=$(value '.bounds.webhook_steady_state_success_p99_ms')
  maximum_disruption=$(value '.bounds.maximum_client_disruption_seconds')
  timeout=$(value '.load_generator.request_timeout_seconds')
  webhook_workers=$(value '.load_generator.webhook_workers')
  api_workers=$(value '.load_generator.bot_api_workers')
  expected_sha=$(shasum -a 256 "$repository_root/test/v2lab/restricted/telegram-api.json" | awk '{print $1}')
  monitor_duration=$((duration + 10))

  guest "$gateway_instance" sudo /usr/local/libexec/vpnctl-v2-capacity/monitor \
    --duration "$monitor_duration" --interval 2 \
    --diagnostic-start "$fault_start" --diagnostic-end "$fault_end" \
    --unit "$controller_unit" --unit "$ingress_unit" --unit "$tunnel_auth_unit" \
    --unit "$tunnel_server_unit" --unit "$restricted_gateway_unit" \
    --unit "$restricted_echo_unit" --unit "$restricted_udp_unit" \
    > "$run_root/gateway-resources.json" &
  background_pids+=("$!")
  background_labels+=("gateway-resource-monitor")
  guest "$node_instance" sudo env VPNCTL_CAPACITY_FRPC_PASSWORD="$capacity_admin_password" /tmp/monitor.py \
    --duration "$monitor_duration" --interval 2 \
    --diagnostic-start "$fault_start" --diagnostic-end "$fault_end" \
    --frpc-url http://127.0.0.1:17400/api/status --frpc-user vpnctl \
    --unit "$restricted_node_unit" --unit "$tunnel_backend_unit" --unit "$tunnel_client_unit" \
    > "$run_root/node-resources.json" &
  background_pids+=("$!")
  background_labels+=("node-resource-monitor")
  guest "$node_instance" sudo /usr/local/libexec/vpnctl-v2-capacity/client-load --duration "$duration" \
    > "$run_root/clients.json" &
  background_pids+=("$!")
  background_labels+=("five-client-workload")
  guest "$node_instance" python3 /usr/local/libexec/vpnctl-v2-capacity/load webhook \
    --duration "$duration" --rate "$webhook_rate" --workers "$webhook_workers" --timeout "$timeout" \
    --failure-window-start "$fault_start" --failure-window-end "$fault_end" \
    --stable-recovery-probes "$stable_recovery" --recovery-success-max-ms "$recovery_success" \
    --maximum-disruption-seconds "$maximum_disruption" \
    --public-ip "$gateway_ip" --certificate /tmp/vpnctl-v2-capacity-gateway.crt --body-bytes "$body" \
    > "$run_root/webhook-load.json" &
  background_pids+=("$!")
  background_labels+=("webhook-load-generator")
  guest "$node_instance" python3 /usr/local/libexec/vpnctl-v2-capacity/load api \
    --duration "$duration" --rate "$api_rate" --workers "$api_workers" --timeout "$timeout" \
    --failure-window-start "$fault_start" --failure-window-end "$fault_end" \
    --target http://127.0.0.1:18080/telegram-api.json --expected-sha256 "$expected_sha" \
    > "$run_root/api-load.json" &
  background_pids+=("$!")
  background_labels+=("bot-api-load-generator")
}

start_reconnect() {
  local gateway_ip down_seconds recovery_limit reconnect_base fault_after attempt ready=false
  gateway_ip=$(lab_ip "$gateway_instance")
  down_seconds=$(value '.fault.frps_down_seconds')
  recovery_limit=$(value '.bounds.tunnel_reconnect_seconds')
  fault_after=$(value '.fault.frps_stop_after_seconds')
  reconnect_base="$run_root/reconnect.base.json"
  guest "$gateway_instance" sudo /usr/local/libexec/vpnctl-v2-capacity/fault \
    --unit "$tunnel_server_unit" --public-ip "$gateway_ip" \
    --certificate /etc/vpnctl-v2-spike/ingress/gateway.crt \
    --down-seconds "$down_seconds" --recovery-limit-seconds "$recovery_limit" \
    --start-after-seconds "$fault_after" > "$reconnect_base" &
  reconnect_pid=$!
  for attempt in $(seq 1 120); do
    if guest "$gateway_instance" sudo test -f "$capacity_fault_start_ready" &&
       ! guest "$gateway_instance" sudo test -L "$capacity_fault_start_ready"; then
      ready=true
      break
    fi
    if ! kill -0 "$reconnect_pid" >/dev/null 2>&1; then
      wait "$reconnect_pid" || true
      reconnect_pid=
      echo "capacity reconnect fault exited before start readiness" >&2
      return 1
    fi
    sleep 0.25
  done
  if [ "$ready" != true ]; then
    echo "capacity reconnect fault did not become ready before load" >&2
    return 4
  fi
  guest "$gateway_instance" sudo install -m 0600 /dev/null "$capacity_fault_start_trigger"
}

wait_reconnect() {
  local fault_status=0
  if [ -z "$reconnect_pid" ]; then
    echo "capacity reconnect fault was not started" >&2
    return 3
  fi
  wait "$reconnect_pid" || fault_status=$?
  reconnect_pid=
  if [ "$fault_status" -ne 0 ]; then
    finalize_reconnect_process_state
    jq '.unavailable_probe' "$run_root/reconnect.json" > "$run_root/reconnect-unavailable-probe.json"
    return "$fault_status"
  fi
}

wait_loads() {
  wait_background_group "capacity sustained workload"
}

write_summary() {
  local source_commit=$1 topology_sha
  topology_sha=$(fixture_topology_sha256)
  python3 "$fixture_root/evaluate.py" --manifest "$manifest" --run-root "$run_root" \
    --source-commit "$source_commit" --fixture-contract-sha256 "$topology_sha" \
    > "$run_root/summary.json"
}

assert_summary() {
  jq -e '
    .schema_version == 3 and .status == "passed" and .measurement_classification == "passed" and
    .topology.capacity_boundary_role == "gateway" and .topology.load_generator_role == "node" and
    .gateway_capacity.within_contract and .node_fixture_health.within_contract and
    .measurement_validity.within_contract and
    .load_generator_validity.within_contract and .fault_reconnect.within_contract and
    .client_disruption.within_contract and .steady_state_latency.within_contract and
    .client_health.within_contract and
    .node_fixture_health.resource_acceptance_thresholds_applied == false and
    (.fixture_contract_sha256 | test("^[0-9a-f]{64}$")) and
    (.failure_reasons.load_generator | length) == 0 and
    (.failure_reasons.measurement | length) == 0 and
    (.failure_reasons.node_fixture | length) == 0 and
    (.failure_reasons.product | length) == 0 and
    .cleanup == {owner_scoped:true,temporary_resources_absent:true,prior_fixture_states_restored:true}
  ' "$run_root/summary.json" >/dev/null
}

verify() {
  local stamp source_commit duration fault_after elapsed remaining step reconnect_status=0 load_status=0
  VPNCTL_V2_TIMING_PRODUCER=capacity
  v2_timing_begin
  if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    echo "capacity E2E requires a clean source tree" >&2
    exit 3
  fi
  source_commit=$(git rev-parse HEAD)
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  run_root=$artifact_root/run-$stamp
  (umask 077; mkdir -p "$run_root")
  assert_cached_archive "$repository_root/test/v2lab/tunnel/manifest.json" '.frp'
  assert_cached_archive "$repository_root/test/v2lab/restricted/manifest.json" '.mihomo'
  PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -v -s test/v2lab/capacity -p 'test_*.py' \
    > "$run_root/source-tests.log" 2>&1
  bash -n "$fixture_root/fault.sh"
  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./test/v2lab/capacity/controller > "$run_root/controller-build-test.log"
  prepare_capacity_binaries
  v2_timing_mark source_and_build
  trap cleanup_on_exit EXIT INT TERM

  assert_instance_contract "$gateway_instance"
  assert_instance_contract "$node_instance"
  gateway_initial=$(instance_status "$gateway_instance")
  node_initial=$(instance_status "$node_instance")
  record_fixture "$gateway_instance" "$run_root/gateway-before.json"
  record_fixture "$node_instance" "$run_root/node-before.json"
  start_fixture "$gateway_instance" gateway_started
  start_fixture "$node_instance" node_started
  cleanup_owned
  assert_clean
  assert_capacity_temporary_absent
  copy_capacity_files
  setup_clients
  compose_ingress_tunnel
  setup_controller
  run_connection_limits
  run_warmup
  capture_tunnel_client_process_state_before
  start_reconnect
  start_loads
  v2_timing_mark fixture_and_provider_setup

  fault_after=$(value '.fault.frps_stop_after_seconds')
  elapsed=0
  while [ "$elapsed" -lt "$fault_after" ]; do
    remaining=$((fault_after - elapsed))
    step=30
    [ "$remaining" -lt "$step" ] && step=$remaining
    sleep "$step"
    elapsed=$((elapsed + step))
    printf 'capacity sustained load: %ss/%ss before reconnect injection\n' "$elapsed" "$fault_after"
  done
  wait_reconnect || reconnect_status=$?
  duration=$(value '.profile.duration_seconds')
  remaining=$((duration - fault_after))
  elapsed=$fault_after
  while [ "$remaining" -gt 0 ]; do
    step=30
    [ "$remaining" -lt "$step" ] && step=$remaining
    sleep "$step"
    remaining=$((remaining - step))
    elapsed=$((elapsed + step))
    printf 'capacity sustained load: %ss/%ss after FRP recovery\n' "$elapsed" "$duration"
  done
  wait_loads || load_status=$?
  if [ "$reconnect_finalized" != true ] && [ -f "$run_root/reconnect.base.json" ]; then
    finalize_reconnect_process_state
  fi
  if [ -f "$run_root/reconnect.json" ]; then
    jq '.unavailable_probe' "$run_root/reconnect.json" > "$run_root/reconnect-unavailable-probe.json" || true
  fi
  capture_node_health
  v2_timing_mark sustained_load_and_reconnect

  stop_background
  cleanup_owned
  assert_clean
  trap - EXIT INT TERM
  restore_fixture_states
  if [ "$(instance_status "$gateway_instance")" != "$gateway_initial" ] ||
     [ "$(instance_status "$node_instance")" != "$node_initial" ]; then
    echo "capacity E2E did not restore prior fixture states" >&2
    exit 3
  fi
  rm -rf -- "$temporary_root"
  temporary_root=
  write_summary "$source_commit"
  if ! assert_summary; then
    printf 'capacity measurement failed: %s\n' "$(jq -r '.measurement_classification' "$run_root/summary.json")" >&2
    printf 'inspect: %s\n' "$run_root/summary.json" >&2
    exit 1
  fi
  if [ "$reconnect_status" -ne 0 ] || [ "$load_status" -ne 0 ]; then
    echo "capacity subprocess failed despite a passing aggregate" >&2
    exit 3
  fi
  v2_timing_finish cleanup_and_validation
  printf 'minimum-gateway capacity E2E evidence: %s\n' "$run_root/summary.json"
}

status() {
  local instance
  for instance in "$gateway_instance" "$node_instance"; do
    assert_instance_contract "$instance"
    printf '%s=%s\n' "$instance" "$(instance_status "$instance")"
  done
  if instance_running "$gateway_instance" && instance_running "$node_instance"; then
    assert_clean
    echo 'temporary_resources=absent'
  else
    echo 'temporary_resources=not-inspected-while-stopped'
  fi
}

cd "$repository_root"
case "${1:-}" in
  verify) [ "$#" -eq 1 ] || { usage >&2; exit 2; }; verify ;;
  status) [ "$#" -eq 1 ] || { usage >&2; exit 2; }; status ;;
  *) usage >&2; exit 2 ;;
esac
