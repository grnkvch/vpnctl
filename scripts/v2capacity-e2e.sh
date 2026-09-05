#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
fixture_root=$repository_root/test/v2lab/capacity
manifest=$fixture_root/manifest.json
artifact_root=$repository_root/artifacts/v2lab/capacity-e2e
cache_root=$repository_root/artifacts/v2lab/cache
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
capacity_owner=vpnctl-v2-capacity-v1
capacity_root=/etc/vpnctl-v2-capacity
capacity_owner_path=$capacity_root/.owner
controller_unit=vpnctl-v2-capacity-controller.service
backend_unit=vpnctl-v2-capacity-backend.service
tunnel_server_unit=vpnctl-v2-spike-tunnel-server.service
tunnel_backend_unit=vpnctl-v2-spike-tunnel-backend.service
ingress_unit=vpnctl-v2-spike-ingress.service
ingress_webhook_unit=vpnctl-v2-spike-webhook.service
restricted_gateway_unit=vpnctl-v2-spike-restricted-gateway.service
restricted_echo_unit=vpnctl-v2-spike-echo.service
restricted_udp_unit=vpnctl-v2-spike-udp-echo.service
tunnel_auth_unit=vpnctl-v2-spike-tunnel-auth.service
gateway_initial=
node_initial=
gateway_started=false
node_started=false
temporary_root=
run_root=
background_pids=()

usage() {
  cat <<'EOF'
Usage:
  scripts/v2capacity-e2e.sh verify
  scripts/v2capacity-e2e.sh status

The verify command runs the fixed five-minute 300-user profile on the two
minimum-host Lima fixtures. It never contacts Telegram or a public VPS.
EOF
}

value() {
  jq -er "$1" "$manifest"
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
  if ! instance_json "$instance" | jq -e --arg digest "$lab_image_digest" '
    (.status == "Running" or .status == "Stopped") and
    .vmType == "qemu" and .arch == "x86_64" and .cpus == 1 and
    .memory == 536870912 and .disk == 10737418240 and
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
  local instance=$1 marker=$2
  assert_instance_contract "$instance"
  if instance_running "$instance"; then
    return
  fi
  limactl start --tty=false "$instance"
  printf -v "$marker" '%s' true
  assert_instance_contract "$instance"
  instance_running "$instance" || { echo "fixture did not become ready: $instance" >&2; exit 4; }
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
      guest "$instance" sudo systemctl stop "$controller_unit" >/dev/null 2>&1 || true
      if guest "$instance" sudo test -x /usr/local/libexec/vpnctl-v2-capacity/clients; then
        guest "$instance" sudo /usr/local/libexec/vpnctl-v2-capacity/clients cleanup-gateway
      else
        guest "$instance" sudo ip link delete v2capwg >/dev/null 2>&1 || true
      fi
      ;;
    node)
      guest "$instance" sudo systemctl stop "$backend_unit" >/dev/null 2>&1 || true
      if guest "$instance" sudo test -x /usr/local/libexec/vpnctl-v2-capacity/clients; then
        guest "$instance" sudo /usr/local/libexec/vpnctl-v2-capacity/clients cleanup-node
      else
        echo "capacity node cleanup helper is absent" >&2
        return 3
      fi
      ;;
    *) return 2 ;;
  esac
  guest "$instance" sudo rm -f "/etc/systemd/system/$controller_unit" "/etc/systemd/system/$backend_unit"
  guest "$instance" sudo rm -rf -- /usr/local/libexec/vpnctl-v2-capacity /var/lib/vpnctl-v2-capacity
  guest "$instance" sudo systemctl daemon-reload
  guest "$instance" sudo systemctl reset-failed "$controller_unit" "$backend_unit" >/dev/null 2>&1 || true
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
    /tmp/clients.sh /tmp/monitor.py /tmp/controller "/tmp/$controller_unit" \
    /tmp/vpnctl-v2-capacity-peers.conf >/dev/null 2>&1 || true
  guest "$node_instance" sudo rm -f \
    /tmp/clients.sh /tmp/client_load.py /tmp/load.py "/tmp/$backend_unit" \
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
  for pid in "${background_pids[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  for pid in "${background_pids[@]:-}"; do
    wait "$pid" >/dev/null 2>&1 || true
  done
  background_pids=()
}

restore_fixture_states() {
  local result=0
  if [ "$node_started" = true ] && instance_running "$node_instance"; then
    limactl stop "$node_instance" >/dev/null || result=$?
  fi
  if [ "$gateway_started" = true ] && instance_running "$gateway_instance"; then
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
  if guest "$1" sudo test -e "$2"; then
    echo "capacity path remains on $1: $2" >&2
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
  for unit in "$controller_unit" "$backend_unit"; do
    if guest "$gateway_instance" systemctl is-active --quiet "$unit" ||
       guest "$node_instance" systemctl is-active --quiet "$unit"; then
      echo "capacity unit remains active: $unit" >&2
      exit 3
    fi
  done
  for package in nginx nginx-common; do
    if guest "$gateway_instance" dpkg-query -W "$package" >/dev/null 2>&1; then
      echo "owned capacity nginx package remains: $package" >&2
      exit 3
    fi
  done
}

assert_capacity_temporary_absent() {
  local instance path
  for path in /tmp/clients.sh /tmp/monitor.py /tmp/controller "/tmp/$controller_unit" /tmp/vpnctl-v2-capacity-peers.conf; do
    assert_path_absent "$gateway_instance" "$path"
  done
  for path in /tmp/clients.sh /tmp/client_load.py /tmp/load.py "/tmp/$backend_unit" \
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

prepare_controller_binary() {
  temporary_root=$(mktemp -d /private/tmp/vpnctl-v2-capacity.XXXXXX)
  env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOCACHE=/private/tmp/vpnctl-go-cache \
    go build -trimpath -ldflags '-s -w' -o "$temporary_root/controller" ./test/v2lab/capacity/controller
  shasum -a 256 "$temporary_root/controller" > "$run_root/controller.sha256"
}

copy_capacity_files() {
  limactl copy --backend=scp \
    "$fixture_root/clients.sh" "$fixture_root/monitor.py" "$fixture_root/$controller_unit" \
    "$temporary_root/controller" "$gateway_instance:/tmp/"
  limactl copy --backend=scp \
    "$fixture_root/clients.sh" "$fixture_root/client_load.py" "$fixture_root/load.py" \
    "$fixture_root/$backend_unit" "$repository_root/test/v2lab/ingress/webhook_receiver.py" \
    "$repository_root/test/v2lab/ingress/ingress_load.py" "$node_instance:/tmp/"
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
  local gateway_ip attempt probe_output
  gateway_ip=$(lab_ip "$gateway_instance")
  "$repository_root/scripts/v2restricted-spike.sh" prepare > "$run_root/restricted-prepare.log"
  "$repository_root/scripts/v2tunnel-spike.sh" prepare > "$run_root/tunnel-prepare.log"
  "$repository_root/scripts/v2ingress-spike.sh" prepare "$gateway_ip" > "$run_root/ingress-prepare.log"

  guest "$node_instance" sudo install -m 0755 /tmp/webhook_receiver.py \
    /usr/local/libexec/vpnctl-v2-capacity/webhook-receiver
  guest "$node_instance" sudo install -m 0755 /tmp/load.py /usr/local/libexec/vpnctl-v2-capacity/load
  guest "$node_instance" sudo install -m 0755 /tmp/client_load.py /usr/local/libexec/vpnctl-v2-capacity/client-load
  guest "$node_instance" sudo install -m 0755 /tmp/ingress_load.py /usr/local/libexec/vpnctl-v2-capacity/ingress-load
  guest "$node_instance" sudo install -m 0644 "/tmp/$backend_unit" "/etc/systemd/system/$backend_unit"
  guest "$node_instance" sudo systemctl stop "$tunnel_backend_unit"
  guest "$node_instance" sudo systemctl daemon-reload
  guest "$node_instance" sudo systemctl start "$backend_unit"

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
    "$backend_unit" "$tunnel_backend_unit" vpnctl-v2-spike-tunnel-client.service \
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
    -u "$backend_unit" -u vpnctl-v2-spike-tunnel-client.service \
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

run_connection_limits() {
  local gateway_ip
  gateway_ip=$(lab_ip "$gateway_instance")
  guest "$node_instance" python3 /usr/local/libexec/vpnctl-v2-capacity/ingress-load load \
    --public-ip "$gateway_ip" --certificate /tmp/vpnctl-v2-capacity-gateway.crt \
    --requests 45 --delay-ms 3000 --body-bytes 32 --timeout 20 --path /load/a \
    > "$run_root/per-expose-limit.json"
  jq -e '.responses == 45 and (.errors | length) == 0 and .status_counts["200"] == 40 and .status_counts["503"] == 5' \
    "$run_root/per-expose-limit.json" >/dev/null
  guest "$node_instance" python3 /usr/local/libexec/vpnctl-v2-capacity/ingress-load load \
    --public-ip "$gateway_ip" --certificate /tmp/vpnctl-v2-capacity-gateway.crt \
    --requests 72 --delay-ms 3000 --body-bytes 32 --timeout 20 --path /load/a --path /load/b \
    > "$run_root/gateway-limit.json"
  jq -e '.responses == 72 and (.errors | length) == 0 and .status_counts["200"] == 64 and .status_counts["503"] == 8' \
    "$run_root/gateway-limit.json" >/dev/null
}

start_loads() {
  local gateway_ip duration webhook_rate api_rate body fault_start fault_end expected_sha monitor_duration
  gateway_ip=$(lab_ip "$gateway_instance")
  duration=$(value '.profile.duration_seconds')
  webhook_rate=$(value '.profile.webhook_requests_per_second')
  api_rate=$(value '.profile.bot_api_requests_per_second')
  body=$(value '.profile.webhook_body_bytes')
  fault_start=$(value '.fault.accepted_failure_window_start_seconds')
  fault_end=$(value '.fault.accepted_failure_window_end_seconds')
  expected_sha=$(shasum -a 256 "$repository_root/test/v2lab/restricted/telegram-api.json" | awk '{print $1}')
  monitor_duration=$((duration + 10))

  guest "$gateway_instance" sudo /usr/local/libexec/vpnctl-v2-capacity/monitor \
    --duration "$monitor_duration" --interval 2 \
    --unit "$controller_unit" --unit "$ingress_unit" --unit "$tunnel_auth_unit" \
    --unit "$tunnel_server_unit" --unit "$restricted_gateway_unit" \
    --unit "$restricted_echo_unit" --unit "$restricted_udp_unit" \
    > "$run_root/gateway-resources.json" &
  background_pids+=("$!")
  guest "$node_instance" sudo /usr/local/libexec/vpnctl-v2-capacity/client-load --duration "$duration" \
    > "$run_root/clients.json" &
  background_pids+=("$!")
  guest "$node_instance" python3 /usr/local/libexec/vpnctl-v2-capacity/load webhook \
    --duration "$duration" --rate "$webhook_rate" --workers 32 --timeout 8 \
    --failure-window-start "$fault_start" --failure-window-end "$fault_end" \
    --public-ip "$gateway_ip" --certificate /tmp/vpnctl-v2-capacity-gateway.crt --body-bytes "$body" \
    > "$run_root/webhook-load.json" &
  background_pids+=("$!")
  guest "$node_instance" python3 /usr/local/libexec/vpnctl-v2-capacity/load api \
    --duration "$duration" --rate "$api_rate" --workers 24 --timeout 8 \
    --failure-window-start -1 --failure-window-end -1 \
    --target http://127.0.0.1:18080/telegram-api.json --expected-sha256 "$expected_sha" \
    > "$run_root/api-load.json" &
  background_pids+=("$!")
}

inject_reconnect() {
  local down_seconds attempt unavailable=false recovered=false
  local recovery_started recovery_finished
  down_seconds=$(value '.fault.frps_down_seconds')
  guest "$gateway_instance" sudo systemctl stop "$tunnel_server_unit"
  for attempt in $(seq 1 20); do
    if [ "$(probe_webhook 2>/dev/null | jq -r '.status' || true)" = 503 ]; then
      unavailable=true
      break
    fi
    sleep 0.1
  done
  [ "$unavailable" = true ] || { echo "ingress did not become 503 while frps was stopped" >&2; exit 1; }
  sleep "$down_seconds"
  guest "$gateway_instance" sudo systemctl start "$tunnel_server_unit"
  recovery_started=$(python3 -c 'import time; print(time.monotonic())')
  for attempt in $(seq 1 40); do
    if probe_webhook 2>/dev/null | jq -e '.status == 200 and .ok == true' >/dev/null; then
      recovered=true
      break
    fi
    sleep 0.25
  done
  recovery_finished=$(python3 -c 'import time; print(time.monotonic())')
  [ "$recovered" = true ] || { echo "FRP did not reconnect under sustained load" >&2; exit 1; }
  jq -n --argjson down_seconds "$down_seconds" \
    --argjson recovery_seconds "$(awk -v start="$recovery_started" -v finish="$recovery_finished" 'BEGIN {printf "%.3f", finish-start}')" \
    '{unavailable_status: 503, down_seconds: $down_seconds, recovery_seconds: $recovery_seconds, recovered_without_client_restart: true}' \
    > "$run_root/reconnect.json"
}

wait_loads() {
  local pid result=0
  for pid in "${background_pids[@]}"; do
    wait "$pid" || result=$?
  done
  background_pids=()
  [ "$result" -eq 0 ] || { echo "one or more sustained workload processes failed" >&2; exit "$result"; }
}

write_summary() {
  local source_commit=$1
  jq -n \
    --arg source_commit "$source_commit" \
    --slurpfile profile "$manifest" \
    --slurpfile controller "$run_root/controller-idle.json" \
    --slurpfile webhook "$run_root/webhook-load.json" \
    --slurpfile api "$run_root/api-load.json" \
    --slurpfile clients "$run_root/clients.json" \
    --slurpfile resources "$run_root/gateway-resources.json" \
    --slurpfile reconnect "$run_root/reconnect.json" \
    --slurpfile expose_limit "$run_root/per-expose-limit.json" \
    --slurpfile gateway_limit "$run_root/gateway-limit.json" '
    {
      schema_version: 1,
      status: "passed",
      source_commit: $source_commit,
      profile: $profile[0].profile,
      target: $profile[0].target,
      controller: $controller[0],
      workload: {webhook: $webhook[0], bot_api: $api[0], clients: $clients[0]},
      resources: $resources[0],
      reconnect: $reconnect[0],
      connection_limits: {
        per_expose: {accepted: $expose_limit[0].status_counts["200"], rejected: $expose_limit[0].status_counts["503"]},
        gateway: {accepted: $gateway_limit[0].status_counts["200"], rejected: $gateway_limit[0].status_counts["503"]}
      },
      no_oom: ([ $resources[0].services[].oom_kills ] | add) == 0,
      no_deadlock: ($webhook[0].status == "completed" and $api[0].status == "completed" and $clients[0].status == "passed"),
      cleanup: {owner_scoped: true, temporary_resources_absent: true, prior_fixture_states_restored: true}
    }' > "$run_root/summary.json"
}

assert_summary() {
  jq -e --slurpfile limits "$manifest" '
    .status == "passed" and
    .profile.logical_telegram_users == 300 and .profile.personal_clients == 5 and
    .controller.within_target and
    .workload.webhook.scheduled_requests == (.profile.duration_seconds * .profile.webhook_requests_per_second) and
    .workload.webhook.successful_requests >= $limits[0].bounds.webhook_successful_requests_minimum and
    .workload.webhook.failures_outside_accepted_window == $limits[0].bounds.webhook_failures_outside_reconnect_window and
    .workload.webhook.tail_30_seconds_successful and
    .workload.webhook.latency_ms.p95 <= $limits[0].bounds.webhook_success_p95_ms and
    .workload.webhook.latency_ms.p99 <= $limits[0].bounds.webhook_success_p99_ms and
    .workload.bot_api.scheduled_requests == (.profile.duration_seconds * .profile.bot_api_requests_per_second) and
    .workload.bot_api.failed_requests == 0 and .workload.bot_api.tail_30_seconds_successful and
    .workload.bot_api.latency_ms.p95 <= $limits[0].bounds.bot_api_success_p95_ms and
    .workload.bot_api.latency_ms.p99 <= $limits[0].bounds.bot_api_success_p99_ms and
    (.workload.clients.clients | length) == 5 and
    all(.workload.clients.clients[]; .packet_loss_percent == $limits[0].bounds.client_packet_loss_percent) and
    .resources.cpu_percent.average <= $limits[0].bounds.maximum_average_cpu_percent and
    .resources.memory.minimum_available_bytes >= $limits[0].bounds.minimum_mem_available_bytes and
    .resources.memory.maximum_swap_used_bytes <= $limits[0].bounds.maximum_swap_used_bytes and
    .resources.disk.minimum_free_bytes >= $limits[0].bounds.minimum_free_disk_bytes and
    .resources.disk.growth_bytes <= $limits[0].bounds.maximum_disk_growth_bytes and
    .reconnect.recovery_seconds <= $limits[0].bounds.tunnel_reconnect_seconds and
    .connection_limits.per_expose == {accepted: 40, rejected: 5} and
    .connection_limits.gateway == {accepted: 64, rejected: 8} and
    .no_oom and .no_deadlock
  ' "$run_root/summary.json" >/dev/null
}

verify() {
  local stamp source_commit duration fault_after elapsed remaining step
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
  PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test/v2lab/capacity/test_load.py > "$run_root/source-tests.log" 2>&1
  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./test/v2lab/capacity/controller > "$run_root/controller-build-test.log"
  prepare_controller_binary
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
  start_loads

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
  inject_reconnect
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
  wait_loads

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
  assert_summary
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
