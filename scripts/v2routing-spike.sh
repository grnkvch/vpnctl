#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
fixture_root="$repository_root/test/v2lab/routing"
manifest="$fixture_root/manifest.json"
artifact_root="$repository_root/artifacts/v2lab/routing-spike"
cache_root="$repository_root/artifacts/v2lab/cache"
node_instance=vpnctl-v2-node
gateway_instance=vpnctl-v2-gateway
node_ns=vpnctl-v2-rnode
direct_ns=vpnctl-v2-rdirect
gateway_ns=vpnctl-v2-rgateway
owner_value=vpnctl-v2-routing-spike-v1
owner_path=/etc/vpnctl-v2-spike/routing/.owner
config_root=/etc/vpnctl-v2-spike/routing
runtime_root=/run/vpnctl-v2-spike-routing
libexec_root=/usr/local/libexec/vpnctl-v2-spike-routing
guard_unit=vpnctl-v2-spike-routing-guard.service
engine_unit=vpnctl-v2-spike-routing-engine.service
direct_unit=vpnctl-v2-spike-routing-direct.service
gateway_unit=vpnctl-v2-spike-routing-gateway.service
node_unit=vpnctl-v2-spike-routing-node.service
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
mihomo_binary=
cleanup_armed=false

usage() {
  cat <<'EOF'
Usage:
  scripts/v2routing-spike.sh prepare
  scripts/v2routing-spike.sh verify [evidence-directory]
  scripts/v2routing-spike.sh status
  scripts/v2routing-spike.sh stop
  scripts/v2routing-spike.sh uninstall
EOF
}

manifest_value() {
  jq -er "$1" "$manifest"
}

instance_json() {
  limactl list --json | jq -ce --arg name "$1" 'select(.name == $name)'
}

assert_lab_instance() {
  local instance=$1
  if ! instance_json "$instance" | jq -e --arg digest "$lab_image_digest" '
    .status == "Running" and
    .vmType == "qemu" and
    .arch == "x86_64" and
    .cpus == 1 and
    .memory == 536870912 and
    .disk == 10737418240 and
    .config.images[0].digest == $digest and
    any(.network[]?; .lima == "user-v2")
  ' >/dev/null; then
    echo "required contract-matching lab instance is not running: $instance" >&2
    exit 4
  fi
}

lab_ip() {
  limactl shell --tty=false "$1" -- ip -4 -o address show scope global | \
    awk '$4 ~ /^192[.]168[.]104[.]/ {sub(/\/.*/, "", $4); print $4; exit}'
}

unit_active() {
  limactl shell --tty=false "$node_instance" -- systemctl is-active --quiet "$1"
}

namespace_exists() {
  limactl shell --tty=false "$node_instance" -- sudo ip netns list | \
    awk '{print $1}' | grep -Fxq "$1"
}

assert_owned_or_absent() {
  if limactl shell --tty=false "$node_instance" -- sudo test -e "$config_root"; then
    if ! limactl shell --tty=false "$node_instance" -- sudo grep -Fxq "$owner_value" "$owner_path"; then
      echo "refusing to overwrite unowned routing spike path" >&2
      exit 3
    fi
  fi
}

assert_other_spikes_inactive() {
  local unit
  for unit in \
    vpnctl-v2-spike-restricted-node.service \
    vpnctl-v2-spike-tunnel-client.service \
    vpnctl-v2-spike-tunnel-backend.service; do
    if unit_active "$unit"; then
      echo "refusing routing mutation while another node data-plane spike is active: $unit" >&2
      exit 3
    fi
  done
}

copy_to_guest_tmp() {
  local source=$1
  limactl copy --backend=scp "$source" "$node_instance:/tmp/$(basename "$source")"
}

verify_archive() {
  local archive=$1 expected actual
  expected=$(manifest_value '.mihomo.sha256')
  actual=$(shasum -a 256 "$archive" | awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    echo "pinned Mihomo archive checksum mismatch: $archive" >&2
    exit 3
  fi
}

fetch_mihomo() {
  local asset archive binary temporary
  asset=$(manifest_value '.mihomo.asset')
  archive="$cache_root/$asset"
  binary="$cache_root/mihomo-linux-amd64"
  mkdir -p "$cache_root"
  if [ -e "$archive" ]; then
    verify_archive "$archive"
  else
    temporary="$archive.tmp.$$"
    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
      --output "$temporary" "$(manifest_value '.mihomo.url')"
    verify_archive "$temporary"
    mv "$temporary" "$archive"
  fi
  temporary="$binary.tmp.$$"
  gzip -dc "$archive" > "$temporary"
  chmod 0755 "$temporary"
  mv "$temporary" "$binary"
  mihomo_binary=$binary
}

node_exec() {
  limactl shell --tty=false "$node_instance" -- sudo ip netns exec "$node_ns" "$@"
}

gateway_exec() {
  limactl shell --tty=false "$node_instance" -- sudo ip netns exec "$gateway_ns" "$@"
}

node_policy() {
  node_exec "$libexec_root/policy" "$@"
}

node_probe() {
  node_exec "$libexec_root/probe" "$@"
}

gateway_probe() {
  gateway_exec "$libexec_root/probe" "$@"
}

wait_unit_active() {
  local unit=$1 attempt
  for attempt in $(seq 1 80); do
    unit_active "$unit" && return
    sleep 0.25
  done
  limactl shell --tty=false "$node_instance" -- systemctl status --no-pager "$unit" >&2 || true
  echo "routing spike unit did not become active: $unit" >&2
  exit 1
}

wait_readiness() {
  local expected=$1 attempt current
  for attempt in $(seq 1 80); do
    current=$(node_policy status | jq -r '.readiness')
    [ "$current" = "$expected" ] && return
    sleep 0.25
  done
  echo "routing readiness did not become $expected" >&2
  exit 1
}

request_node() {
  local protocol=$1 host=$2 label=$3
  node_probe request --protocol "$protocol" --host "$host" --port 18080 \
    --expect "$label" --timeout 1 >/dev/null
}

wait_node_request() {
  local protocol=$1 host=$2 label=$3 attempt
  for attempt in $(seq 1 80); do
    if node_probe request --protocol "$protocol" --host "$host" --port 18080 \
      --expect "$label" --timeout 0.5 >/dev/null 2>&1; then
      return
    fi
    sleep 0.25
  done
  request_node "$protocol" "$host" "$label"
}

blocked_node() {
  local protocol=$1 host=$2
  node_probe blocked --protocol "$protocol" --host "$host" --port 18080 \
    --timeout 0.5 >/dev/null
}

recovery_node() {
  node_probe request --protocol tcp --host 10.202.0.1 --port 19000 \
    --expect recovery --timeout 1 >/dev/null
}

root_network_snapshot() {
  local prefix=$1
  limactl shell --tty=false "$node_instance" -- sudo nft --stateless -nn list ruleset > "$prefix-nft.txt"
  limactl shell --tty=false "$node_instance" -- ip -j -4 rule show > "$prefix-rules4.json"
  limactl shell --tty=false "$node_instance" -- ip -j -6 rule show > "$prefix-rules6.json"
  limactl shell --tty=false "$node_instance" -- ip -j -4 route show table all > "$prefix-routes4.json"
  limactl shell --tty=false "$node_instance" -- ip -j -6 route show table all > "$prefix-routes6.json"
}

foreign_snapshot() {
  local prefix=$1
  node_exec nft --stateless -nn list table inet foreign_keep > "$prefix-nft.txt"
  node_exec ip -4 rule show | awk '$1 == "12000:"' > "$prefix-rule.txt"
}

assert_same_files() {
  local before=$1 after=$2 label=$3
  if ! cmp -s "$before" "$after"; then
    echo "$label changed unexpectedly" >&2
    diff -u "$before" "$after" >&2 || true
    exit 1
  fi
}

stop_units_best_effort() {
  limactl shell --tty=false "$node_instance" -- sudo systemctl stop \
    "$engine_unit" "$guard_unit" "$node_unit" "$gateway_unit" "$direct_unit" >/dev/null 2>&1 || true
}

clean_runtime_best_effort() {
  stop_units_best_effort
  if namespace_exists "$node_ns"; then
    node_policy remove >/dev/null 2>&1 || true
  fi
  if limactl shell --tty=false "$node_instance" -- sudo test -x "$libexec_root/topology"; then
    limactl shell --tty=false "$node_instance" -- sudo "$libexec_root/topology" cleanup >/dev/null 2>&1 || true
  else
    for namespace in "$node_ns" "$direct_ns" "$gateway_ns"; do
      limactl shell --tty=false "$node_instance" -- sudo ip netns delete "$namespace" >/dev/null 2>&1 || true
    done
  fi
  return 0
}

install_files() {
  local unit
  limactl shell --tty=false "$node_instance" -- sudo install -d -m 0700 \
    "$config_root" "$libexec_root" "$runtime_root"
  limactl shell --tty=false "$node_instance" -- sudo sh -c \
    "printf '%s\n' '$owner_value' > '$owner_path' && chmod 0600 '$owner_path'"

  copy_to_guest_tmp "$fixture_root/base.nft"
  copy_to_guest_tmp "$fixture_root/mihomo.yaml"
  copy_to_guest_tmp "$fixture_root/backend.py"
  copy_to_guest_tmp "$fixture_root/probe.py"
  copy_to_guest_tmp "$fixture_root/topology.sh"
  copy_to_guest_tmp "$fixture_root/policy.sh"
  copy_to_guest_tmp "$fixture_root/fault.sh"
  copy_to_guest_tmp "$mihomo_binary"
  limactl shell --tty=false "$node_instance" -- sudo install -m 0600 /tmp/base.nft "$config_root/base.nft"
  limactl shell --tty=false "$node_instance" -- sudo install -m 0600 /tmp/mihomo.yaml "$config_root/config.yaml"
  limactl shell --tty=false "$node_instance" -- sudo install -m 0755 /tmp/backend.py "$libexec_root/backend"
  limactl shell --tty=false "$node_instance" -- sudo install -m 0755 /tmp/probe.py "$libexec_root/probe"
  limactl shell --tty=false "$node_instance" -- sudo install -m 0755 /tmp/topology.sh "$libexec_root/topology"
  limactl shell --tty=false "$node_instance" -- sudo install -m 0755 /tmp/policy.sh "$libexec_root/policy"
  limactl shell --tty=false "$node_instance" -- sudo install -m 0755 /tmp/fault.sh "$libexec_root/fault"
  limactl shell --tty=false "$node_instance" -- sudo install -m 0755 /tmp/mihomo-linux-amd64 "$libexec_root/mihomo"

  for unit in "$guard_unit" "$engine_unit" "$direct_unit" "$gateway_unit" "$node_unit"; do
    copy_to_guest_tmp "$fixture_root/systemd/$unit"
    limactl shell --tty=false "$node_instance" -- sudo install -m 0644 "/tmp/$unit" "/etc/systemd/system/$unit"
  done
  limactl shell --tty=false "$node_instance" -- sudo rm -f \
    /tmp/base.nft /tmp/mihomo.yaml /tmp/backend.py /tmp/probe.py /tmp/topology.sh \
    /tmp/policy.sh /tmp/fault.sh /tmp/mihomo-linux-amd64 \
    "/tmp/$guard_unit" "/tmp/$engine_unit" "/tmp/$direct_unit" "/tmp/$gateway_unit" "/tmp/$node_unit"
  limactl shell --tty=false "$node_instance" -- sudo systemctl daemon-reload
  local version
  version=$(limactl shell --tty=false "$node_instance" -- sudo "$libexec_root/mihomo" -v | awk 'NR == 1 {print $3}')
  if [ "$version" != "$(manifest_value '.mihomo.version')" ]; then
    echo "installed routing Mihomo version mismatch: $version" >&2
    exit 3
  fi
}

prepare() {
  assert_lab_instance "$node_instance"
  assert_lab_instance "$gateway_instance"
  assert_other_spikes_inactive
  assert_owned_or_absent
  fetch_mihomo
  if limactl shell --tty=false "$node_instance" -- sudo test -e "$config_root"; then
    clean_runtime_best_effort
  else
    for namespace in "$node_ns" "$direct_ns" "$gateway_ns"; do
      if namespace_exists "$namespace"; then
        echo "refusing to claim existing routing namespace: $namespace" >&2
        exit 3
      fi
    done
  fi
  install_files
  trap 'clean_runtime_best_effort' EXIT
  limactl shell --tty=false "$node_instance" -- sudo "$libexec_root/topology" prepare
  node_exec "$libexec_root/mihomo" -t -d "$config_root" >/dev/null
  node_policy preflight
  limactl shell --tty=false "$node_instance" -- sudo systemctl reset-failed \
    "$guard_unit" "$engine_unit" "$direct_unit" "$gateway_unit" "$node_unit" >/dev/null 2>&1 || true
  limactl shell --tty=false "$node_instance" -- sudo systemctl start \
    "$direct_unit" "$gateway_unit" "$node_unit"
  wait_unit_active "$direct_unit"
  wait_unit_active "$gateway_unit"
  wait_unit_active "$node_unit"
  wait_node_request tcp 203.0.113.10 direct-selected
  wait_node_request udp 203.0.113.10 direct-selected
  wait_node_request tcp 203.0.113.20 direct-unmatched
  wait_node_request tcp 2001:db8:1::10 direct-v6-selected
  wait_node_request udp 2001:db8:1::10 direct-v6-selected
  wait_node_request tcp 2001:db8:1::11 direct-v6-resolved-selected
  wait_node_request udp 2001:db8:1::11 direct-v6-resolved-selected
  wait_node_request tcp 2001:db8:1::20 direct-v6-unmatched
  if unit_active "$guard_unit" || unit_active "$engine_unit"; then
    echo "routing guard or engine became active during prepare" >&2
    exit 1
  fi
  trap - EXIT
  echo "routing spike prepared in isolated namespaces; root VM networking remains a read-only control"
}

uninstall_internal() {
  local quiet=${1:-false}
  if ! limactl shell --tty=false "$node_instance" -- sudo test -e "$config_root"; then
    [ "$quiet" = true ] || echo "routing spike is not installed"
    return
  fi
  if ! limactl shell --tty=false "$node_instance" -- sudo grep -Fxq "$owner_value" "$owner_path"; then
    echo "refusing to uninstall unowned routing spike path" >&2
    exit 3
  fi
  clean_runtime_best_effort
  limactl shell --tty=false "$node_instance" -- sudo rm -f \
    "/etc/systemd/system/$guard_unit" "/etc/systemd/system/$engine_unit" \
    "/etc/systemd/system/$direct_unit" "/etc/systemd/system/$gateway_unit" \
    "/etc/systemd/system/$node_unit"
  limactl shell --tty=false "$node_instance" -- sudo rm -rf "$config_root" "$libexec_root" "$runtime_root"
  limactl shell --tty=false "$node_instance" -- sudo systemctl daemon-reload
  limactl shell --tty=false "$node_instance" -- sudo systemctl reset-failed \
    "$guard_unit" "$engine_unit" "$direct_unit" "$gateway_unit" "$node_unit" >/dev/null 2>&1 || true
  [ "$quiet" = true ] || echo "owner-checked routing spike resources removed"
}

verification_cleanup() {
  if [ "$cleanup_armed" = true ]; then
    uninstall_internal true >/dev/null 2>&1 || true
  fi
}

verify() {
  local evidence_dir=${1:-"$artifact_root/evidence-$(date -u +%Y%m%dT%H%M%SZ)"}
  local gateway_ip resource_dir foreign_counter ipv6_drop_counter resolved_ipv6_entries
  assert_lab_instance "$node_instance"
  assert_lab_instance "$gateway_instance"
  assert_other_spikes_inactive
  if ! limactl shell --tty=false "$node_instance" -- sudo grep -Fxq "$owner_value" "$owner_path"; then
    echo "routing spike is not owner-prepared" >&2
    exit 3
  fi
  mkdir -p "$evidence_dir"
  chmod 0700 "$evidence_dir"
  cleanup_armed=true
  trap verification_cleanup EXIT

  root_network_snapshot "$evidence_dir/root-before"
  foreign_snapshot "$evidence_dir/foreign-before"
  gateway_ip=$(lab_ip "$gateway_instance")
  limactl shell --tty=false "$node_instance" -- ping -c 1 -W 2 "$gateway_ip" >/dev/null

  if node_policy guard after-nft >/dev/null 2>&1; then
    echo "injected routing activation failure unexpectedly succeeded" >&2
    exit 1
  fi
  node_policy assert-clean
  foreign_snapshot "$evidence_dir/foreign-after-injected-rollback"
  assert_same_files "$evidence_dir/foreign-before-nft.txt" "$evidence_dir/foreign-after-injected-rollback-nft.txt" "foreign nftables table after injected rollback"
  assert_same_files "$evidence_dir/foreign-before-rule.txt" "$evidence_dir/foreign-after-injected-rollback-rule.txt" "foreign policy rule after injected rollback"

  limactl shell --tty=false "$node_instance" -- sudo systemctl start "$guard_unit"
  wait_unit_active "$guard_unit"
  wait_readiness not-ready
  blocked_node tcp 203.0.113.10
  blocked_node udp 203.0.113.10
  blocked_node tcp 203.0.113.20
  blocked_node udp 203.0.113.20
  blocked_node tcp 2001:db8:1::10
  blocked_node udp 2001:db8:1::10
  blocked_node tcp 2001:db8:1::11
  blocked_node udp 2001:db8:1::11
  blocked_node tcp 2001:db8:1::20
  blocked_node udp 2001:db8:1::20
  recovery_node

  limactl shell --tty=false "$node_instance" -- sudo systemctl start "$engine_unit"
  wait_unit_active "$engine_unit"
  wait_readiness ready
  request_node tcp 203.0.113.10 gateway-selected
  request_node udp 203.0.113.10 gateway-selected
  request_node tcp 203.0.113.20 direct-unmatched
  request_node udp 203.0.113.20 direct-unmatched
  blocked_node tcp 2001:db8:1::10
  blocked_node udp 2001:db8:1::10
  blocked_node tcp 2001:db8:1::11
  blocked_node udp 2001:db8:1::11
  request_node tcp 2001:db8:1::20 direct-v6-unmatched
  request_node udp 2001:db8:1::20 direct-v6-unmatched
  node_probe request --protocol udp --host 203.0.113.20 --port 18080 \
    --expect direct-unmatched --mark 0x00001234 --timeout 1 >/dev/null
  gateway_probe request --protocol tcp --host 10.202.0.2 --port 18082 \
    --bind 198.51.100.50 --expect node-ingress --timeout 2 >/dev/null

  node_exec nft -j list table inet vpnctl_v2_spike_routing > "$evidence_dir/ready-nft.json"
  node_policy status > "$evidence_dir/ready-policy.json"
  foreign_counter=$(jq '[.nftables[] | .counter? | select(.name == "foreign_bits_preserved") | .packets] | add // 0' "$evidence_dir/ready-nft.json")
  if [ "$foreign_counter" -lt 1 ]; then
    echo "routing mark namespace did not preserve lower foreign bits" >&2
    exit 1
  fi
  ipv6_drop_counter=$(jq '[.nftables[] | .counter? | select(.name == "selected_ipv6_drop") | .packets] | if length == 1 then .[0] else -1 end' "$evidence_dir/ready-nft.json")
  if [ "$ipv6_drop_counter" -lt 4 ]; then
    echo "selected IPv6 TCP/UDP paths did not increment the shared drop counter" >&2
    exit 1
  fi
  resolved_ipv6_entries=$(jq '[.nftables[] | .set? | select(.name == "selected_resolved_v6") | .elem[]?] | length' "$evidence_dir/ready-nft.json")
  if [ "$resolved_ipv6_entries" -ne 1 ]; then
    echo "selected resolved IPv6 fixture set differs from its one-address contract" >&2
    exit 1
  fi

  limactl shell --tty=false "$node_instance" -- sudo "$libexec_root/fault" \
    gateway-outage "$runtime_root/gateway-outage.json"
  limactl shell --tty=false "$node_instance" -- sudo cat "$runtime_root/gateway-outage.json" > "$evidence_dir/gateway-outage.json"
  jq -e '.status == "passed" and .fault == "gateway" and .selected_tcp_blocked and .selected_udp_blocked and .unrelated_tcp_direct and .unrelated_udp_direct and .routing_engine_ready and .active_transport_preserved and (.automatic_fallback | not) and .recovered_without_engine_restart' \
    "$evidence_dir/gateway-outage.json" >/dev/null

  limactl shell --tty=false "$node_instance" -- sudo "$libexec_root/fault" \
    transport-outage "$runtime_root/transport-outage.json"
  limactl shell --tty=false "$node_instance" -- sudo cat "$runtime_root/transport-outage.json" > "$evidence_dir/transport-outage.json"
  jq -e '.status == "passed" and .fault == "transport" and .selected_tcp_blocked and .selected_udp_blocked and .unrelated_tcp_direct and .unrelated_udp_direct and .routing_engine_ready and .active_transport_preserved and (.automatic_fallback | not) and .recovered_without_engine_restart' \
    "$evidence_dir/transport-outage.json" >/dev/null

  limactl shell --tty=false "$node_instance" -- sudo "$libexec_root/fault" \
    crash "$runtime_root/crash.json"
  limactl shell --tty=false "$node_instance" -- sudo cat "$runtime_root/crash.json" > "$evidence_dir/crash.json"
  limactl shell --tty=false "$node_instance" -- sudo "$libexec_root/fault" \
    restart "$runtime_root/restart.json"
  limactl shell --tty=false "$node_instance" -- sudo cat "$runtime_root/restart.json" > "$evidence_dir/restart.json"
  limactl shell --tty=false "$node_instance" -- sudo "$libexec_root/fault" \
    component-update "$runtime_root/component-update.json"
  limactl shell --tty=false "$node_instance" -- sudo cat "$runtime_root/component-update.json" > "$evidence_dir/component-update.json"
  jq -e '.status == "passed" and .replacement == "atomic-same-version" and .checksum_preserved and .process_restarted and .selected_tcp_never_direct and .selected_udp_never_direct and .selected_ipv6_never_direct and .unrelated_direct_recovered' \
    "$evidence_dir/component-update.json" >/dev/null

  limactl shell --tty=false "$node_instance" -- sudo systemctl stop "$engine_unit"
  wait_readiness not-ready
  blocked_node tcp 203.0.113.10
  blocked_node udp 203.0.113.10
  blocked_node tcp 203.0.113.20
  blocked_node udp 203.0.113.20
  blocked_node tcp 2001:db8:1::10
  blocked_node udp 2001:db8:1::10
  blocked_node tcp 2001:db8:1::11
  blocked_node udp 2001:db8:1::11
  blocked_node tcp 2001:db8:1::20
  blocked_node udp 2001:db8:1::20
  recovery_node

  limactl shell --tty=false "$node_instance" -- sudo systemctl stop "$guard_unit"
  node_policy remove
  node_policy assert-clean
  request_node tcp 203.0.113.10 direct-selected
  request_node udp 203.0.113.10 direct-selected
  request_node tcp 203.0.113.20 direct-unmatched
  request_node tcp 2001:db8:1::10 direct-v6-selected
  request_node udp 2001:db8:1::10 direct-v6-selected
  request_node tcp 2001:db8:1::11 direct-v6-resolved-selected
  request_node udp 2001:db8:1::11 direct-v6-resolved-selected
  request_node tcp 2001:db8:1::20 direct-v6-unmatched
  request_node udp 2001:db8:1::20 direct-v6-unmatched
  foreign_snapshot "$evidence_dir/foreign-after-uninstall"
  assert_same_files "$evidence_dir/foreign-before-nft.txt" "$evidence_dir/foreign-after-uninstall-nft.txt" "foreign nftables table after policy uninstall"
  assert_same_files "$evidence_dir/foreign-before-rule.txt" "$evidence_dir/foreign-after-uninstall-rule.txt" "foreign policy rule after policy uninstall"

  resource_dir="$evidence_dir/resources"
  mkdir -p "$resource_dir"
  limactl shell --tty=false "$node_instance" -- sudo /usr/local/libexec/vpnctl-v2-lab-report node "$gateway_ip" > "$resource_dir/node.json"
  jq -s '{schema_version: 1, hosts: .}' "$resource_dir/node.json" > "$resource_dir/summary.json"

  limactl shell --tty=false "$node_instance" -- sudo cat "$runtime_root/direct.json" > "$evidence_dir/direct-backend.json"
  limactl shell --tty=false "$node_instance" -- sudo cat "$runtime_root/gateway.json" > "$evidence_dir/gateway-backend.json"
  node_exec nft --stateless -nn list table inet foreign_keep > "$evidence_dir/foreign-final.txt"

  jq -n \
    --arg status passed \
    --arg mark_mask "$(manifest_value '.marks.mask')" \
    --arg direct_mark "$(manifest_value '.marks.direct')" \
    --arg selected_mark "$(manifest_value '.marks.selected')" \
    --arg recovery_mark "$(manifest_value '.marks.recovery')" \
    --arg ingress_mark "$(manifest_value '.marks.ingress_response')" \
    --argjson selected_table "$(manifest_value '.routing.selected_table')" \
    --argjson gateway_table "$(manifest_value '.routing.gateway_table')" \
    --argjson ipv6_drop_packets "$ipv6_drop_counter" \
    --argjson resolved_ipv6_entries "$resolved_ipv6_entries" \
    --slurpfile gateway_outage "$evidence_dir/gateway-outage.json" \
    --slurpfile transport_outage "$evidence_dir/transport-outage.json" \
    --slurpfile component_update "$evidence_dir/component-update.json" \
    '{
      schema_version: 1,
      status: $status,
      marks: {mask: $mark_mask, direct: $direct_mark, selected: $selected_mark, recovery: $recovery_mark, ingress_response: $ingress_mark, lower_bits_preserved: true},
      routing: {selected_table: $selected_table, gateway_table: $gateway_table, unreachable_fallback: true},
      hooks: {prerouting_priority: -150, output_route_priority: -150, after_conntrack: true},
      boot: {guard_before_tun: true, new_application_blocked: true, recovery_allowed: true},
      ready: {selected_tcp_gateway: true, selected_udp_gateway: true, unmatched_ipv4_direct: true, unmatched_ipv6_direct: true, selected_ipv6_blocked: true},
      ipv6: {mode: "selected-block-only", full_data_plane: false, unmatched_behavior: "preserve-system", static_tcp_udp_blocked: true, resolved_aaaa_tcp_udp_blocked: true, unrelated_tcp_udp_direct: true, selected_drop_packets: $ipv6_drop_packets, resolved_selected_entries: $resolved_ipv6_entries},
      outages: {gateway: $gateway_outage[0], transport: $transport_outage[0]},
      component_update: $component_update[0],
      conntrack: {established_direct_retained_after_crash: true, selected_never_failed_direct: true},
      ingress: {response_symmetry_gateway: true},
      lifecycle: {injected_activation_rolled_back: true, crash_fail_closed: true, restart_fail_closed: true, component_update_fail_closed: true, policy_uninstall_restored_networking: true},
      coexistence: {foreign_nft_preserved: true, foreign_rule_preserved: true, root_namespace_preserved: true}
    }' > "$evidence_dir/summary.json"

  uninstall_internal true
  cleanup_armed=false
  trap - EXIT

  root_network_snapshot "$evidence_dir/root-after"
  for suffix in nft.txt rules4.json rules6.json routes4.json routes6.json; do
    assert_same_files "$evidence_dir/root-before-$suffix" "$evidence_dir/root-after-$suffix" "root namespace $suffix"
  done
  for namespace in "$node_ns" "$direct_ns" "$gateway_ns"; do
    if namespace_exists "$namespace"; then
      echo "routing namespace remained after uninstall: $namespace" >&2
      exit 1
    fi
  done
  printf 'routing spike evidence: %s\n' "$evidence_dir/summary.json"
}

status() {
  assert_lab_instance "$node_instance"
  local unit namespace
  for unit in "$guard_unit" "$engine_unit" "$direct_unit" "$gateway_unit" "$node_unit"; do
    limactl shell --tty=false "$node_instance" -- systemctl show "$unit" \
      -p Id -p LoadState -p ActiveState -p SubState -p MainPID 2>/dev/null || true
  done
  for namespace in "$node_ns" "$direct_ns" "$gateway_ns"; do
    if namespace_exists "$namespace"; then
      printf '%s=present\n' "$namespace"
    else
      printf '%s=absent\n' "$namespace"
    fi
  done
  if namespace_exists "$node_ns" && limactl shell --tty=false "$node_instance" -- sudo test -x "$libexec_root/policy"; then
    node_policy status
  fi
}

stop() {
  assert_lab_instance "$node_instance"
  assert_owned_or_absent
  if ! namespace_exists "$node_ns"; then
    echo "routing spike has no active namespace"
    return
  fi
  limactl shell --tty=false "$node_instance" -- sudo systemctl stop "$engine_unit"
  wait_readiness not-ready
  echo "routing engine stopped; fail-closed guard remains active by design"
}

uninstall() {
  assert_lab_instance "$node_instance"
  assert_owned_or_absent
  uninstall_internal false
}

case "${1:-}" in
  prepare) prepare ;;
  verify) verify "${2:-}" ;;
  status) status ;;
  stop) stop ;;
  uninstall) uninstall ;;
  *) usage >&2; exit 2 ;;
esac
