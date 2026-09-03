#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
fixture_root="$repository_root/test/v2lab/dns"
manifest="$fixture_root/manifest.json"
artifact_root="$repository_root/artifacts/v2lab/dns-spike"
cache_root="$repository_root/artifacts/v2lab/cache"
node_instance=vpnctl-v2-node
gateway_instance=vpnctl-v2-gateway
direct_ns=vpnctl-v2-dns-direct
gateway_ns=vpnctl-v2-dns-gateway
owner_value=vpnctl-v2-dns-spike-v1
config_root=/etc/vpnctl-v2-spike/dns
owner_path="$config_root/.owner"
runtime_root=/run/vpnctl-v2-spike-dns
state_root=/var/lib/vpnctl-v2-spike-dns
libexec_root=/usr/local/libexec/vpnctl-v2-spike-dns
dns_user=vpnctl-v2-dns-spike
resolver_unit=vpnctl-v2-spike-dns-resolver.service
direct_unit=vpnctl-v2-spike-dns-direct.service
gateway_unit=vpnctl-v2-spike-dns-gateway.service
resolved_dropin=/etc/systemd/resolved.conf.d/vpnctl-v2-dns-spike.conf
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
mihomo_binary=
cleanup_armed=false
verification_evidence_dir=
verification_stage=not-started

usage() {
  cat <<'EOF'
Usage:
  scripts/v2dns-spike.sh prepare
  scripts/v2dns-spike.sh verify [evidence-directory]
  scripts/v2dns-spike.sh status
  scripts/v2dns-spike.sh stop
  scripts/v2dns-spike.sh uninstall
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

node_shell() {
  limactl shell --tty=false "$node_instance" -- "$@"
}

node_root() {
  limactl shell --tty=false "$node_instance" -- sudo "$@"
}

unit_active() {
  node_shell systemctl is-active --quiet "$1"
}

namespace_exists() {
  node_root ip netns list | awk '{print $1}' | grep -Fxq "$1"
}

assert_other_spikes_inactive() {
  local unit
  for unit in \
    vpnctl-v2-spike-restricted-node.service \
    vpnctl-v2-spike-tunnel-client.service \
    vpnctl-v2-spike-tunnel-backend.service \
    vpnctl-v2-spike-routing-guard.service \
    vpnctl-v2-spike-routing-engine.service; do
    if unit_active "$unit"; then
      echo "refusing DNS mutation while another node data-plane spike is active: $unit" >&2
      exit 3
    fi
  done
}

assert_owned_or_absent() {
  if node_root test -e "$config_root"; then
    if ! node_root grep -Fxq "$owner_value" "$owner_path"; then
      echo "refusing to overwrite unowned DNS spike path" >&2
      exit 3
    fi
  fi
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

root_network_snapshot() {
  local prefix=$1
  node_root nft --stateless -nn list ruleset > "$prefix-nft.txt"
  node_shell ip -j -4 address show | jq -S '[.[] | {ifindex, ifname, mtu, flags: (.flags | sort), addr_info: [.addr_info[] | {family, local, prefixlen, scope, label}]}] | sort_by(.ifindex)' > "$prefix-addresses.json"
  node_shell ip -j -4 route show table all | jq -S '[.[] | {type, dst, gateway, dev, table, protocol, scope, prefsrc, metric}] | sort_by([.table // "main", .dst // "default", .type // "unicast", .dev // ""])' > "$prefix-routes.json"
  node_root sh -c 'find /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d /run/systemd/resolved.conf.d /usr/lib/systemd/resolved.conf.d -maxdepth 1 -type f -exec sha256sum {} + 2>/dev/null | sort' > "$prefix-resolved-files.txt"
  node_shell readlink -f /etc/resolv.conf > "$prefix-resolv-conf.txt"
  node_shell resolvectl dns > "$prefix-resolvectl-dns.txt"
  node_shell resolvectl domain > "$prefix-resolvectl-domain.txt"
  node_shell resolvectl default-route > "$prefix-resolvectl-default-route.txt"
  node_shell systemctl is-active systemd-resolved.service > "$prefix-resolved-active.txt"
}

assert_same_files() {
  local before=$1 after=$2 label=$3
  if ! cmp -s "$before" "$after"; then
    echo "$label changed unexpectedly" >&2
    diff -u "$before" "$after" >&2 || true
    exit 1
  fi
}

ensure_dns_user() {
  local user_record
  user_record=$(node_shell getent passwd "$dns_user" || true)
  if [ -n "$user_record" ]; then
    if ! node_root grep -Fxq "$owner_value" "$owner_path"; then
      echo "refusing pre-existing DNS service user without owner marker" >&2
      exit 3
    fi
    if [ "$(printf '%s\n' "$user_record" | cut -d: -f6-7)" != "/nonexistent:/usr/sbin/nologin" ]; then
      echo "owned DNS service user shape drifted" >&2
      exit 3
    fi
    if ! node_root test -f "$config_root/ownership.env"; then
      node_root sh -c "printf '%s\n' 'USER_CREATED_BY_SPIKE=true' > '$config_root/ownership.env' && chmod 0600 '$config_root/ownership.env'"
    fi
    return
  fi
  if node_shell getent group "$dns_user" >/dev/null; then
    echo "refusing pre-existing DNS service group" >&2
    exit 3
  fi
  node_root groupadd --system "$dns_user"
  if ! node_root useradd --system --gid "$dns_user" --home-dir /nonexistent \
    --shell /usr/sbin/nologin --no-create-home "$dns_user"; then
    node_root groupdel "$dns_user" >/dev/null 2>&1 || true
    return 1
  fi
  node_root sh -c "printf '%s\n' 'USER_CREATED_BY_SPIKE=true' > '$config_root/ownership.env' && chmod 0600 '$config_root/ownership.env'"
}

dns_uid() {
  node_shell getent passwd "$dns_user" | cut -d: -f3
}

validate_mihomo_file() {
  local guest_file=$1 validate_dir="$state_root/validate"
  node_root rm -rf "$validate_dir"
  node_root install -d -o "$dns_user" -g "$dns_user" -m 0700 "$validate_dir"
  node_root install -o "$dns_user" -g "$dns_user" -m 0600 "$guest_file" "$validate_dir/config.yaml"
  node_root sudo -u "$dns_user" env HOME="$validate_dir" "$libexec_root/mihomo" -t -d "$validate_dir" >/dev/null
  node_root rm -rf "$validate_dir"
}

wait_unit_active() {
  local unit=$1 attempt
  for attempt in $(seq 1 100); do
    unit_active "$unit" && return
    sleep 0.2
  done
  node_shell systemctl show "$unit" -p Id -p LoadState -p ActiveState -p SubState -p Result -p ExecMainStatus >&2 || true
  echo "DNS spike unit did not become active: $unit" >&2
  exit 1
}

dig_answer() {
  local server=$1 port=$2 name=$3 protocol=${4:-udp}
  if [ "$protocol" = tcp ]; then
    node_shell dig "@$server" -p "$port" "$name" A +tcp +short +time=1 +tries=1 | awk '/^[0-9]+([.][0-9]+){3}$/ {print; exit}'
  else
    node_shell dig "@$server" -p "$port" "$name" A +short +time=1 +tries=1 | awk '/^[0-9]+([.][0-9]+){3}$/ {print; exit}'
  fi
}

dig_answer_and_ttl() {
  local server=$1 port=$2 name=$3
  node_shell dig "@$server" -p "$port" "$name" A +noall +answer +time=1 +tries=1 |
    awk '$4 == "A" && $5 ~ /^[0-9]+([.][0-9]+){3}$/ {print $5 "|" $2; exit}'
}

wait_dns_answer() {
  local server=$1 port=$2 name=$3 expected=$4 attempt answer
  for attempt in $(seq 1 120); do
    answer=$(dig_answer "$server" "$port" "$name" 2>/dev/null || true)
    if [ "$answer" = "$expected" ]; then
      return
    fi
    sleep 0.25
  done
  node_shell systemctl show "$direct_unit" "$gateway_unit" "$resolver_unit" \
    -p Id -p ActiveState -p SubState -p Result -p ExecMainStatus -p MainPID >&2 || true
  for namespace in "$direct_ns" "$gateway_ns"; do
    if namespace_exists "$namespace"; then
      node_root ip netns exec "$namespace" ss -H -lnut >&2 || true
    fi
  done
  node_root cat "$runtime_root/direct.json" >&2 2>/dev/null || true
  node_root cat "$runtime_root/gateway.json" >&2 2>/dev/null || true
  node_shell dig "@$server" -p "$port" "$name" A +time=1 +tries=1 +comments >&2 || true
  echo "DNS endpoint $server:$port did not return expected answer for $name" >&2
  exit 1
}

upstream_dig_answer() {
  local server=$1 name=$2
  node_root sudo -u "$dns_user" dig "@$server" -p 53 "$name" A +short +time=1 +tries=1 | awk '/^[0-9]+([.][0-9]+){3}$/ {print; exit}'
}

wait_upstream_dns_answer() {
  local server=$1 name=$2 expected=$3 attempt answer
  for attempt in $(seq 1 120); do
    answer=$(upstream_dig_answer "$server" "$name" 2>/dev/null || true)
    if [ "$answer" = "$expected" ]; then
      return
    fi
    sleep 0.25
  done
  echo "authoritative DNS endpoint $server:53 did not return expected answer for $name" >&2
  exit 1
}

wait_namespace_dns_listener() {
  local namespace=$1 address=$2 attempt count
  for attempt in $(seq 1 100); do
    count=$(node_root ip netns exec "$namespace" ss -H -lnut | awk -v endpoint="$address:53" '$5 == endpoint {count++} END {print count + 0}')
    [ "$count" -eq 2 ] && return
    sleep 0.2
  done
  echo "DNS fixture did not bind TCP+UDP in namespace $namespace" >&2
  exit 1
}

wait_local_dns_listener() {
  local attempt count
  for attempt in $(seq 1 100); do
    count=$(node_root ss -H -lnut | awk '$5 == "127.0.0.1:1053" {count++} END {print count + 0}')
    [ "$count" -eq 2 ] && return
    sleep 0.2
  done
  echo "local DNS resolver did not bind TCP+UDP on loopback" >&2
  exit 1
}

node_policy() {
  node_root "$libexec_root/policy" "$@"
}

switch_mode() {
  local mode=$1 source="$config_root/candidates/$1.yaml"
  validate_mihomo_file "$source"
  node_root install -o root -g "$dns_user" -m 0640 "$source" "$config_root/.config.yaml.next"
  node_root mv "$config_root/.config.yaml.next" "$config_root/config.yaml"
  node_root systemctl restart "$resolver_unit"
  wait_unit_active "$resolver_unit"
  wait_local_dns_listener
  sleep 1
  node_root resolvectl flush-caches >/dev/null 2>&1 || true
}

stop_units_best_effort() {
  node_root systemctl stop "$resolver_unit" "$gateway_unit" "$direct_unit" >/dev/null 2>&1 || true
}

clean_runtime_best_effort() {
  if node_root test -x "$libexec_root/policy"; then
    node_policy restore >/dev/null 2>&1 || true
  fi
  stop_units_best_effort
  if node_root test -x "$libexec_root/topology"; then
    node_root "$libexec_root/topology" cleanup >/dev/null 2>&1 || true
  else
    for namespace in "$direct_ns" "$gateway_ns"; do
      node_root ip netns delete "$namespace" >/dev/null 2>&1 || true
    done
  fi
  return 0
}

install_files() {
  local uid rendered_nft unit config profile version
  node_root install -d -m 0700 "$config_root"
  node_root sh -c "printf '%s\n' '$owner_value' > '$owner_path' && chmod 0600 '$owner_path'"
  ensure_dns_user
  uid=$(dns_uid)
  node_root chown "root:$dns_user" "$config_root"
  node_root chmod 0750 "$config_root"
  node_root install -d -m 0755 "$libexec_root"
  node_root install -d -o "$dns_user" -g "$dns_user" -m 0700 "$state_root"
  node_root install -d -m 0700 "$runtime_root"
  node_root install -d -o root -g "$dns_user" -m 0750 "$config_root/candidates"
  node_root install -d -o root -g root -m 0700 "$config_root/profiles"

  rendered_nft=$(mktemp /tmp/vpnctl-v2-dns-nft.XXXXXX)
  sed "s/@DNS_UID@/$uid/g" "$fixture_root/capture.nft.tmpl" > "$rendered_nft"
  copy_to_guest_tmp "$rendered_nft"
  node_root install -m 0600 "/tmp/$(basename "$rendered_nft")" "$config_root/capture.nft"
  node_root rm -f "/tmp/$(basename "$rendered_nft")"
  rm -f "$rendered_nft"

  for config in policy-fake-ip policy-redir-host direct-redir-host; do
    copy_to_guest_tmp "$fixture_root/config/$config.yaml"
    node_root install -o root -g "$dns_user" -m 0640 "/tmp/$config.yaml" "$config_root/candidates/$config.yaml"
    node_root rm -f "/tmp/$config.yaml"
  done
  node_root install -o root -g "$dns_user" -m 0640 \
    "$config_root/candidates/policy-fake-ip.yaml" "$config_root/config.yaml"

  for profile in policy-fake-ip policy-redir-host direct-redir-host; do
    copy_to_guest_tmp "$fixture_root/profiles/$profile.yaml"
    node_root install -m 0600 "/tmp/$profile.yaml" "$config_root/profiles/$profile.yaml"
    node_root rm -f "/tmp/$profile.yaml"
  done

  for source in resolved.conf policy.sh topology.sh authoritative_dns.py; do
    copy_to_guest_tmp "$fixture_root/$source"
  done
  node_root install -m 0600 /tmp/resolved.conf "$config_root/resolved.conf"
  node_root install -m 0755 /tmp/policy.sh "$libexec_root/policy"
  node_root install -m 0755 /tmp/topology.sh "$libexec_root/topology"
  node_root install -m 0755 /tmp/authoritative_dns.py "$libexec_root/authoritative-dns"
  node_root rm -f /tmp/resolved.conf /tmp/policy.sh /tmp/topology.sh /tmp/authoritative_dns.py

  copy_to_guest_tmp "$mihomo_binary"
  node_root install -m 0755 /tmp/mihomo-linux-amd64 "$libexec_root/mihomo"
  node_root rm -f /tmp/mihomo-linux-amd64
  version=$(node_root "$libexec_root/mihomo" -v | awk 'NR == 1 {print $3}')
  if [ "$version" != "$(manifest_value '.mihomo.version')" ]; then
    echo "installed DNS Mihomo version mismatch: $version" >&2
    exit 3
  fi

  for unit in "$resolver_unit" "$direct_unit" "$gateway_unit"; do
    copy_to_guest_tmp "$fixture_root/systemd/$unit"
    node_root install -m 0644 "/tmp/$unit" "/etc/systemd/system/$unit"
    node_root rm -f "/tmp/$unit"
  done
  node_root systemctl daemon-reload

  for config in policy-fake-ip policy-redir-host direct-redir-host; do
    validate_mihomo_file "$config_root/candidates/$config.yaml"
    validate_mihomo_file "$config_root/profiles/$config.yaml"
  done
}

prepare() {
  local baseline="$artifact_root/prepared-baseline"
  assert_lab_instance "$node_instance"
  assert_lab_instance "$gateway_instance"
  assert_other_spikes_inactive
  assert_owned_or_absent
  fetch_mihomo
  if node_root test -e "$config_root"; then
    clean_runtime_best_effort
    if node_root test -e "$resolved_dropin"; then
      echo "owned DNS integration did not restore before prepare" >&2
      exit 3
    fi
  else
    for namespace in "$direct_ns" "$gateway_ns"; do
      if namespace_exists "$namespace"; then
        echo "refusing to claim existing DNS namespace: $namespace" >&2
        exit 3
      fi
    done
    if node_root test -e "$resolved_dropin"; then
      echo "refusing existing DNS resolved drop-in" >&2
      exit 3
    fi
    if node_shell getent passwd "$dns_user" >/dev/null || node_shell getent group "$dns_user" >/dev/null; then
      echo "refusing existing DNS spike user or group" >&2
      exit 3
    fi
  fi
  rm -rf "$baseline"
  mkdir -p "$baseline"
  chmod 0700 "$baseline"
  root_network_snapshot "$baseline/root"
  install_files
  trap 'clean_runtime_best_effort' EXIT
  node_root "$libexec_root/topology" prepare
  node_policy preflight
  node_root systemctl reset-failed "$resolver_unit" "$direct_unit" "$gateway_unit" >/dev/null 2>&1 || true
  node_root systemctl start "$direct_unit"
  wait_unit_active "$direct_unit"
  wait_namespace_dns_listener "$direct_ns" 10.211.0.1
  sleep 1
  wait_upstream_dns_answer 10.211.0.1 readiness.direct.test 192.0.2.77
  node_root systemctl start "$gateway_unit"
  wait_unit_active "$gateway_unit"
  wait_namespace_dns_listener "$gateway_ns" 10.212.0.1
  sleep 1
  wait_upstream_dns_answer 10.212.0.1 readiness.selected.test 203.0.113.77
  node_root systemctl start "$resolver_unit"
  wait_unit_active "$resolver_unit"
  wait_local_dns_listener
  sleep 1
  wait_dns_answer 127.0.0.1 1053 readiness.direct.test 192.0.2.77
  trap - EXIT
  echo "DNS spike prepared; systemd-resolved and classic port-53 policy remain unchanged"
}

remove_dns_user() {
  if ! node_shell getent passwd "$dns_user" >/dev/null; then
    return
  fi
  local record
  record=$(node_shell getent passwd "$dns_user")
  if [ "$(printf '%s\n' "$record" | cut -d: -f6-7)" != "/nonexistent:/usr/sbin/nologin" ]; then
    echo "refusing to remove drifted DNS service user" >&2
    exit 3
  fi
  if node_root pgrep -u "$dns_user" >/dev/null 2>&1; then
    echo "refusing to remove DNS service user with running processes" >&2
    exit 3
  fi
  node_root userdel "$dns_user"
  if node_shell getent group "$dns_user" >/dev/null; then
    node_root groupdel "$dns_user"
  fi
}

uninstall_internal() {
  local quiet=${1:-false} created_user=false
  if ! node_root test -e "$config_root"; then
    [ "$quiet" = true ] || echo "DNS spike is not installed"
    return
  fi
  if ! node_root grep -Fxq "$owner_value" "$owner_path"; then
    echo "refusing to uninstall unowned DNS spike path" >&2
    exit 3
  fi
  if node_root grep -Fxq 'USER_CREATED_BY_SPIKE=true' "$config_root/ownership.env"; then
    created_user=true
  fi
  clean_runtime_best_effort
  node_policy assert-clean
  if node_root test -e "$resolved_dropin"; then
    echo "refusing DNS uninstall after incomplete resolved restoration" >&2
    exit 3
  fi
  node_root rm -f "/etc/systemd/system/$resolver_unit" "/etc/systemd/system/$direct_unit" "/etc/systemd/system/$gateway_unit"
  node_root systemctl daemon-reload
  node_root rm -rf "$config_root" "$libexec_root" "$state_root" "$runtime_root"
  if [ "$created_user" = true ]; then
    remove_dns_user
  fi
  node_root systemctl reset-failed "$resolver_unit" "$direct_unit" "$gateway_unit" >/dev/null 2>&1 || true
  [ "$quiet" = true ] || echo "owner-checked DNS spike resources removed"
}

verification_cleanup() {
  local exit_status=$?
  if [ "$cleanup_armed" = true ]; then
    if [ "$exit_status" -ne 0 ] && [ -n "$verification_evidence_dir" ]; then
      jq -n \
        --arg stage "$verification_stage" \
        --argjson exit_code "$exit_status" \
        '{schema_version: 1, stage: $stage, exit_code: $exit_code}' \
        > "$verification_evidence_dir/failure.json" 2>/dev/null || true
    fi
    uninstall_internal true >/dev/null 2>&1 || true
  fi
  return "$exit_status"
}

expect_dns_answer() {
  local server=$1 port=$2 name=$3 expected=$4 protocol=${5:-udp} answer
  answer=$(dig_answer "$server" "$port" "$name" "$protocol" 2>/dev/null || true)
  if [ "$answer" != "$expected" ]; then
    echo "unexpected DNS answer for $name through $server:$port/$protocol: ${answer:-<none>}" >&2
    exit 1
  fi
}

expect_fake_answer() {
  local server=$1 port=$2 name=$3 protocol=${4:-udp} answer
  answer=$(dig_answer "$server" "$port" "$name" "$protocol" 2>/dev/null || true)
  case "$answer" in
    198.19.*) printf '%s\n' "$answer" ;;
    *) echo "selected name did not receive conflict-checked fake IP: $name -> ${answer:-<none>}" >&2; exit 1 ;;
  esac
}

expect_dns_blocked() {
  local server=$1 port=$2 name=$3 protocol=${4:-udp} answer
  answer=$(dig_answer "$server" "$port" "$name" "$protocol" 2>/dev/null || true)
  if [ -n "$answer" ]; then
    echo "DNS query unexpectedly returned an address while blocked: $name -> $answer" >&2
    exit 1
  fi
}

expect_getent_answer() {
  local name=$1 expected=$2 answer
  answer=$(node_shell getent ahostsv4 "$name" | awk 'NR == 1 {print $1}')
  if [ "$answer" != "$expected" ]; then
    echo "libc/NSS returned unexpected address for $name: ${answer:-<none>}" >&2
    exit 1
  fi
}

expect_resolvectl_answer() {
  local name=$1 expected=$2 output
  output=$(node_shell resolvectl -4 --type=A --legend=no query "$name")
  if ! printf '%s\n' "$output" | grep -Fq "$expected"; then
    echo "resolvectl returned unexpected answer for $name" >&2
    exit 1
  fi
}

restart_upstreams() {
  node_root systemctl restart "$direct_unit" "$gateway_unit"
  wait_unit_active "$direct_unit"
  wait_unit_active "$gateway_unit"
  wait_namespace_dns_listener "$direct_ns" 10.211.0.1
  wait_namespace_dns_listener "$gateway_ns" 10.212.0.1
  sleep 1
  wait_upstream_dns_answer 10.211.0.1 upstream-ready.direct.test 192.0.2.77
  wait_upstream_dns_answer 10.212.0.1 upstream-ready.selected.test 203.0.113.77
}

backend_count() {
  local backend=$1 name=$2
  node_root jq -r --arg suffix ":1:$name" \
    '[.queries | to_entries[] | select(.key | endswith($suffix)) | .value] | add // 0' \
    "$runtime_root/$backend.json"
}

capture_backend_states() {
  local prefix=$1
  node_root cat "$runtime_root/direct.json" > "$prefix-direct.json"
  node_root cat "$runtime_root/gateway.json" > "$prefix-gateway.json"
}

assert_separated_names() {
  local prefix=$1 direct_name=$2 selected_name=$3
  local direct_direct direct_selected gateway_direct gateway_selected
  direct_direct=$(jq -r --arg suffix ":1:$direct_name" '[.queries | to_entries[] | select(.key | endswith($suffix)) | .value] | add // 0' "$prefix-direct.json")
  direct_selected=$(jq -r --arg suffix ":1:$selected_name" '[.queries | to_entries[] | select(.key | endswith($suffix)) | .value] | add // 0' "$prefix-direct.json")
  gateway_direct=$(jq -r --arg suffix ":1:$direct_name" '[.queries | to_entries[] | select(.key | endswith($suffix)) | .value] | add // 0' "$prefix-gateway.json")
  gateway_selected=$(jq -r --arg suffix ":1:$selected_name" '[.queries | to_entries[] | select(.key | endswith($suffix)) | .value] | add // 0' "$prefix-gateway.json")
  if [ "$direct_direct" -lt 1 ] || [ "$gateway_selected" -lt 1 ] ||
    [ "$direct_selected" -ne 0 ] || [ "$gateway_direct" -ne 0 ]; then
    echo "DNS upstream separation failed for $direct_name / $selected_name" >&2
    exit 1
  fi
}

assert_fake_ip_candidate_behavior() {
  local prefix=$1 direct_name=$2 selected_name=$3
  local direct_direct direct_selected gateway_direct gateway_selected
  direct_direct=$(jq -r --arg suffix ":1:$direct_name" '[.queries | to_entries[] | select(.key | endswith($suffix)) | .value] | add // 0' "$prefix-direct.json")
  direct_selected=$(jq -r --arg suffix ":1:$selected_name" '[.queries | to_entries[] | select(.key | endswith($suffix)) | .value] | add // 0' "$prefix-direct.json")
  gateway_direct=$(jq -r --arg suffix ":1:$direct_name" '[.queries | to_entries[] | select(.key | endswith($suffix)) | .value] | add // 0' "$prefix-gateway.json")
  gateway_selected=$(jq -r --arg suffix ":1:$selected_name" '[.queries | to_entries[] | select(.key | endswith($suffix)) | .value] | add // 0' "$prefix-gateway.json")
  if [ "$direct_direct" -lt 1 ] || [ "$direct_selected" -ne 0 ] ||
    [ "$gateway_direct" -ne 0 ] || [ "$gateway_selected" -ne 0 ]; then
    echo "unexpected eager upstream behavior for fake-IP candidate" >&2
    exit 1
  fi
}

verify() {
  local evidence_dir=${1:-"$artifact_root/evidence-$(date -u +%Y%m%dT%H%M%SZ)"}
  local prepared_baseline="$artifact_root/prepared-baseline/root"
  local redir_selected=policy-redir.selected.test
  local redir_direct=policy-redir.direct.test
  local fake_selected=policy-fake.selected.test
  local fake_direct=policy-fake.direct.test
  local fake_answer cached_answer immediate_cached after_ttl_record after_ttl_answer after_ttl_ttl
  local cache_name=cache.direct.test cache_first cache_second cache_third
  local classic_udp_name=classic-udp.selected.test
  local classic_tcp_name=classic-tcp.direct.test
  local resolver_loss_selected=resolver-loss.selected.test
  local resolver_loss_direct=resolver-loss.direct.test
  local resolver_loss_selected_before resolver_loss_selected_after
  local resolver_loss_direct_before resolver_loss_direct_after
  local direct_mode_name=compat.selected.test
  local direct_mode_count gateway_mode_count counter
  local suffix

  assert_lab_instance "$node_instance"
  assert_lab_instance "$gateway_instance"
  assert_other_spikes_inactive
  if ! node_root grep -Fxq "$owner_value" "$owner_path"; then
    echo "DNS spike is not owner-prepared" >&2
    exit 3
  fi
  for unit in "$resolver_unit" "$direct_unit" "$gateway_unit"; do
    wait_unit_active "$unit"
  done
  if [ ! -f "$prepared_baseline-nft.txt" ]; then
    echo "DNS pre-prepare root baseline is missing" >&2
    exit 3
  fi
  mkdir -p "$evidence_dir"
  chmod 0700 "$evidence_dir"
  verification_evidence_dir=$evidence_dir
  verification_stage=integration-apply
  cleanup_armed=true
  trap verification_cleanup EXIT

  root_network_snapshot "$evidence_dir/root-prepared-before"
  node_policy apply
  node_policy assert-applied
  node_policy status > "$evidence_dir/integration-ready.json"

  restart_upstreams
  verification_stage=policy-redir-host
  switch_mode policy-redir-host
  expect_dns_answer 127.0.0.1 1053 "$redir_selected" 203.0.113.77
  expect_dns_answer 127.0.0.1 1053 "$redir_direct" 192.0.2.77
  expect_dns_answer 127.0.0.53 53 stub-redir.selected.test 203.0.113.77
  expect_getent_answer libc-redir.direct.test 192.0.2.77
  expect_resolvectl_answer resolvectl-redir.selected.test 203.0.113.77
  capture_backend_states "$evidence_dir/redir-host"
  assert_separated_names "$evidence_dir/redir-host" "$redir_direct" "$redir_selected"

  restart_upstreams
  verification_stage=policy-fake-ip
  switch_mode policy-fake-ip
  fake_answer=$(expect_fake_answer 127.0.0.1 1053 "$fake_selected")
  expect_dns_answer 127.0.0.1 1053 "$fake_direct" 192.0.2.77
  expect_getent_answer "$fake_selected" "$fake_answer"
  expect_getent_answer libc-fake.direct.test 192.0.2.77
  expect_resolvectl_answer resolvectl-fake.selected.test "198.19."
  capture_backend_states "$evidence_dir/fake-ip"
  assert_fake_ip_candidate_behavior "$evidence_dir/fake-ip" "$fake_direct" "$fake_selected"

  restart_upstreams
  verification_stage=classic-port-53
  switch_mode policy-redir-host
  expect_dns_answer 203.0.113.53 53 "$classic_udp_name" 203.0.113.77
  expect_dns_answer 203.0.113.53 53 "$classic_tcp_name" 192.0.2.77 tcp
  node_root nft -j list table inet vpnctl_v2_spike_dns > "$evidence_dir/capture-nft.json"
  for counter in classic_udp_captured classic_tcp_captured resolver_uid_bypass resolved_stub_passthrough; do
    if [ "$(jq -r --arg counter "$counter" '[.nftables[] | .counter? | select(.name == $counter) | .packets] | add // 0' "$evidence_dir/capture-nft.json")" -lt 1 ]; then
      echo "DNS capture counter did not advance: $counter" >&2
      exit 1
    fi
  done

  restart_upstreams
  verification_stage=direct-cache
  switch_mode policy-redir-host
  expect_dns_answer 127.0.0.53 53 "$cache_name" 192.0.2.77
  cache_first=$(backend_count direct "$cache_name")
  expect_dns_answer 127.0.0.53 53 "$cache_name" 192.0.2.77
  cache_second=$(backend_count direct "$cache_name")
  if [ "$cache_first" -lt 1 ] || [ "$cache_second" -ne "$cache_first" ]; then
    echo "Mihomo did not retain the direct DNS answer within TTL" >&2
    exit 1
  fi
  sleep 3
  expect_dns_answer 127.0.0.53 53 "$cache_name" 192.0.2.77
  cache_third=$(backend_count direct "$cache_name")
  if [ "$cache_third" -le "$cache_second" ]; then
    echo "Mihomo DNS answer did not expire after bounded upstream TTL" >&2
    exit 1
  fi

  cached_answer=$(dig_answer 127.0.0.53 53 outage-cache.selected.test 2>/dev/null || true)
  if [ "$cached_answer" != "203.0.113.77" ]; then
    echo "selected gateway DNS answer was not accepted before outage: ${cached_answer:-<none>}" >&2
    exit 1
  fi
  node_root systemctl stop "$gateway_unit"
  verification_stage=gateway-dns-outage-resolver-survival
  if ! unit_active "$resolver_unit"; then
    echo "local resolver stopped with the shared gateway DNS fixture" >&2
    exit 1
  fi
  verification_stage=gateway-dns-outage-cache-within-ttl
  immediate_cached=$(dig_answer 127.0.0.53 53 outage-cache.selected.test 2>/dev/null || true)
  if [ "$immediate_cached" != "$cached_answer" ]; then
    echo "accepted selected answer was not retained within its TTL" >&2
    exit 1
  fi
  verification_stage=gateway-dns-outage-fresh-selected
  expect_dns_blocked 127.0.0.53 53 outage-fresh.selected.test
  verification_stage=gateway-dns-outage-direct-continues
  expect_dns_answer 127.0.0.53 53 outage-fresh.direct.test 192.0.2.77
  sleep 3
  verification_stage=gateway-dns-outage-stale-while-revalidate
  after_ttl_record=$(dig_answer_and_ttl 127.0.0.53 53 outage-cache.selected.test 2>/dev/null || true)
  after_ttl_answer=${after_ttl_record%%|*}
  after_ttl_ttl=${after_ttl_record##*|}
  if [ "$after_ttl_answer" != "$cached_answer" ] || [ -z "$after_ttl_ttl" ] || [ "$after_ttl_ttl" -gt 1 ]; then
    echo "expired selected cache did not follow pinned stale-while-revalidate semantics: ${after_ttl_record:-<none>}" >&2
    exit 1
  fi
  capture_backend_states "$evidence_dir/outage"
  for name in outage-cache.selected.test outage-fresh.selected.test; do
    if [ "$(jq -r --arg suffix ":1:$name" '[.queries | to_entries[] | select(.key | endswith($suffix)) | .value] | add // 0' "$evidence_dir/outage-direct.json")" -ne 0 ]; then
      echo "selected DNS cache/outage query leaked to the direct upstream: $name" >&2
      exit 1
    fi
  done
  verification_stage=gateway-dns-outage-recovery
  node_root systemctl start "$gateway_unit"
  wait_unit_active "$gateway_unit"
  wait_upstream_dns_answer 10.212.0.1 recovered.selected.test 203.0.113.77
  expect_dns_answer 127.0.0.53 53 recovered.selected.test 203.0.113.77
  jq -n \
    --arg cached_answer "$cached_answer" \
    --argjson stale_ttl "$after_ttl_ttl" \
    --argjson direct_cache_first "$cache_first" \
    --argjson direct_cache_second "$cache_second" \
    --argjson direct_cache_after_ttl "$cache_third" \
    '{schema_version: 1, selected_cached_within_ttl: true, selected_stale_while_revalidate: true, selected_stale_ttl: $stale_ttl, selected_fresh_failed_closed: true, selected_direct_fallback_queries: 0, direct_continued: true, recovered: true, cached_answer: $cached_answer, direct_cache_upstream_counts: {first: $direct_cache_first, within_ttl: $direct_cache_second, after_ttl: $direct_cache_after_ttl}}' \
    > "$evidence_dir/cache-and-outage.json"

  verification_stage=resolver-loss-prepare
  restart_upstreams
  switch_mode policy-redir-host
  resolver_loss_selected_before=$(backend_count gateway "$resolver_loss_selected")
  resolver_loss_direct_before=$(backend_count direct "$resolver_loss_direct")
  node_root systemctl stop "$resolver_unit"
  if unit_active "$resolver_unit"; then
    echo "local resolver remained active during injected resolver loss" >&2
    exit 1
  fi
  verification_stage=resolver-loss-fail-closed
  expect_dns_blocked 127.0.0.53 53 "$resolver_loss_selected"
  expect_dns_blocked 127.0.0.53 53 "$resolver_loss_direct"
  expect_dns_blocked 203.0.113.53 53 resolver-loss-classic.selected.test
  expect_dns_blocked 203.0.113.53 53 resolver-loss-classic.direct.test tcp
  resolver_loss_selected_after=$(backend_count gateway "$resolver_loss_selected")
  resolver_loss_direct_after=$(backend_count direct "$resolver_loss_direct")
  if [ "$resolver_loss_selected_after" -ne "$resolver_loss_selected_before" ] ||
    [ "$resolver_loss_direct_after" -ne "$resolver_loss_direct_before" ]; then
    echo "resolver outage bypassed the managed local DNS path" >&2
    exit 1
  fi
  verification_stage=resolver-loss-recovery
  node_root systemctl start "$resolver_unit"
  wait_unit_active "$resolver_unit"
  wait_local_dns_listener
  sleep 1
  expect_dns_answer 127.0.0.53 53 recovered-after-resolver-loss.selected.test 203.0.113.77
  expect_dns_answer 127.0.0.53 53 recovered-after-resolver-loss.direct.test 192.0.2.77
  jq -n \
    --argjson selected_before "$resolver_loss_selected_before" \
    --argjson selected_after "$resolver_loss_selected_after" \
    --argjson direct_before "$resolver_loss_direct_before" \
    --argjson direct_after "$resolver_loss_direct_after" \
    '{schema_version: 1, status: "passed", resolver_stopped: true, selected_blocked: true, direct_blocked_while_classifier_unavailable: true, classic_udp_blocked: true, classic_tcp_blocked: true, upstream_bypass_queries: (($selected_after - $selected_before) + ($direct_after - $direct_before)), recovered_selected: true, recovered_direct: true}' \
    > "$evidence_dir/resolver-loss.json"

  restart_upstreams
  verification_stage=direct-compatibility
  switch_mode direct-redir-host
  expect_dns_answer 127.0.0.53 53 "$direct_mode_name" 192.0.2.77
  direct_mode_count=$(backend_count direct "$direct_mode_name")
  gateway_mode_count=$(backend_count gateway "$direct_mode_name")
  if [ "$direct_mode_count" -lt 1 ] || [ "$gateway_mode_count" -ne 0 ]; then
    echo "direct compatibility mode did not keep selected-name DNS on direct upstream" >&2
    exit 1
  fi
  capture_backend_states "$evidence_dir/direct-mode"

  node_root systemctl show "$resolver_unit" "$direct_unit" "$gateway_unit" \
    -p Id -p ActiveState -p Result -p MemoryCurrent -p MemoryPeak -p MemorySwapCurrent -p TasksCurrent > "$evidence_dir/unit-resources.txt"
  verification_stage=integration-restore
  node_policy restore
  node_policy assert-clean
  root_network_snapshot "$evidence_dir/root-prepared-after"
  for suffix in nft.txt addresses.json routes.json resolved-files.txt resolv-conf.txt \
    resolvectl-dns.txt resolvectl-domain.txt resolvectl-default-route.txt resolved-active.txt; do
    assert_same_files "$evidence_dir/root-prepared-before-$suffix" "$evidence_dir/root-prepared-after-$suffix" "prepared root DNS state $suffix"
  done

  jq -n \
    --arg status passed \
    --arg accepted_mode policy-redir-host \
    --arg fake_ip_range "$(manifest_value '.policy.fake_ip_range')" \
    --arg rejected_default "$(manifest_value '.policy.rejected_default_fake_ip_range')" \
    --arg fake_answer "$fake_answer" \
    --slurpfile resolver_loss "$evidence_dir/resolver-loss.json" \
    '{schema_version: 1, status: $status, accepted_mode: $accepted_mode, fake_ip_range: $fake_ip_range, rejected_default_fake_ip_range: $rejected_default, candidates: {policy_redir_host: {query_separation: true, linux_clients: true, accepted: true}, policy_fake_ip: {linux_clients: true, selected_only_fake_ip: true, eager_gateway_lookup: false, rejected_reason: "fresh selected DNS can receive a synthetic answer without the gateway DNS path"}, direct_redir_host: {all_queries_direct: true}}, systemd_resolved: {dropin: true, stub_preserved: true, second_cache_disabled: true, original_link_state_restored: true}, classic_port_53: {udp_captured: true, tcp_captured: true, resolver_uid_bypass: true}, failure: {selected_fresh_fail_closed: true, selected_stale_while_revalidate: true, selected_direct_fallback_queries: 0, direct_continued: true, resolver_loss: $resolver_loss[0]}, profiles: {pinned_mihomo_validated: true, clash_mi_deferred_to_task_16_11: true}, coexistence: {foreign_nftables_preserved: true, root_network_restored: true}}' \
    > "$evidence_dir/summary.json"

  verification_stage=full-uninstall
  uninstall_internal true
  cleanup_armed=false
  trap - EXIT
  verification_stage=final-baseline
  root_network_snapshot "$evidence_dir/root-final"
  for suffix in nft.txt addresses.json routes.json resolved-files.txt resolv-conf.txt \
    resolvectl-dns.txt resolvectl-domain.txt resolvectl-default-route.txt resolved-active.txt; do
    assert_same_files "$prepared_baseline-$suffix" "$evidence_dir/root-final-$suffix" "final root DNS state $suffix"
  done
  for namespace in "$direct_ns" "$gateway_ns"; do
    if namespace_exists "$namespace"; then
      echo "DNS namespace remained after uninstall: $namespace" >&2
      exit 1
    fi
  done
  printf 'DNS spike evidence: %s\n' "$evidence_dir/summary.json"
}

status() {
  assert_lab_instance "$node_instance"
  local unit namespace
  for unit in "$resolver_unit" "$direct_unit" "$gateway_unit"; do
    node_shell systemctl show "$unit" -p Id -p LoadState -p ActiveState -p SubState -p MainPID 2>/dev/null || true
  done
  for namespace in "$direct_ns" "$gateway_ns"; do
    if namespace_exists "$namespace"; then
      printf '%s=present\n' "$namespace"
    else
      printf '%s=absent\n' "$namespace"
    fi
  done
  if node_root test -x "$libexec_root/policy"; then
    node_policy status
  fi
}

stop() {
  assert_lab_instance "$node_instance"
  assert_owned_or_absent
  if ! node_root test -e "$config_root"; then
    echo "DNS spike is not installed"
    return
  fi
  node_policy restore
  stop_units_best_effort
  echo "DNS integration restored and exact spike units stopped"
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
