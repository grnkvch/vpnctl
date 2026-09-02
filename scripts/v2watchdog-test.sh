#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
fixture_root="$repository_root/test/v2lab/watchdog"
node_instance=vpnctl-v2-node
namespace=vpnctl-v2-watchdog-test
owner_value=vpnctl-v2-watchdog-test-v1
state_root=/var/lib/vpnctl
owner_path="$state_root/.watchdog-test-owner"
libexec_root=/usr/local/libexec/vpnctl-v2-watchdog-test
runtime_root=/tmp/vpnctl-v2-watchdog-test
service_unit=vpnctl-watchdog@.service
timer_unit=vpnctl-watchdog@.timer
dropin_root=/etc/systemd/system/vpnctl-watchdog@.service.d
dropin_path="$dropin_root/vpnctl-v2-test.conf"
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
host_build_dir=

usage() {
  cat <<'EOF'
Usage:
  scripts/v2watchdog-test.sh verify [evidence-directory]
  scripts/v2watchdog-test.sh status
  scripts/v2watchdog-test.sh cleanup
EOF
}

instance_json() {
  limactl list --json | jq -ce --arg name "$1" 'select(.name == $name)'
}

assert_lab_instance() {
  if ! instance_json "$node_instance" | jq -e --arg digest "$lab_image_digest" '
    .status == "Running" and
    .vmType == "qemu" and
    .arch == "x86_64" and
    .cpus == 1 and
    .memory == 536870912 and
    .disk == 10737418240 and
    .config.images[0].digest == $digest and
    any(.network[]?; .lima == "user-v2")
  ' >/dev/null; then
    echo "required contract-matching lab instance is not running: $node_instance" >&2
    exit 4
  fi
}

guest_root() {
  limactl shell --tty=false "$node_instance" -- sudo "$@"
}

namespace_exists() {
  guest_root ip netns list | awk '{print $1}' | grep -Fxq "$namespace"
}

ns_root() {
  guest_root ip netns exec "$namespace" "$@"
}

assert_owned_or_absent() {
  if guest_root test -e "$state_root"; then
    if ! guest_root test -f "$owner_path" || ! guest_root grep -Fxq "$owner_value" "$owner_path"; then
      echo "refusing to use unowned $state_root" >&2
      exit 3
    fi
  fi
  if guest_root test -e "$libexec_root"; then
    if ! guest_root test -f "$libexec_root/.owner" || ! guest_root grep -Fxq "$owner_value" "$libexec_root/.owner"; then
      echo "refusing to use unowned watchdog test libexec root" >&2
      exit 3
    fi
  fi
  if guest_root test -e "$runtime_root"; then
    if ! guest_root test -f "$runtime_root/.owner" || ! guest_root grep -Fxq "$owner_value" "$runtime_root/.owner"; then
      echo "refusing to use unowned watchdog test runtime root" >&2
      exit 3
    fi
  fi
  if guest_root test -e "/etc/systemd/system/$service_unit" || guest_root test -e "/etc/systemd/system/$timer_unit"; then
    if ! guest_root test -f "$libexec_root/.owner" || ! guest_root grep -Fxq "$owner_value" "$libexec_root/.owner"; then
      echo "refusing to replace existing watchdog systemd templates" >&2
      exit 3
    fi
  fi
  if guest_root test -e "$dropin_path" && { ! guest_root test -f "$libexec_root/.owner" || ! guest_root grep -Fxq "$owner_value" "$libexec_root/.owner"; }; then
    echo "refusing to replace existing watchdog service drop-in" >&2
    exit 3
  fi
}

assert_other_spikes_inactive() {
  local unit
  for unit in \
    vpnctl-v2-spike-routing-guard.service \
    vpnctl-v2-spike-routing-engine.service \
    vpnctl-v2-spike-dns-resolver.service \
    vpnctl-v2-spike-restricted-node.service \
    vpnctl-v2-spike-tunnel-client.service; do
    if guest_root systemctl is-active --quiet "$unit"; then
      echo "refusing watchdog mutation while another node data-plane spike is active: $unit" >&2
      exit 3
    fi
  done
}

copy_to_guest_tmp() {
  local source=$1
  limactl copy --backend=scp "$source" "$node_instance:/tmp/$(basename "$source")"
}

build_binaries_and_units() {
  host_build_dir=$(mktemp -d /private/tmp/vpnctl-v2-watchdog-build.XXXXXX)
  env GOCACHE=/tmp/vpnctl-go-cache GOMODCACHE=/tmp/vpnctl-go-mod \
    go build -trimpath -o "$host_build_dir/watchdog-helper-host" ./test/v2lab/watchdog/helper
  env GOCACHE=/tmp/vpnctl-go-cache GOMODCACHE=/tmp/vpnctl-go-mod \
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -o "$host_build_dir/vpnctl" ./cmd/vpnctl
  env GOCACHE=/tmp/vpnctl-go-cache GOMODCACHE=/tmp/vpnctl-go-mod \
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -o "$host_build_dir/watchdog-helper" ./test/v2lab/watchdog/helper
  "$host_build_dir/watchdog-helper-host" render-units "$host_build_dir/units" "$libexec_root/vpnctl"
}

install_owned_files() {
  guest_root install -d -m 0700 "$state_root" "$libexec_root" "$runtime_root"
  guest_root sh -c "printf '%s\n' '$owner_value' > '$owner_path' && chmod 0600 '$owner_path'"
  guest_root sh -c "printf '%s\n' '$owner_value' > '$libexec_root/.owner' && chmod 0600 '$libexec_root/.owner'"
  guest_root sh -c "printf '%s\n' '$owner_value' > '$runtime_root/.owner' && chmod 0600 '$runtime_root/.owner'"
  copy_to_guest_tmp "$host_build_dir/vpnctl"
  copy_to_guest_tmp "$host_build_dir/watchdog-helper"
  copy_to_guest_tmp "$host_build_dir/units/$service_unit"
  copy_to_guest_tmp "$host_build_dir/units/$timer_unit"
  copy_to_guest_tmp "$fixture_root/vpnctl-watchdog-test.conf"
  guest_root install -m 0755 /tmp/vpnctl "$libexec_root/vpnctl"
  guest_root install -m 0755 /tmp/watchdog-helper "$libexec_root/watchdog-helper"
  guest_root install -m 0644 "/tmp/$service_unit" "/etc/systemd/system/$service_unit"
  guest_root install -m 0644 "/tmp/$timer_unit" "/etc/systemd/system/$timer_unit"
  guest_root install -d -m 0755 "$dropin_root"
  guest_root install -m 0644 /tmp/vpnctl-watchdog-test.conf "$dropin_path"
  guest_root rm -f /tmp/vpnctl /tmp/watchdog-helper "/tmp/$service_unit" "/tmp/$timer_unit" /tmp/vpnctl-watchdog-test.conf
  guest_root systemctl daemon-reload
}

prepare_namespace() {
  guest_root ip netns add "$namespace"
  ns_root ip link set lo up
  ns_root sysctl -q -w net.ipv4.ip_forward=0
  ns_root sysctl -q -w net.ipv4.conf.all.src_valid_mark=0
  ns_root sysctl -q -w net.ipv4.conf.all.rp_filter=0
  ns_root sysctl -q -w net.ipv4.conf.all.accept_redirects=0
  ns_root sysctl -q -w net.ipv4.tcp_syncookies=1
  ns_root nft --file - <<'EOF'
table inet foreign_keep {
  chain keep {
    type filter hook output priority 100; policy accept;
  }
}
table inet vpnctl {
  chain prior {
    type filter hook input priority filter; policy accept;
  }
}
EOF
  ns_root ip -4 route add unreachable default metric 42760 table 20001
  ns_root ip -4 route add blackhole 198.51.100.0/24 metric 7 table 20002
  ns_root ip -4 route add blackhole 192.0.2.0/24 metric 17 table 21000
  ns_root ip -4 rule add priority 10020 fwmark 0x02000000/0xff000000 table 20001
  ns_root ip -4 rule add priority 12000 fwmark 0x00001234/0x0000ffff table 21000
}

capture_owned() {
  local prefix=$1
  ns_root nft --stateless -nn list table inet vpnctl > "$prefix-nft.txt"
  ns_root ip -json -4 route show table 20001 | jq -S . > "$prefix-routes-20001.json"
  ns_root ip -json -4 route show table 20002 | jq -S . > "$prefix-routes-20002.json"
  ns_root ip -json -4 rule show | jq -S '[.[] | select(.priority == 10000 or .priority == 10010 or .priority == 10020)]' > "$prefix-rules.json"
  jq -n \
	--arg accept_redirects "$(ns_root sysctl -n net.ipv4.conf.all.accept_redirects)" \
    --arg ip_forward "$(ns_root sysctl -n net.ipv4.ip_forward)" \
    --arg src_valid_mark "$(ns_root sysctl -n net.ipv4.conf.all.src_valid_mark)" \
    --arg rp_filter "$(ns_root sysctl -n net.ipv4.conf.all.rp_filter)" \
	'{accept_redirects: $accept_redirects, ip_forward: $ip_forward, src_valid_mark: $src_valid_mark, rp_filter: $rp_filter}' > "$prefix-sysctls.json"
  ns_root sysctl -a 2>/dev/null | awk '/^net[.]ipv4[.]conf[.]/ || /^net[.]ipv4[.]ip_forward =/' | sort > "$prefix-ipv4-conf.txt"
}

capture_foreign() {
  local prefix=$1
  ns_root nft --stateless -nn list table inet foreign_keep > "$prefix-nft.txt"
  ns_root ip -json -4 route show table 21000 | jq -S . > "$prefix-routes.json"
  ns_root ip -json -4 rule show | jq -S '[.[] | select(.priority == 12000)]' > "$prefix-rules.json"
  ns_root sysctl -n net.ipv4.tcp_syncookies > "$prefix-sysctl.txt"
}

assert_capture_equal() {
  local before=$1 after=$2 label=$3 suffix
  for suffix in nft.txt routes-20001.json routes-20002.json rules.json sysctls.json ipv4-conf.txt; do
    if [ -f "$before-$suffix" ] && ! cmp -s "$before-$suffix" "$after-$suffix"; then
      echo "$label changed unexpectedly: $suffix" >&2
      diff -u "$before-$suffix" "$after-$suffix" >&2 || true
      exit 1
    fi
  done
}

assert_foreign_equal() {
  local before=$1 after=$2 suffix
  for suffix in nft.txt routes.json rules.json sysctl.txt; do
    if ! cmp -s "$before-$suffix" "$after-$suffix"; then
      echo "foreign state changed unexpectedly: $suffix" >&2
      diff -u "$before-$suffix" "$after-$suffix" >&2 || true
      exit 1
    fi
  done
}

controller_start() {
  guest_root sh -c "nohup /usr/bin/sleep 300 </dev/null >/dev/null 2>&1 & echo \$! > '$runtime_root/controller.pid'"
}

controller_kill() {
  local pid command_name
  pid=$(guest_root cat "$runtime_root/controller.pid")
  command_name=$(guest_root cat "/proc/$pid/comm" 2>/dev/null || true)
  if [ "$command_name" = sleep ]; then
    guest_root kill -KILL "$pid"
  else
    echo "refusing to kill unexpected controller fixture pid $pid" >&2
    exit 3
  fi
}

transaction_id() {
  guest_root find "$state_root/operations/watchdog" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | \
    awk '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/ {print}'
}

wait_for_rollback() {
  local id=$1 attempt
  for attempt in $(seq 1 140); do
    if guest_root test -f "$state_root/operations/watchdog/$id/rolled-back.json"; then
      return
    fi
    sleep 1
  done
  echo "watchdog did not roll back within 140 seconds" >&2
  exit 1
}

cleanup_internal() {
  local id pid command_name
  if guest_root test -d "$state_root/operations/watchdog"; then
    while IFS= read -r id; do
      case "$id" in
        ????????-????-????-????-????????????)
          guest_root systemctl stop "vpnctl-watchdog@$id.timer" "vpnctl-watchdog@$id.service" >/dev/null 2>&1 || true
          ;;
      esac
    done < <(transaction_id || true)
  fi
  if guest_root test -f "$runtime_root/controller.pid"; then
    pid=$(guest_root cat "$runtime_root/controller.pid")
    command_name=$(guest_root cat "/proc/$pid/comm" 2>/dev/null || true)
    if [ "$command_name" = sleep ]; then
      guest_root kill -KILL "$pid" >/dev/null 2>&1 || true
    fi
  fi
  if namespace_exists; then
    guest_root ip netns delete "$namespace"
  fi
  if guest_root test -f "$libexec_root/.owner" && guest_root grep -Fxq "$owner_value" "$libexec_root/.owner"; then
    guest_root rm -f "/etc/systemd/system/$service_unit" "/etc/systemd/system/$timer_unit" "$dropin_path"
    guest_root rmdir "$dropin_root" >/dev/null 2>&1 || true
    guest_root rm -f "$libexec_root/vpnctl" "$libexec_root/watchdog-helper" "$libexec_root/.owner"
    guest_root rmdir "$libexec_root"
  fi
  if guest_root test -f "$owner_path" && guest_root grep -Fxq "$owner_value" "$owner_path"; then
    if guest_root test -d "$state_root/operations/watchdog"; then
      while IFS= read -r id; do
        case "$id" in
          ????????-????-????-????-????????????)
            guest_root rm -f \
              "$state_root/operations/watchdog/$id/snapshot.json" \
              "$state_root/operations/watchdog/$id/transaction.lock" \
              "$state_root/operations/watchdog/$id/activated.json" \
              "$state_root/operations/watchdog/$id/rolled-back.json"
            guest_root rmdir "$state_root/operations/watchdog/$id"
            ;;
        esac
      done < <(transaction_id || true)
      guest_root rmdir "$state_root/operations/watchdog"
    fi
    guest_root rmdir "$state_root/operations" >/dev/null 2>&1 || true
    guest_root rm -f "$owner_path"
    guest_root rmdir "$state_root"
  fi
  if guest_root test -f "$runtime_root/.owner" && guest_root grep -Fxq "$owner_value" "$runtime_root/.owner"; then
    guest_root rm -f "$runtime_root/controller.pid" "$runtime_root/timer-start-monotonic-nsec" "$runtime_root/.owner"
    guest_root rmdir "$runtime_root"
  fi
  guest_root systemctl daemon-reload
}

cleanup_host_build() {
  if [ -n "$host_build_dir" ] && [ -d "$host_build_dir" ]; then
    case "$host_build_dir" in
      /private/tmp/vpnctl-v2-watchdog-build.*) rm -rf "$host_build_dir" ;;
      *) echo "refusing unexpected host build cleanup: $host_build_dir" >&2; return 1 ;;
    esac
  fi
}

verify() {
  local evidence_dir=${1:-"$repository_root/artifacts/v2lab/watchdog-test/evidence-$(date -u +%Y%m%dT%H%M%SZ)"}
  local id prepared rolled wall_elapsed timer_start_nsec rollback_observed_nsec monotonic_elapsed_nsec monotonic_elapsed
  assert_lab_instance
  assert_other_spikes_inactive
  assert_owned_or_absent
  if namespace_exists; then
    echo "refusing to claim existing namespace $namespace" >&2
    exit 3
  fi
  mkdir -p "$evidence_dir"
  build_binaries_and_units
  trap 'cleanup_internal; cleanup_host_build' EXIT
  install_owned_files
  prepare_namespace
  capture_owned "$evidence_dir/prior"
  capture_foreign "$evidence_dir/foreign-before"
  controller_start
  set +e
  ns_root "$libexec_root/watchdog-helper" arm-kill
  helper_exit=$?
  set -e
  if [ "$helper_exit" -ne 137 ] && [ "$helper_exit" -ne 255 ]; then
    echo "initiating CLI did not return a local or Lima/SSH signal exit: $helper_exit" >&2
    exit 1
  fi
  id=$(transaction_id)
  if ! [[ "$id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    echo "unexpected watchdog transaction set: $id" >&2
    exit 1
  fi
  if ! guest_root test -f "$state_root/operations/watchdog/$id/activated.json"; then
    echo "initiating CLI exited before candidate activation was recorded" >&2
    exit 1
  fi
  controller_kill
  if ! guest_root systemctl is-active --quiet "vpnctl-watchdog@$id.timer"; then
    echo "watchdog timer is not active after CLI/controller kill" >&2
    exit 1
  fi
  timer_start_nsec=$(guest_root cat "$runtime_root/timer-start-monotonic-nsec")
  if ! [[ "$timer_start_nsec" =~ ^[0-9]+$ ]]; then
    echo "initiating helper did not record the monotonic timer-start boundary" >&2
    exit 1
  fi
  capture_owned "$evidence_dir/candidate"
  if cmp -s "$evidence_dir/prior-nft.txt" "$evidence_dir/candidate-nft.txt"; then
    echo "candidate firewall was not activated before CLI kill" >&2
    exit 1
  fi
  wait_for_rollback "$id"
  rollback_observed_nsec=$(ns_root "$libexec_root/watchdog-helper" monotonic)
  monotonic_elapsed_nsec=$((rollback_observed_nsec - timer_start_nsec))
  if [ "$monotonic_elapsed_nsec" -lt 120000000000 ] || [ "$monotonic_elapsed_nsec" -gt 140000000000 ]; then
    echo "watchdog rollback observed after $monotonic_elapsed_nsec monotonic nsec, expected 120000000000..140000000000" >&2
    exit 1
  fi
  monotonic_elapsed=$(awk -v value="$monotonic_elapsed_nsec" 'BEGIN {printf "%.9f", value / 1000000000}')
  capture_owned "$evidence_dir/restored"
  capture_foreign "$evidence_dir/foreign-after"
  assert_capture_equal "$evidence_dir/prior" "$evidence_dir/restored" "vpnctl-owned state"
  assert_foreign_equal "$evidence_dir/foreign-before" "$evidence_dir/foreign-after"
  prepared=$(guest_root jq -r .prepared_at "$state_root/operations/watchdog/$id/snapshot.json")
  rolled=$(guest_root jq -r .rolled_back_at "$state_root/operations/watchdog/$id/rolled-back.json")
  wall_elapsed=$("$host_build_dir/watchdog-helper-host" elapsed "$prepared" "$rolled")
  jq -n \
    --arg transaction_id "$id" \
    --argjson scheduled_seconds 120 \
    --argjson monotonic_elapsed_seconds "$monotonic_elapsed" \
    --argjson wall_elapsed_seconds "$wall_elapsed" \
    '{schema_version: 1, status: "passed", transaction_id: $transaction_id, scheduled_seconds: $scheduled_seconds, monotonic_elapsed_seconds: $monotonic_elapsed_seconds, wall_elapsed_seconds: $wall_elapsed_seconds, verified: {initiating_cli_sigkilled: true, controller_sigkilled: true, timer_survived_both: true, timeout_monotonic_seconds_at_least_120: true, prior_nftables_restored: true, prior_routes_restored: true, prior_policy_rules_restored: true, prior_sysctls_restored: true, foreign_nftables_preserved: true, foreign_routes_preserved: true, foreign_policy_rules_preserved: true, foreign_sysctl_preserved: true}}' > "$evidence_dir/summary.json"
  jq . "$evidence_dir/summary.json"
  cleanup_internal
  cleanup_host_build
  trap - EXIT
  status
}

status() {
  assert_lab_instance
  local namespace_state=absent state=absent units=absent process=absent
  namespace_exists && namespace_state=present
  guest_root test -e "$state_root" && state=present
  if guest_root test -e "/etc/systemd/system/$service_unit" || guest_root test -e "/etc/systemd/system/$timer_unit"; then units=present; fi
  if guest_root pgrep -f "^$libexec_root/(vpnctl|watchdog-helper)" >/dev/null 2>&1; then process=present; fi
  jq -n --arg namespace "$namespace_state" --arg state "$state" --arg units "$units" --arg process "$process" \
    '{namespace: $namespace, state: $state, units: $units, process: $process}'
}

cleanup() {
  assert_lab_instance
  assert_owned_or_absent
  cleanup_internal
  cleanup_host_build
  status
}

case "${1:-}" in
  verify) verify "${2:-}" ;;
  status) status ;;
  cleanup) cleanup ;;
  *) usage; exit 2 ;;
esac
