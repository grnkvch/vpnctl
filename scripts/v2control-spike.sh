#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
fixture_root="$repository_root/test/v2lab/control"
manifest="$fixture_root/manifest.json"
artifact_root="$repository_root/artifacts/v2lab/control-spike"
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
owner_value=vpnctl-v2-control-spike-v1
state_root=/var/lib/vpnctl-v2-spike-control
owner_path="$state_root/.owner"
test_binary="$state_root/vpnctl-v2-control-spike.test"
cleanup_armed=false
host_build_dir=

usage() {
  cat <<'EOF'
Usage:
  scripts/v2control-spike.sh verify [evidence-directory]
  scripts/v2control-spike.sh status
  scripts/v2control-spike.sh uninstall
EOF
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

gateway_shell() {
  limactl shell --tty=false "$gateway_instance" -- "$@"
}

gateway_root() {
  limactl shell --tty=false "$gateway_instance" -- sudo "$@"
}

unit_active_on() {
  local instance=$1 unit=$2
  limactl shell --tty=false "$instance" -- systemctl is-active --quiet "$unit"
}

assert_other_spikes_inactive() {
  local instance unit
  for instance in "$gateway_instance" "$node_instance"; do
    for unit in \
      vpnctl-v2-spike-ingress.service \
      vpnctl-v2-spike-tunnel-server.service \
      vpnctl-v2-spike-tunnel-client.service \
      vpnctl-v2-spike-routing-guard.service \
      vpnctl-v2-spike-routing-engine.service \
      vpnctl-v2-spike-dns-resolver.service; do
      if unit_active_on "$instance" "$unit"; then
        echo "refusing control spike while another vpnctl lab spike is active: $instance/$unit" >&2
        exit 3
      fi
    done
  done
}

assert_owned_or_absent() {
  if gateway_root test -e "$state_root"; then
    if ! gateway_root grep -Fxq "$owner_value" "$owner_path"; then
      echo "refusing to overwrite unowned control spike path" >&2
      exit 3
    fi
  fi
}

assert_no_test_process() {
  if gateway_root pgrep -f "^$test_binary" >/dev/null 2>&1; then
    echo "control spike test process is still active" >&2
    exit 3
  fi
}

remove_host_build_dir() {
  if [ -n "$host_build_dir" ] && [ -d "$host_build_dir" ]; then
    case "$host_build_dir" in
      /private/tmp/vpnctl-v2-control-build.*) rm -rf "$host_build_dir" ;;
      *) echo "refusing unexpected host build cleanup path: $host_build_dir" >&2; return 1 ;;
    esac
  fi
  host_build_dir=
}

uninstall_internal() {
  local quiet=${1:-false}
  assert_owned_or_absent
  assert_no_test_process
  if gateway_root test -e "$state_root"; then
    gateway_root rm -rf "$state_root"
  fi
  if gateway_root test -e "$state_root"; then
    echo "control spike state path remained after uninstall" >&2
    exit 1
  fi
  [ "$quiet" = true ] || echo "owner-checked control spike resources removed"
}

verification_cleanup() {
  local exit_status=$?
  if [ "$cleanup_armed" = true ]; then
    uninstall_internal true >/dev/null 2>&1 || true
  fi
  remove_host_build_dir >/dev/null 2>&1 || true
  return "$exit_status"
}

build_test_binary() {
  host_build_dir=$(mktemp -d /private/tmp/vpnctl-v2-control-build.XXXXXX)
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    GOCACHE=/private/tmp/vpnctl-v2-control-linux-gocache \
    go test -c -o "$host_build_dir/vpnctl-v2-control-spike.test" ./test/v2lab/control
}

install_test_binary() {
  local source=$1 temporary=/tmp/vpnctl-v2-control-spike.test
  gateway_root install -d -m 0700 "$state_root" "$state_root/tmp"
  gateway_root sh -c "printf '%s\n' '$owner_value' > '$owner_path' && chmod 0600 '$owner_path'"
  limactl copy --backend=scp "$source" "$gateway_instance:$temporary"
  gateway_root install -m 0700 "$temporary" "$test_binary"
  gateway_root rm -f "$temporary"
}

verify() {
  local evidence_dir=${1:-"$artifact_root/evidence-$(date -u +%Y%m%dT%H%M%SZ)"}
  local binary_sha openssl_version max_rss
  assert_lab_instance "$gateway_instance"
  assert_lab_instance "$node_instance"
  assert_other_spikes_inactive
  assert_owned_or_absent
  assert_no_test_process
  if gateway_root test -e "$state_root"; then
    echo "control spike is already owner-prepared; uninstall before verify" >&2
    exit 3
  fi

  mkdir -p "$evidence_dir"
  chmod 0700 "$evidence_dir"
  build_test_binary
  binary_sha=$(shasum -a 256 "$host_build_dir/vpnctl-v2-control-spike.test" | awk '{print $1}')
  cleanup_armed=true
  trap verification_cleanup EXIT
  install_test_binary "$host_build_dir/vpnctl-v2-control-spike.test"
  cp "$manifest" "$evidence_dir/manifest.json"

  gateway_root env \
    VPNCTL_V2_CONTROL_SPIKE=1 \
    TMPDIR="$state_root/tmp" \
    /usr/bin/time -v "$test_binary" -test.v -test.count=1 \
    > "$evidence_dir/test-output.txt" 2>&1
  openssl_version=$(gateway_shell openssl version)
  max_rss=$(awk -F: '/Maximum resident set size/ {gsub(/^[[:space:]]+/, "", $2); print $2; exit}' "$evidence_dir/test-output.txt")
  if [ -z "$max_rss" ]; then
    echo "control spike resource evidence is missing" >&2
    exit 1
  fi
  if ! grep -Fq 'PASS' "$evidence_dir/test-output.txt"; then
    echo "control spike test output lacks PASS" >&2
    exit 1
  fi
  assert_no_test_process

  jq -n \
    --arg status passed \
    --arg binary_sha256 "$binary_sha" \
    --arg openssl "$openssl_version" \
    --argjson maximum_rss_kib "$max_rss" \
    --slurpfile manifest "$manifest" \
    '{schema_version: 1, status: $status, binary_sha256: $binary_sha256, openssl: $openssl, maximum_rss_kib: $maximum_rss_kib, accepted: {pki: $manifest[0].pki, enrollment: $manifest[0].enrollment, rpc: $manifest[0].rpc}, verified: {go_openssl_interoperability: true, uri_san_validation: true, renewal_window: true, ca_overlap: true, transcript_context_binding: true, transcript_replay_rejected: true, mtls_required: true, tls_1_2_rejected: true, authoritative_generation_checked: true, malformed_requests_bounded: true, header_bytes_bounded: true, read_header_timeout: true, read_body_timeout: true, write_timeout: true, idle_timeout: true, concurrent_connections_bounded: true, private_loopback_listener_only: true}}' \
    > "$evidence_dir/summary.json"

  uninstall_internal true
  cleanup_armed=false
  trap - EXIT
  remove_host_build_dir
  assert_no_test_process
  printf 'control spike evidence: %s\n' "$evidence_dir/summary.json"
}

status() {
  assert_lab_instance "$gateway_instance"
  if gateway_root test -e "$state_root"; then
    if gateway_root grep -Fxq "$owner_value" "$owner_path"; then
      printf 'state=owned-present\n'
    else
      printf 'state=foreign-conflict\n'
    fi
  else
    printf 'state=absent\n'
  fi
  if gateway_root pgrep -af "^$test_binary"; then
    :
  else
    printf 'process=absent\n'
  fi
}

command=${1:-}
case "$command" in
  verify) verify "${2:-}" ;;
  status) status ;;
  uninstall)
    assert_lab_instance "$gateway_instance"
    assert_lab_instance "$node_instance"
    uninstall_internal false
    ;;
  *) usage >&2; exit 2 ;;
esac
