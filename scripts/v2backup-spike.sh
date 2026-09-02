#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
fixture_root="$repository_root/test/v2lab/backup"
manifest="$fixture_root/manifest.json"
artifact_root="$repository_root/artifacts/v2lab/backup-spike"
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
owner_value=vpnctl-v2-backup-spike-v1
state_root=/var/lib/vpnctl-v2-spike-backup
owner_path="$state_root/.owner"
test_binary="$state_root/vpnctl-v2-backup-spike.test"
cleanup_armed=false
host_build_dir=

usage() {
  cat <<'EOF'
Usage:
  scripts/v2backup-spike.sh verify [evidence-directory]
  scripts/v2backup-spike.sh status
  scripts/v2backup-spike.sh uninstall
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
        echo "refusing backup spike while another vpnctl lab spike is active: $instance/$unit" >&2
        exit 3
      fi
    done
  done
}

assert_owned_or_absent() {
  if gateway_root test -e "$state_root"; then
    if ! gateway_root grep -Fxq "$owner_value" "$owner_path"; then
      echo "refusing to overwrite unowned backup spike path" >&2
      exit 3
    fi
  fi
}

assert_no_test_process() {
  if gateway_root pgrep -f "^$test_binary" >/dev/null 2>&1; then
    echo "backup spike test process is still active" >&2
    exit 3
  fi
}

remove_host_build_dir() {
  if [ -n "$host_build_dir" ] && [ -d "$host_build_dir" ]; then
    case "$host_build_dir" in
      /private/tmp/vpnctl-v2-backup-build.*) rm -rf "$host_build_dir" ;;
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
    echo "backup spike state path remained after uninstall" >&2
    exit 1
  fi
  [ "$quiet" = true ] || echo "owner-checked backup spike resources removed"
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
  host_build_dir=$(mktemp -d /private/tmp/vpnctl-v2-backup-build.XXXXXX)
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    GOMODCACHE=/private/tmp/vpnctl-v2-backup-modcache \
    GOCACHE=/private/tmp/vpnctl-v2-backup-gocache \
    go test -c -o "$host_build_dir/vpnctl-v2-backup-spike.test" ./test/v2lab/backup
}

install_test_binary() {
  local source=$1 temporary=/tmp/vpnctl-v2-backup-spike.test
  gateway_root install -d -m 0700 "$state_root" "$state_root/tmp"
  gateway_root sh -c "printf '%s\n' '$owner_value' > '$owner_path' && chmod 0600 '$owner_path'"
  limactl copy --backend=scp "$source" "$gateway_instance:$temporary"
  gateway_root install -m 0700 "$temporary" "$test_binary"
  gateway_root rm -f "$temporary"
}

run_kdf_candidate() {
  local evidence_dir=$1 id=$2 memory_kib=$3 time_cost=$4 lanes=$5
  local output="$evidence_dir/kdf-$id.txt" metric rss
  gateway_root env \
    VPNCTL_V2_BACKUP_SPIKE=1 \
    VPNCTL_V2_BACKUP_ARGON_MEMORY_KIB="$memory_kib" \
    VPNCTL_V2_BACKUP_ARGON_TIME="$time_cost" \
    VPNCTL_V2_BACKUP_ARGON_LANES="$lanes" \
    TMPDIR="$state_root/tmp" \
    /usr/bin/time -v "$test_binary" -test.v -test.count=1 -test.run '^TestKDFCandidate$' \
    > "$output" 2>&1 < /dev/null
  metric=$(sed -n 's/^.*KDF_METRIC //p' "$output" | tail -1)
  rss=$(awk -F: '/Maximum resident set size/ {gsub(/^[[:space:]]+/, "", $2); print $2; exit}' "$output")
  if [ -z "$metric" ] || [ -z "$rss" ]; then
    echo "KDF benchmark evidence is missing for $id" >&2
    exit 1
  fi
  jq -e --arg id "$id" --argjson rss "$rss" '. + {id: $id, maximum_rss_kib: $rss} | select(.maximum_rss_kib <= 196608)' \
    <<<"$metric" > "$evidence_dir/kdf-$id.json"
}

verify() {
  local evidence_dir=${1:-"$artifact_root/evidence-$(date -u +%Y%m%dT%H%M%SZ)"}
  local binary_sha correctness_rss archive_metric selected_metric
  assert_lab_instance "$gateway_instance"
  assert_lab_instance "$node_instance"
  assert_other_spikes_inactive
  assert_owned_or_absent
  assert_no_test_process
  if gateway_root test -e "$state_root"; then
    echo "backup spike is already owner-prepared; uninstall before verify" >&2
    exit 3
  fi

  mkdir -p "$evidence_dir"
  chmod 0700 "$evidence_dir"
  build_test_binary
  binary_sha=$(shasum -a 256 "$host_build_dir/vpnctl-v2-backup-spike.test" | awk '{print $1}')
  cleanup_armed=true
  trap verification_cleanup EXIT
  install_test_binary "$host_build_dir/vpnctl-v2-backup-spike.test"
  cp "$manifest" "$evidence_dir/manifest.json"

  while IFS=$'\t' read -r id memory_kib time_cost lanes; do
    run_kdf_candidate "$evidence_dir" "$id" "$memory_kib" "$time_cost" "$lanes"
  done < <(jq -r '.kdf_candidates[] | [.id, .memory_kib, .time, .lanes] | @tsv' "$manifest")
  jq -s '.' "$evidence_dir"/kdf-*.json > "$evidence_dir/kdf-benchmarks.json"

  gateway_root env VPNCTL_V2_BACKUP_SPIKE=1 TMPDIR="$state_root/tmp" \
    /usr/bin/time -v "$test_binary" -test.v -test.count=1 -test.run '^TestAEADCandidates$' \
    > "$evidence_dir/aead-output.txt" 2>&1
  sed -n 's/^.*AEAD_METRIC //p' "$evidence_dir/aead-output.txt" | jq -s '.' > "$evidence_dir/aead-benchmarks.json"
  if [ "$(jq 'length' "$evidence_dir/aead-benchmarks.json")" -ne 4 ]; then
    echo "AEAD benchmark evidence is incomplete" >&2
    exit 1
  fi

  gateway_root env VPNCTL_V2_BACKUP_SPIKE=1 TMPDIR="$state_root/tmp" \
    /usr/bin/time -v "$test_binary" -test.v -test.count=1 \
      -test.run '^(TestArchiveRoundTripAndFailureAtomicity|TestHeaderResourceLimitsBeforeKDF)$' \
    > "$evidence_dir/correctness-output.txt" 2>&1
  correctness_rss=$(awk -F: '/Maximum resident set size/ {gsub(/^[[:space:]]+/, "", $2); print $2; exit}' "$evidence_dir/correctness-output.txt")
  archive_metric=$(sed -n 's/^.*ARCHIVE_METRIC //p' "$evidence_dir/correctness-output.txt" | tail -1)
  if [ -z "$correctness_rss" ] || [ -z "$archive_metric" ] || ! grep -Fq 'PASS' "$evidence_dir/correctness-output.txt"; then
    echo "backup correctness evidence is incomplete" >&2
    exit 1
  fi
  selected_metric=$(jq -c '.[] | select(.id == "m65536-t3-p4")' "$evidence_dir/kdf-benchmarks.json")
  if [ -z "$selected_metric" ]; then
    echo "selected KDF benchmark is absent" >&2
    exit 1
  fi
  jq -e --argjson correctness_rss "$correctness_rss" '
    .median_ms <= 2000 and .maximum_rss_kib <= 131072 and $correctness_rss <= 262144
  ' <<<"$selected_metric" >/dev/null
  assert_no_test_process

  jq -n \
    --arg status passed \
    --arg binary_sha256 "$binary_sha" \
    --argjson correctness_maximum_rss_kib "$correctness_rss" \
    --argjson archive "$archive_metric" \
    --slurpfile manifest "$manifest" \
    --slurpfile kdf "$evidence_dir/kdf-benchmarks.json" \
    --slurpfile aead "$evidence_dir/aead-benchmarks.json" \
    '{schema_version: 1, status: $status, binary_sha256: $binary_sha256, selected: {format: $manifest[0].format, kdf: $manifest[0].selected_kdf}, restore_limits: $manifest[0].restore_limits, acceptance_bounds: $manifest[0].acceptance_bounds, benchmarks: {kdf: $kdf[0], aead: $aead[0], archive: $archive, correctness_maximum_rss_kib: $correctness_maximum_rss_kib}, verified: {streaming_round_trip: true, mode_0600: true, no_overwrite: true, wrong_passphrase_rejected: true, authenticated_header_corruption_rejected: true, record_order_corruption_rejected: true, ciphertext_corruption_rejected: true, truncation_rejected: true, appended_data_rejected: true, failed_restore_output_absent: true, resource_limits_before_kdf: true}}' \
    > "$evidence_dir/summary.json"

  uninstall_internal true
  cleanup_armed=false
  trap - EXIT
  remove_host_build_dir
  assert_no_test_process
  printf 'backup spike evidence: %s\n' "$evidence_dir/summary.json"
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
