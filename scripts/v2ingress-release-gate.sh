#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
spike_script="$repository_root/scripts/v2ingress-spike.sh"
fixture_root="$repository_root/test/v2lab/ingress"
manifest="$fixture_root/manifest.json"
harness_manifest="$fixture_root/telegram-harness-manifest.json"
harness_source="$fixture_root/telegram_webhook_gate.py"
harness_test="$fixture_root/test_telegram_webhook_gate.py"
artifact_root="$repository_root/artifacts/v2lab/ingress-release-gate"
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
guest_test=/tmp/vpnctl-v2-ingress-production-task-12.11.test
guest_summary=/tmp/vpnctl-v2-ingress-production-task-12.11.json
guest_harness_dir=/tmp/vpnctl-v2-telegram-harness-task-12.11
ingress_owner=/etc/vpnctl-v2-spike/ingress/.owner
ingress_owner_value=vpnctl-v2-ingress-spike-v1
temporary_root=
ingress_cleanup=false

cd "$repository_root"

usage() {
  cat <<'EOF'
Usage:
  scripts/v2ingress-release-gate.sh run [evidence-directory]

The evidence directory must be a new child of artifacts/v2lab/ingress-release-gate.
Both vpnctl v2 minimum-host Lima fixtures must already be running. This task-12.11
gate never contacts Telegram; the packaged harness is reserved for task 16.11.
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
    echo "ingress release gate requires a running contract-matching fixture: $instance" >&2
    exit 4
  fi
}

lab_ip() {
  limactl shell --tty=false "$1" -- ip -4 -o address show scope global |
    awk '$4 ~ /^192[.]168[.]104[.]/ {sub(/\/.*/, "", $4); print $4; exit}'
}

assert_ingress_fixture_absent() {
  if limactl shell --tty=false "$gateway_instance" -- sudo test -e /etc/vpnctl-v2-spike/ingress; then
    echo "ingress release gate requires an absent ingress spike fixture" >&2
    exit 3
  fi
  local package
  for package in nginx nginx-common; do
    if limactl shell --tty=false "$gateway_instance" -- dpkg-query -W "$package" >/dev/null 2>&1; then
      echo "ingress release gate refuses to co-own a pre-existing package: $package" >&2
      exit 3
    fi
  done
}

assert_guest_path_absent() {
  local path=$1
  if limactl shell --tty=false "$gateway_instance" -- sudo test -e "$path"; then
    echo "ingress release gate guest path is already occupied: $path" >&2
    exit 3
  fi
}

cleanup_native_guest() {
  limactl shell --tty=false "$gateway_instance" -- sudo rm -f \
    "$guest_test" "$guest_summary" \
    "$guest_harness_dir/telegram_webhook_gate.py" \
    "$guest_harness_dir/test_telegram_webhook_gate.py" >/dev/null 2>&1 || true
  limactl shell --tty=false "$gateway_instance" -- sudo rmdir "$guest_harness_dir" >/dev/null 2>&1 || true
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  cleanup_native_guest
  if [ "$ingress_cleanup" = true ] && \
     limactl shell --tty=false "$gateway_instance" -- sudo grep -Fxq "$ingress_owner_value" "$ingress_owner"; then
    "$spike_script" uninstall >/dev/null 2>&1
  fi
  if [ -n "$temporary_root" ] && [ -d "$temporary_root" ]; then
    rm -rf "$temporary_root"
  fi
  exit "$status"
}

record_fixture() {
  local instance=$1
  local destination=$2
  instance_json "$instance" | jq '{
    name, status, vmType, arch, cpus, memory, disk,
    image_digest: .config.images[0].digest,
    network: [.network[]? | {lima, interface}]
  }' > "$destination"
}

prepare_native_test() {
  env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOCACHE="$temporary_root/go-cache" \
    go test -c -o "$temporary_root/ingress.test" ./internal/ingress
  shasum -a 256 "$temporary_root/ingress.test" > "$evidence_dir/native-input.sha256"
  limactl copy --backend=scp "$temporary_root/ingress.test" "$gateway_instance:$guest_test"
  limactl shell --tty=false "$gateway_instance" -- sudo chmod 0755 "$guest_test"
}

run_production_native_gate() {
  limactl shell --tty=false "$gateway_instance" -- sudo "$guest_test" \
    -test.list '^TestNginx' > "$evidence_dir/native-tests.list"
  for expected in \
    TestNginxConfigParsesWithPinnedNginx \
    TestNginxRuntimeDoesNotReplayNonIdempotentRequests \
    TestNginxProductionRuntimeRegression; do
    if ! grep -Fxq "$expected" "$evidence_dir/native-tests.list"; then
      echo "ingress release gate native suite is missing: $expected" >&2
      exit 3
    fi
  done
  limactl shell --tty=false "$gateway_instance" -- sudo env \
    VPNCTL_PINNED_NGINX=/usr/sbin/nginx \
    VPNCTL_NGINX_RUNTIME=/usr/sbin/nginx \
    VPNCTL_NGINX_PRODUCTION_RUNTIME=/usr/sbin/nginx \
    VPNCTL_NGINX_PRODUCTION_SUMMARY="$guest_summary" \
    "$guest_test" \
    -test.run '^TestNginx(ConfigParsesWithPinnedNginx|RuntimeDoesNotReplayNonIdempotentRequests|ProductionRuntimeRegression)$' \
    -test.v -test.timeout=180s > "$evidence_dir/native-tests.log"
  grep -Fxq PASS "$evidence_dir/native-tests.log"
  limactl shell --tty=false "$gateway_instance" -- sudo cat "$guest_summary" \
    > "$evidence_dir/production-native.json"
  jq -e --arg version "$(manifest_value '.nginx.version' | sed 's/-.*//')" '
    .schema_version == 1 and .status == "passed" and .nginx_version == $version and
    .http1_forwarding == true and .http2_forwarding == true and .upstream_http11 == true and
    .path_query_headers_body == true and .safe_concurrent == 32 and
    .expose_accepted == 40 and .expose_rejected == 5 and
    .gateway_accepted == 64 and .gateway_rejected == 8 and
    .unknown_status == 404 and .body_limit_status == 413 and
    .unavailable_status == 503 and .timeout_status == 504 and
    .maximum_rss_bytes > 0 and .maximum_rss_bytes < 134217728 and
    .body_temp_files == 0 and .request_replay == false
  ' "$evidence_dir/production-native.json" >/dev/null
}

run_offline_telegram_harness_tests() {
  limactl shell --tty=false "$gateway_instance" -- mkdir -m 0700 "$guest_harness_dir"
  limactl copy --backend=scp "$harness_source" "$harness_test" "$gateway_instance:$guest_harness_dir/"
  limactl shell --tty=false "$gateway_instance" -- sudo chmod 0700 \
    "$guest_harness_dir/telegram_webhook_gate.py"
  limactl shell --tty=false "$gateway_instance" -- sudo chmod 0600 \
    "$guest_harness_dir/test_telegram_webhook_gate.py"
  limactl shell --tty=false "$gateway_instance" -- sudo sh -c \
    "cd '$guest_harness_dir' && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_telegram_webhook_gate.py" \
    > "$evidence_dir/telegram-harness-tests.log" 2>&1
  grep -Fq 'Ran 4 tests' "$evidence_dir/telegram-harness-tests.log"
  grep -Fxq 'OK' "$evidence_dir/telegram-harness-tests.log"

  install -m 0700 "$harness_source" "$evidence_dir/telegram-webhook-gate.py"
  install -m 0600 "$harness_manifest" "$evidence_dir/telegram-harness-manifest.json"
  shasum -a 256 "$evidence_dir/telegram-webhook-gate.py" \
    "$evidence_dir/telegram-harness-manifest.json" > "$evidence_dir/telegram-harness.sha256"
  for required in \
    'open("/dev/tty"' 'getpass.getpass' 'refusing to replace an existing Telegram webhook' \
    'cleanup_created_webhook' 'setWebhook' 'getWebhookInfo' 'deleteWebhook' \
    'has_custom_certificate' 'sensitive_values_emitted'; do
    grep -Fq "$required" "$evidence_dir/telegram-webhook-gate.py"
  done
  for forbidden in 'os.environ' 'token = args.' 'print(token' 'logging.'; do
    if grep -Fq "$forbidden" "$evidence_dir/telegram-webhook-gate.py"; then
      echo "packaged Telegram harness contains forbidden token/logging surface: $forbidden" >&2
      exit 3
    fi
  done
}

validate_spike_summaries() {
  jq -e '
    .schema_version == 1 and .status == "local-development-passed" and
    .protocols.http == ["1.1", "2"] and
    .webhook_proxy.synthetic_post_http11 == true and
    .webhook_proxy.synthetic_post_http2 == true and
    .webhook_proxy.unknown_path_status == 404 and
    .telegram.set_webhook_executed == false and
    .telegram.real_request_received == false and .production_ready == false
  ' "$evidence_dir/spike-verify/summary.json" >/dev/null
  jq -e '
    .schema_version == 1 and .status == "development-candidate-passed" and
    .limits.gateway_concurrent_requests == 64 and
    .limits.expose_default_concurrent_requests == 40 and
    .streaming.upstream_observed_before_upload_complete == true and
    .streaming.body_temp_files == 0 and .streaming.request_retry == false and
    .concurrency.expose_overload.status_counts["200"] == 40 and
    .concurrency.expose_overload.status_counts["503"] == 5 and
    .concurrency.gateway_overload.status_counts["200"] == 64 and
    .concurrency.gateway_overload.status_counts["503"] == 8 and
    .outcomes == {unknown: 404, body_limit: 413, unavailable: 503, timeout: 504} and
    .resources.ingress_peak_bytes < 134217728 and .resources.oom_events == 0 and
    .production_ready == false and .deferred_release_gate == "task 16.11 real Telegram provider flow"
  ' "$evidence_dir/spike-stress/summary.json" >/dev/null
}

write_summary() {
  local source_commit harness_sha256
  source_commit=$(git rev-parse HEAD)
  harness_sha256=$(shasum -a 256 "$evidence_dir/telegram-webhook-gate.py" | awk '{print $1}')
  jq -n \
    --arg source_commit "$source_commit" \
    --arg nginx_version "$(manifest_value '.nginx.version')" \
    --arg nginx_sha256 "$(manifest_value '.nginx.package_sha256')" \
    --arg harness_sha256 "$harness_sha256" \
    --slurpfile native "$evidence_dir/production-native.json" \
    --slurpfile stress "$evidence_dir/spike-stress/summary.json" \
    '{
      schema_version: 1,
      status: "passed",
      source_commit: $source_commit,
      target: {os: "Ubuntu 24.04", architecture: "amd64", vcpu: 1, memory_bytes: 536870912, disk_bytes: 10737418240},
      provider: {name: "nginx", version: $nginx_version, package_sha256: $nginx_sha256},
      production_native: $native[0],
      minimum_host_regression: $stress[0],
      telegram_harness: {
        status: "packaged-offline-tested",
        sha256: $harness_sha256,
        token_channel: "controlling-tty-only",
        existing_webhook_replacement: false,
        ownership_checked_cleanup: true,
        provider_calls_executed: false,
        deferred_gate: "task 16.11"
      },
      production_ready: false
    }' > "$evidence_dir/summary.json"
}

run_gate() {
  local instance public_ip
  if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    echo "ingress release gate requires a clean source tree" >&2
    exit 3
  fi
  for instance in "$gateway_instance" "$node_instance"; do
    assert_lab_instance "$instance"
  done
  assert_ingress_fixture_absent
  for path in "$guest_test" "$guest_summary" "$guest_harness_dir"; do
    assert_guest_path_absent "$path"
  done
  public_ip=$(lab_ip "$gateway_instance")
  if [ -z "$public_ip" ]; then
    echo "ingress release gate could not discover the isolated gateway fixture IPv4" >&2
    exit 3
  fi

  mkdir -p "$artifact_root"
  if [ -e "$evidence_dir" ]; then
    echo "ingress release gate refuses to replace evidence: $evidence_dir" >&2
    exit 3
  fi
  mkdir "$evidence_dir"
  chmod 0700 "$evidence_dir"
  temporary_root=$(mktemp -d /private/tmp/vpnctl-v2-ingress-release.XXXXXX)
  trap cleanup EXIT INT TERM
  record_fixture "$gateway_instance" "$evidence_dir/gateway-fixture.json"
  record_fixture "$node_instance" "$evidence_dir/node-fixture.json"

  prepare_native_test
  ingress_cleanup=true
  "$spike_script" prepare "$public_ip" > "$evidence_dir/spike-prepare.log"
  run_production_native_gate
  run_offline_telegram_harness_tests
  "$spike_script" verify "$evidence_dir/spike-verify" > "$evidence_dir/spike-verify.log"
  "$spike_script" stress "$evidence_dir/spike-stress" > "$evidence_dir/spike-stress.log"
  validate_spike_summaries
  "$spike_script" uninstall > "$evidence_dir/spike-uninstall.log"
  ingress_cleanup=false
  cleanup_native_guest

  for path in "$guest_test" "$guest_summary" "$guest_harness_dir" /etc/vpnctl-v2-spike/ingress; do
    assert_guest_path_absent "$path"
  done
  local package
  for package in nginx nginx-common; do
    if limactl shell --tty=false "$gateway_instance" -- dpkg-query -W "$package" >/dev/null 2>&1; then
      echo "ingress release gate cleanup retained its package: $package" >&2
      exit 3
    fi
  done
  write_summary
  printf 'ingress release gate evidence: %s\n' "$evidence_dir/summary.json"
}

command=${1:-}
case "$command" in
  run)
    [ "$#" -le 2 ] || { usage >&2; exit 2; }
    evidence_dir=${2:-"$artifact_root/evidence-$(date -u +%Y%m%dT%H%M%SZ)"}
    case "$evidence_dir" in
      "$artifact_root"/*) ;;
      *) echo "evidence directory must be below $artifact_root" >&2; exit 2 ;;
    esac
    run_gate
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
