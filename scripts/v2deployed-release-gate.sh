#!/bin/bash
set -euo pipefail
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
artifact_root="$repository_root/artifacts/v2lab/deployed-release-gate"
fixture_root="$repository_root/test/v2lab/deployed-release-gate"
tasks_file="$repository_root/openspec/changes/vpnctl-v2/tasks.md"
telegram_helper="$repository_root/test/v2lab/ingress/telegram_webhook_gate.py"
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
owner_value=vpnctl-v2-deployed-release-gate-v1
gateway_started=false
node_started=false

cd "$repository_root"

usage() {
  cat <<'EOF'
Usage:
  scripts/v2deployed-release-gate.sh prepare <vMAJOR.MINOR.PATCH> [evidence-directory]
  scripts/v2deployed-release-gate.sh run-automated <evidence-directory>
  scripts/v2deployed-release-gate.sh status <evidence-directory>
  scripts/v2deployed-release-gate.sh finalize <evidence-directory> <absolute-release-assets-directory>

prepare/status/finalize never contact Telegram or mutate a deployed server.
run-automated runs the complete local/Lima suite and restores fixtures that it starts.
Real Clash Mi and Telegram evidence is collected manually as documented in
docs/v2/DEPLOYED_RELEASE_GATE.md.
EOF
}

assert_clean_source() {
  if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    echo "deployed release gate requires a clean source tree" >&2
    exit 3
  fi
}

assert_release_version() {
  local version=$1
  if ! printf '%s\n' "$version" | jq -eR 'test("^v(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$") and length <= 65' >/dev/null; then
    echo "release version must be canonical vMAJOR.MINOR.PATCH" >&2
    exit 2
  fi
}

assert_only_deployed_task_pending() {
  if [ "$(grep -Ec '^- \[ \] ' "$tasks_file")" -ne 1 ] ||
     ! grep -Fxq -- '- [ ] 16.11 Re-run the requirement traceability audit, strict OpenSpec validation, full Go/unit/integration/E2E/security/resource/migration suites, and release artifact verification; against an actually deployed gateway and node, manually verify supported Clash Mi profile import, selected TCP, proxy-bound DNS, UoT, strict wrong-host rejection, no fail-direct behavior, and reconnect, then use the token-safe harness to register the IP-only five-year public certificate with Telegram, receive and validate a real webhook request, and remove only the test-created registration; verify every non-backlog requirement is green before labeling the release v2.0.' "$tasks_file"; then
    echo "deployed release gate requires task 16.11 to be the only pending task" >&2
    exit 3
  fi
}

assert_evidence_path() {
  local path=$1 name
  case "$path" in
    "$artifact_root"/*) ;;
    *) echo "evidence directory must be below $artifact_root" >&2; exit 2 ;;
  esac
  if [ "$(dirname -- "$path")" != "$artifact_root" ] || [ "$(basename -- "$path")" = . ] ||
     [ "$(basename -- "$path")" = .. ]; then
    echo "evidence directory must be a direct named child of $artifact_root" >&2
    exit 2
  fi
  name=$(basename -- "$path")
  if ! [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
    echo "evidence directory name must be a bounded safe identifier" >&2
    exit 2
  fi
}

path_mode() {
  stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1"
}

assert_private_regular_file() {
  local path=$1
  if [ ! -f "$path" ] || [ -L "$path" ] || [ "$(path_mode "$path")" != 600 ] ||
     [ "$(wc -c < "$path" | tr -d ' ')" -gt 65536 ]; then
    echo "release evidence must be a bounded mode-0600 regular file: $(basename "$path")" >&2
    exit 3
  fi
}

assert_private_executable_file() {
  local path=$1
  if [ ! -f "$path" ] || [ -L "$path" ] || [ "$(path_mode "$path")" != 700 ] ||
     [ "$(wc -c < "$path" | tr -d ' ')" -gt 65536 ]; then
    echo "release helper must be a bounded mode-0700 regular file" >&2
    exit 3
  fi
}

assert_evidence_directory() {
  local path=$1
  assert_evidence_path "$path"
  if [ ! -d "$path" ] || [ -L "$path" ] || [ "$(path_mode "$path")" != 700 ] ||
     [ ! -f "$path/.owner" ] || [ -L "$path/.owner" ] ||
     [ "$(path_mode "$path/.owner")" != 600 ] ||
     [ "$(tr -d '\n' < "$path/.owner")" != "$owner_value" ]; then
    echo "release evidence directory is absent, unsafe, or not owned by this gate" >&2
    exit 3
  fi
  assert_private_regular_file "$path/candidate.json"
}

candidate_value() {
  jq -er "$1" "$evidence_dir/candidate.json"
}

assert_candidate() {
  local source_commit release_version
  source_commit=$(git rev-parse HEAD)
  release_version=$(candidate_value '.release_version')
  assert_release_version "$release_version"
  jq -e --arg source_commit "$source_commit" --arg release_version "$release_version" '
    .schema_version == 1 and .status == "collecting-evidence" and
    .source_commit == $source_commit and .release_version == $release_version and
    .production_ready == false and
    (.created_at | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  ' "$evidence_dir/candidate.json" >/dev/null || {
    echo "release evidence candidate does not match the clean source commit" >&2
    exit 3
  }
}

prepare_gate() {
  local version=$1 requested_path=${2:-} source_commit created_at temporary
  assert_clean_source
  assert_only_deployed_task_pending
  assert_release_version "$version"
  source_commit=$(git rev-parse HEAD)
  created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  mkdir -p "$artifact_root"
  if [ -n "$requested_path" ]; then
    evidence_dir=$requested_path
  else
    evidence_dir="$artifact_root/evidence-${created_at//:/}"
  fi
  assert_evidence_path "$evidence_dir"
  if [ -e "$evidence_dir" ] || [ -L "$evidence_dir" ]; then
    echo "deployed release gate refuses to replace evidence: $evidence_dir" >&2
    exit 3
  fi
  temporary=$(mktemp -d "$artifact_root/.prepare.XXXXXX")
  chmod 0700 "$temporary"
  trap 'rm -rf -- "$temporary"' EXIT INT TERM
  printf '%s\n' "$owner_value" > "$temporary/.owner"
  jq -n --arg source_commit "$source_commit" --arg release_version "$version" --arg created_at "$created_at" '{
    schema_version: 1,
    status: "collecting-evidence",
    source_commit: $source_commit,
    release_version: $release_version,
    created_at: $created_at,
    production_ready: false
  }' > "$temporary/candidate.json"
  jq --arg source_commit "$source_commit" --arg release_version "$version" '
    .source_commit = $source_commit | .release_version = $release_version
  ' "$fixture_root/deployment.example.json" > "$temporary/deployment.json"
  jq --arg source_commit "$source_commit" --arg release_version "$version" '
    .source_commit = $source_commit | .release_version = $release_version
  ' "$fixture_root/clash-mi.example.json" > "$temporary/clash-mi.json"
  install -m 0700 "$telegram_helper" "$temporary/telegram-webhook-gate.py"
  (cd "$temporary" && shasum -a 256 telegram-webhook-gate.py) > "$temporary/telegram-helper.sha256"
  chmod 0600 "$temporary/.owner" "$temporary/candidate.json" "$temporary/deployment.json" \
    "$temporary/clash-mi.json" "$temporary/telegram-helper.sha256"
  mv "$temporary" "$evidence_dir"
  trap - EXIT INT TERM
  printf 'deployed release gate evidence prepared: %s\n' "$evidence_dir"
}

instance_json() {
  limactl list --json | jq -ce --arg name "$1" 'select(.name == $name)'
}

assert_lab_instance() {
  local instance=$1 expected_status=$2
  if ! instance_json "$instance" | jq -e --arg digest "$lab_image_digest" --arg status "$expected_status" '
    .status == $status and .vmType == "qemu" and .arch == "x86_64" and
    .cpus == 1 and .memory == 536870912 and .disk == 10737418240 and
    .config.images[0].digest == $digest and any(.network[]?; .lima == "user-v2")
  ' >/dev/null; then
    echo "release gate fixture does not match contract: $instance/$expected_status" >&2
    exit 4
  fi
}

assert_fixtures_stopped() {
  assert_lab_instance "$gateway_instance" Stopped
  assert_lab_instance "$node_instance" Stopped
}

cleanup_started_fixtures() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  if [ "$node_started" = true ]; then limactl stop "$node_instance" >/dev/null 2>&1; fi
  if [ "$gateway_started" = true ]; then limactl stop "$gateway_instance" >/dev/null 2>&1; fi
  exit "$status"
}

run_logged() {
  local name=$1
  shift
  printf 'running release gate: %s\n' "$name"
  "$@" > "$evidence_dir/automated-logs/$name.log" 2>&1
}

run_automated_gate() {
  local source_commit release_version short run_id
  assert_clean_source
  assert_only_deployed_task_pending
  assert_evidence_directory "$evidence_dir"
  assert_candidate
  assert_fixtures_stopped
  source_commit=$(candidate_value '.source_commit')
  release_version=$(candidate_value '.release_version')
  short=${source_commit:0:7}
  run_id=$(basename -- "$evidence_dir")
  if [ -e "$evidence_dir/automated.json" ] || [ -e "$evidence_dir/automated-logs" ]; then
    echo "deployed release gate refuses to replace automated evidence" >&2
    exit 3
  fi
  (umask 077; mkdir "$evidence_dir/automated-logs")

  run_logged traceability env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/regression -run '^TestV2RequirementTraceabilityIsComplete$' -count=1
  run_logged openspec openspec validate vpnctl-v2 --strict --no-interactive
  run_logged go-test env GOCACHE=/private/tmp/vpnctl-go-cache go test ./... -count=1
  run_logged go-race env GOCACHE=/private/tmp/vpnctl-go-race-cache go test -race ./... -count=1
  run_logged go-vet env GOCACHE=/private/tmp/vpnctl-go-vet-cache go vet ./...
  run_logged credential-lifecycle "$repository_root/scripts/v2credential-lifecycle-e2e.sh" verify
  run_logged update-restore "$repository_root/scripts/v2update-restore-e2e.sh" verify
  run_logged node-transport "$repository_root/scripts/v2node-transport-e2e.sh" verify
  assert_fixtures_stopped
  run_logged fleet-isolation "$repository_root/scripts/v2fleet-isolation-e2e.sh" verify
  assert_fixtures_stopped
  run_logged failure "$repository_root/scripts/v2failure-e2e.sh" verify
  assert_fixtures_stopped
  run_logged adversarial "$repository_root/scripts/v2adversarial-e2e.sh" verify
  assert_fixtures_stopped
  run_logged capacity "$repository_root/scripts/v2capacity-e2e.sh" verify
  assert_fixtures_stopped

  trap cleanup_started_fixtures EXIT INT TERM
  gateway_started=true
  limactl start "$gateway_instance" > "$evidence_dir/automated-logs/gateway-start.log" 2>&1
  assert_lab_instance "$gateway_instance" Running
  node_started=true
  limactl start "$node_instance" > "$evidence_dir/automated-logs/node-start.log" 2>&1
  assert_lab_instance "$node_instance" Running
  run_logged personal-client "$repository_root/scripts/v2personal-client-test.sh" verify
  run_logged transport-supervision "$repository_root/scripts/v2transport-supervision-test.sh" verify
  run_logged restricted-process "$repository_root/scripts/v2restricted-test.sh" verify
  run_logged watchdog-timeout "$repository_root/scripts/v2watchdog-test.sh" verify \
    "$repository_root/artifacts/v2lab/watchdog-test/task-16.11-$short-$run_id"
  run_logged watchdog-confirm "$repository_root/scripts/v2watchdog-test.sh" verify-confirm \
    "$repository_root/artifacts/v2lab/watchdog-confirm-test/task-16.11-$short-$run_id"
  run_logged tunnel-release "$repository_root/scripts/v2tunnel-release-gate.sh" run \
    "$repository_root/artifacts/v2lab/tunnel-release-gate/task-16.11-$short-$run_id"
  run_logged ingress-release "$repository_root/scripts/v2ingress-release-gate.sh" run \
    "$repository_root/artifacts/v2lab/ingress-release-gate/task-16.11-$short-$run_id"
  limactl stop "$node_instance" > "$evidence_dir/automated-logs/node-stop.log" 2>&1
  node_started=false
  limactl stop "$gateway_instance" > "$evidence_dir/automated-logs/gateway-stop.log" 2>&1
  gateway_started=false
  trap - EXIT INT TERM
  assert_fixtures_stopped

  jq -n --arg source_commit "$source_commit" --arg release_version "$release_version" '{
    schema_version: 1,
    status: "passed",
    source_commit: $source_commit,
    release_version: $release_version,
    checks: {
      requirement_traceability: true,
      strict_openspec: true,
      go_unit_integration: true,
      race_detector: true,
      vet: true,
      credential_lifecycle: true,
      update_restore_migration: true,
      node_transport: true,
      fleet_isolation: true,
      failure_paths: true,
      adversarial_security: true,
      minimum_host_capacity: true,
      personal_clients: true,
      transport_supervision: true,
      restricted_process_lifecycle: true,
      ssh_watchdog_timeout_and_confirm: true,
      reverse_tunnel_release: true,
      ingress_release: true,
      fixtures_restored_stopped: true
    }
  }' > "$evidence_dir/automated.json"
  chmod 0600 "$evidence_dir/automated.json"
  printf 'automated release evidence: %s\n' "$evidence_dir/automated.json"
}

json_passes() {
  local path=$1 filter=$2
  [ -f "$path" ] && [ ! -L "$path" ] && jq -e "$filter" "$path" >/dev/null 2>&1
}

json_matches_candidate() {
  local path=$1 filter=$2 source_commit=$3 release_version=$4
  [ -f "$path" ] && [ ! -L "$path" ] && jq -e --arg source_commit "$source_commit" --arg release_version "$release_version" \
    ".source_commit == \$source_commit and .release_version == \$release_version and ($filter)" "$path" >/dev/null 2>&1
}

status_gate() {
  local source_commit release_version source_matches=false automated=false deployment=false clash=false telegram=false final=false
  assert_evidence_directory "$evidence_dir"
  source_commit=$(jq -er '.source_commit | select(type == "string" and test("^[0-9a-f]{40}$"))' "$evidence_dir/candidate.json")
  release_version=$(jq -er '.release_version | select(type == "string")' "$evidence_dir/candidate.json")
  assert_release_version "$release_version"
  if [ "$(git rev-parse HEAD)" = "$source_commit" ] && [ -z "$(git status --porcelain --untracked-files=normal)" ]; then source_matches=true; fi
  json_matches_candidate "$evidence_dir/automated.json" '.status == "passed"' "$source_commit" "$release_version" && automated=true
  json_matches_candidate "$evidence_dir/deployment.json" '.status == "passed" and .actual_deployment == true' "$source_commit" "$release_version" && deployment=true
  json_matches_candidate "$evidence_dir/clash-mi.json" '.status == "passed"' "$source_commit" "$release_version" && clash=true
  json_passes "$evidence_dir/telegram.json" '.status == "passed" and .provider_authenticated_request == true and .cleanup_succeeded == true' && telegram=true
  json_matches_candidate "$evidence_dir/final-summary.json" '.status == "passed" and .production_ready == true' "$source_commit" "$release_version" && final=true
  if [ "$source_matches" != true ]; then final=false; fi
  jq -n --argjson source_matches "$source_matches" --argjson automated "$automated" --argjson deployment "$deployment" --argjson clash "$clash" \
    --argjson telegram "$telegram" --argjson final "$final" '{
      schema_version: 1,
      source_commit_matches_clean_tree: $source_matches,
      automated: $automated,
      deployed_gateway_node: $deployment,
      clash_mi: $clash,
      telegram: $telegram,
      release_artifacts_and_finalization: $final,
      production_ready: $final
    }'
}

assert_global_ipv4() {
  python3 - "$1" <<'PY'
import ipaddress
import sys
try:
    address = ipaddress.IPv4Address(sys.argv[1])
except ipaddress.AddressValueError:
    raise SystemExit(1)
raise SystemExit(0 if address.is_global else 1)
PY
}

finalize_gate() {
  local release_directory=$1 source_commit release_version certificate_sha release_output
  assert_clean_source
  assert_only_deployed_task_pending
  assert_evidence_directory "$evidence_dir"
  assert_candidate
  source_commit=$(candidate_value '.source_commit')
  release_version=$(candidate_value '.release_version')
  for file in automated.json deployment.json clash-mi.json telegram.json; do
    assert_private_regular_file "$evidence_dir/$file"
  done
  assert_private_regular_file "$evidence_dir/telegram-helper.sha256"
  assert_private_executable_file "$evidence_dir/telegram-webhook-gate.py"
  if ! (cd "$evidence_dir" && shasum -a 256 -c telegram-helper.sha256) >/dev/null 2>&1; then
    echo "Telegram helper differs from the candidate prepared by this gate" >&2
    exit 3
  fi
  if [ -e "$evidence_dir/release.json" ] || [ -e "$evidence_dir/final-summary.json" ]; then
    echo "deployed release gate refuses to replace final evidence" >&2
    exit 3
  fi
  jq -e --arg source_commit "$source_commit" --arg release_version "$release_version" '
    (keys == ["checks", "release_version", "schema_version", "source_commit", "status"]) and
    .schema_version == 1 and .status == "passed" and
    .source_commit == $source_commit and .release_version == $release_version and
    (.checks | keys == ["adversarial_security", "credential_lifecycle", "failure_paths", "fixtures_restored_stopped", "fleet_isolation", "go_unit_integration", "ingress_release", "minimum_host_capacity", "node_transport", "personal_clients", "race_detector", "requirement_traceability", "restricted_process_lifecycle", "reverse_tunnel_release", "ssh_watchdog_timeout_and_confirm", "strict_openspec", "transport_supervision", "update_restore_migration", "vet"]) and
    (.checks | type == "object" and length == 19 and all(.[]; . == true))
  ' "$evidence_dir/automated.json" >/dev/null || { echo "automated release evidence is incomplete" >&2; exit 3; }
  jq -e --arg source_commit "$source_commit" --arg release_version "$release_version" '
    (keys == ["actual_deployment", "checks", "gateway", "node", "public_certificate", "release_version", "schema_version", "source_commit", "status", "target"]) and
    .schema_version == 1 and .status == "passed" and .source_commit == $source_commit and
    .release_version == $release_version and .actual_deployment == true and
    (.target | keys == ["architecture", "os"]) and
    .target == {os: "Ubuntu 24.04", architecture: "amd64"} and
    (.gateway | keys == ["healthy", "public_ipv4", "role"]) and
    .gateway.role == "gateway" and .gateway.healthy == true and
    (.gateway.public_ipv4 | type == "string") and
    (.node | keys == ["active_transport", "assigned_presets", "connected_to_gateway", "healthy", "role"]) and
    .node.role == "node" and .node.healthy == true and .node.connected_to_gateway == true and
    .node.active_transport == "restricted" and .node.assigned_presets == ["telegram"] and
    (.public_certificate | keys == ["ip_san", "private_key_exported", "rsa_bits", "sha256", "signature", "validity_days"]) and
    (.public_certificate.sha256 | test("^[0-9a-f]{64}$")) and
    .public_certificate.rsa_bits == 2048 and .public_certificate.signature == "SHA-256" and
    .public_certificate.validity_days == 1825 and .public_certificate.ip_san == true and
    .public_certificate.private_key_exported == false and
    (.checks | keys == ["candidate_installed_on_both_hosts", "gateway_node_control_healthy", "logging_disabled_by_default", "restricted_transport_healthy", "temporary_telegram_expose_ready", "temporary_telegram_expose_removed_after_provider_cleanup"]) and
    (.checks | type == "object" and length == 6 and all(.[]; . == true))
  ' "$evidence_dir/deployment.json" >/dev/null || { echo "deployed gateway/node evidence is incomplete" >&2; exit 3; }
  assert_global_ipv4 "$(jq -er '.gateway.public_ipv4' "$evidence_dir/deployment.json")" || {
    echo "deployed gateway evidence requires a manually supplied global IPv4" >&2
    exit 3
  }
  jq -e --arg source_commit "$source_commit" --arg release_version "$release_version" '
    (keys == ["app", "checks", "profile_sha256", "release_version", "schema_version", "source_commit", "status", "tested_at"]) and
    .schema_version == 1 and .status == "passed" and .source_commit == $source_commit and
    .release_version == $release_version and
    (.tested_at | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
    (.app | keys == ["name", "platform", "platform_version", "version"]) and
    .app.name == "Clash Mi" and (.app.version | type == "string" and length > 0 and length <= 128) and
    .app.platform == "iOS" and (.app.platform_version | type == "string" and length > 0 and length <= 128) and
    (.profile_sha256 | test("^[0-9a-f]{64}$")) and
    (.checks | keys == ["no_fail_direct_observed", "profile_import", "proxy_bound_dns", "reconnect_after_gateway_return", "selected_tcp", "selected_tcp_blocked_without_gateway", "selected_udp_blocked_without_gateway", "selected_uot", "strict_wrong_host_rejected"]) and
    (.checks | type == "object" and length == 9 and all(.[]; . == true))
  ' "$evidence_dir/clash-mi.json" >/dev/null || { echo "Clash Mi evidence is incomplete" >&2; exit 3; }
  jq -e '
    (keys == ["cleanup_succeeded", "custom_certificate", "provider_authenticated_request", "public_certificate_sha256", "real_request_received", "registered", "schema_version", "sensitive_values_emitted", "status"]) and
    .schema_version == 1 and .status == "passed" and .registered == true and
    .custom_certificate == true and .real_request_received == true and
    .provider_authenticated_request == true and .cleanup_succeeded == true and
    (.public_certificate_sha256 | test("^[0-9a-f]{64}$")) and .sensitive_values_emitted == false
  ' "$evidence_dir/telegram.json" >/dev/null || { echo "Telegram provider evidence is incomplete" >&2; exit 3; }
  certificate_sha=$(jq -er '.public_certificate.sha256' "$evidence_dir/deployment.json")
  if [ "$(jq -er '.public_certificate_sha256' "$evidence_dir/telegram.json")" != "$certificate_sha" ]; then
    echo "Telegram gate used a different public certificate" >&2
    exit 3
  fi
  case "$release_directory" in /*) ;; *) echo "release assets directory must be absolute" >&2; exit 2 ;; esac
  release_output=$(mktemp "$evidence_dir/.release.XXXXXX")
  if ! env GOCACHE=/private/tmp/vpnctl-go-cache go run ./cmd/vpnctl-release-verify \
    -assets "$release_directory" -version "$release_version" > "$release_output"; then
    rm -f "$release_output"
    echo "signed release asset verification failed" >&2
    exit 3
  fi
  chmod 0600 "$release_output"
  jq -e --arg release_version "$release_version" '
    .schema_version == 1 and .status == "passed" and .version == $release_version and
    .platform == "ubuntu-24.04-amd64" and .signature == "ed25519-verified" and
    .bundle == "manifest-and-artifacts-verified" and .migration == "backward-reversible"
  ' "$release_output" >/dev/null || { rm -f "$release_output"; echo "release verification result is invalid" >&2; exit 3; }
  mv "$release_output" "$evidence_dir/release.json"
  jq -n --arg source_commit "$source_commit" --arg release_version "$release_version" \
    --arg certificate_sha "$certificate_sha" \
    --arg profile_sha "$(jq -er '.profile_sha256' "$evidence_dir/clash-mi.json")" \
    --arg binary_sha "$(jq -er '.binary_sha256' "$evidence_dir/release.json")" \
    --arg bundle_sha "$(jq -er '.bundle_sha256' "$evidence_dir/release.json")" '{
      schema_version: 1,
      status: "passed",
      source_commit: $source_commit,
      release_version: $release_version,
      evidence: {
        automated: true,
        deployed_gateway_node: true,
        clash_mi: true,
        telegram_provider: true,
        telegram_registration_cleaned: true,
        temporary_expose_removed: true,
        signed_release_assets: true
      },
      fingerprints: {
        public_certificate_sha256: $certificate_sha,
        clash_profile_sha256: $profile_sha,
        vpnctl_binary_sha256: $binary_sha,
        release_bundle_sha256: $bundle_sha
      },
      production_ready: true,
      release_labeled: false
    }' > "$evidence_dir/final-summary.json"
  chmod 0600 "$evidence_dir/release.json" "$evidence_dir/final-summary.json"
  printf 'deployed release gate passed; labeling remains a separate manual action: %s\n' "$evidence_dir/final-summary.json"
}

command=${1:-}
case "$command" in
  prepare)
    [ "$#" -ge 2 ] && [ "$#" -le 3 ] || { usage >&2; exit 2; }
    prepare_gate "$2" "${3:-}"
    ;;
  run-automated)
    [ "$#" -eq 2 ] || { usage >&2; exit 2; }
    evidence_dir=$2
    run_automated_gate
    ;;
  status)
    [ "$#" -eq 2 ] || { usage >&2; exit 2; }
    evidence_dir=$2
    status_gate
    ;;
  finalize)
    [ "$#" -eq 3 ] || { usage >&2; exit 2; }
    evidence_dir=$2
    finalize_gate "$3"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
