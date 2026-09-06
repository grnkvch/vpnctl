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
attempts_directory_name=automated-attempts
fixture_sessions_directory_name=automated-fixture-sessions
all_automated_stages='traceability openspec go-test go-race go-vet credential-lifecycle update-restore node-transport fleet-isolation failure adversarial capacity personal-client transport-supervision restricted-process watchdog-timeout watchdog-confirm tunnel-release ingress-release'
self_managed_lima_stages='node-transport fleet-isolation failure adversarial capacity'
shared_lima_stages='personal-client transport-supervision restricted-process watchdog-timeout watchdog-confirm tunnel-release ingress-release'
gateway_started=false
node_started=false
fixture_session_directory=
fixture_session_log=
current_source_commit=
current_release_version=
current_source_tree_sha256=
current_short_commit=
current_run_id=
current_attempt_name=
current_attempt_directory=

cd "$repository_root"

usage() {
  cat <<'EOF'
Usage:
  scripts/v2deployed-release-gate.sh prepare <vMAJOR.MINOR.PATCH> [evidence-directory]
  scripts/v2deployed-release-gate.sh run-automated <evidence-directory>
  scripts/v2deployed-release-gate.sh run-automated --resume <evidence-directory>
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
     ! grep -Eq -- '^- \[ \] 16[.]11 ' "$tasks_file"; then
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
    .schema_version == 2 and .automated_attempts_schema_version == 1 and
    .status == "collecting-evidence" and
    .source_commit == $source_commit and .release_version == $release_version and
    .production_ready == false and
    (.created_at | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  ' "$evidence_dir/candidate.json" >/dev/null || {
    if jq -e '.schema_version == 1' "$evidence_dir/candidate.json" >/dev/null 2>&1; then
      echo "legacy release evidence is read-only; prepare a new resumable evidence directory" >&2
    else
      echo "release evidence candidate does not match the clean source commit" >&2
    fi
    exit 3
  }
  if [ ! -d "$evidence_dir/$attempts_directory_name" ] ||
     [ -L "$evidence_dir/$attempts_directory_name" ] ||
     [ "$(path_mode "$evidence_dir/$attempts_directory_name")" != 700 ]; then
    echo "resumable release evidence attempt directory is absent or unsafe" >&2
    exit 3
  fi
  if [ ! -d "$evidence_dir/$fixture_sessions_directory_name" ] ||
     [ -L "$evidence_dir/$fixture_sessions_directory_name" ] ||
     [ "$(path_mode "$evidence_dir/$fixture_sessions_directory_name")" != 700 ]; then
    echo "resumable release evidence fixture-session directory is absent or unsafe" >&2
    exit 3
  fi
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
    schema_version: 2,
    automated_attempts_schema_version: 1,
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
  mkdir "$temporary/$attempts_directory_name"
  mkdir "$temporary/$fixture_sessions_directory_name"
  (cd "$temporary" && shasum -a 256 telegram-webhook-gate.py) > "$temporary/telegram-helper.sha256"
  chmod 0600 "$temporary/.owner" "$temporary/candidate.json" "$temporary/deployment.json" \
    "$temporary/clash-mi.json" "$temporary/telegram-helper.sha256"
  chmod 0700 "$temporary/$attempts_directory_name"
  chmod 0700 "$temporary/$fixture_sessions_directory_name"
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
    return 4
  fi
}

assert_fixtures_stopped() {
  assert_lab_instance "$gateway_instance" Stopped
  assert_lab_instance "$node_instance" Stopped
}

stage_in_list() {
  local stage=$1 stages=$2
  case " $stages " in
    *" $stage "*) return 0 ;;
    *) return 1 ;;
  esac
}

is_known_stage() {
  stage_in_list "$1" "$all_automated_stages"
}

stage_uses_lima() {
  stage_in_list "$1" "$self_managed_lima_stages $shared_lima_stages"
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

source_tree_sha256() {
  git ls-tree -r --full-tree HEAD | shasum -a 256 | awk '{print $1}'
}

stage_command_contract() {
  case "$1" in
    traceability) printf '%s\n' "go test ./internal/regression -run ^TestV2RequirementTraceabilityIsComplete$ -count=1" ;;
    openspec) printf '%s\n' "openspec validate vpnctl-v2 --strict --no-interactive" ;;
    go-test) printf '%s\n' "go test -p 1 ./... -count=1" ;;
    go-race) printf '%s\n' "go test -race -p 1 ./... -count=1" ;;
    go-vet) printf '%s\n' "go vet ./..." ;;
    credential-lifecycle) printf '%s\n' "scripts/v2credential-lifecycle-e2e.sh verify" ;;
    update-restore) printf '%s\n' "scripts/v2update-restore-e2e.sh verify" ;;
    node-transport) printf '%s\n' "scripts/v2node-transport-e2e.sh verify" ;;
    fleet-isolation) printf '%s\n' "scripts/v2fleet-isolation-e2e.sh verify" ;;
    failure) printf '%s\n' "scripts/v2failure-e2e.sh verify" ;;
    adversarial) printf '%s\n' "scripts/v2adversarial-e2e.sh verify" ;;
    capacity) printf '%s\n' "scripts/v2capacity-e2e.sh verify" ;;
    personal-client) printf '%s\n' "scripts/v2personal-client-test.sh verify" ;;
    transport-supervision) printf '%s\n' "scripts/v2transport-supervision-test.sh verify" ;;
    restricted-process) printf '%s\n' "scripts/v2restricted-test.sh verify" ;;
    watchdog-timeout) printf '%s\n' "scripts/v2watchdog-test.sh verify artifacts/v2lab/watchdog-test/task-16.11-{candidate}-{evidence}-{attempt}" ;;
    watchdog-confirm) printf '%s\n' "scripts/v2watchdog-test.sh verify-confirm artifacts/v2lab/watchdog-confirm-test/task-16.11-{candidate}-{evidence}-{attempt}" ;;
    tunnel-release) printf '%s\n' "scripts/v2tunnel-release-gate.sh run artifacts/v2lab/tunnel-release-gate/task-16.11-{candidate}-{evidence}-{attempt}" ;;
    ingress-release) printf '%s\n' "scripts/v2ingress-release-gate.sh run artifacts/v2lab/ingress-release-gate/task-16.11-{candidate}-{evidence}-{attempt}" ;;
    *) echo "unknown deployed release gate stage: $1" >&2; return 3 ;;
  esac
}

stage_contract_sha256() {
  local stage=$1 command lima_digest=none
  command=$(stage_command_contract "$stage")
  if stage_uses_lima "$stage"; then lima_digest=$lab_image_digest; fi
  printf '%s\0%s\0%s\0%s\0%s\0%s\0' \
    "vpnctl-v2-deployed-stage-contract-v1" "$stage" "$current_source_commit" \
    "$current_release_version" "$current_source_tree_sha256" "$command|$lima_digest" |
    shasum -a 256 | awk '{print $1}'
}

execute_stage() {
  local stage=$1 attempt=$2 scoped
  scoped="$current_short_commit-$current_run_id-$attempt"
  case "$stage" in
    traceability) env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/regression -run '^TestV2RequirementTraceabilityIsComplete$' -count=1 ;;
    openspec) openspec validate vpnctl-v2 --strict --no-interactive ;;
    go-test) env GOCACHE=/private/tmp/vpnctl-go-cache go test -p 1 ./... -count=1 ;;
    go-race) env GOCACHE=/private/tmp/vpnctl-go-race-cache go test -race -p 1 ./... -count=1 ;;
    go-vet) env GOCACHE=/private/tmp/vpnctl-go-vet-cache go vet ./... ;;
    credential-lifecycle) "$repository_root/scripts/v2credential-lifecycle-e2e.sh" verify ;;
    update-restore) "$repository_root/scripts/v2update-restore-e2e.sh" verify ;;
    node-transport) "$repository_root/scripts/v2node-transport-e2e.sh" verify ;;
    fleet-isolation) "$repository_root/scripts/v2fleet-isolation-e2e.sh" verify ;;
    failure) "$repository_root/scripts/v2failure-e2e.sh" verify ;;
    adversarial) "$repository_root/scripts/v2adversarial-e2e.sh" verify ;;
    capacity) "$repository_root/scripts/v2capacity-e2e.sh" verify ;;
    personal-client) "$repository_root/scripts/v2personal-client-test.sh" verify ;;
    transport-supervision) "$repository_root/scripts/v2transport-supervision-test.sh" verify ;;
    restricted-process) "$repository_root/scripts/v2restricted-test.sh" verify ;;
    watchdog-timeout) "$repository_root/scripts/v2watchdog-test.sh" verify \
      "$repository_root/artifacts/v2lab/watchdog-test/task-16.11-$scoped" ;;
    watchdog-confirm) "$repository_root/scripts/v2watchdog-test.sh" verify-confirm \
      "$repository_root/artifacts/v2lab/watchdog-confirm-test/task-16.11-$scoped" ;;
    tunnel-release) "$repository_root/scripts/v2tunnel-release-gate.sh" run \
      "$repository_root/artifacts/v2lab/tunnel-release-gate/task-16.11-$scoped" ;;
    ingress-release) "$repository_root/scripts/v2ingress-release-gate.sh" run \
      "$repository_root/artifacts/v2lab/ingress-release-gate/task-16.11-$scoped" ;;
    *) echo "unknown deployed release gate stage: $stage" >&2; return 3 ;;
  esac
}

assert_bounded_regular_file() {
  local path=$1 allowed_modes=$2 maximum_bytes=$3 mode
  if [ ! -f "$path" ] || [ -L "$path" ]; then
    echo "release attempt contains an unsafe file: $path" >&2
    return 3
  fi
  mode=$(path_mode "$path")
  case " $allowed_modes " in
    *" $mode "*) ;;
    *) echo "release attempt file has unsafe mode $mode: $path" >&2; return 3 ;;
  esac
  if [ "$(wc -c < "$path" | tr -d ' ')" -gt "$maximum_bytes" ]; then
    echo "release attempt file exceeds its bound: $path" >&2
    return 3
  fi
}

assert_attempt_ledger() {
  local root="$evidence_dir/$attempts_directory_name" stage_dir stage attempt_dir attempt mode entry name count
  for stage_dir in "$root"/*; do
    [ -e "$stage_dir" ] || [ -L "$stage_dir" ] || continue
    stage=$(basename -- "$stage_dir")
    if ! is_known_stage "$stage" || [ ! -d "$stage_dir" ] || [ -L "$stage_dir" ] ||
       [ "$(path_mode "$stage_dir")" != 700 ]; then
      echo "release attempt ledger contains an unsafe stage directory: $stage" >&2
      return 3
    fi
    for attempt_dir in "$stage_dir"/*; do
      [ -e "$attempt_dir" ] || [ -L "$attempt_dir" ] || continue
      attempt=$(basename -- "$attempt_dir")
      if ! [[ "$attempt" =~ ^attempt-[0-9]{4}$ ]] || [ ! -d "$attempt_dir" ] || [ -L "$attempt_dir" ]; then
        echo "release attempt ledger contains an unsafe attempt: $stage/$attempt" >&2
        return 3
      fi
      mode=$(path_mode "$attempt_dir")
      if [ "$mode" != 500 ] && [ "$mode" != 700 ]; then
        echo "release attempt directory has unsafe mode $mode: $stage/$attempt" >&2
        return 3
      fi
      count=0
      for entry in "$attempt_dir"/*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        name=$(basename -- "$entry")
        case "$name" in input.json|output.log|result.json) ;; *)
          echo "release attempt contains an unexpected entry: $stage/$attempt/$name" >&2
          return 3 ;;
        esac
        count=$((count + 1))
      done
      if [ "$mode" = 500 ]; then
        [ "$count" -eq 3 ] || { echo "sealed release attempt is incomplete: $stage/$attempt" >&2; return 3; }
        assert_bounded_regular_file "$attempt_dir/input.json" 400 65536
        assert_bounded_regular_file "$attempt_dir/output.log" 400 134217728
        assert_bounded_regular_file "$attempt_dir/result.json" 400 65536
      else
        [ "$count" -le 3 ] || {
          echo "interrupted release attempt has an unsafe shape: $stage/$attempt" >&2
          return 3
        }
        if [ -e "$attempt_dir/input.json" ] || [ -L "$attempt_dir/input.json" ]; then
          assert_bounded_regular_file "$attempt_dir/input.json" '400 600' 65536
        fi
        if [ -e "$attempt_dir/output.log" ] || [ -L "$attempt_dir/output.log" ]; then
          assert_bounded_regular_file "$attempt_dir/output.log" '400 600' 134217728
        fi
        if [ -e "$attempt_dir/result.json" ] || [ -L "$attempt_dir/result.json" ]; then
          assert_bounded_regular_file "$attempt_dir/result.json" '400 600' 65536
        fi
      fi
    done
  done
}

assert_fixture_session_ledger() {
  local root="$evidence_dir/$fixture_sessions_directory_name" session_dir session mode entry name count
  for session_dir in "$root"/*; do
    [ -e "$session_dir" ] || [ -L "$session_dir" ] || continue
    session=$(basename -- "$session_dir")
    mode=$(path_mode "$session_dir")
    if ! [[ "$session" =~ ^session-[0-9]{4}$ ]] || [ ! -d "$session_dir" ] || [ -L "$session_dir" ] ||
       { [ "$mode" != 500 ] && [ "$mode" != 700 ]; }; then
      echo "release fixture-session ledger contains an unsafe entry: $session" >&2
      return 3
    fi
    count=0
    for entry in "$session_dir"/*; do
      [ -e "$entry" ] || [ -L "$entry" ] || continue
      name=$(basename -- "$entry")
      [ "$name" = session.log ] || {
        echo "release fixture-session contains an unexpected entry: $session/$name" >&2
        return 3
      }
      count=$((count + 1))
    done
    if [ "$mode" = 500 ]; then
      [ "$count" -eq 1 ] || { echo "sealed release fixture-session is incomplete: $session" >&2; return 3; }
      assert_bounded_regular_file "$session_dir/session.log" 400 134217728
    elif [ "$count" -eq 1 ]; then
      assert_bounded_regular_file "$session_dir/session.log" '400 600' 134217728
    fi
  done
}

find_reusable_attempt() {
  local stage=$1 stage_dir="$evidence_dir/$attempts_directory_name/$1" attempt_dir attempt contract input_sha log_sha lima_digest=
  [ -d "$stage_dir" ] && [ ! -L "$stage_dir" ] || return 1
  contract=$(stage_contract_sha256 "$stage")
  if stage_uses_lima "$stage"; then lima_digest=$lab_image_digest; fi
  for attempt_dir in "$stage_dir"/attempt-*; do
    [ -d "$attempt_dir" ] && [ ! -L "$attempt_dir" ] && [ "$(path_mode "$attempt_dir")" = 500 ] || continue
    attempt=$(basename -- "$attempt_dir")
    input_sha=$(sha256_file "$attempt_dir/input.json")
    log_sha=$(sha256_file "$attempt_dir/output.log")
    if jq -e --arg stage "$stage" --arg attempt "$attempt" --arg source_commit "$current_source_commit" \
      --arg release_version "$current_release_version" --arg source_tree "$current_source_tree_sha256" \
      --arg contract "$contract" --arg lima "$lima_digest" '
        .schema_version == 1 and .stage == $stage and .attempt == $attempt and
        .source_commit == $source_commit and .release_version == $release_version and
        .source_tree_sha256 == $source_tree and .contract_sha256 == $contract and
        (($lima == "" and .lima_image_digest == null) or .lima_image_digest == $lima)
      ' "$attempt_dir/input.json" >/dev/null 2>&1 &&
      jq -e --arg stage "$stage" --arg attempt "$attempt" --arg source_commit "$current_source_commit" \
        --arg release_version "$current_release_version" --arg contract "$contract" --arg input_sha "$input_sha" \
        --arg log_sha "$log_sha" --arg lima "$lima_digest" '
          .schema_version == 1 and .stage == $stage and .attempt == $attempt and .status == "passed" and
          .exit_code == 0 and .source_commit == $source_commit and .release_version == $release_version and
          .contract_sha256 == $contract and .input_sha256 == $input_sha and .log_sha256 == $log_sha and
          (($lima == "" and .lima_image_digest == null) or .lima_image_digest == $lima)
        ' "$attempt_dir/result.json" >/dev/null 2>&1; then
      printf '%s\n' "$attempt"
      return 0
    fi
  done
  return 1
}

allocate_attempt() {
  local stage=$1 stage_dir="$evidence_dir/$attempts_directory_name/$1" number=1 candidate
  if [ ! -e "$stage_dir" ] && [ ! -L "$stage_dir" ]; then
    mkdir "$stage_dir"
    chmod 0700 "$stage_dir"
  fi
  while [ "$number" -le 9999 ]; do
    printf -v candidate 'attempt-%04d' "$number"
    if [ ! -e "$stage_dir/$candidate" ] && [ ! -L "$stage_dir/$candidate" ]; then break; fi
    number=$((number + 1))
  done
  [ "$number" -le 9999 ] || { echo "release stage attempt limit reached: $stage" >&2; return 3; }
  current_attempt_name=$candidate
  current_attempt_directory="$stage_dir/$candidate"
  mkdir "$current_attempt_directory"
  chmod 0700 "$current_attempt_directory"
}

run_stage_attempt() {
  local stage=$1 reused command contract started_at finished_at exit_status status input_sha log_sha
  local lima_digest= fixtures_stopped=null cleanup_status=0
  if reused=$(find_reusable_attempt "$stage"); then
    printf 'reusing release gate: %s (%s)\n' "$stage" "$reused"
    return 0
  fi
  if stage_in_list "$stage" "$self_managed_lima_stages"; then assert_fixtures_stopped; fi
  allocate_attempt "$stage"
  command=$(stage_command_contract "$stage")
  contract=$(stage_contract_sha256 "$stage")
  if stage_uses_lima "$stage"; then lima_digest=$lab_image_digest; fi
  started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  jq -n --arg stage "$stage" --arg attempt "$current_attempt_name" \
    --arg source_commit "$current_source_commit" --arg release_version "$current_release_version" \
    --arg source_tree "$current_source_tree_sha256" --arg command "$command" --arg contract "$contract" \
    --arg lima "$lima_digest" --arg started_at "$started_at" '{
      schema_version: 1, stage: $stage, attempt: $attempt,
      source_commit: $source_commit, release_version: $release_version,
      source_tree_sha256: $source_tree, command: $command, contract_sha256: $contract,
      lima_image_digest: (if $lima == "" then null else $lima end), started_at: $started_at
    }' > "$current_attempt_directory/input.json"
  chmod 0400 "$current_attempt_directory/input.json"
  : > "$current_attempt_directory/output.log"
  chmod 0600 "$current_attempt_directory/output.log"
  printf 'running release gate: %s (%s)\n' "$stage" "$current_attempt_name"
  set +e
  (umask 022; execute_stage "$stage" "$current_attempt_name") > "$current_attempt_directory/output.log" 2>&1
  exit_status=$?
  set -e
  if stage_in_list "$stage" "$self_managed_lima_stages"; then
    if assert_fixtures_stopped >> "$current_attempt_directory/output.log" 2>&1; then
      fixtures_stopped=true
    else
      printf '%s\n' 'stage did not restore the exact Lima fixtures; applying owner-scoped cleanup' >> "$current_attempt_directory/output.log"
      set +e
      restore_exact_fixtures_stopped >> "$current_attempt_directory/output.log" 2>&1
      cleanup_status=$?
      set -e
      [ "$cleanup_status" -eq 0 ] && fixtures_stopped=true || fixtures_stopped=false
      exit_status=4
    fi
  fi
  [ "$exit_status" -eq 0 ] && status=passed || status=failed
  finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  input_sha=$(sha256_file "$current_attempt_directory/input.json")
  log_sha=$(sha256_file "$current_attempt_directory/output.log")
  jq -n --arg stage "$stage" --arg attempt "$current_attempt_name" --arg status "$status" \
    --arg source_commit "$current_source_commit" --arg release_version "$current_release_version" \
    --arg contract "$contract" --arg input_sha "$input_sha" --arg log_sha "$log_sha" \
    --arg lima "$lima_digest" --arg started_at "$started_at" --arg finished_at "$finished_at" \
    --argjson exit_code "$exit_status" --argjson fixtures_stopped "$fixtures_stopped" '{
      schema_version: 1, stage: $stage, attempt: $attempt, status: $status, exit_code: $exit_code,
      source_commit: $source_commit, release_version: $release_version, contract_sha256: $contract,
      lima_image_digest: (if $lima == "" then null else $lima end),
      input_sha256: $input_sha, log_sha256: $log_sha,
      fixtures_stopped_after: $fixtures_stopped, started_at: $started_at, finished_at: $finished_at
    }' > "$current_attempt_directory/result.json"
  chmod 0400 "$current_attempt_directory/input.json" "$current_attempt_directory/output.log" "$current_attempt_directory/result.json"
  chmod 0500 "$current_attempt_directory"
  if [ "$exit_status" -ne 0 ]; then
    printf 'release gate stage failed: %s (%s)\n' "$stage" "$current_attempt_name" >&2
    printf 'inspect: %s/output.log\n' "$current_attempt_directory" >&2
    printf 'continue: scripts/v2deployed-release-gate.sh run-automated --resume %s\n' "$evidence_dir" >&2
    return "$exit_status"
  fi
}

restore_exact_fixtures_stopped() {
  local instance status
  for instance in "$node_instance" "$gateway_instance"; do
    status=$(instance_json "$instance" | jq -er '.status') || return 4
    case "$status" in
      Stopped) assert_lab_instance "$instance" Stopped || return ;;
      Running)
        assert_lab_instance "$instance" Running || return
        limactl stop "$instance" || return 4
        ;;
      *) echo "release fixture is in an unsafe transitional state: $instance/$status" >&2; return 4 ;;
    esac
  done
  assert_fixtures_stopped
}

allocate_fixture_session() {
  local root="$evidence_dir/$fixture_sessions_directory_name" number=1 candidate
  while [ "$number" -le 9999 ]; do
    printf -v candidate 'session-%04d' "$number"
    if [ ! -e "$root/$candidate" ] && [ ! -L "$root/$candidate" ]; then break; fi
    number=$((number + 1))
  done
  [ "$number" -le 9999 ] || { echo "release fixture-session limit reached" >&2; return 3; }
  fixture_session_directory="$root/$candidate"
  fixture_session_log="$fixture_session_directory/session.log"
  mkdir "$fixture_session_directory"
  chmod 0700 "$fixture_session_directory"
  : > "$fixture_session_log"
  chmod 0600 "$fixture_session_log"
}

seal_fixture_session() {
  local status=0
  if [ -n "$fixture_session_directory" ] && [ -d "$fixture_session_directory" ]; then
    if [ ! -e "$fixture_session_log" ] && [ ! -L "$fixture_session_log" ]; then
      : > "$fixture_session_log" || status=4
      chmod 0600 "$fixture_session_log" || status=4
    fi
    chmod 0400 "$fixture_session_log" || status=4
    chmod 0500 "$fixture_session_directory" || status=4
  fi
  fixture_session_directory=
  fixture_session_log=
  return "$status"
}

stop_started_fixtures() {
  local status=0
  set +e
  if [ "$node_started" = true ]; then
    limactl stop "$node_instance" >> "$fixture_session_log" 2>&1 || status=4
    node_started=false
  fi
  if [ "$gateway_started" = true ]; then
    limactl stop "$gateway_instance" >> "$fixture_session_log" 2>&1 || status=4
    gateway_started=false
  fi
  set -e
  return "$status"
}

cleanup_started_fixtures() {
  local status=${1:-1} cleanup_status=0
  trap - EXIT INT TERM
  set +e
  stop_started_fixtures || cleanup_status=$?
  if [ -n "$fixture_session_log" ]; then
    assert_fixtures_stopped >> "$fixture_session_log" 2>&1 || cleanup_status=4
  else
    assert_fixtures_stopped >/dev/null 2>&1 || cleanup_status=4
  fi
  seal_fixture_session || cleanup_status=$?
  [ "$cleanup_status" -eq 0 ] || status=$cleanup_status
  exit "$status"
}

run_shared_lima_stages() {
  local stage needed=false stage_status=0 cleanup_status=0
  for stage in $shared_lima_stages; do
    if ! find_reusable_attempt "$stage" >/dev/null; then needed=true; break; fi
  done
  [ "$needed" = true ] || return 0
  assert_fixtures_stopped
  allocate_fixture_session
  trap 'cleanup_started_fixtures $?' EXIT
  trap 'cleanup_started_fixtures 130' INT
  trap 'cleanup_started_fixtures 143' TERM
  gateway_started=true
  limactl start "$gateway_instance" >> "$fixture_session_log" 2>&1
  assert_lab_instance "$gateway_instance" Running
  node_started=true
  limactl start "$node_instance" >> "$fixture_session_log" 2>&1
  assert_lab_instance "$node_instance" Running
  for stage in $shared_lima_stages; do
    if run_stage_attempt "$stage"; then
      :
    else
      stage_status=$?
      stop_started_fixtures || cleanup_status=$?
      seal_fixture_session || cleanup_status=$?
      trap - EXIT INT TERM
      assert_fixtures_stopped || cleanup_status=4
      [ "$cleanup_status" -eq 0 ] || return "$cleanup_status"
      return "$stage_status"
    fi
  done
  stop_started_fixtures || cleanup_status=$?
  seal_fixture_session || cleanup_status=$?
  trap - EXIT INT TERM
  assert_fixtures_stopped || cleanup_status=4
  [ "$cleanup_status" -eq 0 ] || return "$cleanup_status"
}

attempt_ledger_has_entries() {
  local stage_dir attempt_dir
  for stage_dir in "$evidence_dir/$attempts_directory_name"/*; do
    [ -d "$stage_dir" ] && [ ! -L "$stage_dir" ] || continue
    for attempt_dir in "$stage_dir"/*; do
      [ -e "$attempt_dir" ] || [ -L "$attempt_dir" ] || continue
      return 0
    done
  done
  return 1
}

aggregate_automated_evidence() {
  local records output attempts_json stage attempt attempt_dir result_sha
  assert_fixtures_stopped
  [ ! -e "$evidence_dir/automated.json" ] && [ ! -L "$evidence_dir/automated.json" ] || {
    echo "deployed release gate refuses to replace automated evidence" >&2
    return 3
  }
  records=$(mktemp /private/tmp/vpnctl-v2-automated-records.XXXXXX)
  output=$(mktemp "$evidence_dir/.automated.XXXXXX")
  trap 'rm -f -- "$records" "$output"' EXIT INT TERM
  for stage in $all_automated_stages; do
    attempt=$(find_reusable_attempt "$stage") || {
      echo "mandatory release stage has no reusable passing attempt: $stage" >&2
      return 3
    }
    attempt_dir="$evidence_dir/$attempts_directory_name/$stage/$attempt"
    result_sha=$(sha256_file "$attempt_dir/result.json")
    jq -cn --arg stage "$stage" --arg attempt "$attempt" --arg result_sha "$result_sha" \
      '{stage: $stage, attempt: $attempt, result_sha256: $result_sha}' >> "$records"
  done
  attempts_json=$(jq -sc 'map({key: .stage, value: {attempt: .attempt, result_sha256: .result_sha256}}) | from_entries' "$records")
  jq -n --arg source_commit "$current_source_commit" --arg release_version "$current_release_version" \
    --arg source_tree "$current_source_tree_sha256" --argjson stage_attempts "$attempts_json" '{
      schema_version: 2,
      status: "passed",
      source_commit: $source_commit,
      release_version: $release_version,
      source_tree_sha256: $source_tree,
      stage_attempts: $stage_attempts,
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
    }' > "$output"
  chmod 0600 "$output"
  mv "$output" "$evidence_dir/automated.json"
  rm -f -- "$records"
  trap - EXIT INT TERM
  printf 'automated release evidence: %s\n' "$evidence_dir/automated.json"
}

run_automated_gate() {
  local resume=$1 stage
  assert_clean_source
  assert_only_deployed_task_pending
  assert_evidence_directory "$evidence_dir"
  assert_candidate
  assert_fixtures_stopped
  assert_attempt_ledger
  assert_fixture_session_ledger
  current_source_commit=$(candidate_value '.source_commit')
  current_release_version=$(candidate_value '.release_version')
  current_source_tree_sha256=$(source_tree_sha256)
  current_short_commit=${current_source_commit:0:7}
  current_run_id=$(basename -- "$evidence_dir")
  if [ -e "$evidence_dir/automated.json" ] || [ -L "$evidence_dir/automated.json" ]; then
    if [ "$resume" = true ] && assert_private_regular_file "$evidence_dir/automated.json" &&
       assert_automated_evidence; then
      printf 'automated release evidence already complete: %s\n' "$evidence_dir/automated.json"
      return 0
    fi
    echo "deployed release gate refuses to replace automated evidence" >&2
    return 3
  fi
  if [ "$resume" != true ] && attempt_ledger_has_entries; then
    echo "automated attempts already exist; continue explicitly with run-automated --resume" >&2
    return 3
  fi
  for stage in traceability openspec go-test go-race go-vet credential-lifecycle update-restore \
    node-transport fleet-isolation failure adversarial capacity; do
    run_stage_attempt "$stage"
  done
  run_shared_lima_stages
  aggregate_automated_evidence
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

assert_automated_evidence() {
  local stage attempt expected_attempt result_sha
  jq -e --arg source_commit "$current_source_commit" --arg release_version "$current_release_version" \
    --arg source_tree "$current_source_tree_sha256" '
    (keys == ["checks", "release_version", "schema_version", "source_commit", "source_tree_sha256", "stage_attempts", "status"]) and
    .schema_version == 2 and .status == "passed" and
    .source_commit == $source_commit and .release_version == $release_version and
    .source_tree_sha256 == $source_tree and
    (.stage_attempts | keys == ["adversarial", "capacity", "credential-lifecycle", "failure", "fleet-isolation", "go-race", "go-test", "go-vet", "ingress-release", "node-transport", "openspec", "personal-client", "restricted-process", "traceability", "transport-supervision", "tunnel-release", "update-restore", "watchdog-confirm", "watchdog-timeout"]) and
    (.stage_attempts | length == 19 and all(.[];
      keys == ["attempt", "result_sha256"] and
      (.attempt | test("^attempt-[0-9]{4}$")) and (.result_sha256 | test("^[0-9a-f]{64}$")))) and
    (.checks | keys == ["adversarial_security", "credential_lifecycle", "failure_paths", "fixtures_restored_stopped", "fleet_isolation", "go_unit_integration", "ingress_release", "minimum_host_capacity", "node_transport", "personal_clients", "race_detector", "requirement_traceability", "restricted_process_lifecycle", "reverse_tunnel_release", "ssh_watchdog_timeout_and_confirm", "strict_openspec", "transport_supervision", "update_restore_migration", "vet"]) and
    (.checks | length == 19 and all(.[]; . == true))
  ' "$evidence_dir/automated.json" >/dev/null || {
    echo "automated release evidence is incomplete" >&2
    return 3
  }
  for stage in $all_automated_stages; do
    attempt=$(jq -er --arg stage "$stage" '.stage_attempts[$stage].attempt' "$evidence_dir/automated.json") || return 3
    expected_attempt=$(find_reusable_attempt "$stage") || {
      echo "automated release evidence references a non-reusable stage: $stage" >&2
      return 3
    }
    [ "$attempt" = "$expected_attempt" ] || {
      echo "automated release evidence selected an unexpected stage attempt: $stage/$attempt" >&2
      return 3
    }
    result_sha=$(sha256_file "$evidence_dir/$attempts_directory_name/$stage/$attempt/result.json")
    [ "$result_sha" = "$(jq -er --arg stage "$stage" '.stage_attempts[$stage].result_sha256' "$evidence_dir/automated.json")" ] || {
      echo "automated release evidence stage result changed: $stage/$attempt" >&2
      return 3
    }
  done
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
  current_source_commit=$source_commit
  current_release_version=$release_version
  current_source_tree_sha256=$(source_tree_sha256)
  current_short_commit=${source_commit:0:7}
  current_run_id=$(basename -- "$evidence_dir")
  assert_attempt_ledger
  assert_fixture_session_ledger
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
  assert_automated_evidence
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
    echo "checksum-governed release asset verification failed" >&2
    exit 3
  fi
  chmod 0600 "$release_output"
  jq -e --arg release_version "$release_version" '
    .schema_version == 1 and .status == "passed" and .version == $release_version and
    .platform == "ubuntu-24.04-amd64" and .integrity == "sha256-and-bundle-verified" and
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
        checksummed_release_assets: true
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
    if [ "$#" -eq 2 ]; then
      evidence_dir=$2
      run_automated_gate false
    elif [ "$#" -eq 3 ] && [ "$2" = --resume ]; then
      evidence_dir=$3
      run_automated_gate true
    else
      usage >&2
      exit 2
    fi
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
