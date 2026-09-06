#!/bin/bash
set -euo pipefail
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
artifact_root="$repository_root/artifacts/v2lab/deployed-release-gate"
fixture_root="$repository_root/test/v2lab/deployed-release-gate"
stage_registry="$fixture_root/stages.json"
clean_state_witness="$repository_root/scripts/v2release-clean-state.sh"
tasks_file="$repository_root/openspec/changes/vpnctl-v2/tasks.md"
telegram_helper="$repository_root/test/v2lab/ingress/telegram_webhook_gate.py"
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
owner_value=vpnctl-v2-deployed-release-gate-v1
attempts_directory_name=automated-attempts
fixture_sessions_directory_name=automated-fixture-sessions
all_automated_stages=
fast_automated_stages=
vm_automated_stages=
stage_registry_sha256=
gateway_started=false
node_started=false
fixture_session_directory=
fixture_session_log=
fixture_session_started_at=
fixture_session_started_mono=0
fixture_session_startup_ms=0
fixture_session_execution_ms=0
fixture_session_witness_ms=0
fixture_session_cleanup_ms=0
fixture_session_shutdown_ms=0
fixture_witness_number=0
current_pre_witness_sha256=
current_post_witness_sha256=
current_gate_command=run-automated
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
  scripts/v2deployed-release-gate.sh run-fast <evidence-directory>
  scripts/v2deployed-release-gate.sh run-fast --resume <evidence-directory>
  scripts/v2deployed-release-gate.sh run-vm <evidence-directory>
  scripts/v2deployed-release-gate.sh run-vm --resume <evidence-directory>
  scripts/v2deployed-release-gate.sh run-automated <evidence-directory>
  scripts/v2deployed-release-gate.sh run-automated --resume <evidence-directory>
  scripts/v2deployed-release-gate.sh status <evidence-directory>
  scripts/v2deployed-release-gate.sh finalize <evidence-directory> <absolute-release-assets-directory>

prepare/status/finalize never contact Telegram or mutate a deployed server.
run-fast runs host-only checks and never invokes Lima. run-vm runs the heavy Lima checks.
run-automated composes both phases. Every VM invocation restores the exact fixtures to Stopped.
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
    .schema_version == 2 and .automated_attempts_schema_version == 2 and
    .status == "collecting-evidence" and
    .source_commit == $source_commit and .release_version == $release_version and
    .production_ready == false and
    (.created_at | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  ' "$evidence_dir/candidate.json" >/dev/null || {
    if jq -e '.schema_version == 1 or .automated_attempts_schema_version == 1' "$evidence_dir/candidate.json" >/dev/null 2>&1; then
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
  validate_stage_registry
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
    automated_attempts_schema_version: 2,
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

monotonic_ms() {
  perl -MTime::HiRes=clock_gettime,CLOCK_MONOTONIC -e 'printf "%.0f\n", clock_gettime(CLOCK_MONOTONIC) * 1000'
}

elapsed_ms() {
  if [ "$2" -ge "$1" ]; then printf '%s\n' "$(( $2 - $1 ))"; else printf '0\n'; fi
}

validate_stage_registry() {
  jq -e '
    . as $registry |
    (keys == ["contract_version", "schema_version", "stages"]) and
    .schema_version == 1 and .contract_version == 2 and (.stages | length == 19) and
    ([.stages[].name] | length == (unique | length)) and
    ([.stages[].order] | length == (unique | length)) and
    ([.stages[].order] == ([.stages[].order] | sort)) and
    ([.stages[].name] | sort) == (["adversarial","capacity","credential-lifecycle","failure","fleet-isolation","go-race","go-test","go-vet","ingress-release","node-transport","openspec","personal-client","restricted-process","traceability","transport-supervision","tunnel-release","update-restore","watchdog-confirm","watchdog-timeout"] | sort) and
    all(.stages[];
      (keys == ["cleanup_adapter","command","dependencies","name","order","phase","uses_lima"]) and
      (.name | test("^[a-z0-9-]{1,64}$")) and (.phase == "fast" or .phase == "vm") and
      (.order | type == "number" and floor == .) and (.command | type == "string" and length > 0 and length <= 1024) and
      (.cleanup_adapter == null or (.cleanup_adapter | type == "string" and startswith("scripts/") and length <= 256)) and
      (.dependencies | type == "array" and length == (unique | length)) and
      ((.phase == "fast" and .uses_lima == false and (.dependencies | length == 0)) or (.phase == "vm" and .uses_lima == true))) and
    ([.stages[] as $stage | $stage.dependencies[] as $dependency | {stage:$stage, dependency:$dependency}] |
      all(.[]; . as $edge | any($registry.stages[]; .name == $edge.dependency and .order < $edge.stage.order))) and
    ([.stages[] | select(.cleanup_adapter != null) | [.name,.cleanup_adapter]] == [
      ["personal-client","scripts/v2personal-client-test.sh cleanup"],
      ["restricted-process","scripts/v2restricted-test.sh cleanup"],
      ["transport-supervision","scripts/v2transport-supervision-test.sh cleanup"],
      ["watchdog-confirm","scripts/v2watchdog-test.sh cleanup"],
      ["watchdog-timeout","scripts/v2watchdog-test.sh cleanup"]
    ]) and
    (.stages[-1].name == "capacity") and
    (.stages[] | select(.name == "failure").dependencies == ["tunnel-release","ingress-release"])
  ' "$stage_registry" >/dev/null || {
    echo "deployed release stage registry is invalid" >&2
    return 3
  }
  "$clean_state_witness" validate-manifest
  stage_registry_sha256=$(sha256_file "$stage_registry")
  all_automated_stages=$(jq -r '.stages[].name' "$stage_registry")
  fast_automated_stages=$(jq -r '.stages[] | select(.phase == "fast") | .name' "$stage_registry")
  vm_automated_stages=$(jq -r '.stages[] | select(.phase == "vm") | .name' "$stage_registry")
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

stage_record() {
  jq -ce --arg stage "$1" '.stages[] | select(.name == $stage)' "$stage_registry"
}

is_known_stage() {
  stage_record "$1" >/dev/null
}

stage_uses_lima() {
  [ "$(stage_record "$1" | jq -r '.uses_lima')" = true ]
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

source_tree_sha256() {
  git ls-tree -r --full-tree HEAD | shasum -a 256 | awk '{print $1}'
}

stage_command_contract() {
  stage_record "$1" | jq -r '.command'
}

stage_dependencies_json() {
  local stage=$1 dependency attempt result_path result_sha contract records
  records=$(mktemp /private/tmp/vpnctl-v2-dependencies.XXXXXX)
  while IFS= read -r dependency; do
    [ -n "$dependency" ] || continue
    attempt=$(find_reusable_attempt "$dependency") || { rm -f -- "$records"; return 3; }
    result_path="$evidence_dir/$attempts_directory_name/$dependency/$attempt/result.json"
    result_sha=$(sha256_file "$result_path")
    contract=$(jq -er '.contract_sha256' "$result_path")
    jq -cn --arg dependency "$dependency" --arg attempt "$attempt" --arg path "$result_path" \
      --arg result_sha "$result_sha" --arg contract "$contract" \
      '{key:$dependency,value:{attempt:$attempt,result_path:$path,result_sha256:$result_sha,contract_sha256:$contract}}' >> "$records"
  done < <(stage_record "$stage" | jq -r '.dependencies[]')
  jq -sc 'from_entries' "$records"
  rm -f -- "$records"
}

stage_contract_sha256() {
  local stage=$1 command lima_digest=none dependencies
  command=$(stage_command_contract "$stage")
  dependencies=$(stage_dependencies_json "$stage") || return 3
  if stage_uses_lima "$stage"; then lima_digest=$lab_image_digest; fi
  printf '%s\0%s\0%s\0%s\0%s\0%s\0%s\0%s\0' \
    "vpnctl-v2-deployed-stage-contract-v2" "$stage_registry_sha256" "$stage" "$current_source_commit" \
    "$current_release_version" "$current_source_tree_sha256" "$command|$lima_digest" "$dependencies" |
    shasum -a 256 | awk '{print $1}'
}

stage_artifact_summary() {
  local stage=$1 attempt=$2 scoped
  scoped="$current_short_commit-$current_run_id-$attempt"
  case "$stage" in
    tunnel-release) printf '%s\n' "$repository_root/artifacts/v2lab/tunnel-release-gate/task-16.11-$scoped/summary.json" ;;
    ingress-release) printf '%s\n' "$repository_root/artifacts/v2lab/ingress-release-gate/task-16.11-$scoped/summary.json" ;;
    *) return 1 ;;
  esac
}

render_stage_command() {
  local stage=$1 attempt=$2 command dependencies value quoted
  command=$(stage_command_contract "$stage")
  command=${command//\{candidate\}/$current_short_commit}
  command=${command//\{evidence\}/$current_run_id}
  command=${command//\{attempt\}/$attempt}
  if [ "$stage" = failure ]; then
    dependencies=$(stage_dependencies_json "$stage")
    for value in tunnel-result tunnel-sha ingress-result ingress-sha; do
      case "$value" in
        tunnel-result) quoted=$(jq -r '.["tunnel-release"].result_path | @sh' <<<"$dependencies") ;;
        tunnel-sha) quoted=$(jq -r '.["tunnel-release"].result_sha256 | @sh' <<<"$dependencies") ;;
        ingress-result) quoted=$(jq -r '.["ingress-release"].result_path | @sh' <<<"$dependencies") ;;
        ingress-sha) quoted=$(jq -r '.["ingress-release"].result_sha256 | @sh' <<<"$dependencies") ;;
      esac
      command=${command//\{$value\}/$quoted}
    done
  fi
  printf '%s\n' "$command"
}

execute_stage() {
  local stage=$1 attempt=$2 command cache=/private/tmp/vpnctl-go-cache
  command=$(render_stage_command "$stage" "$attempt")
  [ "$stage" = go-race ] && cache=/private/tmp/vpnctl-go-race-cache
  [ "$stage" = go-vet ] && cache=/private/tmp/vpnctl-go-vet-cache
  if stage_uses_lima "$stage"; then
    env GOCACHE="$cache" VPNCTL_V2_TIMING_OUTPUT="$current_attempt_directory/child-timing.json" \
      VPNCTL_V2_SHARED_LIMA_SESSION=true bash -c "cd \"$repository_root\" && $command"
  else
    env -u VPNCTL_V2_TIMING_OUTPUT -u VPNCTL_V2_SHARED_LIMA_SESSION GOCACHE="$cache" \
      bash -c "cd \"$repository_root\" && $command"
  fi
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
        case "$name" in input.json|output.log|child-timing.json|child-timing.json.parts|child-timing.json.tmp|result.json) ;; *)
          echo "release attempt contains an unexpected entry: $stage/$attempt/$name" >&2
          return 3 ;;
        esac
        count=$((count + 1))
      done
      if [ "$mode" = 500 ]; then
        [ "$count" -eq 4 ] || { echo "sealed release attempt is incomplete: $stage/$attempt" >&2; return 3; }
        assert_bounded_regular_file "$attempt_dir/input.json" 400 65536
        assert_bounded_regular_file "$attempt_dir/output.log" 400 134217728
        assert_bounded_regular_file "$attempt_dir/child-timing.json" 400 65536
        assert_bounded_regular_file "$attempt_dir/result.json" 400 65536
      else
        [ "$count" -le 6 ] || {
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
        if [ -e "$attempt_dir/child-timing.json" ] || [ -L "$attempt_dir/child-timing.json" ]; then
          assert_bounded_regular_file "$attempt_dir/child-timing.json" '400 600' 65536
        fi
        for entry in "$attempt_dir/child-timing.json.parts" "$attempt_dir/child-timing.json.tmp"; do
          if [ -e "$entry" ] || [ -L "$entry" ]; then assert_bounded_regular_file "$entry" 600 65536; fi
        done
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
      case "$name" in input.json|session.log|result.json|witness-[0-9][0-9][0-9][0-9].json) ;; *)
        echo "release fixture-session contains an unexpected entry: $session/$name" >&2
        return 3 ;;
      esac
      count=$((count + 1))
    done
    if [ "$mode" = 500 ]; then
      [ "$count" -ge 4 ] || { echo "sealed release fixture-session is incomplete: $session" >&2; return 3; }
      assert_bounded_regular_file "$session_dir/input.json" 400 65536
      assert_bounded_regular_file "$session_dir/session.log" 400 134217728
      assert_bounded_regular_file "$session_dir/result.json" 400 65536
      for entry in "$session_dir"/witness-*.json; do
        [ -e "$entry" ] || continue
        assert_bounded_regular_file "$entry" 400 65536
      done
    else
      for entry in "$session_dir"/*; do
        [ -e "$entry" ] || continue
        case "$(basename -- "$entry")" in
          session.log) assert_bounded_regular_file "$entry" '400 600' 134217728 ;;
          *) assert_bounded_regular_file "$entry" '400 600' 65536 ;;
        esac
      done
    fi
  done
}

session_witnesses_valid() {
  local directory=$1 file sha
  while IFS=$'\t' read -r file sha; do
    [ -f "$directory/$file" ] && [ ! -L "$directory/$file" ] && [ "$(sha256_file "$directory/$file")" = "$sha" ] || return 1
  done < <(jq -r '.witnesses[] | [.file,.sha256] | @tsv' "$directory/result.json")
}

find_reusable_fixture_session() {
  local root="$evidence_dir/$fixture_sessions_directory_name" directory input_sha log_sha file sha
  for directory in "$root"/session-*; do
    [ -d "$directory" ] && [ ! -L "$directory" ] && [ "$(path_mode "$directory")" = 500 ] || continue
    input_sha=$(sha256_file "$directory/input.json")
    log_sha=$(sha256_file "$directory/session.log")
    jq -e --arg source_commit "$current_source_commit" --arg release_version "$current_release_version" \
      --arg source_tree "$current_source_tree_sha256" --arg registry "$stage_registry_sha256" --arg lima "$lab_image_digest" '
      .schema_version == 2 and .phase == "vm" and .source_commit == $source_commit and
      .release_version == $release_version and .source_tree_sha256 == $source_tree and
      .stage_registry_sha256 == $registry and .lima_image_digest == $lima and
      (.pending_stages | type == "array") and .transport_supervision_gateway_restart_exception == 1
    ' "$directory/input.json" >/dev/null 2>&1 || continue
    jq -e --arg source_commit "$current_source_commit" --arg release_version "$current_release_version" \
      --arg registry "$stage_registry_sha256" --arg input_sha "$input_sha" --arg log_sha "$log_sha" '
      .schema_version == 2 and .status == "passed" and .exit_code == 0 and
      .source_commit == $source_commit and .release_version == $release_version and
      .stage_registry_sha256 == $registry and .input_sha256 == $input_sha and .log_sha256 == $log_sha and
      (.witnesses | type == "array" and length > 0 and all(.[];
        keys == ["file","sha256"] and (.file | test("^witness-[0-9]{4}[.]json$")) and (.sha256 | test("^[0-9a-f]{64}$")))) and
      (.timings | keys == ["cleanup_ms","execution_ms","shutdown_ms","startup_ms","total_ms","witness_ms"] and
        all(.[]; type == "number" and floor == . and . >= 0))
    ' "$directory/result.json" >/dev/null 2>&1 || continue
    session_witnesses_valid "$directory" || continue
    basename -- "$directory"
    return 0
  done
  return 1
}

witness_sha_exists() {
  local expected=$1 session witness
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || return 1
  for session in "$evidence_dir/$fixture_sessions_directory_name"/session-*; do
    [ -d "$session" ] && [ ! -L "$session" ] || continue
    for witness in "$session"/witness-*.json; do
      [ -f "$witness" ] && [ ! -L "$witness" ] && [ "$(path_mode "$witness")" = 400 ] || continue
      [ "$(sha256_file "$witness")" = "$expected" ] && return 0
    done
  done
  return 1
}

find_reusable_attempt() {
  local stage=$1 stage_dir="$evidence_dir/$attempts_directory_name/$1" attempt_dir attempt contract input_sha log_sha child_sha lima_digest=
  local dependencies artifact_path artifact_sha pre_witness post_witness
  [ -d "$stage_dir" ] && [ ! -L "$stage_dir" ] || return 1
  contract=$(stage_contract_sha256 "$stage")
  dependencies=$(stage_dependencies_json "$stage") || return 1
  if stage_uses_lima "$stage"; then lima_digest=$lab_image_digest; fi
  for attempt_dir in "$stage_dir"/attempt-*; do
    [ -d "$attempt_dir" ] && [ ! -L "$attempt_dir" ] && [ "$(path_mode "$attempt_dir")" = 500 ] || continue
    attempt=$(basename -- "$attempt_dir")
    input_sha=$(sha256_file "$attempt_dir/input.json")
    log_sha=$(sha256_file "$attempt_dir/output.log")
    child_sha=$(sha256_file "$attempt_dir/child-timing.json")
    if jq -e --arg stage "$stage" --arg attempt "$attempt" --arg source_commit "$current_source_commit" \
      --arg release_version "$current_release_version" --arg source_tree "$current_source_tree_sha256" \
      --arg contract "$contract" --arg lima "$lima_digest" --arg registry "$stage_registry_sha256" \
      --argjson dependencies "$dependencies" '
        .schema_version == 2 and .stage == $stage and .attempt == $attempt and
        .source_commit == $source_commit and .release_version == $release_version and
        .source_tree_sha256 == $source_tree and .contract_sha256 == $contract and .stage_registry_sha256 == $registry and
        .dependencies == $dependencies and
        (($lima == "" and .pre_clean_witness_sha256 == null) or (.pre_clean_witness_sha256 | test("^[0-9a-f]{64}$"))) and
        (($lima == "" and .lima_image_digest == null) or .lima_image_digest == $lima)
      ' "$attempt_dir/input.json" >/dev/null 2>&1 &&
      jq -e --arg stage "$stage" --arg attempt "$attempt" --arg source_commit "$current_source_commit" \
        --arg release_version "$current_release_version" --arg contract "$contract" --arg input_sha "$input_sha" \
        --arg log_sha "$log_sha" --arg child_sha "$child_sha" --arg lima "$lima_digest" --argjson dependencies "$dependencies" '
          .schema_version == 2 and .stage == $stage and .attempt == $attempt and .status == "passed" and
          .exit_code == 0 and .source_commit == $source_commit and .release_version == $release_version and
          .contract_sha256 == $contract and .input_sha256 == $input_sha and .log_sha256 == $log_sha and
          .child_timing_sha256 == $child_sha and .dependencies == $dependencies and
          (($lima == "" and .post_clean_witness_sha256 == null) or (.post_clean_witness_sha256 | test("^[0-9a-f]{64}$"))) and
          (.timings | type == "object" and all(.[]; type == "number" and floor == . and . >= 0)) and
          (($lima == "" and .lima_image_digest == null) or .lima_image_digest == $lima)
        ' "$attempt_dir/result.json" >/dev/null 2>&1; then
      if stage_uses_lima "$stage"; then
        pre_witness=$(jq -er '.pre_clean_witness_sha256' "$attempt_dir/input.json")
        post_witness=$(jq -er '.post_clean_witness_sha256' "$attempt_dir/result.json")
        witness_sha_exists "$pre_witness" && witness_sha_exists "$post_witness" || continue
      fi
      if artifact_path=$(stage_artifact_summary "$stage" "$attempt" 2>/dev/null); then
        artifact_sha=$(sha256_file "$artifact_path" 2>/dev/null || true)
        [ -n "$artifact_sha" ] || continue
        jq -e --arg path "$artifact_path" --arg sha "$artifact_sha" \
          '.artifact == {summary_path:$path,summary_sha256:$sha}' "$attempt_dir/result.json" >/dev/null 2>&1 || continue
      fi
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

capture_clean_witness() {
  local started finished witness_path status
  fixture_witness_number=$((fixture_witness_number + 1))
  printf -v witness_path '%s/witness-%04d.json' "$fixture_session_directory" "$fixture_witness_number"
  started=$(monotonic_ms)
  set +e
  "$clean_state_witness" capture "$witness_path" >> "$fixture_session_log" 2>&1
  status=$?
  set -e
  finished=$(monotonic_ms)
  fixture_session_witness_ms=$((fixture_session_witness_ms + $(elapsed_ms "$started" "$finished")))
  [ "$status" -eq 0 ] || return "$status"
  current_post_witness_sha256=$(sha256_file "$witness_path")
  printf 'clean-state witness passed: %s\n' "$(basename -- "$witness_path")" >> "$fixture_session_log"
}

run_stage_cleanup_adapter() {
  local stage=$1 adapter started finished status
  adapter=$(stage_record "$stage" | jq -r '.cleanup_adapter // empty')
  [ -n "$adapter" ] || return 1
  started=$(monotonic_ms)
  set +e
  (cd "$repository_root" && bash -c "$adapter") >> "$current_attempt_directory/output.log" 2>&1
  status=$?
  set -e
  finished=$(monotonic_ms)
  current_stage_cleanup_ms=$(elapsed_ms "$started" "$finished")
  fixture_session_cleanup_ms=$((fixture_session_cleanup_ms + current_stage_cleanup_ms))
  current_stage_cleanup_exit_code=$status
  return "$status"
}

run_stage_attempt() {
  local stage=$1 reused command contract started_at finished_at exit_status status input_sha log_sha child_sha
  local lima_digest= dependencies validation_start validation_end execution_start execution_end validation_ms execution_ms
  local witness_ms=0 witness_start witness_end artifact_path= artifact_sha= artifact_json=null child_producer=parent-command-wrapper timing_scratch
  current_stage_cleanup_ms=0
  current_stage_cleanup_exit_code=null
  if reused=$(find_reusable_attempt "$stage"); then
    printf 'reusing release gate: %s (%s)\n' "$stage" "$reused"
    return 0
  fi
  validation_start=$(monotonic_ms)
  allocate_attempt "$stage"
  command=$(stage_command_contract "$stage")
  contract=$(stage_contract_sha256 "$stage")
  dependencies=$(stage_dependencies_json "$stage")
  if stage_uses_lima "$stage"; then lima_digest=$lab_image_digest; fi
  started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  jq -n --arg stage "$stage" --arg attempt "$current_attempt_name" \
    --arg source_commit "$current_source_commit" --arg release_version "$current_release_version" \
    --arg source_tree "$current_source_tree_sha256" --arg command "$command" --arg contract "$contract" \
    --arg lima "$lima_digest" --arg started_at "$started_at" --arg registry "$stage_registry_sha256" \
    --arg pre_witness "$current_pre_witness_sha256" --argjson dependencies "$dependencies" '{
      schema_version: 2, stage: $stage, attempt: $attempt,
      source_commit: $source_commit, release_version: $release_version,
      source_tree_sha256: $source_tree, command: $command, contract_sha256: $contract,
      stage_registry_sha256: $registry, dependencies: $dependencies,
      lima_image_digest: (if $lima == "" then null else $lima end),
      pre_clean_witness_sha256: (if $pre_witness == "" then null else $pre_witness end), started_at: $started_at
    }' > "$current_attempt_directory/input.json"
  chmod 0400 "$current_attempt_directory/input.json"
  : > "$current_attempt_directory/output.log"
  chmod 0600 "$current_attempt_directory/output.log"
  validation_end=$(monotonic_ms)
  validation_ms=$(elapsed_ms "$validation_start" "$validation_end")
  printf 'running release gate: %s (%s)\n' "$stage" "$current_attempt_name"
  execution_start=$(monotonic_ms)
  set +e
  (umask 022; execute_stage "$stage" "$current_attempt_name") > "$current_attempt_directory/output.log" 2>&1
  exit_status=$?
  set -e
  execution_end=$(monotonic_ms)
  execution_ms=$(elapsed_ms "$execution_start" "$execution_end")
  fixture_session_execution_ms=$((fixture_session_execution_ms + execution_ms))
  for timing_scratch in "$current_attempt_directory/child-timing.json.parts" "$current_attempt_directory/child-timing.json.tmp"; do
    if [ -f "$timing_scratch" ] && [ ! -L "$timing_scratch" ]; then rm -f -- "$timing_scratch"; fi
  done
  if [ ! -e "$current_attempt_directory/child-timing.json" ] && [ ! -L "$current_attempt_directory/child-timing.json" ]; then
    jq -n --arg producer "$child_producer" --argjson execute_ms "$execution_ms" \
      '{schema_version:1,producer:$producer,phases:{execute_ms:$execute_ms}}' > "$current_attempt_directory/child-timing.json"
  fi
  if [ -L "$current_attempt_directory/child-timing.json" ] || ! jq -e '
    .schema_version == 1 and (.producer | type == "string" and length > 0 and length <= 64) and
    (.phases | type == "object" and length > 0 and all(.[]; type == "number" and floor == . and . >= 0))
  ' "$current_attempt_directory/child-timing.json" >/dev/null 2>&1; then
    printf '%s\n' 'stage emitted invalid child timing evidence' >> "$current_attempt_directory/output.log"
    exit_status=3
  fi
  if [ "$exit_status" -eq 0 ] && artifact_path=$(stage_artifact_summary "$stage" "$current_attempt_name" 2>/dev/null); then
    if [ ! -f "$artifact_path" ] || [ -L "$artifact_path" ]; then
      printf 'stage artifact summary is missing or unsafe: %s\n' "$artifact_path" >> "$current_attempt_directory/output.log"
      exit_status=3
    else
      artifact_sha=$(sha256_file "$artifact_path")
      artifact_json=$(jq -cn --arg path "$artifact_path" --arg sha "$artifact_sha" '{summary_path:$path,summary_sha256:$sha}')
    fi
  fi
  if stage_uses_lima "$stage"; then
    witness_start=$(monotonic_ms)
    current_post_witness_sha256=
    if ! capture_clean_witness; then
      printf '%s\n' 'post-stage clean-state witness failed; applying only the registered owner-scoped cleanup adapter' >> "$current_attempt_directory/output.log"
      run_stage_cleanup_adapter "$stage" || true
      current_post_witness_sha256=
      capture_clean_witness || true
      exit_status=4
    fi
    witness_end=$(monotonic_ms)
    witness_ms=$(elapsed_ms "$witness_start" "$witness_end")
  fi
  [ "$exit_status" -eq 0 ] && status=passed || status=failed
  finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  input_sha=$(sha256_file "$current_attempt_directory/input.json")
  log_sha=$(sha256_file "$current_attempt_directory/output.log")
  child_sha=$(sha256_file "$current_attempt_directory/child-timing.json")
  jq -n --arg stage "$stage" --arg attempt "$current_attempt_name" --arg status "$status" \
    --arg source_commit "$current_source_commit" --arg release_version "$current_release_version" \
    --arg contract "$contract" --arg input_sha "$input_sha" --arg log_sha "$log_sha" \
    --arg lima "$lima_digest" --arg started_at "$started_at" --arg finished_at "$finished_at" \
    --arg child_sha "$child_sha" --arg post_witness "$current_post_witness_sha256" \
    --argjson dependencies "$dependencies" --argjson artifact "$artifact_json" \
    --argjson validation_ms "$validation_ms" --argjson execution_ms "$execution_ms" \
    --argjson witness_ms "$witness_ms" --argjson cleanup_ms "$current_stage_cleanup_ms" \
    --argjson cleanup_exit_code "$current_stage_cleanup_exit_code" \
    --argjson exit_code "$exit_status" '{
      schema_version: 2, stage: $stage, attempt: $attempt, status: $status, exit_code: $exit_code,
      source_commit: $source_commit, release_version: $release_version, contract_sha256: $contract,
      lima_image_digest: (if $lima == "" then null else $lima end),
      input_sha256: $input_sha, log_sha256: $log_sha, child_timing_sha256: $child_sha,
      dependencies: $dependencies, artifact: $artifact,
      post_clean_witness_sha256: (if $post_witness == "" then null else $post_witness end),
      cleanup_adapter_exit_code: $cleanup_exit_code,
      timings: {validation_ms:$validation_ms,execution_ms:$execution_ms,witness_ms:$witness_ms,cleanup_ms:$cleanup_ms},
      started_at: $started_at, finished_at: $finished_at
    }' > "$current_attempt_directory/result.json"
  chmod 0400 "$current_attempt_directory/input.json" "$current_attempt_directory/output.log" \
    "$current_attempt_directory/child-timing.json" "$current_attempt_directory/result.json"
  chmod 0500 "$current_attempt_directory"
  current_pre_witness_sha256=$current_post_witness_sha256
  if [ "$exit_status" -ne 0 ]; then
    printf 'release gate stage failed: %s (%s)\n' "$stage" "$current_attempt_name" >&2
    printf 'inspect: %s/output.log\n' "$current_attempt_directory" >&2
    printf 'continue: scripts/v2deployed-release-gate.sh %s --resume %s\n' "$current_gate_command" "$evidence_dir" >&2
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
  local root="$evidence_dir/$fixture_sessions_directory_name" number=1 candidate pending_records pending_json
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
  fixture_session_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  fixture_session_started_mono=$(monotonic_ms)
  fixture_session_startup_ms=0
  fixture_session_execution_ms=0
  fixture_session_witness_ms=0
  fixture_session_cleanup_ms=0
  fixture_session_shutdown_ms=0
  fixture_witness_number=0
  pending_records=$(mktemp /private/tmp/vpnctl-v2-pending-stages.XXXXXX)
  for candidate in $vm_automated_stages; do
    if ! find_reusable_attempt "$candidate" >/dev/null; then jq -cn --arg value "$candidate" '$value' >> "$pending_records"; fi
  done
  pending_json=$(jq -sc '.' "$pending_records")
  rm -f -- "$pending_records"
  jq -n --arg source_commit "$current_source_commit" --arg release_version "$current_release_version" \
    --arg source_tree "$current_source_tree_sha256" --arg registry "$stage_registry_sha256" \
    --arg lima "$lab_image_digest" --arg started_at "$fixture_session_started_at" --argjson pending "$pending_json" '{
      schema_version:2,phase:"vm",source_commit:$source_commit,release_version:$release_version,
      source_tree_sha256:$source_tree,stage_registry_sha256:$registry,lima_image_digest:$lima,
      pending_stages:$pending,transport_supervision_gateway_restart_exception:1,started_at:$started_at
    }' > "$fixture_session_directory/input.json"
  chmod 0400 "$fixture_session_directory/input.json"
}

write_fixture_session_result() {
  local exit_status=$1 status=$2 finished_at finished_mono input_sha log_sha witnesses records total_ms
  [ -n "$fixture_session_directory" ] || return 0
  [ ! -e "$fixture_session_directory/result.json" ] && [ ! -L "$fixture_session_directory/result.json" ] || return 3
  finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  finished_mono=$(monotonic_ms)
  total_ms=$(elapsed_ms "$fixture_session_started_mono" "$finished_mono")
  input_sha=$(sha256_file "$fixture_session_directory/input.json")
  log_sha=$(sha256_file "$fixture_session_log")
  records=$(mktemp /private/tmp/vpnctl-v2-witness-records.XXXXXX)
  for witnesses in "$fixture_session_directory"/witness-*.json; do
    [ -f "$witnesses" ] || continue
    jq -cn --arg file "$(basename -- "$witnesses")" --arg sha "$(sha256_file "$witnesses")" \
      '{file:$file,sha256:$sha}' >> "$records"
  done
  witnesses=$(jq -sc '.' "$records")
  rm -f -- "$records"
  jq -n --arg status "$status" --arg source_commit "$current_source_commit" --arg release_version "$current_release_version" \
    --arg registry "$stage_registry_sha256" --arg input_sha "$input_sha" --arg log_sha "$log_sha" \
    --arg started_at "$fixture_session_started_at" --arg finished_at "$finished_at" --argjson witnesses "$witnesses" \
    --argjson exit_code "$exit_status" --argjson startup "$fixture_session_startup_ms" \
    --argjson execution "$fixture_session_execution_ms" --argjson witness "$fixture_session_witness_ms" \
    --argjson cleanup "$fixture_session_cleanup_ms" --argjson shutdown "$fixture_session_shutdown_ms" --argjson total "$total_ms" '{
      schema_version:2,status:$status,exit_code:$exit_code,source_commit:$source_commit,release_version:$release_version,
      stage_registry_sha256:$registry,input_sha256:$input_sha,log_sha256:$log_sha,witnesses:$witnesses,
      timings:{startup_ms:$startup,execution_ms:$execution,witness_ms:$witness,cleanup_ms:$cleanup,shutdown_ms:$shutdown,total_ms:$total},
      started_at:$started_at,finished_at:$finished_at
    }' > "$fixture_session_directory/result.json"
  chmod 0400 "$fixture_session_directory/result.json"
}

seal_fixture_session() {
  local status=0 entry witness_count=0
  if [ -n "$fixture_session_directory" ] && [ -d "$fixture_session_directory" ]; then
    if [ ! -e "$fixture_session_log" ] && [ ! -L "$fixture_session_log" ]; then
      : > "$fixture_session_log" || status=4
      chmod 0600 "$fixture_session_log" || status=4
    fi
    for entry in "$fixture_session_directory"/witness-*.json; do [ -f "$entry" ] && witness_count=$((witness_count + 1)); done
    if [ -f "$fixture_session_directory/input.json" ] && [ -f "$fixture_session_directory/result.json" ] && [ "$witness_count" -gt 0 ]; then
      chmod 0400 "$fixture_session_directory/input.json" "$fixture_session_log" \
        "$fixture_session_directory/result.json" "$fixture_session_directory"/witness-*.json || status=4
      chmod 0500 "$fixture_session_directory" || status=4
    fi
  fi
  fixture_session_directory=
  fixture_session_log=
  return "$status"
}

stop_started_fixtures() {
  local status=0 started finished
  started=$(monotonic_ms)
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
  finished=$(monotonic_ms)
  fixture_session_shutdown_ms=$((fixture_session_shutdown_ms + $(elapsed_ms "$started" "$finished")))
  return "$status"
}

cleanup_started_fixtures() {
  local status=${1:-1} cleanup_status=0
  trap - EXIT INT TERM
  set +e
  stop_started_fixtures || cleanup_status=$?
  if [ -n "$fixture_session_log" ]; then
    if ! assert_fixtures_stopped >> "$fixture_session_log" 2>&1; then
      restore_exact_fixtures_stopped >> "$fixture_session_log" 2>&1 || cleanup_status=4
    fi
  else
    assert_fixtures_stopped >/dev/null 2>&1 || cleanup_status=4
  fi
  if [ -n "$fixture_session_directory" ] && [ ! -e "$fixture_session_directory/result.json" ]; then
    write_fixture_session_result "$status" failed || cleanup_status=$?
  fi
  seal_fixture_session || cleanup_status=$?
  [ "$cleanup_status" -eq 0 ] || status=$cleanup_status
  exit "$status"
}

run_vm_stages() {
  local stage needed=false stage_status=0 cleanup_status=0 started finished
  for stage in $vm_automated_stages; do
    if ! find_reusable_attempt "$stage" >/dev/null; then needed=true; break; fi
  done
  if [ "$needed" != true ] && ! find_reusable_fixture_session >/dev/null; then needed=true; fi
  [ "$needed" = true ] || return 0
  assert_fixtures_stopped
  allocate_fixture_session
  trap 'cleanup_started_fixtures $?' EXIT
  trap 'cleanup_started_fixtures 130' INT
  trap 'cleanup_started_fixtures 143' TERM
  started=$(monotonic_ms)
  gateway_started=true
  limactl start "$gateway_instance" >> "$fixture_session_log" 2>&1
  assert_lab_instance "$gateway_instance" Running
  node_started=true
  limactl start "$node_instance" >> "$fixture_session_log" 2>&1
  assert_lab_instance "$node_instance" Running
  finished=$(monotonic_ms)
  fixture_session_startup_ms=$(elapsed_ms "$started" "$finished")
  current_post_witness_sha256=
  capture_clean_witness
  current_pre_witness_sha256=$current_post_witness_sha256
  for stage in $vm_automated_stages; do
    if run_stage_attempt "$stage"; then
      :
    else
      stage_status=$?
      stop_started_fixtures || cleanup_status=$?
      if ! assert_fixtures_stopped >> "$fixture_session_log" 2>&1; then
        restore_exact_fixtures_stopped >> "$fixture_session_log" 2>&1 || cleanup_status=4
      fi
      write_fixture_session_result "$stage_status" failed || cleanup_status=$?
      seal_fixture_session || cleanup_status=$?
      trap - EXIT INT TERM
      [ "$cleanup_status" -eq 0 ] || return "$cleanup_status"
      return "$stage_status"
    fi
  done
  stop_started_fixtures || cleanup_status=$?
  if ! assert_fixtures_stopped >> "$fixture_session_log" 2>&1; then
    restore_exact_fixtures_stopped >> "$fixture_session_log" 2>&1 || cleanup_status=4
  fi
  if [ "$cleanup_status" -eq 0 ]; then
    write_fixture_session_result 0 passed || cleanup_status=$?
  else
    write_fixture_session_result "$cleanup_status" failed || true
  fi
  seal_fixture_session || cleanup_status=$?
  trap - EXIT INT TERM
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

phase_attempt_ledger_has_entries() {
  local phase=$1 stage stage_dir attempt_dir
  for stage in $( [ "$phase" = fast ] && printf '%s\n' "$fast_automated_stages" || printf '%s\n' "$vm_automated_stages" ); do
    stage_dir="$evidence_dir/$attempts_directory_name/$stage"
    [ -d "$stage_dir" ] && [ ! -L "$stage_dir" ] || continue
    for attempt_dir in "$stage_dir"/*; do
      [ -e "$attempt_dir" ] || [ -L "$attempt_dir" ] || continue
      return 0
    done
  done
  return 1
}

phase_is_complete() {
  local phase=$1 stage stages
  [ "$phase" = fast ] && stages=$fast_automated_stages || stages=$vm_automated_stages
  for stage in $stages; do find_reusable_attempt "$stage" >/dev/null || return 1; done
}

aggregate_automated_evidence() {
  local records output attempts_json stage attempt attempt_dir result_sha
  assert_fixtures_stopped
  find_reusable_fixture_session >/dev/null || {
    echo "mandatory release gate has no reusable passing VM session" >&2
    return 3
  }
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

initialize_automated_gate() {
  assert_clean_source
  assert_only_deployed_task_pending
  validate_stage_registry
  assert_evidence_directory "$evidence_dir"
  assert_candidate
  assert_attempt_ledger
  assert_fixture_session_ledger
  current_source_commit=$(candidate_value '.source_commit')
  current_release_version=$(candidate_value '.release_version')
  current_source_tree_sha256=$(source_tree_sha256)
  current_short_commit=${current_source_commit:0:7}
  current_run_id=$(basename -- "$evidence_dir")
}

run_automated_gate() {
  local mode=$1 resume=$2 stage stages phase
  initialize_automated_gate
  if [ -e "$evidence_dir/automated.json" ] || [ -L "$evidence_dir/automated.json" ]; then
    if [ "$resume" = true ] && assert_private_regular_file "$evidence_dir/automated.json" &&
       assert_automated_evidence; then
      printf 'automated release evidence already complete: %s\n' "$evidence_dir/automated.json"
      return 0
    fi
    echo "deployed release gate refuses to replace automated evidence" >&2
    return 3
  fi
  if [ "$mode" = automated ]; then
    if [ "$resume" != true ] && attempt_ledger_has_entries; then
      echo "automated attempts already exist; continue explicitly with run-automated --resume" >&2
      return 3
    fi
  else
    phase=$mode
    if phase_is_complete "$phase" && { [ "$phase" != vm ] || find_reusable_fixture_session >/dev/null; }; then
      printf 'release gate phase already complete: %s\n' "$phase"
      [ "$phase" = vm ] && aggregate_automated_evidence
      return 0
    fi
    if [ "$resume" != true ] && phase_attempt_ledger_has_entries "$phase"; then
      echo "$phase attempts already exist; continue explicitly with run-$phase --resume" >&2
      return 3
    fi
  fi
  if [ "$mode" = fast ] || [ "$mode" = automated ]; then
    current_gate_command=$( [ "$mode" = automated ] && printf run-automated || printf run-fast )
    for stage in $fast_automated_stages; do run_stage_attempt "$stage"; done
  fi
  [ "$mode" = fast ] && return 0
  for stage in $fast_automated_stages; do
    find_reusable_attempt "$stage" >/dev/null || {
      echo "run-vm requires complete reusable fast-phase evidence: $stage" >&2
      return 3
    }
  done
  current_gate_command=$( [ "$mode" = automated ] && printf run-automated || printf run-vm )
  assert_fixtures_stopped
  run_vm_stages
  aggregate_automated_evidence
}

run_phase_command() {
  local mode=$1
  shift
  if [ "$#" -eq 1 ]; then
    evidence_dir=$1
    run_automated_gate "$mode" false
  elif [ "$#" -eq 2 ] && [ "$1" = --resume ]; then
    evidence_dir=$2
    run_automated_gate "$mode" true
  else
    usage >&2
    return 2
  fi
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
  find_reusable_fixture_session >/dev/null || {
    echo "automated release evidence has no reusable passing VM session" >&2
    return 3
  }
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
  validate_stage_registry
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
  run-fast) shift; run_phase_command fast "$@" ;;
  run-vm) shift; run_phase_command vm "$@" ;;
  run-automated) shift; run_phase_command automated "$@" ;;
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
