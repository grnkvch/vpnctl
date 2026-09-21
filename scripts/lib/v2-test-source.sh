#!/bin/bash
# Source provenance for test harnesses. Never used to relax final qualification.

v2_test_source_revision() {
  local label=${1:-} context=${VPNCTL_V2_DEVELOPMENT_RUN:-} root
  root="$repository_root/artifacts/v2lab/development-runs"
  if [ -n "$context" ] && [ "$(dirname -- "$context")" = "$root" ]; then
    if [ ! -d "$context" ] || [ -L "$context" ] ||
       [ ! -f "$context/.owner" ] || [ -L "$context/.owner" ] ||
       [ "$(cat "$context/.owner")" != vpnctl-v2-development-run-v1 ]; then
      echo "invalid development source context" >&2
      return 3
    fi
    local file manifest_sha snapshot_sha
    for file in input.json inputs.json inputs.tar; do
      if [ ! -f "$context/$file" ] || [ -L "$context/$file" ]; then
        echo "development source context is incomplete" >&2
        return 3
      fi
    done
    manifest_sha=$(shasum -a 256 "$context/inputs.json" | awk '{print $1}')
    snapshot_sha=$(shasum -a 256 "$context/inputs.tar" | awk '{print $1}')
    jq -e --arg repository "$repository_root" --arg manifest "$manifest_sha" --arg snapshot "$snapshot_sha" '
      .schema_version == 1 and .mode == "development" and .production_ready == false and
      .repository == $repository and .source_commit == null and
      .inputs_sha256 == $manifest and .snapshot_sha256 == $snapshot
    ' "$context/input.json" >/dev/null || {
      echo "development input identity is invalid" >&2
      return 3
    }
    printf '%s\n' development
    return 0
  fi
  # A foreign repository's context is not authority over this checkout.
  if [ -n "$label" ] && [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    printf '%s requires a clean source tree\n' "$label" >&2
    return 3
  fi
  git rev-parse HEAD
}
