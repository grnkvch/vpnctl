#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
node_instance=vpnctl-v2-node
namespace=vpnctl-v2-restricted
runtime_root=/tmp/vpnctl-v2-restricted-test
owner_value=vpnctl-v2-restricted-test-v1
owner_path="$runtime_root/.owner"
cache_archive="$repository_root/artifacts/v2lab/cache/mihomo-linux-amd64-v1.19.30.gz"
pinned_sha256=cf06ce2c7d1421bdbda14ee4a5b6046672dc35ebf8eecd8e77504ec3c0ed9a84
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
local_test_binary=
local_mihomo_binary=

usage() {
  cat <<'EOF'
Usage:
  scripts/v2restricted-test.sh verify
  scripts/v2restricted-test.sh status
  scripts/v2restricted-test.sh cleanup
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

guest() {
  limactl shell --tty=false "$node_instance" -- "$@"
}

assert_cached_archive() {
  if [ ! -f "$cache_archive" ]; then
    echo "pinned Mihomo archive cache is absent; run scripts/v2restricted-spike.sh prepare first" >&2
    exit 4
  fi
  local actual
  actual=$(shasum -a 256 "$cache_archive" | awk '{print $1}')
  if [ "$actual" != "$pinned_sha256" ]; then
    echo "cached Mihomo archive checksum does not match the pinned manifest" >&2
    exit 3
  fi
}

assert_owned_runtime() {
  if ! guest sudo test -f "$owner_path" || ! guest sudo grep -Fxq "$owner_value" "$owner_path"; then
    echo "refusing to operate on unowned restricted test runtime: $runtime_root" >&2
    return 3
  fi
}

create_runtime() {
  if guest test -e "$runtime_root"; then
    echo "restricted test runtime already exists: $runtime_root" >&2
    exit 3
  fi
  if guest sudo ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
    echo "restricted test namespace already exists without an owned runtime: $namespace" >&2
    exit 3
  fi
  guest install -d -m 0700 "$runtime_root"
  if ! guest sh -c "printf '%s\n' '$owner_value' > '$owner_path' && chmod 0600 '$owner_path'"; then
    guest rmdir "$runtime_root" >/dev/null 2>&1 || true
    return 1
  fi
}

build_test_binary() {
  local_test_binary=$(mktemp -t vpnctl-v2-restricted-test)
  env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOCACHE=/private/tmp/vpnctl-go-cache \
    go test -c -o "$local_test_binary" ./internal/transport
}

build_mihomo_binary() {
  local_mihomo_binary=$(mktemp -t vpnctl-v2-restricted-mihomo)
  gzip -dc "$cache_archive" > "$local_mihomo_binary"
  chmod 0755 "$local_mihomo_binary"
}

copy_input() {
  local source=$1 name=$2
  limactl copy --backend=scp "$source" "$node_instance:$runtime_root/$name"
}

install_inputs() {
  copy_input "$local_test_binary" transport.test
  copy_input "$local_mihomo_binary" mihomo
  guest sudo chown root:root "$runtime_root" "$owner_path" "$runtime_root/transport.test" "$runtime_root/mihomo"
  guest sudo chmod 0700 "$runtime_root"
  guest sudo chmod 0600 "$owner_path"
  guest sudo chmod 0755 "$runtime_root/transport.test" "$runtime_root/mihomo"
  local local_sha256 guest_sha256
  local_sha256=$(shasum -a 256 "$local_mihomo_binary" | awk '{print $1}')
  guest_sha256=$(guest sudo sha256sum "$runtime_root/mihomo" | awk '{print $1}')
  if [ "$guest_sha256" != "$local_sha256" ]; then
    echo "copied Mihomo binary differs from the verified archive payload" >&2
    exit 3
  fi
}

cleanup_local() {
  if [ -n "$local_test_binary" ] && [ -f "$local_test_binary" ]; then
    rm -f -- "$local_test_binary"
  fi
  if [ -n "$local_mihomo_binary" ] && [ -f "$local_mihomo_binary" ]; then
    rm -f -- "$local_mihomo_binary"
  fi
  local_test_binary=
  local_mihomo_binary=
}

cleanup_guest() {
  local namespace_exists=0
  if guest sudo ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
    namespace_exists=1
  fi
  if guest test -e "$runtime_root"; then
    assert_owned_runtime
  elif [ "$namespace_exists" -ne 0 ]; then
    echo "refusing to delete restricted namespace without the owned runtime marker" >&2
    return 3
  else
    return
  fi
  if [ "$namespace_exists" -ne 0 ]; then
    local pid
    for pid in $(guest sudo ip netns pids "$namespace"); do
      guest sudo kill -TERM "$pid" >/dev/null 2>&1 || true
    done
    guest sudo ip netns delete "$namespace"
  fi
  guest sudo rm -rf -- "$runtime_root"
}

cleanup_all() {
  cleanup_guest
  cleanup_local
}

verify() {
  assert_lab_instance
  assert_cached_archive
  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/transport ./internal/platform/linux ./internal/cli -count=1
  trap cleanup_local EXIT INT TERM
  build_test_binary
  build_mihomo_binary
  create_runtime
  trap cleanup_all EXIT INT TERM
  install_inputs
  guest sudo ip netns add "$namespace"
  guest sudo ip netns exec "$namespace" ip link set lo up
  guest sudo ip netns exec "$namespace" env \
    VPNCTL_PINNED_MIHOMO="$runtime_root/mihomo" \
    VPNCTL_RESTRICTED_SOCKET_TEST=1 \
    "$runtime_root/transport.test" -test.v -test.run '^TestRestrictedPinnedMihomoConfigAndSocketContract$'
  trap - EXIT INT TERM
  cleanup_all
}

status() {
  assert_lab_instance
  if guest sudo ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
    printf 'namespace=%s\n' present
  else
    printf 'namespace=%s\n' absent
  fi
  if guest test -e "$runtime_root"; then
    if guest sudo test -f "$owner_path" && guest sudo grep -Fxq "$owner_value" "$owner_path"; then
      printf 'runtime=%s\n' owned
    else
      printf 'runtime=%s\n' foreign
    fi
  else
    printf 'runtime=%s\n' absent
  fi
}

case "${1:-}" in
  verify) verify ;;
  status) status ;;
  cleanup) assert_lab_instance; cleanup_all ;;
  *) usage; exit 2 ;;
esac
