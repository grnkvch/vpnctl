#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
fixture_root="$repository_root/test/v2lab/personal"
gateway_instance=vpnctl-v2-gateway
guest_root=/tmp/vpnctl-v2-personal-client-e2e
guest_owner=$guest_root/.owner
guest_owner_value=vpnctl-v2-personal-client-input-v1
cache_archive="$repository_root/artifacts/v2lab/cache/mihomo-linux-amd64-v1.19.30.gz"
pinned_sha256=cf06ce2c7d1421bdbda14ee4a5b6046672dc35ebf8eecd8e77504ec3c0ed9a84
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
local_root=

namespaces=(vpnctl-v2-pc-net vpnctl-v2-pc-gw vpnctl-v2-pc-clash vpnctl-v2-pc-wg vpnctl-v2-pc-wan)

usage() {
  cat <<'EOF'
Usage:
  scripts/v2personal-client-test.sh verify
  scripts/v2personal-client-test.sh status
  scripts/v2personal-client-test.sh cleanup
EOF
}

instance_json() {
  limactl list --json | jq -ce --arg name "$1" 'select(.name == $name)'
}

assert_lab_instance() {
  if ! instance_json "$gateway_instance" | jq -e --arg digest "$lab_image_digest" '
    .status == "Running" and
    .vmType == "qemu" and
    .arch == "x86_64" and
    .cpus == 1 and
    .memory == 536870912 and
    .disk == 10737418240 and
    .config.images[0].digest == $digest and
    any(.network[]?; .lima == "user-v2")
  ' >/dev/null; then
    echo "required contract-matching lab instance is not running: $gateway_instance" >&2
    exit 4
  fi
}

guest() {
  limactl shell --tty=false "$gateway_instance" -- "$@"
}

assert_spikes_inactive() {
  local unit
  for unit in \
    vpnctl-v2-spike-routing-engine.service \
    vpnctl-v2-spike-routing-guard.service \
    vpnctl-v2-spike-restricted-gateway.service \
    vpnctl-v2-spike-tunnel-server.service \
    vpnctl-v2-spike-ingress.service; do
    if guest systemctl is-active --quiet "$unit"; then
      echo "refusing personal-client E2E while another gateway spike is active: $unit" >&2
      exit 3
    fi
  done
}

assert_cached_archive() {
  [ -f "$cache_archive" ] || {
    echo "pinned Mihomo archive cache is absent; run scripts/v2restricted-spike.sh prepare first" >&2
    exit 4
  }
  local actual
  actual=$(shasum -a 256 "$cache_archive" | awk '{print $1}')
  [ "$actual" = "$pinned_sha256" ] || {
    echo "cached Mihomo archive checksum does not match the pinned manifest" >&2
    exit 3
  }
}

local_is_owned() {
  [ -n "$local_root" ] && [ -d "$local_root" ] && [ ! -L "$local_root" ] &&
    [ -f "$local_root/.owner" ] && [ ! -L "$local_root/.owner" ] &&
    [ "$(tr -d '\n' < "$local_root/.owner")" = "$guest_owner_value" ]
}

create_local_fixture() {
  local_root=$(mktemp -d -t vpnctl-v2-personal-profiles.XXXXXX)
  printf '%s\n' "$guest_owner_value" > "$local_root/.owner"
  chmod 0600 "$local_root/.owner"
  env GOCACHE=/private/tmp/vpnctl-go-cache go run ./test/v2lab/personal --root "$local_root"
  gzip -dc "$cache_archive" > "$local_root/mihomo"
  chmod 0755 "$local_root/mihomo"
}

cleanup_local() {
  if [ -n "$local_root" ]; then
    if local_is_owned; then
      rm -rf -- "$local_root"
    elif [ -e "$local_root" ] || [ -L "$local_root" ]; then
      echo "refusing to remove unowned local personal-client fixture: $local_root" >&2
      return 3
    fi
  fi
  local_root=
}

guest_is_owned() {
  guest sudo test -d "$guest_root" &&
    guest sudo test ! -L "$guest_root" &&
    guest sudo test -f "$guest_owner" &&
    guest sudo grep -Fxq "$guest_owner_value" "$guest_owner"
}

guest_namespaces_present() {
  local namespace
  for namespace in "${namespaces[@]}"; do
    if guest sudo ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
      return 0
    fi
  done
  return 1
}

create_guest_root() {
  if guest test -e "$guest_root" || guest_namespaces_present; then
    echo "personal-client E2E guest resources already exist" >&2
    exit 3
  fi
  guest install -d -m 0700 "$guest_root"
  guest sh -c "printf '%s\\n' '$guest_owner_value' > '$guest_owner' && chmod 0600 '$guest_owner'"
}

copy_input() {
  local source=$1 name=$2
  limactl copy --backend=scp "$source" "$gateway_instance:$guest_root/$name"
}

install_inputs() {
  local clash_path wireguard_path
  clash_path=$(jq -er '.profiles.clash.path' "$local_root/fixture.json")
  wireguard_path=$(jq -er '.profiles.wireguard.path' "$local_root/fixture.json")
  copy_input "$fixture_root/happy_path.sh" happy_path.sh
  copy_input "$fixture_root/backend.py" backend.py
  copy_input "$local_root/fixture.json" fixture.json
  copy_input "$local_root/gateway.key" gateway.key
  copy_input "$local_root/mihomo" mihomo
  copy_input "$clash_path" iphone.clash.yaml
  copy_input "$wireguard_path" steamdeck.wireguard.conf
  guest sudo chown root:root \
    "$guest_root" "$guest_owner" "$guest_root/happy_path.sh" "$guest_root/backend.py" \
    "$guest_root/fixture.json" "$guest_root/gateway.key" "$guest_root/mihomo" \
    "$guest_root/iphone.clash.yaml" "$guest_root/steamdeck.wireguard.conf"
  guest sudo chmod 0700 "$guest_root"
  guest sudo chmod 0600 "$guest_owner" "$guest_root/fixture.json" "$guest_root/gateway.key" \
    "$guest_root/iphone.clash.yaml" "$guest_root/steamdeck.wireguard.conf"
  guest sudo chmod 0755 "$guest_root/happy_path.sh" "$guest_root/backend.py" "$guest_root/mihomo"
}

assert_scp_copies() {
  local kind local_path guest_path expected copied
  for kind in clash wireguard; do
    local_path=$(jq -er ".profiles.$kind.path" "$local_root/fixture.json")
    case "$kind" in
      clash) guest_path=$guest_root/iphone.clash.yaml ;;
      wireguard) guest_path=$guest_root/steamdeck.wireguard.conf ;;
    esac
    expected=$(shasum -a 256 "$local_path" | awk '{print $1}')
    copied=$(guest sudo sha256sum "$guest_path" | awk '{print $1}')
    [ "$copied" = "$expected" ] || {
      echo "$kind profile differs after SCP delivery" >&2
      exit 3
    }
  done
  local expected_mihomo copied_mihomo
  expected_mihomo=$(shasum -a 256 "$local_root/mihomo" | awk '{print $1}')
  copied_mihomo=$(guest sudo sha256sum "$guest_root/mihomo" | awk '{print $1}')
  [ "$copied_mihomo" = "$expected_mihomo" ] || {
    echo "pinned Mihomo differs after SCP delivery" >&2
    exit 3
  }
}

cleanup_guest() {
  if guest test -e "$guest_root"; then
    guest_is_owned || {
      echo "refusing to remove unowned personal-client guest fixture: $guest_root" >&2
      return 3
    }
    if guest sudo test -x "$guest_root/happy_path.sh"; then
      guest sudo "$guest_root/happy_path.sh" cleanup >/dev/null 2>&1 || return $?
    elif guest_namespaces_present; then
      echo "refusing to remove namespaces without the owned cleanup harness" >&2
      return 3
    fi
    guest sudo rm -rf -- "$guest_root"
  elif guest_namespaces_present; then
    echo "refusing to remove personal-client namespaces without the owned input tree" >&2
    return 3
  fi
}

cleanup_all() {
  cleanup_guest
  cleanup_local
}

verify() {
  assert_lab_instance
  assert_spikes_inactive
  assert_cached_archive
  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/routing ./test/v2lab/personal -count=1
  trap cleanup_local EXIT INT TERM
  create_local_fixture
  create_guest_root
  trap cleanup_all EXIT INT TERM
  install_inputs
  assert_scp_copies
  guest sudo "$guest_root/happy_path.sh" verify
  trap - EXIT INT TERM
  cleanup_all
}

status() {
  assert_lab_instance
  if guest sudo test -x "$guest_root/happy_path.sh"; then
    guest sudo "$guest_root/happy_path.sh" status
  else
    local namespace present
    for namespace in "${namespaces[@]}"; do
      present=false
      guest sudo ip netns list | awk '{print $1}' | grep -Fxq "$namespace" && present=true
      printf '%s=%s\n' "$namespace" "$present"
    done
  fi
  if guest test -e "$guest_root"; then
    if guest_is_owned; then
      printf 'input_runtime=owned\n'
    else
      printf 'input_runtime=foreign\n'
    fi
  else
    printf 'input_runtime=absent\n'
  fi
}

case "${1:-}" in
  verify) verify ;;
  status) status ;;
  cleanup) assert_lab_instance; cleanup_all ;;
  *) usage; exit 2 ;;
esac
