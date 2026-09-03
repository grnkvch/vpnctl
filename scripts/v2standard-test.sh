#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
fixture_root="$repository_root/test/v2lab/standard"
backend_path="$repository_root/test/v2lab/routing/backend.py"
probe_path="$repository_root/test/v2lab/routing/probe.py"
node_instance=vpnctl-v2-node
runtime_root=/tmp/vpnctl-v2-standard-test
owner_value=vpnctl-v2-standard-test-v1
owner_path="$runtime_root/.owner"
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
firewall_artifact=
namespaces=(vpnctl-v2-wg-gateway vpnctl-v2-wg-network vpnctl-v2-wg-wan vpnctl-v2-wg-c1 vpnctl-v2-wg-c2 vpnctl-v2-wg-c3 vpnctl-v2-wg-c4 vpnctl-v2-wg-c5 vpnctl-v2-wg-n1 vpnctl-v2-wg-n2)

usage() {
  cat <<'EOF'
Usage:
  scripts/v2standard-test.sh verify
  scripts/v2standard-test.sh status
  scripts/v2standard-test.sh cleanup
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

assert_spikes_inactive() {
  local unit
  for unit in \
    vpnctl-v2-spike-routing-engine.service \
    vpnctl-v2-spike-routing-guard.service \
    vpnctl-v2-spike-restricted-node.service \
    vpnctl-v2-spike-tunnel-client.service \
    vpnctl-v2-spike-dns-node.service; do
    if guest systemctl is-active --quiet "$unit"; then
      echo "refusing standard namespace test while another node spike is active: $unit" >&2
      exit 3
    fi
  done
}

assert_owned_runtime() {
  if ! guest sudo test -f "$owner_path" || ! guest sudo grep -Fxq "$owner_value" "$owner_path"; then
    echo "refusing to operate on unowned standard test runtime: $runtime_root" >&2
    return 3
  fi
}

copy_input() {
  local source=$1 name=$2
  limactl copy --backend=scp "$source" "$node_instance:$runtime_root/$name"
}

create_runtime() {
  if guest test -e "$runtime_root"; then
    echo "standard test runtime already exists: $runtime_root" >&2
    exit 3
  fi
  guest install -d -m 0700 "$runtime_root"
  if ! guest sh -c "printf '%s\n' '$owner_value' > '$owner_path' && chmod 0600 '$owner_path'"; then
    guest rmdir "$runtime_root" >/dev/null 2>&1 || true
    return 1
  fi
}

render_firewall() {
  firewall_artifact=$(mktemp -t vpnctl-v2-standard-firewall)
  env GOCACHE=/private/tmp/vpnctl-go-cache go run ./test/v2lab/standard/render_firewall.go > "$firewall_artifact"
}

install_inputs() {
  copy_input "$fixture_root/namespace.sh" namespace.sh
  copy_input "$backend_path" backend.py
  copy_input "$probe_path" probe.py
  copy_input "$firewall_artifact" gateway.nft
  guest sudo chown root:root "$runtime_root" "$owner_path" \
    "$runtime_root/namespace.sh" "$runtime_root/backend.py" "$runtime_root/probe.py" "$runtime_root/gateway.nft"
  guest sudo chmod 0700 "$runtime_root"
  guest sudo chmod 0600 "$owner_path" "$runtime_root/gateway.nft"
  guest sudo chmod 0755 "$runtime_root/namespace.sh" "$runtime_root/backend.py" "$runtime_root/probe.py"
}

cleanup_local() {
  if [ -n "$firewall_artifact" ] && [ -f "$firewall_artifact" ]; then
    rm -f -- "$firewall_artifact"
  fi
  firewall_artifact=
}

cleanup_guest() {
  if guest test -e "$runtime_root"; then
    assert_owned_runtime
  else
    local existing=0 namespace
    for namespace in "${namespaces[@]}"; do
      if guest sudo ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
        existing=1
      fi
    done
    if [ "$existing" -ne 0 ]; then
      echo "refusing to delete standard namespaces without the owned runtime marker" >&2
      return 3
    fi
    return
  fi
  if guest sudo test -x "$runtime_root/namespace.sh"; then
    guest sudo "$runtime_root/namespace.sh" cleanup >/dev/null 2>&1 || true
  fi
  guest sudo rm -rf -- "$runtime_root"
}

cleanup_all() {
  cleanup_guest
  cleanup_local
}

verify() {
  assert_lab_instance
  assert_spikes_inactive
  env GOCACHE=/private/tmp/vpnctl-go-cache go test ./internal/transport ./internal/platform/linux -count=1
  trap cleanup_local EXIT INT TERM
  render_firewall
  create_runtime
  trap cleanup_all EXIT INT TERM
  install_inputs
  guest sudo "$runtime_root/namespace.sh" verify
  trap - EXIT INT TERM
  cleanup_all
}

status() {
  assert_lab_instance
  if guest sudo test -x "$runtime_root/namespace.sh"; then
    guest sudo "$runtime_root/namespace.sh" status
  else
    local namespace
    for namespace in "${namespaces[@]}"; do
      if guest sudo ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
        printf '%s=present\n' "$namespace"
      else
        printf '%s=absent\n' "$namespace"
      fi
    done
  fi
  if guest test -e "$runtime_root"; then
    if guest sudo test -f "$owner_path" && guest sudo grep -Fxq "$owner_value" "$owner_path"; then
      printf 'runtime=owned\n'
    else
      printf 'runtime=foreign\n'
    fi
  else
    printf 'runtime=absent\n'
  fi
}

case "${1:-}" in
  verify) verify ;;
  status) status ;;
  cleanup) assert_lab_instance; cleanup_all ;;
  *) usage; exit 2 ;;
esac
