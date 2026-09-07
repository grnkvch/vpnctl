#!/bin/bash
set -euo pipefail
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
manifest="$repository_root/test/v2lab/deployed-release-gate/clean-state.json"
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7

usage() {
  echo "Usage: scripts/v2release-clean-state.sh validate-manifest | capture <output.json>" >&2
}

monotonic_ms() {
  perl -MTime::HiRes=clock_gettime,CLOCK_MONOTONIC -e 'printf "%.0f\n", clock_gettime(CLOCK_MONOTONIC) * 1000'
}

elapsed_ms() {
  if [ "$2" -ge "$1" ]; then printf '%s\n' "$(( $2 - $1 ))"; else printf '0\n'; fi
}

validate_manifest() {
  jq -e '
    (keys == ["gateway", "node", "schema_version"]) and .schema_version == 1 and
    ([.gateway, .node] | all(.[];
      keys == ["interfaces_absent", "ip_rules_absent", "namespaces_absent", "nftables_absent", "packages_absent", "paths_absent", "process_prefixes_absent", "routes_absent", "tcp_ports_free", "udp_ports_free", "units_inactive"] and
      ([.paths_absent[], .process_prefixes_absent[]] | all(.[]; type == "string" and startswith("/") and length > 1 and length <= 256 and ((contains("*") or contains("?") or contains("..")) | not))) and
      ([.units_inactive[], .namespaces_absent[], .interfaces_absent[], .ip_rules_absent[], .routes_absent[], .packages_absent[]] | all(.[]; type == "string" and length > 0 and length <= 256 and test("^[A-Za-z0-9@_.:/= -]+$"))) and
      ([.tcp_ports_free[], .udp_ports_free[]] | all(.[]; type == "number" and floor == . and . > 0 and . < 65536)) and
      ([.nftables_absent[]] | all(.[]; keys == ["family", "table"] and (.family == "inet" or .family == "ip" or .family == "ip6") and (.table | test("^[A-Za-z0-9_]{1,64}$")))) and
      ([.paths_absent, .units_inactive, .process_prefixes_absent, .tcp_ports_free, .udp_ports_free, .namespaces_absent, .nftables_absent, .interfaces_absent, .ip_rules_absent, .routes_absent, .packages_absent] | all(.[]; length == (unique | length)))
    ))
  ' "$manifest" >/dev/null
}

instance_json() {
  limactl list --json | jq -ce --arg name "$1" 'select(.name == $name)'
}

assert_running_fixture() {
  instance_json "$1" | jq -e --arg digest "$lab_image_digest" --arg instance "$1" '
    .status == "Running" and .vmType == "qemu" and .arch == "x86_64" and
    .cpus == (if $instance == "vpnctl-v2-node" then 4 else 1 end) and
    .memory == (if $instance == "vpnctl-v2-node" then 2147483648 else 536870912 end) and
    .disk == 10737418240 and
    .config.images[0].digest == $digest and any(.network[]?; .lima == "user-v2")
  ' >/dev/null
}

guest_check() {
  local instance=$1 role=$2 spec
  spec=$(jq -c --arg role "$role" '.[$role]' "$manifest" | base64 | tr -d '\n')
  limactl shell --tty=false "$instance" -- env VPNCTL_CLEAN_SPEC="$spec" bash -c '
    set -euo pipefail
    spec=$(printf "%s" "$VPNCTL_CLEAN_SPEC" | base64 -d)
    fail() { printf "clean-state residue: %s\n" "$1" >&2; exit 3; }
    unknown_owner=$(sudo find /etc /run /var/lib /tmp /opt /usr/local/libexec -xdev -type f \( -name .owner -o -name .watchdog-test-owner \) -size -4096c -exec grep -Il "^vpnctl-v2-" {} + 2>/dev/null | head -n 1 || true)
    [ -z "$unknown_owner" ] || fail "owner-marker:$unknown_owner"
    while IFS= read -r value; do sudo test ! -e "$value" || fail "path:$value"; done < <(jq -r ".paths_absent[]" <<<"$spec")
    while IFS= read -r value; do systemctl is-active --quiet "$value" && fail "unit:$value" || true; done < <(jq -r ".units_inactive[]" <<<"$spec")
    while IFS= read -r value; do
      for executable in /proc/[0-9]*/exe; do
        target=$(sudo readlink "$executable" 2>/dev/null || true)
        case "$target" in "$value"*) fail "process:$value" ;; esac
      done
    done < <(jq -r ".process_prefixes_absent[]" <<<"$spec")
    while IFS= read -r value; do sudo ss -H -ltn "sport = :$value" | grep -q . && fail "tcp:$value" || true; done < <(jq -r ".tcp_ports_free[]" <<<"$spec")
    while IFS= read -r value; do sudo ss -H -lun "sport = :$value" | grep -q . && fail "udp:$value" || true; done < <(jq -r ".udp_ports_free[]" <<<"$spec")
    while IFS= read -r value; do sudo ip netns list | cut -d " " -f 1 | grep -Fxq "$value" && fail "netns:$value" || true; done < <(jq -r ".namespaces_absent[]" <<<"$spec")
    while IFS=$'"'"'\t'"'"' read -r family table; do sudo nft list table "$family" "$table" >/dev/null 2>&1 && fail "nft:$family/$table" || true; done < <(jq -r ".nftables_absent[] | [.family,.table] | @tsv" <<<"$spec")
    while IFS= read -r value; do sudo ip link show dev "$value" >/dev/null 2>&1 && fail "interface:$value" || true; done < <(jq -r ".interfaces_absent[]" <<<"$spec")
    while IFS= read -r value; do sudo ip rule show | grep -Fqx "$value" && fail "rule:$value" || true; done < <(jq -r ".ip_rules_absent[]" <<<"$spec")
    while IFS= read -r value; do sudo ip route show table all | grep -Fqx "$value" && fail "route:$value" || true; done < <(jq -r ".routes_absent[]" <<<"$spec")
    while IFS= read -r value; do dpkg-query -W "$value" >/dev/null 2>&1 && fail "package:$value" || true; done < <(jq -r ".packages_absent[]" <<<"$spec")
  '
}

capture() {
  local output=$1 temporary started finished manifest_sha
  case "$output" in /*) ;; *) echo "clean-state output must be absolute" >&2; exit 2 ;; esac
  [ ! -e "$output" ] && [ ! -L "$output" ] || { echo "clean-state witness refuses to replace output" >&2; exit 3; }
  validate_manifest
  assert_running_fixture "$gateway_instance"
  assert_running_fixture "$node_instance"
  started=$(monotonic_ms)
  guest_check "$gateway_instance" gateway
  guest_check "$node_instance" node
  finished=$(monotonic_ms)
  manifest_sha=$(shasum -a 256 "$manifest" | awk '{print $1}')
  temporary=$(mktemp "$(dirname -- "$output")/.clean-state.XXXXXX")
  jq -n --arg manifest_sha "$manifest_sha" --arg digest "$lab_image_digest" --argjson duration "$(elapsed_ms "$started" "$finished")" '{
    schema_version: 1, status: "passed", manifest_sha256: $manifest_sha,
    lima_image_digest: $digest, fixtures: ["vpnctl-v2-gateway", "vpnctl-v2-node"],
    timings: {verification_ms: $duration}
  }' > "$temporary"
  chmod 0400 "$temporary"
  mv "$temporary" "$output"
}

case "${1:-}" in
  validate-manifest) [ "$#" -eq 1 ] || { usage; exit 2; }; validate_manifest ;;
  capture) [ "$#" -eq 2 ] || { usage; exit 2; }; capture "$2" ;;
  *) usage; exit 2 ;;
esac
