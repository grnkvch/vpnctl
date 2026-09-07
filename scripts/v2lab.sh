#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
gateway_template="$repository_root/test/v2lab/lima.yaml"
node_template="$repository_root/test/v2lab/lima-node.yaml"
fixture_contract="$repository_root/test/v2lab/fixtures.json"
guest_report="$repository_root/test/v2lab/guest/report.sh"
guest_fault="$repository_root/test/v2lab/guest/fault.sh"
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7

usage() {
  cat <<'EOF'
Usage:
  scripts/v2lab.sh up [report-directory]
  scripts/v2lab.sh report [report-directory]
  scripts/v2lab.sh fault <gateway|node> <latency|loss> <value>
  scripts/v2lab.sh fault <gateway|node> <partition|clear>
  scripts/v2lab.sh shell <gateway|node>
  scripts/v2lab.sh down
  scripts/v2lab.sh destroy
EOF
}

instance_for_role() {
  case "$1" in
    gateway) printf '%s\n' "$gateway_instance" ;;
    node) printf '%s\n' "$node_instance" ;;
    *) echo "unknown lab role: $1" >&2; exit 2 ;;
  esac
}

peer_role() {
  case "$1" in
    gateway) printf '%s\n' node ;;
    node) printf '%s\n' gateway ;;
    *) echo "unknown lab role: $1" >&2; exit 2 ;;
  esac
}

instance_exists() {
  limactl list --json | jq -e --arg name "$1" 'select(.name == $name)' >/dev/null
}

instance_json() {
  limactl list --json | jq -ce --arg name "$1" 'select(.name == $name)'
}

assert_instance_contract() {
  local instance=$1 role cpus memory disk json probe_mode probe_description probe_hint expected_probe_sha live_probe_sha
  role=$(role_for_instance "$instance")
  cpus=$(jq -er --arg role "$role" '.roles[$role].cpus' "$fixture_contract")
  memory=$(jq -er --arg role "$role" '.roles[$role].memory_bytes' "$fixture_contract")
  disk=$(jq -er --arg role "$role" '.roles[$role].disk_bytes' "$fixture_contract")
  json=$(instance_json "$instance") || {
    echo "refusing to operate on absent or ambiguous Lima instance: $instance" >&2
    exit 3
  }
  if ! printf '%s\n' "$json" | jq -e --arg digest "$image_digest" \
    --argjson cpus "$cpus" --argjson memory "$memory" --argjson disk "$disk" '
    .vmType == "qemu" and
    .arch == "x86_64" and
    .cpus == $cpus and
    .memory == $memory and
    .disk == $disk and
    .config.images[0].digest == $digest and
    any(.network[]?; .lima == "user-v2")
  ' >/dev/null; then
    echo "refusing to operate on non-lab or drifted Lima instance: $instance" >&2
    exit 3
  fi
  probe_mode=$(jq -er --arg role "$role" '.roles[$role].readiness_probe.mode' "$fixture_contract")
  probe_description=$(jq -er --arg role "$role" '.roles[$role].readiness_probe.description' "$fixture_contract")
  probe_hint=$(jq -er --arg role "$role" '.roles[$role].readiness_probe.hint' "$fixture_contract")
  expected_probe_sha=$(jq -er --arg role "$role" '.roles[$role].readiness_probe.script_sha256' "$fixture_contract")
  if ! printf '%s\n' "$json" | jq -e --arg mode "$probe_mode" --arg description "$probe_description" --arg hint "$probe_hint" '
    (.config.probes | type == "array" and length == 1) and
    .config.probes[0].mode == $mode and .config.probes[0].description == $description and
    .config.probes[0].hint == $hint and (.config.probes[0].script | type == "string")
  ' >/dev/null; then
    echo "refusing to operate on Lima instance with a drifted readiness probe: $instance" >&2
    exit 3
  fi
  live_probe_sha=$(printf '%s\n' "$json" | jq -j '.config.probes[0].script' | shasum -a 256 | awk '{print $1}')
  if [ "$live_probe_sha" != "$expected_probe_sha" ]; then
    echo "refusing to operate on Lima instance with a drifted readiness probe: $instance" >&2
    exit 3
  fi
}

role_for_instance() {
  case "$1" in
    "$gateway_instance") printf '%s\n' gateway ;;
    "$node_instance") printf '%s\n' node ;;
    *) echo "unknown lab instance: $1" >&2; exit 2 ;;
  esac
}

template_for_instance() {
  case "$1" in
    "$gateway_instance") printf '%s\n' "$gateway_template" ;;
    "$node_instance") printf '%s\n' "$node_template" ;;
    *) echo "unknown lab instance: $1" >&2; exit 2 ;;
  esac
}

operate_existing_instances() {
  local operation=$1
  local instance
  local -a instances=()
  for instance in "$gateway_instance" "$node_instance"; do
    if instance_exists "$instance"; then
      assert_instance_contract "$instance"
      instances+=("$instance")
    fi
  done
  if [ "${#instances[@]}" -eq 0 ]; then
    echo "no vpnctl v2 lab instances exist"
    return
  fi
  if [ "$operation" = delete ]; then
    for instance in "${instances[@]}"; do
      if [ "$(instance_json "$instance" | jq -r '.status')" != Stopped ]; then
        echo "refusing to delete running lab instance; run down first: $instance" >&2
        exit 3
      fi
    done
  fi
  for instance in "${instances[@]}"; do
    limactl "$operation" "$instance"
  done
}

start_instance() {
  local instance=$1 template
  template=$(template_for_instance "$instance")
  if instance_exists "$instance"; then
    assert_instance_contract "$instance"
    limactl start --tty=false "$instance"
  else
    limactl start --tty=false --name "$instance" "$template"
  fi
}

install_helpers() {
  local instance=$1
  limactl copy --backend=scp "$guest_report" "$guest_fault" "$instance:/tmp/"
  limactl shell --tty=false "$instance" -- sudo install -D -m 0755 /tmp/report.sh /usr/local/libexec/vpnctl-v2-lab-report
  limactl shell --tty=false "$instance" -- sudo install -D -m 0755 /tmp/fault.sh /usr/local/libexec/vpnctl-v2-lab-fault
}

lab_ip() {
  local instance=$1
  limactl shell --tty=false "$instance" -- ip -4 -o address show scope global | awk '$4 ~ /^192[.]168[.]104[.]/ {sub(/\/.*/, "", $4); print $4; exit}'
}

report_lab() {
  local output_dir=$1
  local gateway_ip node_ip
  assert_instance_contract "$gateway_instance"
  assert_instance_contract "$node_instance"
  gateway_ip=$(lab_ip "$gateway_instance")
  node_ip=$(lab_ip "$node_instance")
  if [ -z "$gateway_ip" ] || [ -z "$node_ip" ]; then
    echo "Lima user-v2 network addresses were not found" >&2
    exit 1
  fi
  mkdir -p "$output_dir"
  limactl shell --tty=false "$gateway_instance" -- sudo /usr/local/libexec/vpnctl-v2-lab-report gateway "$node_ip" > "$output_dir/gateway.json"
  limactl shell --tty=false "$node_instance" -- sudo /usr/local/libexec/vpnctl-v2-lab-report node "$gateway_ip" > "$output_dir/node.json"
  jq -s '{schema_version: 1, hosts: .}' "$output_dir/gateway.json" "$output_dir/node.json" > "$output_dir/summary.json"
  printf 'lab report: %s\n' "$output_dir/summary.json"
}

default_report_dir() {
  date -u +"$repository_root/artifacts/v2lab/%Y%m%dT%H%M%SZ"
}

command=${1:-}
case "$command" in
  up)
    output_dir=${2:-$(default_report_dir)}
    jq -e '
      .schema_version == 1 and .contract_version == 2 and
      .capacity_boundary_role == "gateway" and .load_generator_role == "node" and
      .roles.gateway == {
        instance:"vpnctl-v2-gateway", template:"test/v2lab/lima.yaml", cpus:1,
        memory_bytes:536870912, disk_bytes:10737418240, managed_swap_bytes:1073741824,
        readiness_probe:{mode:"readiness",description:"vpnctl v2 lab prerequisites",
          hint:"See /var/log/cloud-init-output.log in the guest",
          script_sha256:"ce5e71613d3acb6a85308f0ffdf34b26af36c70f01163f61db1cb59871243ae9"},
        normative_capacity_host:true
      } and
      .roles.node == {
        instance:"vpnctl-v2-node", template:"test/v2lab/lima-node.yaml", cpus:4,
        memory_bytes:2147483648, disk_bytes:10737418240, managed_swap_bytes:1073741824,
        readiness_probe:{mode:"readiness",description:"vpnctl v2 functional node prerequisites",
          hint:"See /var/log/cloud-init-output.log in the guest",
          script_sha256:"778c34b783efc3870044facf66b114cfae2686134fa007e1e44b1b69a8fcc143"},
        normative_capacity_host:false
      }
    ' "$fixture_contract" >/dev/null
    limactl template validate "$gateway_template"
    limactl template validate "$node_template"
    start_instance "$gateway_instance"
    start_instance "$node_instance"
    install_helpers "$gateway_instance"
    install_helpers "$node_instance"
    report_lab "$output_dir"
    ;;
  report)
    report_lab "${2:-$(default_report_dir)}"
    ;;
  fault)
    role=${2:-}
    action=${3:-}
    value=${4:-}
    instance=$(instance_for_role "$role")
    peer=$(peer_role "$role")
    peer_instance=$(instance_for_role "$peer")
    assert_instance_contract "$instance"
    assert_instance_contract "$peer_instance"
    peer_ip=$(lab_ip "$peer_instance")
    limactl shell --tty=false "$instance" -- sudo /usr/local/libexec/vpnctl-v2-lab-fault "$action" "$peer_ip" "$value"
    ;;
  shell)
    exec limactl shell "$(instance_for_role "${2:-}")"
    ;;
  down)
    operate_existing_instances stop
    ;;
  destroy)
    operate_existing_instances delete
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
