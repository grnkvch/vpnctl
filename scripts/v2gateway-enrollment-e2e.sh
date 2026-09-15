#!/bin/bash
set -Eeuo pipefail
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
artifact_root="$repository_root/artifacts/v2lab/gateway-enrollment-e2e"
pty_helper="$repository_root/test/v2lab/gateway-enrollment-e2e/pty_secret.py"
installer="$repository_root/scripts/install.sh"
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
gateway_public_ip=203.0.113.10
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
owner_value=vpnctl-v2-gateway-enrollment-e2e-v1
guest_root=/var/lib/vpnctl-v2-gateway-enrollment-e2e
guest_runtime="$guest_root/runtime"
secret_runtime=/run/vpnctl/gateway-enrollment-e2e
upload_root=/tmp/vpnctl-v2-gateway-enrollment-e2e-upload
gateway_started=false
node_started=false
gateway_underlay=
gateway_common_initial=
candidate_dir=
candidate_version=
candidate_binary_sha=
candidate_bundle_sha=
candidate_metadata_sha=
installer_sha=
helper_sha=
run_root=
current_phase=source-preflight

usage() {
  cat <<'EOF'
Usage:
  scripts/v2gateway-enrollment-e2e.sh verify <absolute-release-assets-directory>

The directory must contain exactly the three checksum-governed v2 release
assets. The check uses only the fixed stopped disposable Lima pair and restores
both fixtures to Stopped. It is not a release gate and has no resume mode.
EOF
}

enter_phase() {
  current_phase=$1
  printf 'running focused enrollment: %s\n' "$current_phase"
}

report_error() {
  local code=$1 line=$2
  printf 'focused enrollment failed: phase=%s line=%s exit=%s\n' "$current_phase" "$line" "$code" >&2
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

instance_json() {
  limactl list --json | jq -ce --arg name "$1" 'select(.name == $name)'
}

instance_status() {
  instance_json "$1" | jq -er '.status'
}

assert_instance_contract() {
  local instance=$1 expected_status=$2
  if ! instance_json "$instance" | jq -e \
    --arg digest "$lab_image_digest" --arg instance "$instance" --arg status "$expected_status" '
      .status == $status and .vmType == "qemu" and .arch == "x86_64" and
      .cpus == (if $instance == "vpnctl-v2-node" then 4 else 1 end) and
      .memory == (if $instance == "vpnctl-v2-node" then 2147483648 else 536870912 end) and
      .disk == 10737418240 and .config.images[0].digest == $digest and
      any(.network[]?; .lima == "user-v2")
    ' >/dev/null; then
    echo "refusing non-lab, transition-state, or drifted fixture: $instance" >&2
    exit 3
  fi
}

guest() {
  local instance=$1
  shift
  limactl shell --tty=false "$instance" -- "$@"
}

fresh_guest_root() {
  local instance=$1 ssh_config
  shift
  ssh_config=$(limactl list --format='{{.SSHConfigFile}}' "$instance")
  case "$ssh_config" in
    */.lima/"$instance"/ssh.config) ;;
    *) echo "refusing unexpected Lima SSH config path" >&2; return 3 ;;
  esac
  [ -f "$ssh_config" ] && [ ! -L "$ssh_config" ] || {
    echo "Lima SSH config is unavailable" >&2
    return 3
  }
  ssh -T -F "$ssh_config" \
    -o ControlMaster=no -o ControlPath=none -o ControlPersist=no \
    "lima-$instance" sudo --preserve-env=SSH_CONNECTION "$@"
}

start_fixture() {
  local instance=$1 marker=$2
  assert_instance_contract "$instance" Stopped
  printf -v "$marker" '%s' true
  limactl start --tty=false "$instance"
  assert_instance_contract "$instance" Running
}

package_installed() {
  local instance=$1 package=$2
  guest "$instance" dpkg-query -W '-f=${db:Status-Status}\n' "$package" 2>/dev/null | grep -Fxq installed
}

assert_no_task_root() {
  local instance=$1
  for target in "$guest_root" "$secret_runtime" "$upload_root"; do
    if guest "$instance" sudo test -e "$target"; then
      echo "refusing pre-existing enrollment E2E path on $instance: $target" >&2
      exit 3
    fi
  done
}

assert_guest_clean() {
  local instance=$1 role=$2 unit_count
  assert_no_task_root "$instance"
  guest "$instance" sudo test ! -e /usr/local/bin/vpnctl || {
    echo "vpnctl binary exists before E2E on $instance" >&2
    return 3
  }
  guest "$instance" sudo test ! -e /etc/vpnctl || {
    echo "vpnctl configuration exists before E2E on $instance" >&2
    return 3
  }
  guest "$instance" sudo test ! -e /var/lib/vpnctl/state.json || {
    echo "vpnctl authoritative state exists before E2E on $instance" >&2
    return 3
  }
  guest "$instance" sudo nft list table inet vpnctl >/dev/null 2>&1 && {
    echo "owned product nftables table exists before E2E on $instance" >&2
    exit 3
  }
  for link in vpnctl-wg vpnctl0; do
    guest "$instance" ip link show "$link" >/dev/null 2>&1 && {
      echo "owned product link exists before E2E on $instance: $link" >&2
      exit 3
    }
  done
  unit_count=$(guest "$instance" systemctl list-unit-files --no-legend --no-pager |
    awk '$1 ~ /^vpnctl.*[.]service$/ { count++ } END { print count + 0 }')
  [ "$unit_count" = 0 ] || {
    echo "owned product units exist before E2E on $instance: count=$unit_count" >&2
    return 3
  }
  guest "$instance" systemctl is-enabled --quiet ufw || {
    echo "fixture UFW is not enabled before E2E on $instance" >&2
    return 3
  }
  guest "$instance" systemctl is-active --quiet ufw || {
    echo "fixture UFW is not active before E2E on $instance" >&2
    return 3
  }
  guest "$instance" swapon --noheadings --show=NAME | grep -Fxq /var/lib/vpnctl-v2-lab.swap || {
    echo "fixture swap is not active before E2E on $instance" >&2
    return 3
  }
  if guest "$instance" pgrep -x apt-get >/dev/null || guest "$instance" pgrep -x dpkg >/dev/null; then
    echo "package manager is busy on $instance" >&2
    exit 4
  fi
  if guest "$instance" ip -4 -o addr show dev eth0 | grep -q " inet $gateway_public_ip/32 "; then
    echo "TEST-NET address exists before E2E on $instance" >&2
    exit 3
  fi
  if [ -n "$(guest "$instance" ip -4 route show exact "$gateway_public_ip/32")" ]; then
    echo "TEST-NET route exists before E2E on $instance" >&2
    exit 3
  fi
  if [ "$role" = gateway ] && package_installed "$instance" nginx; then
    echo "nginx must be absent before the clean bootstrap mode" >&2
    exit 3
  fi
}

assert_candidate() {
  candidate_dir=$1
  case "$candidate_dir" in
    /*) ;;
    *) echo "candidate directory must be absolute" >&2; exit 2 ;;
  esac
  [ -d "$candidate_dir" ] && [ ! -L "$candidate_dir" ] || {
    echo "candidate directory must be a real directory" >&2
    exit 3
  }
  mkdir -p "$artifact_root"
  run_root=$(mktemp -d "$artifact_root/run-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
  chmod 0700 "$run_root"
  env GOCACHE=/private/tmp/vpnctl-go-cache go run ./cmd/vpnctl-release-verify \
    --assets "$candidate_dir" --version v2.0.0 > "$run_root/candidate.json"
  chmod 0600 "$run_root/candidate.json"
  jq -e '.schema_version == 1 and .status == "passed" and .integrity == "sha256-and-bundle-verified"' \
    "$run_root/candidate.json" >/dev/null
  candidate_version=$(jq -er '.version' "$run_root/candidate.json")
  candidate_binary_sha=$(jq -er '.binary_sha256' "$run_root/candidate.json")
  candidate_bundle_sha=$(jq -er '.bundle_sha256' "$run_root/candidate.json")
  candidate_metadata_sha=$(sha256_file "$candidate_dir/release-checksums.txt")
  installer_sha=$(sha256_file "$installer")
  helper_sha=$(sha256_file "$pty_helper")
}

write_owner_marker() {
  local instance=$1
  guest "$instance" sudo install -d -m 0700 "$guest_root" "$guest_runtime"
  guest "$instance" sudo sh -c "umask 077; printf '%s\\n' '$owner_value' > '$guest_root/.owner'"
  guest "$instance" sudo chmod 0600 "$guest_root/.owner"
}

copy_candidate() {
  local instance=$1 source name actual
  guest "$instance" install -d -m 0700 "$upload_root"
  guest "$instance" sh -c "umask 077; printf '%s\\n' '$owner_value' > '$upload_root/.owner'"
  for source in \
    "$candidate_dir/vpnctl-linux-amd64" \
    "$candidate_dir/vpnctl-v2-linux-amd64.bundle" \
    "$candidate_dir/release-checksums.txt" \
    "$installer" "$pty_helper"; do
    name=$(basename -- "$source")
    limactl copy --backend=scp "$source" "$instance:$upload_root/$name"
  done
  write_owner_marker "$instance"
  guest "$instance" sudo install -d -m 0700 "$guest_root/candidate"
  for name in vpnctl-linux-amd64 vpnctl-v2-linux-amd64.bundle release-checksums.txt install.sh pty_secret.py; do
    source="$upload_root/$name"
    actual=$(guest "$instance" sha256sum "$source" | awk '{print $1}')
    case "$name" in
      vpnctl-linux-amd64) [ "$actual" = "$candidate_binary_sha" ] ;;
      vpnctl-v2-linux-amd64.bundle) [ "$actual" = "$candidate_bundle_sha" ] ;;
      release-checksums.txt) [ "$actual" = "$candidate_metadata_sha" ] ;;
      install.sh) [ "$actual" = "$installer_sha" ] ;;
      pty_secret.py) [ "$actual" = "$helper_sha" ] ;;
    esac
    guest "$instance" sudo install -m 0600 "$source" "$guest_root/candidate/$name"
  done
  guest "$instance" sudo chmod 0700 "$guest_root/candidate/vpnctl-linux-amd64" \
    "$guest_root/candidate/install.sh" "$guest_root/candidate/pty_secret.py"
  guest "$instance" rm -f \
    "$upload_root/vpnctl-linux-amd64" "$upload_root/vpnctl-v2-linux-amd64.bundle" \
    "$upload_root/release-checksums.txt" "$upload_root/install.sh" "$upload_root/pty_secret.py" \
    "$upload_root/.owner"
  guest "$instance" rmdir "$upload_root"
}

install_candidate() {
  local instance=$1
  guest "$instance" sudo env \
    VPNCTL_RELEASE_ASSET_DIR="$guest_root/candidate" VPNCTL_VERSION="$candidate_version" \
    /bin/sh "$guest_root/candidate/install.sh" >/dev/null
  [ "$(guest "$instance" sudo sha256sum /usr/local/bin/vpnctl | awk '{print $1}')" = "$candidate_binary_sha" ]
  [ "$(guest "$instance" sudo sha256sum /usr/local/lib/vpnctl/release/vpnctl.bundle | awk '{print $1}')" = "$candidate_bundle_sha" ]
  [ "$(guest "$instance" sudo sha256sum /usr/local/lib/vpnctl/release/checksums.txt | awk '{print $1}')" = "$candidate_metadata_sha" ]
}

prepare_network() {
  gateway_underlay=$(guest "$gateway_instance" ip -4 -o address show scope global | awk '$4 ~ /^192[.]168[.]104[.]/ {sub(/\/.*/, "", $4); print $4; exit}')
  case "$gateway_underlay" in
    192.168.104.*) ;;
    *) echo "unexpected Gateway underlay address" >&2; exit 3 ;;
  esac
  guest "$gateway_instance" sudo env DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null
  guest "$gateway_instance" sudo ip address add "$gateway_public_ip/32" dev eth0
  guest "$node_instance" sudo ip route add "$gateway_public_ip/32" via "$gateway_underlay" dev eth0 proto static
  guest "$gateway_instance" sudo systemctl stop ufw
  guest "$gateway_instance" systemctl is-enabled --quiet ufw
  ! guest "$gateway_instance" systemctl is-active --quiet ufw
}

confirm_from_fresh_session() {
  local source_json=$1 output_json=$2 transaction_id
  transaction_id=$(jq -er '.resource_ids.transaction_id // empty' "$source_json")
  if [ -z "$transaction_id" ]; then
    jq -n '{schema_version:1,status:"not-required"}' > "$output_json"
    chmod 0600 "$output_json"
    return
  fi
  fresh_guest_root "$gateway_instance" /usr/local/bin/vpnctl confirm "$transaction_id" --json > "$output_json"
  chmod 0600 "$output_json"
  jq -e '.status == "ok"' "$output_json" >/dev/null
}

run_initialization() {
  guest "$gateway_instance" sudo /usr/local/bin/vpnctl init --gateway \
    --public-ip "$gateway_public_ip" --external-interface eth0 --ssh-port 22 --yes --json \
    > "$run_root/gateway-init.json"
  chmod 0600 "$run_root/gateway-init.json"
  jq -e '.status == "ok" and .data.role == "gateway"' "$run_root/gateway-init.json" >/dev/null
  confirm_from_fresh_session "$run_root/gateway-init.json" "$run_root/gateway-confirm.json"

  guest "$node_instance" sudo /usr/local/bin/vpnctl init --node --yes --json \
    > "$run_root/node-init.json"
  chmod 0600 "$run_root/node-init.json"
  jq -e '.status == "ok" and .data.role == "node" and .data.enrollment_status == "unjoined"' \
    "$run_root/node-init.json" >/dev/null
}

create_invite_and_join() {
  guest "$gateway_instance" sudo install -d -m 0700 "$secret_runtime"
  guest "$gateway_instance" sudo python3 "$guest_root/candidate/pty_secret.py" invite "$secret_runtime" \
    > "$run_root/invite.json"
  chmod 0600 "$run_root/invite.json"
  jq -e '.status == "ok" and .operation == "invite"' "$run_root/invite.json" >/dev/null
  guest "$gateway_instance" sudo test -f "$secret_runtime/invite.token"
  guest "$node_instance" sudo install -d -m 0700 "$secret_runtime"
  guest "$node_instance" sudo install -m 0600 /dev/null "$secret_runtime/invite.token"
  guest "$gateway_instance" sudo cat "$secret_runtime/invite.token" | \
    guest "$node_instance" sudo tee "$secret_runtime/invite.token" >/dev/null
  guest "$gateway_instance" sudo rm -f "$secret_runtime/invite.token"
  guest "$gateway_instance" sudo rmdir "$secret_runtime"

  guest "$node_instance" sudo python3 "$guest_root/candidate/pty_secret.py" join "$secret_runtime" \
    > "$run_root/join.json"
  chmod 0600 "$run_root/join.json"
  jq -e '.status == "ok" and .operation == "join" and .data.active_transport == "standard" and
    .data.presets == ["telegram"]' "$run_root/join.json" >/dev/null
  guest "$node_instance" sudo test ! -e "$secret_runtime/invite.token"
  guest "$node_instance" sudo rmdir "$secret_runtime"
}

capture_health() {
  local phase=$1 document
  guest "$gateway_instance" sudo /usr/local/bin/vpnctl validate --json > "$run_root/$phase-gateway-validate.json"
  guest "$gateway_instance" sudo /usr/local/bin/vpnctl plan --json > "$run_root/$phase-gateway-plan.json"
  guest "$gateway_instance" sudo /usr/local/bin/vpnctl status --all --json > "$run_root/$phase-gateway-status.json"
  guest "$gateway_instance" sudo /usr/local/bin/vpnctl doctor ingress --json > "$run_root/$phase-gateway-ingress.json"
  guest "$gateway_instance" sudo /usr/local/bin/vpnctl doctor tunnel --json > "$run_root/$phase-gateway-tunnel.json"
  guest "$node_instance" sudo /usr/local/bin/vpnctl validate --json > "$run_root/$phase-node-validate.json"
  guest "$node_instance" sudo /usr/local/bin/vpnctl plan --json > "$run_root/$phase-node-plan.json"
  guest "$node_instance" sudo /usr/local/bin/vpnctl doctor dns --json > "$run_root/$phase-node-dns.json"
  guest "$node_instance" sudo /usr/local/bin/vpnctl doctor transport --json > "$run_root/$phase-node-transport.json"
  guest "$node_instance" sudo /usr/local/bin/vpnctl doctor tunnel --json > "$run_root/$phase-node-tunnel.json"
  chmod 0600 "$run_root/$phase-"*.json
  for document in "$run_root/$phase-gateway-validate.json" "$run_root/$phase-node-validate.json"; do
    jq -e '.status == "ok"' "$document" >/dev/null
  done
  for document in "$run_root/$phase-gateway-plan.json" "$run_root/$phase-node-plan.json"; do
    jq -e '.status == "ok" and .data.impact == "none"' "$document" >/dev/null
  done
  jq -e '.status == "ok" and .data.overall == "healthy"' "$run_root/$phase-gateway-status.json" >/dev/null
  for document in \
    "$run_root/$phase-gateway-ingress.json" "$run_root/$phase-gateway-tunnel.json" \
    "$run_root/$phase-node-dns.json" "$run_root/$phase-node-transport.json" "$run_root/$phase-node-tunnel.json"; do
    jq -e '.status == "ok" and .data.overall == "healthy"' "$document" >/dev/null
  done
  for unit in vpnctl-controller.service vpnctl-standard.service vpnctl-dns.service vpnctl-tunnel-server.service nginx.service; do
    guest "$gateway_instance" systemctl is-active --quiet "$unit"
  done
  for unit in vpnctl-standard.service vpnctl-tunnel-client.service vpnctl-routing.service vpnctl-routing-guard.service; do
    guest "$node_instance" systemctl is-active --quiet "$unit"
  done
  [ "$(guest "$gateway_instance" sudo wg show vpnctl-wg peers | wc -l | tr -d ' ')" = 1 ]
  [ "$(guest "$node_instance" curl -ksS --connect-timeout 5 --max-time 15 -o /dev/null -w '%{http_code}' \
    "https://$gateway_public_ip/.well-known/vpnctl/health")" = 204 ]
}

selected_request() {
  local before after status
  before=$(guest "$node_instance" sudo wg show vpnctl0 transfer | awk '{rx += $2; tx += $3} END {print rx + tx + 0}')
  status=$(guest "$node_instance" curl -sS --connect-timeout 5 --max-time 20 -o /dev/null -w '%{http_code}' \
    https://api.telegram.org/)
  case "$status" in
    2??|3??|4??) ;;
    *) echo "selected request did not return HTTP" >&2; exit 4 ;;
  esac
  after=$(guest "$node_instance" sudo wg show vpnctl0 transfer | awk '{rx += $2; tx += $3} END {print rx + tx + 0}')
  [ "$after" -gt "$before" ] || {
    echo "selected request did not move WireGuard counters" >&2
    exit 4
  }
  jq -n --argjson status "$status" --argjson delta "$((after - before))" \
    '{schema_version:1,status:"passed",http_status:$status,aggregate_transfer_delta:$delta}' \
    > "$run_root/selected-request.json"
  chmod 0600 "$run_root/selected-request.json"
}

repair_missing_ingress() {
  guest "$gateway_instance" sudo systemctl stop nginx
  if guest "$node_instance" curl -ksS --connect-timeout 2 --max-time 5 -o /dev/null \
    "https://$gateway_public_ip/.well-known/vpnctl/health"; then
    echo "public ingress remained available after the explicit fault" >&2
    exit 3
  fi
  set +e
  guest "$gateway_instance" sudo /usr/local/bin/vpnctl status --all --json > "$run_root/fault-gateway-status.json"
  local status_code=$?
  guest "$gateway_instance" sudo /usr/local/bin/vpnctl plan --json > "$run_root/fault-gateway-plan.json"
  local plan_code=$?
  set -e
  chmod 0600 "$run_root/fault-gateway-status.json" "$run_root/fault-gateway-plan.json"
  [ "$status_code" -ne 0 ] || {
    echo "passive status unexpectedly exited successfully during ingress fault" >&2
    exit 3
  }
  [ "$plan_code" -eq 0 ] || {
    echo "repair plan was unavailable during ingress fault" >&2
    exit 3
  }
  jq -e '.data.overall == "degraded"' "$run_root/fault-gateway-status.json" >/dev/null
  jq -e '.status == "pending" and .data.impact != "none"' "$run_root/fault-gateway-plan.json" >/dev/null

  guest "$gateway_instance" sudo /usr/local/bin/vpnctl repair --yes --json > "$run_root/gateway-repair.json"
  chmod 0600 "$run_root/gateway-repair.json"
  jq -e '.status == "ok"' "$run_root/gateway-repair.json" >/dev/null
  confirm_from_fresh_session "$run_root/gateway-repair.json" "$run_root/gateway-repair-confirm.json"
  capture_health repaired
}

owned_guest_root() {
  local instance=$1
  guest "$instance" sudo test -d "$guest_root" &&
    guest "$instance" sudo test ! -L "$guest_root" &&
    guest "$instance" sudo test -f "$guest_root/.owner" &&
    guest "$instance" sudo grep -Fxq "$owner_value" "$guest_root/.owner"
}

purge_role() {
  local instance=$1 operation=$2 output=$3
  if ! guest "$instance" sudo test -e /var/lib/vpnctl/state.json; then
    if guest "$instance" sudo test -e /usr/local/bin/vpnctl; then
      [ "$(guest "$instance" sudo sha256sum /usr/local/bin/vpnctl | awk '{print $1}')" = "$candidate_binary_sha" ] || return 1
      guest "$instance" sudo rm -f /usr/local/bin/vpnctl
    fi
    return
  fi
  guest "$instance" sudo install -d -m 0700 "$guest_runtime"
  if ! guest "$instance" sudo python3 "$guest_root/candidate/pty_secret.py" "$operation" "$guest_runtime" > "$output"; then
    guest "$instance" sudo test ! -e /var/lib/vpnctl/state.json || return 1
  fi
  chmod 0600 "$output" 2>/dev/null || true
  guest "$instance" sudo test ! -e /var/lib/vpnctl/state.json
  guest "$instance" sudo test ! -e /usr/local/bin/vpnctl
}

remove_owned_guest_root() {
  local instance=$1
  if owned_guest_root "$instance"; then
    if guest "$instance" sudo test -e "$secret_runtime"; then
      guest "$instance" sudo test -d "$secret_runtime"
      guest "$instance" sudo test ! -L "$secret_runtime"
      guest "$instance" sudo rm -rf -- "$secret_runtime"
    fi
    guest "$instance" sudo rm -rf -- "$guest_root"
  elif guest "$instance" sudo test -e "$guest_root"; then
    return 1
  fi
  if guest "$instance" test -e "$upload_root"; then
    if ! guest "$instance" test -d "$upload_root" ||
       ! guest "$instance" test ! -L "$upload_root" ||
       ! guest "$instance" grep -Fxq "$owner_value" "$upload_root/.owner"; then
      return 1
    fi
    guest "$instance" rm -rf -- "$upload_root"
  fi
}

restore_fixture_baseline() {
  local result=0
  if [ -n "$gateway_underlay" ] && [ "$(instance_status "$node_instance" 2>/dev/null || true)" = Running ] && owned_guest_root "$node_instance"; then
    guest "$node_instance" sudo ip route del "$gateway_public_ip/32" via "$gateway_underlay" dev eth0 proto static >/dev/null 2>&1 || true
  fi
  if [ "$(instance_status "$gateway_instance" 2>/dev/null || true)" = Running ] && owned_guest_root "$gateway_instance"; then
    if [ -z "$gateway_common_initial" ] && guest "$gateway_instance" sudo test -f "$guest_root/nginx-common.initial"; then
      gateway_common_initial=$(guest "$gateway_instance" sudo sed -n '1p' "$guest_root/nginx-common.initial")
    fi
    guest "$gateway_instance" sudo ip address del "$gateway_public_ip/32" dev eth0 >/dev/null 2>&1 || true
    guest "$gateway_instance" sudo systemctl start ufw >/dev/null 2>&1 || result=$?
    if package_installed "$gateway_instance" nginx; then
      guest "$gateway_instance" sudo env DEBIAN_FRONTEND=noninteractive apt-get remove --purge --yes nginx >/dev/null || result=$?
    fi
    if [ "$gateway_common_initial" = absent ] && package_installed "$gateway_instance" nginx-common; then
      guest "$gateway_instance" sudo env DEBIAN_FRONTEND=noninteractive apt-get remove --purge --yes nginx-common >/dev/null || result=$?
    fi
  fi
  return "$result"
}

assert_final_clean() {
  local instance unit_count process_count listener_count
  for instance in "$gateway_instance" "$node_instance"; do
    guest "$instance" sudo test ! -e /usr/local/bin/vpnctl
    guest "$instance" sudo test ! -e /etc/vpnctl
    guest "$instance" sudo test ! -e /var/lib/vpnctl/state.json
    guest "$instance" sudo test ! -e "$guest_root"
    guest "$instance" sudo test ! -e "$secret_runtime"
    guest "$instance" sudo test ! -e "$upload_root"
    guest "$instance" systemctl is-enabled --quiet ufw
    guest "$instance" systemctl is-active --quiet ufw
    guest "$instance" swapon --noheadings --show=NAME | grep -Fxq /var/lib/vpnctl-v2-lab.swap
    ! guest "$instance" sudo nft list table inet vpnctl >/dev/null 2>&1
    ! guest "$instance" ip link show vpnctl-wg >/dev/null 2>&1
    ! guest "$instance" ip link show vpnctl0 >/dev/null 2>&1
    unit_count=$(guest "$instance" systemctl list-unit-files --no-legend --no-pager |
      awk '$1 ~ /^vpnctl.*[.]service$/ { count++ } END { print count + 0 }')
    [ "$unit_count" = 0 ]
    process_count=$(guest "$instance" sh -c '{ pgrep -x frps || true; pgrep -x frpc || true; pgrep -x mihomo || true; } | wc -l')
    [ "$(printf '%s' "$process_count" | tr -d ' ')" = 0 ]
    listener_count=$(guest "$instance" sh -c "ss -H -lntu | grep -Ec '(:443|:51820|:17000)[[:space:]]' || true")
    [ "$(printf '%s' "$listener_count" | tr -d ' ')" = 0 ]
    ! guest "$instance" ip -4 -o address show dev eth0 | grep -q " inet $gateway_public_ip/32 "
    [ -z "$(guest "$instance" ip -4 route show exact "$gateway_public_ip/32")" ]
    if guest "$instance" pgrep -x apt-get >/dev/null || guest "$instance" pgrep -x dpkg >/dev/null; then
      return 1
    fi
  done
  ! package_installed "$gateway_instance" nginx
  ! guest "$gateway_instance" test -x /usr/sbin/nginx
  ! guest "$gateway_instance" systemctl is-active --quiet nginx
  [ "$(package_installed "$gateway_instance" nginx-common && echo installed || echo absent)" = "$gateway_common_initial" ]
}

stop_started_fixtures() {
  local result=0 current
  if [ "$node_started" = true ]; then
    current=$(instance_status "$node_instance" 2>/dev/null || true)
    if [ "$current" != Stopped ]; then
      limactl stop "$node_instance" >/dev/null || result=$?
    fi
    [ "$(instance_status "$node_instance" 2>/dev/null || true)" = Stopped ] || result=1
  fi
  if [ "$gateway_started" = true ]; then
    current=$(instance_status "$gateway_instance" 2>/dev/null || true)
    if [ "$current" != Stopped ]; then
      limactl stop "$gateway_instance" >/dev/null || result=$?
    fi
    [ "$(instance_status "$gateway_instance" 2>/dev/null || true)" = Stopped ] || result=1
  fi
  return "$result"
}

write_safe_diagnostics() {
  local instance role
  [ -n "$run_root" ] || return
  : > "$run_root/diagnostics.txt"
  chmod 0600 "$run_root/diagnostics.txt"
  printf 'phase=%s\n' "$current_phase" >> "$run_root/diagnostics.txt"
  for instance in "$gateway_instance" "$node_instance"; do
    printf 'instance=%s status=%s\n' "$instance" "$(instance_status "$instance" 2>/dev/null || echo unavailable)" >> "$run_root/diagnostics.txt"
    if [ "$(instance_status "$instance" 2>/dev/null || true)" = Running ]; then
      role=$(guest "$instance" sudo jq -r '.host.role // "unknown"' /var/lib/vpnctl/state.json 2>/dev/null || echo absent)
      printf 'instance=%s role=%s binary=%s state=%s tcp443=%s\n' \
        "$instance" "$role" \
        "$(guest "$instance" sudo test -e /usr/local/bin/vpnctl && echo present || echo absent)" \
        "$(guest "$instance" sudo test -e /var/lib/vpnctl/state.json && echo present || echo absent)" \
        "$(guest "$instance" ss -H -ltn sport = :443 | wc -l | tr -d ' ')" \
        >> "$run_root/diagnostics.txt"
    fi
  done
}

cleanup_on_exit() {
  local status=$? cleanup_status=0
  trap - EXIT INT TERM HUP ERR
  set +e
  write_safe_diagnostics
  if [ "$(instance_status "$node_instance" 2>/dev/null || true)" = Running ] && owned_guest_root "$node_instance"; then
    purge_role "$node_instance" purge-node "$run_root/cleanup-node.json" || cleanup_status=1
  fi
  if [ "$(instance_status "$gateway_instance" 2>/dev/null || true)" = Running ] && owned_guest_root "$gateway_instance"; then
    purge_role "$gateway_instance" purge-gateway "$run_root/cleanup-gateway.json" || cleanup_status=1
  fi
  restore_fixture_baseline || cleanup_status=1
  if [ "$(instance_status "$node_instance" 2>/dev/null || true)" = Running ]; then
    remove_owned_guest_root "$node_instance" || cleanup_status=1
  fi
  if [ "$(instance_status "$gateway_instance" 2>/dev/null || true)" = Running ]; then
    remove_owned_guest_root "$gateway_instance" || cleanup_status=1
  fi
  if [ "$cleanup_status" -eq 0 ] && [ "$(instance_status "$gateway_instance" 2>/dev/null || true)" = Running ] && [ "$(instance_status "$node_instance" 2>/dev/null || true)" = Running ]; then
    assert_final_clean || cleanup_status=1
  fi
  stop_started_fixtures || cleanup_status=1
  if [ "$status" -eq 0 ] && [ "$cleanup_status" -ne 0 ]; then
    status=1
  fi
  exit "$status"
}

write_summary() {
  local source_commit
  source_commit=$(git rev-parse HEAD)
  jq -n \
    --arg source_commit "$source_commit" --arg version "$candidate_version" \
    --arg binary_sha256 "$candidate_binary_sha" --arg bundle_sha256 "$candidate_bundle_sha" \
    --arg checksum_metadata_sha256 "$candidate_metadata_sha" '
      {
        schema_version: 1,
        status: "passed",
        orchestration_commit: $source_commit,
        candidate: {
          version: $version,
          binary_sha256: $binary_sha256,
          bundle_sha256: $bundle_sha256,
          checksum_metadata_sha256: $checksum_metadata_sha256,
          maintainer_verifier: "passed"
        },
        clean_bootstrap: {
          no_nginx_precondition: true,
          gateway_init_and_watchdog_confirmed: true,
          node_initialized: true,
          public_join_single_command: true,
          invite_consumed_once: true,
          selected_request_over_wireguard: true,
          readiness: "healthy"
        },
        missing_ingress_repair: {
          nginx_stopped: true,
          public_health_failed_closed: true,
          confirmed_repair: true,
          readiness: "healthy"
        },
        cleanup: {
          owner_scoped: true,
          secrets_absent: true,
          product_state_absent: true,
          fixture_state_restored: "stopped"
        }
      }
    ' > "$run_root/summary.json"
  chmod 0600 "$run_root/summary.json"
}

verify() {
  [ "$#" -eq 1 ] || { usage >&2; exit 2; }
  cd "$repository_root"
  assert_candidate "$1"
  assert_instance_contract "$gateway_instance" Stopped
  assert_instance_contract "$node_instance" Stopped
  trap cleanup_on_exit EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  trap 'report_error "$?" "$LINENO"' ERR
  enter_phase start-gateway
  start_fixture "$gateway_instance" gateway_started
  enter_phase start-node
  start_fixture "$node_instance" node_started

  enter_phase preflight-gateway
  assert_guest_clean "$gateway_instance" gateway
  enter_phase preflight-node
  assert_guest_clean "$node_instance" node
  if package_installed "$gateway_instance" nginx-common; then
    gateway_common_initial=installed
  else
    gateway_common_initial=absent
  fi
  enter_phase stage-gateway-candidate
  copy_candidate "$gateway_instance"
  guest "$gateway_instance" sudo sh -c "umask 077; printf '%s\\n' '$gateway_common_initial' > '$guest_root/nginx-common.initial'"
  enter_phase stage-node-candidate
  copy_candidate "$node_instance"
  enter_phase install-gateway-candidate
  install_candidate "$gateway_instance"
  enter_phase install-node-candidate
  install_candidate "$node_instance"
  enter_phase prepare-network
  prepare_network
  enter_phase initialize-roles
  run_initialization
  enter_phase enroll-node
  create_invite_and_join
  enter_phase verify-joined-health
  capture_health joined
  enter_phase verify-selected-request
  selected_request
  enter_phase repair-missing-ingress
  repair_missing_ingress

  enter_phase cleanup-products
  purge_role "$node_instance" purge-node "$run_root/cleanup-node.json"
  purge_role "$gateway_instance" purge-gateway "$run_root/cleanup-gateway.json"
  restore_fixture_baseline
  remove_owned_guest_root "$node_instance"
  remove_owned_guest_root "$gateway_instance"
  assert_final_clean
  enter_phase stop-fixtures
  stop_started_fixtures
  assert_instance_contract "$gateway_instance" Stopped
  assert_instance_contract "$node_instance" Stopped
  trap - EXIT INT TERM HUP ERR
  write_summary
  printf 'gateway enrollment E2E result: %s\n' "$run_root/summary.json"
}

case "${1:-}" in
  verify)
    shift
    verify "$@"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
