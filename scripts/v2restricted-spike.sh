#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
fixture_root="$repository_root/test/v2lab/restricted"
manifest="$fixture_root/manifest.json"
artifact_root="$repository_root/artifacts/v2lab/restricted-spike"
cache_root="$repository_root/artifacts/v2lab/cache"
credentials_file="$artifact_root/credentials.env"
generated_root="$artifact_root/generated"
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
gateway_unit=vpnctl-v2-spike-restricted-gateway.service
node_unit=vpnctl-v2-spike-restricted-node.service
echo_unit=vpnctl-v2-spike-echo.service
owner_value=vpnctl-v2-restricted-spike-v1
owner_path=/etc/vpnctl-v2-spike/restricted/.owner
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7

usage() {
  cat <<'EOF'
Usage:
  scripts/v2restricted-spike.sh prepare
  scripts/v2restricted-spike.sh verify [evidence-directory]
  scripts/v2restricted-spike.sh reconnect [evidence-directory]
  scripts/v2restricted-spike.sh render-client <gateway-address> [output-file]
  scripts/v2restricted-spike.sh status
  scripts/v2restricted-spike.sh stop
  scripts/v2restricted-spike.sh uninstall
EOF
}

manifest_value() {
  jq -er "$1" "$manifest"
}

instance_json() {
  limactl list --json | jq -ce --arg name "$1" 'select(.name == $name)'
}

assert_lab_instance() {
  local instance=$1
  if ! instance_json "$instance" | jq -e '
    .status == "Running" and
    .vmType == "qemu" and
    .arch == "x86_64" and
    .cpus == 1 and
    .memory == 536870912 and
    .disk == 10737418240 and
    any(.network[]?; .lima == "user-v2")
  ' >/dev/null; then
    echo "required contract-matching lab instance is not running: $instance" >&2
    exit 4
  fi
  if ! instance_json "$instance" | jq -e --arg digest "$lab_image_digest" '.config.images[0].digest == $digest' >/dev/null; then
    echo "lab image digest mismatch: $instance" >&2
    exit 3
  fi
}

assert_forward_ignored() {
  local instance=$1
  local port=$2
  if ! instance_json "$instance" | jq -e --argjson port "$port" '
    any(.config.portForwards[]?; .guestPort == $port and .ignore == true)
  ' >/dev/null; then
    echo "refusing to expose spike port $port through Lima host forwarding on $instance" >&2
    exit 3
  fi
}

lab_ip() {
  limactl shell --tty=false "$1" -- ip -4 -o address show scope global | awk '$4 ~ /^192[.]168[.]104[.]/ {sub(/\/.*/, "", $4); print $4; exit}'
}

ensure_credentials() {
  mkdir -p "$artifact_root" "$generated_root"
  chmod 0700 "$artifact_root" "$generated_root"
  if [ ! -e "$credentials_file" ]; then
    local ss_password shadow_tls_password temporary
    ss_password=$(openssl rand -base64 32 | tr -d '\n')
    shadow_tls_password=$(openssl rand -hex 32)
    temporary="$credentials_file.tmp.$$"
    umask 077
    printf 'SS_PASSWORD=%s\nSHADOW_TLS_PASSWORD=%s\n' "$ss_password" "$shadow_tls_password" > "$temporary"
    mv "$temporary" "$credentials_file"
  fi
  chmod 0600 "$credentials_file"
  # shellcheck disable=SC1090
  source "$credentials_file"
  if [[ ! "$SS_PASSWORD" =~ ^[A-Za-z0-9+/]{43}=$ ]] || [[ ! "$SHADOW_TLS_PASSWORD" =~ ^[a-f0-9]{64}$ ]]; then
    echo "invalid spike credential file; move it aside and rerun prepare" >&2
    exit 3
  fi
}

render_template() {
  local source=$1
  local destination=$2
  local gateway_ip=$3
  local client_gateway_address=$4
  local handshake_host temporary
  handshake_host=$(manifest_value '.handshake_hosts.selected_for_spike')
  temporary="$destination.tmp.$$"
  sed \
    -e "s|@SS_PASSWORD@|$SS_PASSWORD|g" \
    -e "s|@SHADOW_TLS_PASSWORD@|$SHADOW_TLS_PASSWORD|g" \
    -e "s|@HANDSHAKE_HOST@|$handshake_host|g" \
    -e "s|@GATEWAY_IP@|$gateway_ip|g" \
    -e "s|@CLIENT_GATEWAY_ADDRESS@|$client_gateway_address|g" \
    "$source" > "$temporary"
  chmod 0600 "$temporary"
  mv "$temporary" "$destination"
}

render_lab_configs() {
  local gateway_ip=$1
  ensure_credentials
  render_template "$fixture_root/gateway.yaml.tmpl" "$generated_root/gateway.yaml" "$gateway_ip" "$gateway_ip"
  render_template "$fixture_root/node.yaml.tmpl" "$generated_root/node.yaml" "$gateway_ip" "$gateway_ip"
  render_template "$fixture_root/clash-mi.yaml.tmpl" "$generated_root/clash-mi-lab.yaml" "$gateway_ip" "$gateway_ip"
}

verify_archive() {
  local archive=$1
  local expected actual
  expected=$(manifest_value '.mihomo.sha256')
  actual=$(shasum -a 256 "$archive" | awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    echo "pinned Mihomo archive checksum mismatch: $archive" >&2
    exit 3
  fi
}

fetch_mihomo() {
  local asset archive binary temporary
  asset=$(manifest_value '.mihomo.asset')
  archive="$cache_root/$asset"
  binary="$cache_root/mihomo-linux-amd64"
  mkdir -p "$cache_root"
  if [ -e "$archive" ]; then
    verify_archive "$archive"
  else
    temporary="$archive.tmp.$$"
    curl -fL --retry 3 --output "$temporary" "$(manifest_value '.mihomo.url')"
    verify_archive "$temporary"
    mv "$temporary" "$archive"
  fi
  temporary="$binary.tmp.$$"
  gzip -dc "$archive" > "$temporary"
  chmod 0755 "$temporary"
  mv "$temporary" "$binary"
  printf '%s\n' "$binary"
}

assert_owned_or_absent() {
  local instance=$1
  if limactl shell --tty=false "$instance" -- sudo test -e /etc/vpnctl-v2-spike/restricted; then
    if ! limactl shell --tty=false "$instance" -- sudo grep -Fxq "$owner_value" "$owner_path"; then
      echo "refusing to overwrite unowned spike path on $instance" >&2
      exit 3
    fi
  fi
}

assert_port_free_or_owned() {
  local instance=$1
  local unit=$2
  local protocol=$3
  local port=$4
  local socket_output
  if limactl shell --tty=false "$instance" -- systemctl is-active --quiet "$unit"; then
    return
  fi
  case "$protocol" in
    tcp) socket_output=$(limactl shell --tty=false "$instance" -- sudo ss -H -ltn "sport = :$port") ;;
    udp) socket_output=$(limactl shell --tty=false "$instance" -- sudo ss -H -lun "sport = :$port") ;;
    *) echo "unknown socket protocol: $protocol" >&2; exit 2 ;;
  esac
  if [ -n "$socket_output" ]; then
    echo "refusing to claim occupied $protocol port $port on $instance" >&2
    exit 3
  fi
}

copy_to_guest_tmp() {
  local instance=$1
  shift
  limactl copy --backend=scp "$@" "$instance:/tmp/"
}

install_common() {
  local instance=$1
  local binary=$2
  copy_to_guest_tmp "$instance" "$binary"
  limactl shell --tty=false "$instance" -- sudo install -d -m 0755 /usr/local/libexec/vpnctl-v2-spike
  limactl shell --tty=false "$instance" -- sudo install -m 0755 /tmp/mihomo-linux-amd64 /usr/local/libexec/vpnctl-v2-spike/mihomo
  limactl shell --tty=false "$instance" -- sudo install -d -m 0700 /etc/vpnctl-v2-spike/restricted
  limactl shell --tty=false "$instance" -- sudo sh -c "printf '%s\\n' '$owner_value' > '$owner_path'"
  limactl shell --tty=false "$instance" -- sudo chmod 0600 "$owner_path"
}

install_gateway() {
  local binary=$1
  install_common "$gateway_instance" "$binary"
  copy_to_guest_tmp "$gateway_instance" \
    "$generated_root/gateway.yaml" \
    "$fixture_root/systemd/$gateway_unit" \
    "$fixture_root/systemd/$echo_unit"
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0600 /tmp/gateway.yaml /etc/vpnctl-v2-spike/restricted/gateway.yaml
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0644 "/tmp/$gateway_unit" "/etc/systemd/system/$gateway_unit"
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0644 "/tmp/$echo_unit" "/etc/systemd/system/$echo_unit"
  limactl shell --tty=false "$gateway_instance" -- sudo install -d -m 0700 /var/lib/vpnctl-v2-spike-gateway /var/lib/vpnctl-v2-spike-echo
  limactl shell --tty=false "$gateway_instance" -- sudo sh -c "printf '%s\\n' 'vpnctl-v2-shadowtls-ok' > /var/lib/vpnctl-v2-spike-echo/probe.txt"
  limactl shell --tty=false "$gateway_instance" -- sudo chmod 0644 /var/lib/vpnctl-v2-spike-echo/probe.txt
  limactl shell --tty=false "$gateway_instance" -- sudo /usr/local/libexec/vpnctl-v2-spike/mihomo -t -d /var/lib/vpnctl-v2-spike-gateway -f /etc/vpnctl-v2-spike/restricted/gateway.yaml
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl daemon-reload
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl restart "$echo_unit" "$gateway_unit"
}

install_node() {
  local binary=$1
  install_common "$node_instance" "$binary"
  copy_to_guest_tmp "$node_instance" \
    "$generated_root/node.yaml" \
    "$fixture_root/systemd/$node_unit"
  limactl shell --tty=false "$node_instance" -- sudo install -m 0600 /tmp/node.yaml /etc/vpnctl-v2-spike/restricted/node.yaml
  limactl shell --tty=false "$node_instance" -- sudo install -m 0644 "/tmp/$node_unit" "/etc/systemd/system/$node_unit"
  limactl shell --tty=false "$node_instance" -- sudo install -d -m 0700 /var/lib/vpnctl-v2-spike-node
  limactl shell --tty=false "$node_instance" -- sudo /usr/local/libexec/vpnctl-v2-spike/mihomo -t -d /var/lib/vpnctl-v2-spike-node -f /etc/vpnctl-v2-spike/restricted/node.yaml
  limactl shell --tty=false "$node_instance" -- sudo systemctl daemon-reload
  limactl shell --tty=false "$node_instance" -- sudo systemctl restart "$node_unit"
}

wait_for_services() {
  local attempt
  for attempt in $(seq 1 20); do
    if limactl shell --tty=false "$gateway_instance" -- systemctl is-active --quiet "$gateway_unit" && \
       limactl shell --tty=false "$gateway_instance" -- systemctl is-active --quiet "$echo_unit" && \
       limactl shell --tty=false "$node_instance" -- systemctl is-active --quiet "$node_unit"; then
      if limactl shell --tty=false "$node_instance" -- curl -fsS --max-time 2 http://127.0.0.1:19090/version >/dev/null; then
        return
      fi
    fi
    sleep 1
  done
  echo "restricted spike services did not become ready" >&2
  exit 4
}

validate_handshake_host() {
  local output=$1
  local handshake_host
  handshake_host=$(manifest_value '.handshake_hosts.selected_for_spike')
  limactl shell --tty=false "$gateway_instance" -- openssl s_client \
    -connect "$handshake_host:443" -servername "$handshake_host" -tls1_3 -brief > "$output" 2>&1
  grep -Fq 'Protocol version: TLSv1.3' "$output"
  grep -Fq 'Verification: OK' "$output"
}

prepare() {
  local gateway_ip binary
  assert_lab_instance "$gateway_instance"
  assert_lab_instance "$node_instance"
  for port in 8443 18080; do assert_forward_ignored "$gateway_instance" "$port"; done
  for port in 1053 17890 19090; do assert_forward_ignored "$node_instance" "$port"; done
  assert_owned_or_absent "$gateway_instance"
  assert_owned_or_absent "$node_instance"
  assert_port_free_or_owned "$gateway_instance" "$gateway_unit" tcp 8443
  assert_port_free_or_owned "$gateway_instance" "$echo_unit" tcp 18080
  assert_port_free_or_owned "$node_instance" "$node_unit" tcp 1053
  assert_port_free_or_owned "$node_instance" "$node_unit" udp 1053
  assert_port_free_or_owned "$node_instance" "$node_unit" tcp 17890
  assert_port_free_or_owned "$node_instance" "$node_unit" tcp 19090
  gateway_ip=$(lab_ip "$gateway_instance")
  if [ -z "$gateway_ip" ]; then
    echo "gateway lab IP was not found" >&2
    exit 4
  fi
  render_lab_configs "$gateway_ip"
  validate_handshake_host "$artifact_root/handshake-host.txt"
  binary=$(fetch_mihomo)
  install_gateway "$binary"
  install_node "$binary"
  wait_for_services
  echo "restricted spike prepared; generated secrets remain under ignored artifacts/v2lab/restricted-spike"
}

proxy_get() {
  limactl shell --tty=false "$node_instance" -- curl -fsS --max-time 8 \
    --noproxy "" --proxy http://127.0.0.1:17890 http://127.0.0.1:18080/probe.txt
}

select_proxy() {
  local name=$1
  local payload
  payload=$(jq -nc --arg name "$name" '{name: $name}')
  limactl shell --tty=false "$node_instance" -- curl -fsS --max-time 3 \
    -X PUT -H 'Content-Type: application/json' --data "$payload" \
    http://127.0.0.1:19090/proxies/RESTRICTED >/dev/null
}

verify() {
  local evidence_dir=${1:-"$artifact_root/evidence-$(date -u +%Y%m%dT%H%M%SZ)"}
  local proxied dns_answer
  mkdir -p "$evidence_dir"
  chmod 0700 "$evidence_dir"
  wait_for_services
  if limactl shell --tty=false "$node_instance" -- curl -fsS --max-time 3 http://127.0.0.1:18080/probe.txt >/dev/null 2>&1; then
    echo "direct node access unexpectedly reached the gateway loopback probe" >&2
    exit 1
  fi
  proxied=$(proxy_get)
  if [ "$proxied" != vpnctl-v2-shadowtls-ok ]; then
    echo "selected TCP did not traverse restricted transport" >&2
    exit 1
  fi
  dns_answer=$(limactl shell --tty=false "$node_instance" -- dig @127.0.0.1 -p 1053 example.com A +short)
  if [ -z "$dns_answer" ]; then
    echo "selected DNS query returned no A records" >&2
    exit 1
  fi
  select_proxy RESTRICTED-WRONG-HOST
  trap 'select_proxy RESTRICTED-VALID >/dev/null 2>&1 || true' EXIT
  if proxy_get >/dev/null 2>&1; then
    echo "strict ShadowTLS unexpectedly accepted the wrong handshake host" >&2
    exit 1
  fi
  select_proxy RESTRICTED-VALID
  trap - EXIT
  if [ "$(proxy_get)" != vpnctl-v2-shadowtls-ok ]; then
    echo "restricted transport did not recover after restoring the pinned host" >&2
    exit 1
  fi
  copy_to_guest_tmp "$node_instance" "$generated_root/clash-mi-lab.yaml"
  trap 'limactl shell --tty=false "$node_instance" -- sudo rm -f /tmp/clash-mi-lab.yaml >/dev/null 2>&1 || true' EXIT
  limactl shell --tty=false "$node_instance" -- sudo chmod 0600 /tmp/clash-mi-lab.yaml
  limactl shell --tty=false "$node_instance" -- sudo /usr/local/libexec/vpnctl-v2-spike/mihomo \
    -t -d /var/lib/vpnctl-v2-spike-node -f /tmp/clash-mi-lab.yaml > "$evidence_dir/clash-mi-mihomo-validation.txt" 2>&1
  limactl shell --tty=false "$node_instance" -- sudo rm -f /tmp/clash-mi-lab.yaml
  trap - EXIT
  limactl shell --tty=false "$gateway_instance" -- sudo ss -H -ltn 'sport = :8443' > "$evidence_dir/gateway-8443-tcp.txt"
  limactl shell --tty=false "$gateway_instance" -- sudo ss -H -lun 'sport = :8443' > "$evidence_dir/gateway-8443-udp.txt"
  test -s "$evidence_dir/gateway-8443-tcp.txt"
  test ! -s "$evidence_dir/gateway-8443-udp.txt"
  limactl shell --tty=false "$gateway_instance" -- systemctl show "$gateway_unit" -p ActiveState -p MainPID -p MemoryCurrent -p CPUUsageNSec > "$evidence_dir/gateway-service.txt"
  limactl shell --tty=false "$node_instance" -- systemctl show "$node_unit" -p ActiveState -p MainPID -p MemoryCurrent -p CPUUsageNSec > "$evidence_dir/node-service.txt"
  limactl shell --tty=false "$node_instance" -- sudo journalctl -u "$node_unit" --no-pager -n 200 > "$evidence_dir/node-routing.log"
  grep -Fq 'mihomo --> 1.1.1.1:443 using RESTRICTED[RESTRICTED-VALID]' "$evidence_dir/node-routing.log"
  grep -Fq 'not www.apple.com' "$evidence_dir/node-routing.log"
  "$repository_root/scripts/v2lab.sh" report "$evidence_dir/resources"
  cp "$generated_root/clash-mi-lab.yaml" "$evidence_dir/clash-mi-lab.yaml"
  chmod 0600 "$evidence_dir/clash-mi-lab.yaml"
  jq -n \
    --arg status passed \
    --arg tcp_probe "$proxied" \
    --arg dns_answer "$dns_answer" \
    --arg handshake_host "$(manifest_value '.handshake_hosts.selected_for_spike')" \
    '{schema_version: 1, status: $status, selected_tcp: $tcp_probe, selected_dns_a: ($dns_answer | split("\n")), handshake_host: $handshake_host, strict_wrong_host_rejected: true, restricted_udp_listener: false}' \
    > "$evidence_dir/summary.json"
  printf 'restricted spike evidence: %s\n' "$evidence_dir/summary.json"
}

reconnect() {
  local evidence_dir=${1:-"$artifact_root/reconnect-$(date -u +%Y%m%dT%H%M%SZ)"}
  local attempt recovered_at=0
  mkdir -p "$evidence_dir"
  chmod 0700 "$evidence_dir"
  wait_for_services
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl stop "$gateway_unit"
  trap 'limactl shell --tty=false "$gateway_instance" -- sudo systemctl start "$gateway_unit" >/dev/null 2>&1 || true' EXIT
  if proxy_get >/dev/null 2>&1; then
    echo "restricted probe unexpectedly succeeded while gateway listener was stopped" >&2
    exit 1
  fi
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl start "$gateway_unit"
  for attempt in $(seq 1 20); do
    if [ "$(proxy_get 2>/dev/null || true)" = vpnctl-v2-shadowtls-ok ]; then
      recovered_at=$attempt
      break
    fi
    sleep 1
  done
  trap - EXIT
  if [ "$recovered_at" -eq 0 ]; then
    echo "node did not reconnect after gateway restart" >&2
    exit 1
  fi
  "$repository_root/scripts/v2lab.sh" report "$evidence_dir/resources"
  jq -n --argjson recovered_after_attempts "$recovered_at" \
    '{schema_version: 1, outage_probe_failed: true, node_restart_required: false, recovered_after_attempts: $recovered_after_attempts}' \
    > "$evidence_dir/summary.json"
  printf 'restricted reconnect evidence: %s\n' "$evidence_dir/summary.json"
}

render_client() {
  local address=${1:?gateway address is required}
  local output=${2:-"$artifact_root/clash-mi-$address.yaml"}
  if [[ ! "$address" =~ ^([0-9]{1,3}[.]){3}[0-9]{1,3}$ ]] && [[ ! "$address" =~ ^[A-Za-z0-9.-]+$ ]]; then
    echo "invalid gateway address" >&2
    exit 2
  fi
  ensure_credentials
  mkdir -p "$(dirname -- "$output")"
  render_template "$fixture_root/clash-mi.yaml.tmpl" "$output" "" "$address"
  printf 'Clash Mi spike profile: %s\n' "$output"
}

status() {
  assert_lab_instance "$gateway_instance"
  assert_lab_instance "$node_instance"
  limactl shell --tty=false "$gateway_instance" -- systemctl status --no-pager "$echo_unit" "$gateway_unit"
  limactl shell --tty=false "$node_instance" -- systemctl status --no-pager "$node_unit"
}

stop_spike() {
  assert_owned_or_absent "$gateway_instance"
  assert_owned_or_absent "$node_instance"
  limactl shell --tty=false "$node_instance" -- sudo systemctl stop "$node_unit"
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl stop "$gateway_unit" "$echo_unit"
}

uninstall_role() {
  local instance=$1
  shift
  if ! limactl shell --tty=false "$instance" -- sudo grep -Fxq "$owner_value" "$owner_path"; then
    echo "refusing to uninstall unowned spike paths on $instance" >&2
    exit 3
  fi
  limactl shell --tty=false "$instance" -- sudo systemctl stop "$@"
  local unit
  for unit in "$@"; do
    limactl shell --tty=false "$instance" -- sudo systemctl clean --what=state "$unit" || true
    limactl shell --tty=false "$instance" -- sudo rm -f "/etc/systemd/system/$unit"
  done
  limactl shell --tty=false "$instance" -- sudo rm -f /etc/vpnctl-v2-spike/restricted/gateway.yaml /etc/vpnctl-v2-spike/restricted/node.yaml "$owner_path"
  limactl shell --tty=false "$instance" -- sudo rmdir /etc/vpnctl-v2-spike/restricted /etc/vpnctl-v2-spike 2>/dev/null || true
  limactl shell --tty=false "$instance" -- sudo rm -f /usr/local/libexec/vpnctl-v2-spike/mihomo
  limactl shell --tty=false "$instance" -- sudo rmdir /usr/local/libexec/vpnctl-v2-spike 2>/dev/null || true
  limactl shell --tty=false "$instance" -- sudo systemctl daemon-reload
}

uninstall_spike() {
  uninstall_role "$node_instance" "$node_unit"
  uninstall_role "$gateway_instance" "$gateway_unit" "$echo_unit"
}

command=${1:-}
case "$command" in
  prepare) prepare ;;
  verify) verify "${2:-}" ;;
  reconnect) reconnect "${2:-}" ;;
  render-client) render_client "${2:-}" "${3:-}" ;;
  status) status ;;
  stop) stop_spike ;;
  uninstall) uninstall_spike ;;
  *) usage >&2; exit 2 ;;
esac
