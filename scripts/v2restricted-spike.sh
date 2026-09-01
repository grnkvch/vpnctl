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
udp_echo_unit=vpnctl-v2-spike-udp-echo.service
owner_value=vpnctl-v2-restricted-spike-v1
owner_path=/etc/vpnctl-v2-spike/restricted/.owner
capture_table=vpnctl_v2_spike_uot_capture
benchmark_probe_pid=
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7

usage() {
  cat <<'EOF'
Usage:
  scripts/v2restricted-spike.sh prepare
  scripts/v2restricted-spike.sh verify [evidence-directory]
  scripts/v2restricted-spike.sh reconnect [evidence-directory]
  scripts/v2restricted-spike.sh benchmark [evidence-directory]
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
    any(.config.portForwards[]?;
      .guestPort == $port and
      .guestIP == "0.0.0.0" and
      .guestIPMustBeZero == false and
      .proto == "any" and
      .ignore == true
    )
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
  local node_ip=${5:-}
  local handshake_host temporary
  handshake_host=$(manifest_value '.handshake_hosts.selected_for_spike')
  temporary="$destination.tmp.$$"
  sed \
    -e "s|@SS_PASSWORD@|$SS_PASSWORD|g" \
    -e "s|@SHADOW_TLS_PASSWORD@|$SHADOW_TLS_PASSWORD|g" \
    -e "s|@HANDSHAKE_HOST@|$handshake_host|g" \
    -e "s|@GATEWAY_IP@|$gateway_ip|g" \
    -e "s|@CLIENT_GATEWAY_ADDRESS@|$client_gateway_address|g" \
    -e "s|@NODE_IP@|$node_ip|g" \
    "$source" > "$temporary"
  chmod 0600 "$temporary"
  mv "$temporary" "$destination"
}

render_lab_configs() {
  local gateway_ip=$1
  local node_ip=$2
  ensure_credentials
  render_template "$fixture_root/gateway.yaml.tmpl" "$generated_root/gateway.yaml" "$gateway_ip" "$gateway_ip" "$node_ip"
  render_template "$fixture_root/node.yaml.tmpl" "$generated_root/node.yaml" "$gateway_ip" "$gateway_ip" "$node_ip"
  render_template "$fixture_root/clash-mi.yaml.tmpl" "$generated_root/clash-mi-lab.yaml" "$gateway_ip" "$gateway_ip" "$node_ip"
  render_template "$fixture_root/node-uot-capture.nft.tmpl" "$generated_root/node-uot-capture.nft" "$gateway_ip" "$gateway_ip" "$node_ip"
  render_template "$fixture_root/gateway-uot-capture.nft.tmpl" "$generated_root/gateway-uot-capture.nft" "$gateway_ip" "$gateway_ip" "$node_ip"
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
    "$fixture_root/telegram-api.json" \
    "$fixture_root/udp_echo.py" \
    "$fixture_root/systemd/$gateway_unit" \
    "$fixture_root/systemd/$echo_unit" \
    "$fixture_root/systemd/$udp_echo_unit"
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0755 /tmp/udp_echo.py /usr/local/libexec/vpnctl-v2-spike/udp-echo
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0600 /tmp/gateway.yaml /etc/vpnctl-v2-spike/restricted/gateway.yaml
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0644 "/tmp/$gateway_unit" "/etc/systemd/system/$gateway_unit"
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0644 "/tmp/$echo_unit" "/etc/systemd/system/$echo_unit"
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0644 "/tmp/$udp_echo_unit" "/etc/systemd/system/$udp_echo_unit"
  limactl shell --tty=false "$gateway_instance" -- sudo install -d -m 0700 /var/lib/vpnctl-v2-spike-gateway /var/lib/vpnctl-v2-spike-echo
  limactl shell --tty=false "$gateway_instance" -- sudo sh -c "printf '%s\\n' 'vpnctl-v2-shadowtls-ok' > /var/lib/vpnctl-v2-spike-echo/probe.txt"
  limactl shell --tty=false "$gateway_instance" -- sudo chmod 0644 /var/lib/vpnctl-v2-spike-echo/probe.txt
  limactl shell --tty=false "$gateway_instance" -- sudo /usr/local/libexec/vpnctl-v2-spike/mihomo -t -d /var/lib/vpnctl-v2-spike-gateway -f /etc/vpnctl-v2-spike/restricted/gateway.yaml
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl daemon-reload
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0644 /tmp/telegram-api.json /var/lib/vpnctl-v2-spike-echo/telegram-api.json
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl restart "$echo_unit" "$udp_echo_unit" "$gateway_unit"
}

install_node() {
  local binary=$1
  install_common "$node_instance" "$binary"
  copy_to_guest_tmp "$node_instance" \
    "$generated_root/node.yaml" \
    "$fixture_root/http_benchmark.py" \
    "$fixture_root/udp_benchmark.py" \
    "$fixture_root/udp_probe.py" \
    "$fixture_root/systemd/$node_unit"
  limactl shell --tty=false "$node_instance" -- sudo install -m 0755 /tmp/udp_probe.py /usr/local/libexec/vpnctl-v2-spike/udp-probe
  limactl shell --tty=false "$node_instance" -- sudo install -m 0755 /tmp/udp_benchmark.py /usr/local/libexec/vpnctl-v2-spike/udp-benchmark
  limactl shell --tty=false "$node_instance" -- sudo install -m 0755 /tmp/http_benchmark.py /usr/local/libexec/vpnctl-v2-spike/http-benchmark
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
       limactl shell --tty=false "$gateway_instance" -- systemctl is-active --quiet "$udp_echo_unit" && \
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
  local gateway_ip node_ip binary
  assert_lab_instance "$gateway_instance"
  assert_lab_instance "$node_instance"
  for port in 8443 18080; do assert_forward_ignored "$gateway_instance" "$port"; done
  for port in 1053 17890 19090; do assert_forward_ignored "$node_instance" "$port"; done
  assert_owned_or_absent "$gateway_instance"
  assert_owned_or_absent "$node_instance"
  assert_port_free_or_owned "$gateway_instance" "$gateway_unit" tcp 8443
  assert_port_free_or_owned "$gateway_instance" "$echo_unit" tcp 18080
  assert_port_free_or_owned "$gateway_instance" "$udp_echo_unit" udp 18080
  assert_port_free_or_owned "$node_instance" "$node_unit" tcp 1053
  assert_port_free_or_owned "$node_instance" "$node_unit" udp 1053
  assert_port_free_or_owned "$node_instance" "$node_unit" tcp 17890
  assert_port_free_or_owned "$node_instance" "$node_unit" tcp 19090
  assert_port_free_or_owned "$node_instance" "$udp_echo_unit" udp 18080
  gateway_ip=$(lab_ip "$gateway_instance")
  if [ -z "$gateway_ip" ]; then
    echo "gateway lab IP was not found" >&2
    exit 4
  fi
  node_ip=$(lab_ip "$node_instance")
  if [ -z "$node_ip" ]; then
    echo "node lab IP was not found" >&2
    exit 4
  fi
  render_lab_configs "$gateway_ip" "$node_ip"
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

select_group() {
  local group=$1
  local name=$2
  local payload
  payload=$(jq -nc --arg name "$name" '{name: $name}')
  limactl shell --tty=false "$node_instance" -- curl -fsS --max-time 3 \
    -X PUT -H 'Content-Type: application/json' --data "$payload" \
    "http://127.0.0.1:19090/proxies/$group" >/dev/null
}

select_proxy() {
  select_group RESTRICTED "$1"
}

select_udp_guard() {
  select_group RESTRICTED-UDP "$1"
}

proxy_state() {
  local name=$1
  limactl shell --tty=false "$node_instance" -- curl -fsS --max-time 3 \
    "http://127.0.0.1:19090/proxies/$name"
}

udp_probe() {
  local timeout=${1:-5}
  limactl shell --tty=false "$node_instance" -- /usr/local/libexec/vpnctl-v2-spike/udp-probe \
    --proxy 127.0.0.1:17890 \
    --target 127.0.0.1:18080 \
    --payload vpnctl-v2-uot-ok \
    --timeout "$timeout"
}

capture_table_exists() {
  local instance=$1
  limactl shell --tty=false "$instance" -- sudo nft list table inet "$capture_table" >/dev/null 2>&1
}

capture_clear() {
  local instance
  for instance in "$node_instance" "$gateway_instance"; do
    if capture_table_exists "$instance"; then
      limactl shell --tty=false "$instance" -- sudo nft delete table inet "$capture_table"
    fi
  done
}

capture_start() {
  local instance
  for instance in "$node_instance" "$gateway_instance"; do
    if capture_table_exists "$instance"; then
      echo "refusing to replace existing nftables capture table on $instance: $capture_table" >&2
      exit 3
    fi
  done
  copy_to_guest_tmp "$node_instance" "$generated_root/node-uot-capture.nft"
  copy_to_guest_tmp "$gateway_instance" "$generated_root/gateway-uot-capture.nft"
  if ! limactl shell --tty=false "$node_instance" -- sudo nft -f /tmp/node-uot-capture.nft; then
    capture_clear
    return 1
  fi
  if ! limactl shell --tty=false "$gateway_instance" -- sudo nft -f /tmp/gateway-uot-capture.nft; then
    capture_clear
    return 1
  fi
  limactl shell --tty=false "$node_instance" -- sudo rm -f /tmp/node-uot-capture.nft
  limactl shell --tty=false "$gateway_instance" -- sudo rm -f /tmp/gateway-uot-capture.nft
}

capture_snapshot() {
  local evidence_dir=$1
  local phase=$2
  limactl shell --tty=false "$node_instance" -- sudo nft list table inet "$capture_table" > "$evidence_dir/$phase-node-nft.txt"
  limactl shell --tty=false "$gateway_instance" -- sudo nft list table inet "$capture_table" > "$evidence_dir/$phase-gateway-nft.txt"
}

capture_packets() {
  local file=$1
  local marker=$2
  awk -v marker="$marker" '
    index($0, "comment \"" marker "\"") {
      for (field = 1; field <= NF; field++) {
        if ($field == "packets") {
          print $(field + 1)
          exit
        }
      }
    }
  ' "$file"
}

verify() {
  local evidence_dir=${1:-"$artifact_root/evidence-$(date -u +%Y%m%dT%H%M%SZ)"}
  local gateway_ip proxied dns_answer selected_udp
  local positive_tcp positive_node_udp positive_loopback_udp positive_gateway_udp
  local broken_tcp broken_node_udp broken_loopback_udp broken_gateway_udp
  mkdir -p "$evidence_dir"
  chmod 0700 "$evidence_dir"
  wait_for_services
  gateway_ip=$(lab_ip "$gateway_instance")
  if [ -z "$gateway_ip" ]; then
    echo "gateway lab IP was not found" >&2
    exit 4
  fi
  select_proxy RESTRICTED-VALID
  select_udp_guard RESTRICTED
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
  capture_start
  trap 'capture_clear; select_proxy RESTRICTED-VALID >/dev/null 2>&1 || true; select_udp_guard RESTRICTED >/dev/null 2>&1 || true' EXIT
  selected_udp=$(udp_probe)
  if [ "$selected_udp" != vpnctl-v2-uot-ok ]; then
    echo "selected UDP did not traverse restricted UDP-over-TCP" >&2
    exit 1
  fi
  capture_snapshot "$evidence_dir" positive-uot
  positive_tcp=$(capture_packets "$evidence_dir/positive-uot-node-nft.txt" protected-tcp)
  positive_node_udp=$(capture_packets "$evidence_dir/positive-uot-node-nft.txt" native-udp-leak)
  positive_loopback_udp=$(capture_packets "$evidence_dir/positive-uot-node-nft.txt" direct-loopback-leak)
  positive_gateway_udp=$(capture_packets "$evidence_dir/positive-uot-gateway-nft.txt" native-node-udp)
  if [ "${positive_tcp:-0}" -eq 0 ] || [ "${positive_node_udp:-0}" -ne 0 ] || \
     [ "${positive_loopback_udp:-0}" -ne 0 ] || [ "${positive_gateway_udp:-0}" -ne 0 ]; then
    echo "positive UoT capture did not prove TCP-only outer transport" >&2
    exit 1
  fi
  capture_clear

  select_proxy RESTRICTED-UOT-BLOCKED
  select_udp_guard REJECT-DROP
  proxy_state RESTRICTED-UOT-BLOCKED > "$evidence_dir/broken-uot-proxy.json"
  proxy_state RESTRICTED-UDP > "$evidence_dir/broken-uot-guard.json"
  jq -e '.udp == false and .uot == false' "$evidence_dir/broken-uot-proxy.json" >/dev/null
  jq -e '.now == "REJECT-DROP"' "$evidence_dir/broken-uot-guard.json" >/dev/null
  capture_start
  if [ "$(proxy_get)" != vpnctl-v2-shadowtls-ok ]; then
    echo "UoT-disabled negative control did not preserve selected TCP" >&2
    exit 1
  fi
  if udp_probe 2 >/dev/null 2>&1; then
    echo "selected UDP unexpectedly succeeded while UoT was disabled" >&2
    exit 1
  fi
  capture_snapshot "$evidence_dir" broken-uot
  broken_tcp=$(capture_packets "$evidence_dir/broken-uot-node-nft.txt" protected-tcp)
  broken_node_udp=$(capture_packets "$evidence_dir/broken-uot-node-nft.txt" native-udp-leak)
  broken_loopback_udp=$(capture_packets "$evidence_dir/broken-uot-node-nft.txt" direct-loopback-leak)
  broken_gateway_udp=$(capture_packets "$evidence_dir/broken-uot-gateway-nft.txt" native-node-udp)
  if [ "${broken_tcp:-0}" -eq 0 ]; then
    echo "UoT-disabled negative control did not retain protected TCP packets" >&2
    exit 1
  fi
  if [ "${broken_node_udp:-0}" -ne 0 ] || [ "${broken_loopback_udp:-0}" -ne 0 ] || \
     [ "${broken_gateway_udp:-0}" -ne 0 ]; then
    echo "selected UDP leaked through native UDP while UoT was disabled" >&2
    exit 1
  fi
  capture_clear
  select_proxy RESTRICTED-VALID
  select_udp_guard RESTRICTED
  trap - EXIT
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
    --arg udp_probe "$selected_udp" \
    --arg dns_answer "$dns_answer" \
    --arg handshake_host "$(manifest_value '.handshake_hosts.selected_for_spike')" \
    --argjson positive_tcp_packets "${positive_tcp:-0}" \
    --argjson broken_tcp_packets "${broken_tcp:-0}" \
    '{schema_version: 1, status: $status, selected_tcp: $tcp_probe, selected_udp: $udp_probe, selected_dns_a: ($dns_answer | split("\n")), handshake_host: $handshake_host, strict_wrong_host_rejected: true, udp_over_tcp_version: 2, protected_tcp_packets: {positive: $positive_tcp_packets, broken_control: $broken_tcp_packets}, native_udp_packets: {positive_node_gateway: 0, positive_node_loopback: 0, positive_gateway_input: 0, broken_node_gateway: 0, broken_node_loopback: 0, broken_gateway_input: 0}, broken_uot_blocked: true, restricted_udp_listener: false}' \
    > "$evidence_dir/summary.json"
  printf 'restricted spike evidence: %s\n' "$evidence_dir/summary.json"
}

reconnect() {
  local evidence_dir=${1:-"$artifact_root/reconnect-$(date -u +%Y%m%dT%H%M%SZ)"}
  local attempt recovered_at=0 udp_recovered_at=0
  mkdir -p "$evidence_dir"
  chmod 0700 "$evidence_dir"
  wait_for_services
  select_proxy RESTRICTED-VALID
  select_udp_guard RESTRICTED
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
  for attempt in $(seq 1 5); do
    if [ "$(udp_probe 3 2>/dev/null || true)" = vpnctl-v2-uot-ok ]; then
      udp_recovered_at=$attempt
      break
    fi
    sleep 1
  done
  if [ "$udp_recovered_at" -eq 0 ]; then
    echo "UDP-over-TCP did not recover after gateway restart" >&2
    exit 1
  fi
  "$repository_root/scripts/v2lab.sh" report "$evidence_dir/resources"
  jq -n --argjson recovered_after_attempts "$recovered_at" --argjson udp_recovered_after_attempts "$udp_recovered_at" \
    '{schema_version: 1, outage_probe_failed: true, node_restart_required: false, recovered_after_attempts: $recovered_after_attempts, udp_over_tcp_recovered: true, udp_recovered_after_attempts: $udp_recovered_after_attempts}' \
    > "$evidence_dir/summary.json"
  printf 'restricted reconnect evidence: %s\n' "$evidence_dir/summary.json"
}

udp_benchmark() {
  local profile=$1
  local count=$2
  local payload_bytes=$3
  local interval_ms=$4
  local timeout=${5:-5}
  limactl shell --tty=false "$node_instance" -- /usr/local/libexec/vpnctl-v2-spike/udp-benchmark \
    --profile "$profile" \
    --proxy 127.0.0.1:17890 \
    --target 127.0.0.1:18080 \
    --count "$count" \
    --payload-bytes "$payload_bytes" \
    --interval-ms "$interval_ms" \
    --timeout "$timeout"
}

http_benchmark() {
  local expected_sha256=$1
  limactl shell --tty=false "$node_instance" -- /usr/local/libexec/vpnctl-v2-spike/http-benchmark \
    --profile telegram-bot-api-like-tcp \
    --proxy 127.0.0.1:17890 \
    --target http://127.0.0.1:18080/telegram-api.json \
    --expected-sha256 "$expected_sha256" \
    --count 50 \
    --timeout 8
}

benchmark_cleanup() {
  if [ -n "$benchmark_probe_pid" ] && kill -0 "$benchmark_probe_pid" >/dev/null 2>&1; then
    kill "$benchmark_probe_pid" >/dev/null 2>&1 || true
    wait "$benchmark_probe_pid" >/dev/null 2>&1 || true
  fi
  benchmark_probe_pid=
  "$repository_root/scripts/v2lab.sh" fault node clear >/dev/null 2>&1 || true
  capture_clear
  select_proxy RESTRICTED-VALID >/dev/null 2>&1 || true
  select_udp_guard RESTRICTED >/dev/null 2>&1 || true
}

benchmark() {
  local evidence_dir=${1:-"$artifact_root/benchmark-$(date -u +%Y%m%dT%H%M%SZ)"}
  local expected_sha256 protected_tcp native_node_udp direct_loopback_udp native_gateway_udp
  mkdir -p "$evidence_dir"
  chmod 0700 "$evidence_dir"
  wait_for_services
  select_proxy RESTRICTED-VALID
  select_udp_guard RESTRICTED
  "$repository_root/scripts/v2lab.sh" fault node clear
  trap 'benchmark_cleanup' EXIT
  capture_start

  expected_sha256=$(shasum -a 256 "$fixture_root/telegram-api.json" | awk '{print $1}')
  http_benchmark "$expected_sha256" > "$evidence_dir/telegram-bot-api-like-tcp.json"
  udp_benchmark dns-sized-steady 150 64 20 5 > "$evidence_dir/dns-sized-steady.json"
  udp_benchmark small-interactive-steady 100 256 50 5 > "$evidence_dir/small-interactive-steady.json"
  udp_benchmark mtu-safe-steady 100 1200 50 5 > "$evidence_dir/mtu-safe-steady.json"
  udp_benchmark mtu-safe-burst-observational 500 1200 1 8 > "$evidence_dir/mtu-safe-burst-observational.json"
  udp_benchmark hol-baseline 300 256 10 5 > "$evidence_dir/hol-baseline.json"

  udp_benchmark hol-250ms-peer-partition 300 256 10 8 > "$evidence_dir/hol-250ms-peer-partition.json" &
  benchmark_probe_pid=$!
  sleep 0.5
  "$repository_root/scripts/v2lab.sh" fault node partition
  sleep 0.25
  "$repository_root/scripts/v2lab.sh" fault node clear
  if ! wait "$benchmark_probe_pid"; then
    echo "head-of-line benchmark process failed" >&2
    exit 1
  fi
  benchmark_probe_pid=
  udp_benchmark post-fault-recovery 50 256 20 5 > "$evidence_dir/post-fault-recovery.json"

  jq -e '.status == "passed" and .requests == 50 and .success == 50 and .failures == 0' \
    "$evidence_dir/telegram-bot-api-like-tcp.json" >/dev/null
  local profile
  for profile in dns-sized-steady small-interactive-steady mtu-safe-steady hol-baseline post-fault-recovery; do
    jq -e '.status == "passed" and .received == .sent and .lost == 0 and .invalid == 0' \
      "$evidence_dir/$profile.json" >/dev/null
  done
  jq -e --slurpfile baseline "$evidence_dir/hol-baseline.json" '
    .received > 0 and
    .responses_over_100ms > 0 and
    .rtt_ms.max >= 200 and
    (.rtt_ms.max - $baseline[0].rtt_ms.max) >= 100
  ' "$evidence_dir/hol-250ms-peer-partition.json" >/dev/null

  capture_snapshot "$evidence_dir" benchmark
  protected_tcp=$(capture_packets "$evidence_dir/benchmark-node-nft.txt" protected-tcp)
  native_node_udp=$(capture_packets "$evidence_dir/benchmark-node-nft.txt" native-udp-leak)
  direct_loopback_udp=$(capture_packets "$evidence_dir/benchmark-node-nft.txt" direct-loopback-leak)
  native_gateway_udp=$(capture_packets "$evidence_dir/benchmark-gateway-nft.txt" native-node-udp)
  if [ "${protected_tcp:-0}" -eq 0 ] || [ "${native_node_udp:-0}" -ne 0 ] || \
     [ "${direct_loopback_udp:-0}" -ne 0 ] || [ "${native_gateway_udp:-0}" -ne 0 ]; then
    echo "benchmark capture did not retain TCP-only outer transport" >&2
    exit 1
  fi
  capture_clear
  "$repository_root/scripts/v2lab.sh" report "$evidence_dir/resources"

  jq -n \
    --slurpfile telegram "$evidence_dir/telegram-bot-api-like-tcp.json" \
    --slurpfile dns "$evidence_dir/dns-sized-steady.json" \
    --slurpfile interactive "$evidence_dir/small-interactive-steady.json" \
    --slurpfile mtu "$evidence_dir/mtu-safe-steady.json" \
    --slurpfile burst "$evidence_dir/mtu-safe-burst-observational.json" \
    --slurpfile baseline "$evidence_dir/hol-baseline.json" \
    --slurpfile impaired "$evidence_dir/hol-250ms-peer-partition.json" \
    --slurpfile recovery "$evidence_dir/post-fault-recovery.json" \
    --argjson protected_tcp_packets "${protected_tcp:-0}" \
    '{
      schema_version: 1,
      status: "passed",
      environment: {gateway: "1 vCPU/512 MiB/10 GiB", node: "1 vCPU/512 MiB/10 GiB"},
      telegram_bot_api_like_tcp: $telegram[0],
      udp: {
        dns_sized_steady: $dns[0],
        small_interactive_steady: $interactive[0],
        mtu_safe_steady: $mtu[0],
        mtu_safe_burst_observational: $burst[0],
        head_of_line: {
          baseline: $baseline[0],
          peer_partition_ms: 250,
          impaired: $impaired[0],
          observed: true
        },
        post_fault_recovery: $recovery[0]
      },
      supported_functional_bounds: {
        path_condition: "healthy restricted path",
        single_uot_association_profiles: [
          {application_payload_bytes: 64, packets_per_second: 50},
          {application_payload_bytes: 256, packets_per_second: 20},
          {application_payload_bytes: 1200, packets_per_second: 20}
        ],
        required_result: "all probe responses within the bounded validation timeout",
        service_level_objective: false
      },
      no_performance_guarantee: [
        "voice or video calls",
        "gaming",
        "QUIC or HTTP/3",
        "bulk or sustained high-rate UDP",
        "UDP during loss, reordering, congestion, or path interruption",
        "payloads above the tested 1200-byte application datagram"
      ],
      outer_transport: {protected_tcp_packets: $protected_tcp_packets, native_udp_packets: 0}
    }' > "$evidence_dir/summary.json"
  select_proxy RESTRICTED-VALID
  select_udp_guard RESTRICTED
  trap - EXIT
  printf 'restricted benchmark evidence: %s\n' "$evidence_dir/summary.json"
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
  limactl shell --tty=false "$gateway_instance" -- systemctl status --no-pager "$echo_unit" "$udp_echo_unit" "$gateway_unit"
  limactl shell --tty=false "$node_instance" -- systemctl status --no-pager "$node_unit"
}

stop_spike() {
  assert_owned_or_absent "$gateway_instance"
  assert_owned_or_absent "$node_instance"
  limactl shell --tty=false "$node_instance" -- sudo systemctl stop "$node_unit"
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl stop "$gateway_unit" "$udp_echo_unit" "$echo_unit"
  capture_clear
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
  limactl shell --tty=false "$instance" -- sudo rm -f \
    /usr/local/libexec/vpnctl-v2-spike/mihomo \
    /usr/local/libexec/vpnctl-v2-spike/udp-echo \
    /usr/local/libexec/vpnctl-v2-spike/http-benchmark \
    /usr/local/libexec/vpnctl-v2-spike/udp-benchmark \
    /usr/local/libexec/vpnctl-v2-spike/udp-probe
  limactl shell --tty=false "$instance" -- sudo rmdir /usr/local/libexec/vpnctl-v2-spike 2>/dev/null || true
  limactl shell --tty=false "$instance" -- sudo systemctl daemon-reload
}

uninstall_spike() {
  uninstall_role "$node_instance" "$node_unit"
  uninstall_role "$gateway_instance" "$gateway_unit" "$echo_unit" "$udp_echo_unit"
  capture_clear
}

command=${1:-}
case "$command" in
  prepare) prepare ;;
  verify) verify "${2:-}" ;;
  reconnect) reconnect "${2:-}" ;;
  benchmark) benchmark "${2:-}" ;;
  render-client) render_client "${2:-}" "${3:-}" ;;
  status) status ;;
  stop) stop_spike ;;
  uninstall) uninstall_spike ;;
  *) usage >&2; exit 2 ;;
esac
