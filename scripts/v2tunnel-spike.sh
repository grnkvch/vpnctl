#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
fixture_root="$repository_root/test/v2lab/tunnel"
manifest="$fixture_root/manifest.json"
artifact_root="$repository_root/artifacts/v2lab/tunnel-spike"
cache_root="$repository_root/artifacts/v2lab/cache"
generated_root="$artifact_root/generated"
credentials_file="$artifact_root/credentials.env"
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
gateway_auth_unit=vpnctl-v2-spike-tunnel-auth.service
gateway_server_unit=vpnctl-v2-spike-tunnel-server.service
node_client_unit=vpnctl-v2-spike-tunnel-client.service
node_backend_unit=vpnctl-v2-spike-tunnel-backend.service
restricted_gateway_unit=vpnctl-v2-spike-restricted-gateway.service
restricted_node_unit=vpnctl-v2-spike-restricted-node.service
restricted_echo_unit=vpnctl-v2-spike-echo.service
restricted_udp_unit=vpnctl-v2-spike-udp-echo.service
owner_value=vpnctl-v2-tunnel-spike-v1
owner_path=/etc/vpnctl-v2-spike/tunnel/.owner
gateway_state_path=/var/lib/vpnctl-v2-spike-tunnel-auth/state.json
gateway_metrics_path=/var/lib/vpnctl-v2-spike-tunnel-auth/metrics.json
capture_table=vpnctl_v2_spike_tunnel_capture
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
probe_pid=
restricted_started_by_tunnel=false
saved_mihomo_mode=
saved_global_selector=
saved_restricted_selector=
saved_udp_selector=
transport_cleanup_armed=false
auth_state_hidden=false
frpc_binary=
frps_binary=

usage() {
  cat <<'EOF'
Usage:
  scripts/v2tunnel-spike.sh fetch
  scripts/v2tunnel-spike.sh prepare
  scripts/v2tunnel-spike.sh verify [evidence-directory]
  scripts/v2tunnel-spike.sh status
  scripts/v2tunnel-spike.sh stop
  scripts/v2tunnel-spike.sh uninstall
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
  if ! instance_json "$instance" | jq -e --arg digest "$lab_image_digest" '
    .status == "Running" and
    .vmType == "qemu" and
    .arch == "x86_64" and
    .cpus == 1 and
    .memory == 536870912 and
    .disk == 10737418240 and
    .config.images[0].digest == $digest and
    any(.network[]?; .lima == "user-v2")
  ' >/dev/null; then
    echo "required contract-matching lab instance is not running: $instance" >&2
    exit 4
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
    echo "refusing to expose tunnel spike port $port through Lima host forwarding on $instance" >&2
    exit 3
  fi
}

lab_ip() {
  limactl shell --tty=false "$1" -- ip -4 -o address show scope global | \
    awk '$4 ~ /^192[.]168[.]104[.]/ {sub(/\/.*/, "", $4); print $4; exit}'
}

assert_owned_or_absent() {
  local instance=$1
  if limactl shell --tty=false "$instance" -- sudo test -e /etc/vpnctl-v2-spike/tunnel; then
    if ! limactl shell --tty=false "$instance" -- sudo grep -Fxq "$owner_value" "$owner_path"; then
      echo "refusing to overwrite unowned tunnel spike path on $instance" >&2
      exit 3
    fi
  else
    local candidate
    for candidate in \
      /etc/systemd/system/$gateway_auth_unit \
      /etc/systemd/system/$gateway_server_unit \
      /etc/systemd/system/$node_client_unit \
      /etc/systemd/system/$node_backend_unit \
      /usr/local/libexec/vpnctl-v2-spike/frps \
      /usr/local/libexec/vpnctl-v2-spike/frpc; do
      if limactl shell --tty=false "$instance" -- sudo test -e "$candidate"; then
        echo "refusing to claim stale unowned tunnel resource on $instance: $candidate" >&2
        exit 3
      fi
    done
  fi
}

assert_port_free_or_owned() {
  local instance=$1
  local port=$2
  local owning_unit=$3
  if limactl shell --tty=false "$instance" -- systemctl is-active --quiet "$owning_unit"; then
    return
  fi
  if [ -n "$(limactl shell --tty=false "$instance" -- sudo ss -H -ltn "sport = :$port")" ]; then
    echo "refusing to claim occupied TCP port $port on $instance" >&2
    exit 3
  fi
}

copy_to_guest_tmp() {
  local instance=$1
  shift
  limactl copy --backend=scp "$@" "$instance:/tmp/"
}

ensure_credentials() {
  local temporary
  mkdir -p "$artifact_root" "$generated_root"
  chmod 0700 "$artifact_root" "$generated_root"
  if [ ! -e "$credentials_file" ]; then
    temporary="$credentials_file.tmp.$$"
    umask 077
    {
      printf 'TUNNEL_TOKEN=%s\n' "$(openssl rand -hex 32)"
      printf 'BOOTSTRAP_TOKEN=%s\n' "$(openssl rand -hex 32)"
      printf 'ADMIN_PASSWORD=%s\n' "$(openssl rand -hex 24)"
    } > "$temporary"
    mv "$temporary" "$credentials_file"
  fi
  chmod 0600 "$credentials_file"
  # shellcheck disable=SC1090
  source "$credentials_file"
  if [[ ! "$TUNNEL_TOKEN" =~ ^[a-f0-9]{64}$ ]] || \
     [[ ! "$BOOTSTRAP_TOKEN" =~ ^[a-f0-9]{64}$ ]] || \
     [[ ! "$ADMIN_PASSWORD" =~ ^[a-f0-9]{48}$ ]]; then
    echo "invalid tunnel spike credential file; move it aside and rerun prepare" >&2
    exit 3
  fi
}

render_client_config() {
  local destination=$1
  local gateway_ip=$2
  local proxy_line=$3
  local temporary="$destination.tmp.$$"
  sed \
    -e "s|@GATEWAY_IP@|$gateway_ip|g" \
    -e "s|@ADMIN_PASSWORD@|$ADMIN_PASSWORD|g" \
    -e "s|@TUNNEL_TOKEN@|$TUNNEL_TOKEN|g" \
    -e "s|@PROXY_URL@|$proxy_line|g" \
    "$fixture_root/frpc.toml.tmpl" > "$temporary"
  chmod 0600 "$temporary"
  mv "$temporary" "$destination"
}

render_configs() {
  local gateway_ip=$1
  local token_sha temporary
  ensure_credentials
  sed "s|@GATEWAY_IP@|$gateway_ip|g" "$fixture_root/frps.toml.tmpl" > "$generated_root/frps.toml"
  chmod 0600 "$generated_root/frps.toml"
  render_client_config "$generated_root/frpc-standard.toml" "$gateway_ip" "# standard transport: direct overlay connection"
  render_client_config "$generated_root/frpc-restricted.toml" "$gateway_ip" 'transport.proxyURL = "socks5://127.0.0.1:17890"'
  sed \
    -e 's/clientID = "vpnctl-node-a"/clientID = "vpnctl-node-a-old-generation"/' \
    -e 's/loginFailExit = false/loginFailExit = true/' \
    -e 's/metadatas.generation = "1"/metadatas.generation = "0"/' \
    -e '/^webServer[.]/d' \
    -e '/^includes =/d' \
    "$generated_root/frpc-standard.toml" > "$generated_root/frpc-old-generation.toml"
  chmod 0600 "$generated_root/frpc-old-generation.toml"
  sed \
    -e 's/clientID = "vpnctl-node-a"/clientID = "vpnctl-node-a-untrusted-server"/' \
    -e 's/loginFailExit = false/loginFailExit = true/' \
    -e 's|transport.tls.trustedCaFile = .*|transport.tls.trustedCaFile = "/etc/ssl/certs/ca-certificates.crt"|' \
    -e '/^webServer[.]/d' \
    -e '/^includes =/d' \
    "$generated_root/frpc-standard.toml" > "$generated_root/frpc-untrusted-server.toml"
  chmod 0600 "$generated_root/frpc-untrusted-server.toml"
  sed \
    -e 's/clientID = "vpnctl-node-a"/clientID = "vpnctl-node-a-pool-negative"/' \
    -e 's/loginFailExit = false/loginFailExit = true/' \
    -e 's/transport.poolCount = 0/transport.poolCount = 2/' \
    -e '/^webServer[.]/d' \
    -e '/^includes =/d' \
    "$generated_root/frpc-standard.toml" > "$generated_root/frpc-pool-negative.toml"
  chmod 0600 "$generated_root/frpc-pool-negative.toml"
  printf '%s\n' "$BOOTSTRAP_TOKEN" > "$generated_root/bootstrap-token"
  chmod 0600 "$generated_root/bootstrap-token"
  token_sha=$(printf '%s' "$TUNNEL_TOKEN" | shasum -a 256 | awk '{print $1}')
  temporary="$generated_root/auth-state.json.tmp.$$"
  jq -n --arg token_sha "$token_sha" '{
    schema_version: 1,
    nodes: {
      "node-a": {
        active: true,
        generation: "1",
        token_sha256: $token_sha,
        allowed_proxies: [
          {name: "node-a-expose-1", type: "tcp", remote_port: 18111, generation: "1"},
          {name: "node-a-expose-2", type: "tcp", remote_port: 18112, generation: "1"}
        ]
      }
    }
  }' > "$temporary"
  chmod 0600 "$temporary"
  mv "$temporary" "$generated_root/auth-state.json"
  sed "s|@GATEWAY_IP@|$gateway_ip|g" "$fixture_root/capture.nft.tmpl" > "$generated_root/capture.nft"
  chmod 0600 "$generated_root/capture.nft"
}

fetch_frp() {
  local archive expected actual version extract_root extracted_dir
  local frpc_cache frps_cache
  mkdir -p "$cache_root"
  version=$(manifest_value '.frp.version')
  archive="$cache_root/$(manifest_value '.frp.asset')"
  frpc_cache="$cache_root/frpc-$version"
  frps_cache="$cache_root/frps-$version"
  expected=$(manifest_value '.frp.sha256')
  if [ ! -e "$archive" ]; then
    curl --fail --location --proto '=https' --tlsv1.2 \
      --output "$archive.partial" "$(manifest_value '.frp.url')"
    mv "$archive.partial" "$archive"
  fi
  actual=$(shasum -a 256 "$archive" | awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    echo "frp archive checksum mismatch" >&2
    exit 3
  fi
  if [ ! -x "$frpc_cache" ] || [ ! -x "$frps_cache" ]; then
    extract_root=$(mktemp -d "$cache_root/frp-extract.XXXXXX")
    tar -xzf "$archive" -C "$extract_root"
    extracted_dir="$extract_root/frp_${version}_linux_amd64"
    install -m 0755 "$extracted_dir/frpc" "$frpc_cache.tmp"
    install -m 0755 "$extracted_dir/frps" "$frps_cache.tmp"
    mv "$frpc_cache.tmp" "$frpc_cache"
    mv "$frps_cache.tmp" "$frps_cache"
    rm -r "$extract_root"
  fi
  frpc_binary=$frpc_cache
  frps_binary=$frps_cache
}

install_gateway() {
  local frps_binary=$1
  limactl shell --tty=false "$gateway_instance" -- sudo install -d -m 0700 /etc/vpnctl-v2-spike/tunnel
  limactl shell --tty=false "$gateway_instance" -- sudo sh -c "printf '%s\n' '$owner_value' > '$owner_path'"
  limactl shell --tty=false "$gateway_instance" -- sudo chmod 0600 "$owner_path"
  copy_to_guest_tmp "$gateway_instance" \
    "$frps_binary" \
    "$generated_root/frps.toml" \
    "$generated_root/bootstrap-token" \
    "$generated_root/auth-state.json" \
    "$fixture_root/auth_plugin.py" \
    "$fixture_root/probe.py" \
    "$fixture_root/systemd/$gateway_auth_unit" \
    "$fixture_root/systemd/$gateway_server_unit"
  limactl shell --tty=false "$gateway_instance" -- sudo install -d -m 0755 /usr/local/libexec/vpnctl-v2-spike
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0755 \
    "/tmp/$(basename "$frps_binary")" /usr/local/libexec/vpnctl-v2-spike/frps
  if [ "$(limactl shell --tty=false "$gateway_instance" -- /usr/local/libexec/vpnctl-v2-spike/frps --version)" != "$(manifest_value '.frp.version')" ]; then
    echo "installed gateway frps version mismatch" >&2
    exit 3
  fi
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0755 \
    /tmp/auth_plugin.py /usr/local/libexec/vpnctl-v2-spike/tunnel-auth-plugin
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0755 \
    /tmp/probe.py /usr/local/libexec/vpnctl-v2-spike/tunnel-probe
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0600 \
    /tmp/frps.toml /etc/vpnctl-v2-spike/tunnel/frps.toml
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0600 \
    /tmp/bootstrap-token /etc/vpnctl-v2-spike/tunnel/bootstrap-token
  limactl shell --tty=false "$gateway_instance" -- sudo install -d -m 0700 /var/lib/vpnctl-v2-spike-tunnel-auth
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0600 \
    /tmp/auth-state.json "$gateway_state_path"
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0644 \
    "/tmp/$gateway_auth_unit" "/etc/systemd/system/$gateway_auth_unit"
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0644 \
    "/tmp/$gateway_server_unit" "/etc/systemd/system/$gateway_server_unit"

  if ! limactl shell --tty=false "$gateway_instance" -- sudo test -e /etc/vpnctl-v2-spike/tunnel/server.key; then
    limactl shell --tty=false "$gateway_instance" -- sudo openssl req \
      -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
      -subj /CN=vpnctl-tunnel-gateway \
      -addext subjectAltName=DNS:vpnctl-tunnel-gateway \
      -keyout /etc/vpnctl-v2-spike/tunnel/server.key.tmp \
      -out /etc/vpnctl-v2-spike/tunnel/server.crt.tmp >/dev/null 2>&1
    limactl shell --tty=false "$gateway_instance" -- sudo chmod 0600 /etc/vpnctl-v2-spike/tunnel/server.key.tmp
    limactl shell --tty=false "$gateway_instance" -- sudo chmod 0644 /etc/vpnctl-v2-spike/tunnel/server.crt.tmp
    limactl shell --tty=false "$gateway_instance" -- sudo mv \
      /etc/vpnctl-v2-spike/tunnel/server.key.tmp /etc/vpnctl-v2-spike/tunnel/server.key
    limactl shell --tty=false "$gateway_instance" -- sudo mv \
      /etc/vpnctl-v2-spike/tunnel/server.crt.tmp /etc/vpnctl-v2-spike/tunnel/server.crt
  fi
  limactl shell --tty=false "$gateway_instance" -- sudo openssl verify \
    -CAfile /etc/vpnctl-v2-spike/tunnel/server.crt /etc/vpnctl-v2-spike/tunnel/server.crt >/dev/null
  limactl shell --tty=false "$gateway_instance" -- sudo openssl x509 \
    -in /etc/vpnctl-v2-spike/tunnel/server.crt -noout -checkhost vpnctl-tunnel-gateway | \
    grep -Fq 'does match certificate'
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0644 \
    /etc/vpnctl-v2-spike/tunnel/server.crt /tmp/vpnctl-v2-tunnel-server.crt
  limactl copy --backend=scp "$gateway_instance:/tmp/vpnctl-v2-tunnel-server.crt" "$generated_root/server.crt"
  limactl shell --tty=false "$gateway_instance" -- sudo rm -f /tmp/vpnctl-v2-tunnel-server.crt
  chmod 0644 "$generated_root/server.crt"
  limactl shell --tty=false "$gateway_instance" -- sudo /usr/local/libexec/vpnctl-v2-spike/frps verify \
    -c /etc/vpnctl-v2-spike/tunnel/frps.toml
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl daemon-reload
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl reset-failed \
    "$gateway_auth_unit" "$gateway_server_unit" >/dev/null 2>&1 || true
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl restart \
    "$gateway_auth_unit" "$gateway_server_unit"
}

install_node() {
  local frpc_binary=$1
  limactl shell --tty=false "$node_instance" -- sudo install -d -m 0700 /etc/vpnctl-v2-spike/tunnel
  limactl shell --tty=false "$node_instance" -- sudo sh -c "printf '%s\n' '$owner_value' > '$owner_path'"
  limactl shell --tty=false "$node_instance" -- sudo chmod 0600 "$owner_path"
  copy_to_guest_tmp "$node_instance" \
    "$frpc_binary" \
    "$generated_root/frpc-standard.toml" \
    "$generated_root/bootstrap-token" \
    "$generated_root/server.crt" \
    "$fixture_root/proxies-one.toml" \
    "$fixture_root/backend.py" \
    "$fixture_root/probe.py" \
    "$fixture_root/systemd/$node_client_unit" \
    "$fixture_root/systemd/$node_backend_unit"
  limactl shell --tty=false "$node_instance" -- sudo install -d -m 0755 /usr/local/libexec/vpnctl-v2-spike
  limactl shell --tty=false "$node_instance" -- sudo install -m 0755 \
    "/tmp/$(basename "$frpc_binary")" /usr/local/libexec/vpnctl-v2-spike/frpc
  if [ "$(limactl shell --tty=false "$node_instance" -- /usr/local/libexec/vpnctl-v2-spike/frpc --version)" != "$(manifest_value '.frp.version')" ]; then
    echo "installed node frpc version mismatch" >&2
    exit 3
  fi
  limactl shell --tty=false "$node_instance" -- sudo install -m 0755 \
    /tmp/backend.py /usr/local/libexec/vpnctl-v2-spike/tunnel-backend
  limactl shell --tty=false "$node_instance" -- sudo install -m 0755 \
    /tmp/probe.py /usr/local/libexec/vpnctl-v2-spike/tunnel-probe
  limactl shell --tty=false "$node_instance" -- sudo install -m 0600 \
    /tmp/frpc-standard.toml /etc/vpnctl-v2-spike/tunnel/frpc.toml
  limactl shell --tty=false "$node_instance" -- sudo install -m 0600 \
    /tmp/bootstrap-token /etc/vpnctl-v2-spike/tunnel/bootstrap-token
  limactl shell --tty=false "$node_instance" -- sudo install -m 0644 \
    /tmp/server.crt /etc/vpnctl-v2-spike/tunnel/server.crt
  limactl shell --tty=false "$node_instance" -- sudo install -m 0600 \
    /tmp/proxies-one.toml /etc/vpnctl-v2-spike/tunnel/proxies.toml
  limactl shell --tty=false "$node_instance" -- sudo install -m 0644 \
    "/tmp/$node_client_unit" "/etc/systemd/system/$node_client_unit"
  limactl shell --tty=false "$node_instance" -- sudo install -m 0644 \
    "/tmp/$node_backend_unit" "/etc/systemd/system/$node_backend_unit"
  limactl shell --tty=false "$node_instance" -- sudo /usr/local/libexec/vpnctl-v2-spike/frpc verify \
    -c /etc/vpnctl-v2-spike/tunnel/frpc.toml
  limactl shell --tty=false "$node_instance" -- sudo systemctl daemon-reload
  limactl shell --tty=false "$node_instance" -- sudo systemctl reset-failed \
    "$node_backend_unit" "$node_client_unit" >/dev/null 2>&1 || true
  limactl shell --tty=false "$node_instance" -- sudo systemctl restart \
    "$node_backend_unit" "$node_client_unit"
}

wait_unit_active() {
  local instance=$1
  local unit=$2
  local attempt
  for attempt in $(seq 1 30); do
    if limactl shell --tty=false "$instance" -- systemctl is-active --quiet "$unit"; then
      return
    fi
    sleep 1
  done
  echo "unit did not become active on $instance: $unit" >&2
  exit 4
}

gateway_port_open() {
  local port=$1
  limactl shell --tty=false "$gateway_instance" -- nc -z -w 1 127.0.0.1 "$port" >/dev/null 2>&1
}

wait_gateway_port() {
  local port=$1
  local expected=$2
  local attempt
  for attempt in $(seq 1 40); do
    if gateway_port_open "$port"; then
      [ "$expected" = open ] && return
    else
      [ "$expected" = closed ] && return
    fi
    sleep 0.25
  done
  echo "gateway port $port did not become $expected" >&2
  exit 4
}

wait_initial_tunnel() {
  wait_unit_active "$gateway_instance" "$gateway_auth_unit"
  wait_unit_active "$gateway_instance" "$gateway_server_unit"
  wait_unit_active "$node_instance" "$node_backend_unit"
  wait_unit_active "$node_instance" "$node_client_unit"
  wait_gateway_port 18111 open
  wait_gateway_port 18112 closed
}

probe_gateway() {
  local port=$1
  local label=$2
  limactl shell --tty=false "$gateway_instance" -- \
    /usr/local/libexec/vpnctl-v2-spike/tunnel-probe \
    --target "127.0.0.1:$port=$label" --streams-per-target 1 --timeout 3 >/dev/null
}

prepare() {
  local gateway_ip
  assert_lab_instance "$gateway_instance"
  assert_lab_instance "$node_instance"
  local instance port
  for instance in "$gateway_instance" "$node_instance"; do
    for port in 17000 17400 18111 18112 18121 18122 19091; do
      assert_forward_ignored "$instance" "$port"
    done
    assert_owned_or_absent "$instance"
  done
  assert_port_free_or_owned "$gateway_instance" 17000 "$gateway_server_unit"
  assert_port_free_or_owned "$gateway_instance" 18111 "$gateway_server_unit"
  assert_port_free_or_owned "$gateway_instance" 18112 "$gateway_server_unit"
  assert_port_free_or_owned "$gateway_instance" 19091 "$gateway_auth_unit"
  assert_port_free_or_owned "$node_instance" 17400 "$node_client_unit"
  assert_port_free_or_owned "$node_instance" 18121 "$node_backend_unit"
  assert_port_free_or_owned "$node_instance" 18122 "$node_backend_unit"
  if lsof -nP -iTCP:17000 -sTCP:LISTEN 2>/dev/null | grep . >/dev/null; then
    echo "refusing to overlap an existing development-host TCP/17000 listener" >&2
    exit 3
  fi
  gateway_ip=$(lab_ip "$gateway_instance")
  if [ -z "$gateway_ip" ]; then
    echo "gateway lab IP was not found" >&2
    exit 4
  fi
  render_configs "$gateway_ip"
  fetch_frp
  if [ -z "$frpc_binary" ] || [ -z "$frps_binary" ]; then
    echo "failed to resolve pinned frp binaries" >&2
    exit 3
  fi
  install_gateway "$frps_binary"
  install_node "$frpc_binary"
  wait_initial_tunnel
  probe_gateway 18111 backend-one
  if lsof -nP -iTCP:17000 -sTCP:LISTEN 2>/dev/null | grep . >/dev/null; then
    echo "Lima unexpectedly forwarded tunnel server port to the development host" >&2
    exit 3
  fi
  echo "frp tunnel spike prepared; secrets remain only in root-owned guest files and ignored artifacts"
}

node_frpc_pid() {
  limactl shell --tty=false "$node_instance" -- systemctl show "$node_client_unit" -p MainPID --value
}

direct_control_connections() {
  limactl shell --tty=false "$node_instance" -- sudo ss -Htnp state established \( dport = :17000 \) | \
    awk '/frpc/ {count++} END {print count + 0}'
}

local_proxy_connections() {
  limactl shell --tty=false "$node_instance" -- sudo ss -Htnp state established \( dport = :17890 \) | \
    awk '/frpc/ {count++} END {print count + 0}'
}

gateway_control_connections() {
  limactl shell --tty=false "$gateway_instance" -- sudo ss -Htnp state established \( sport = :17000 \) | \
    awk '/frps/ {count++} END {print count + 0}'
}

apply_proxy_file() {
  local source=$1
  local source_name
  source_name=$(basename "$source")
  copy_to_guest_tmp "$node_instance" "$source"
  if ! limactl shell --tty=false "$node_instance" -- sudo sh -c "
    set -eu
    install -m 0600 '/tmp/$source_name' /etc/vpnctl-v2-spike/tunnel/proxies.toml.next
    cp -p /etc/vpnctl-v2-spike/tunnel/proxies.toml /etc/vpnctl-v2-spike/tunnel/proxies.toml.previous
    mv /etc/vpnctl-v2-spike/tunnel/proxies.toml.next /etc/vpnctl-v2-spike/tunnel/proxies.toml
    if ! /usr/local/libexec/vpnctl-v2-spike/frpc verify -c /etc/vpnctl-v2-spike/tunnel/frpc.toml; then
      mv /etc/vpnctl-v2-spike/tunnel/proxies.toml.previous /etc/vpnctl-v2-spike/tunnel/proxies.toml
      exit 1
    fi
    if ! /usr/local/libexec/vpnctl-v2-spike/frpc reload -c /etc/vpnctl-v2-spike/tunnel/frpc.toml; then
      mv /etc/vpnctl-v2-spike/tunnel/proxies.toml.previous /etc/vpnctl-v2-spike/tunnel/proxies.toml
      /usr/local/libexec/vpnctl-v2-spike/frpc reload -c /etc/vpnctl-v2-spike/tunnel/frpc.toml >/dev/null 2>&1 || true
      exit 1
    fi
    rm -f /etc/vpnctl-v2-spike/tunnel/proxies.toml.previous '/tmp/$source_name'
  "; then
    echo "atomic frpc proxy reload failed" >&2
    return 1
  fi
}

apply_client_config() {
  local source=$1
  local source_name
  source_name=$(basename "$source")
  copy_to_guest_tmp "$node_instance" "$source"
  if ! limactl shell --tty=false "$node_instance" -- sudo sh -c "
    set -eu
    install -m 0600 '/tmp/$source_name' /etc/vpnctl-v2-spike/tunnel/frpc.toml.next
    cp -p /etc/vpnctl-v2-spike/tunnel/frpc.toml /etc/vpnctl-v2-spike/tunnel/frpc.toml.previous
    mv /etc/vpnctl-v2-spike/tunnel/frpc.toml.next /etc/vpnctl-v2-spike/tunnel/frpc.toml
    if ! /usr/local/libexec/vpnctl-v2-spike/frpc verify -c /etc/vpnctl-v2-spike/tunnel/frpc.toml; then
      mv /etc/vpnctl-v2-spike/tunnel/frpc.toml.previous /etc/vpnctl-v2-spike/tunnel/frpc.toml
      exit 1
    fi
    if ! systemctl restart '$node_client_unit'; then
      mv /etc/vpnctl-v2-spike/tunnel/frpc.toml.previous /etc/vpnctl-v2-spike/tunnel/frpc.toml
      systemctl restart '$node_client_unit' >/dev/null 2>&1 || true
      exit 1
    fi
    rm -f /etc/vpnctl-v2-spike/tunnel/frpc.toml.previous '/tmp/$source_name'
  "; then
    echo "atomic frpc transport switch failed" >&2
    return 1
  fi
}

plugin_metrics() {
  limactl shell --tty=false "$gateway_instance" -- sudo cat "$gateway_metrics_path"
}

metric_total() {
  local operation=$1
  plugin_metrics | jq -er --arg operation "$operation" \
    '.requests[$operation] | .allowed + .rejected'
}

run_rejected_client() {
  local source=$1
  local source_name
  source_name=$(basename "$source")
  copy_to_guest_tmp "$node_instance" "$source"
  limactl shell --tty=false "$node_instance" -- sudo chmod 0600 "/tmp/$source_name"
  if limactl shell --tty=false "$node_instance" -- sudo timeout 8 \
    /usr/local/libexec/vpnctl-v2-spike/frpc -c "/tmp/$source_name" >/dev/null 2>&1; then
    limactl shell --tty=false "$node_instance" -- sudo rm -f "/tmp/$source_name"
    echo "negative frpc identity unexpectedly connected: $source_name" >&2
    return 1
  fi
  limactl shell --tty=false "$node_instance" -- sudo rm -f "/tmp/$source_name"
}

set_node_active() {
  local active=$1
  limactl shell --tty=false "$gateway_instance" -- sudo \
    /usr/local/libexec/vpnctl-v2-spike/tunnel-auth-plugin set-active \
    --state "$gateway_state_path" --node node-a --active "$active"
}

hide_auth_state() {
  limactl shell --tty=false "$gateway_instance" -- sudo sh -c "
    set -eu
    test -e '$gateway_state_path'
    test ! -e '$gateway_state_path.unavailable'
    mv '$gateway_state_path' '$gateway_state_path.unavailable'
  "
  auth_state_hidden=true
}

restore_auth_state() {
  if [ "$auth_state_hidden" != true ]; then
    return
  fi
  limactl shell --tty=false "$gateway_instance" -- sudo sh -c "
    set -eu
    test ! -e '$gateway_state_path'
    test -e '$gateway_state_path.unavailable'
    mv '$gateway_state_path.unavailable' '$gateway_state_path'
  "
  auth_state_hidden=false
}

restore_auth_state_best_effort() {
  if [ "$auth_state_hidden" != true ]; then
    return
  fi
  limactl shell --tty=false "$gateway_instance" -- sudo sh -c "
    if [ ! -e '$gateway_state_path' ] && [ -e '$gateway_state_path.unavailable' ]; then
      mv '$gateway_state_path.unavailable' '$gateway_state_path'
    fi
  " >/dev/null 2>&1 || true
  auth_state_hidden=false
}

capture_exists() {
  limactl shell --tty=false "$node_instance" -- sudo nft list table inet "$capture_table" >/dev/null 2>&1
}

capture_clear() {
  if capture_exists; then
    limactl shell --tty=false "$node_instance" -- sudo nft delete table inet "$capture_table"
  fi
}

capture_start() {
  if capture_exists; then
    echo "refusing to replace existing tunnel capture table" >&2
    exit 3
  fi
  copy_to_guest_tmp "$node_instance" "$generated_root/capture.nft"
  if ! limactl shell --tty=false "$node_instance" -- sudo nft -f /tmp/capture.nft; then
    capture_clear
    return 1
  fi
  limactl shell --tty=false "$node_instance" -- sudo rm -f /tmp/capture.nft
}

capture_snapshot() {
  local destination=$1
  limactl shell --tty=false "$node_instance" -- sudo nft list table inet "$capture_table" > "$destination"
}

capture_packets() {
  local source=$1
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
  ' "$source"
}

restricted_active_count() {
  local count=0 unit instance
  for unit in "$restricted_gateway_unit" "$restricted_echo_unit" "$restricted_udp_unit"; do
    instance=$gateway_instance
    if limactl shell --tty=false "$instance" -- systemctl is-active --quiet "$unit"; then
      count=$((count + 1))
    fi
  done
  if limactl shell --tty=false "$node_instance" -- systemctl is-active --quiet "$restricted_node_unit"; then
    count=$((count + 1))
  fi
  printf '%s\n' "$count"
}

ensure_restricted_transport() {
  local active_count
  active_count=$(restricted_active_count)
  case "$active_count" in
    0)
      "$repository_root/scripts/v2restricted-spike.sh" prepare
      restricted_started_by_tunnel=true
      ;;
    4)
      restricted_started_by_tunnel=false
      ;;
    *)
      echo "restricted spike has a partial active state; refusing transport-switch mutation" >&2
      exit 3
      ;;
  esac
}

mihomo_get() {
  local path=$1
  limactl shell --tty=false "$node_instance" -- curl -fsS --max-time 3 \
    "http://127.0.0.1:19090$path"
}

mihomo_select() {
  local group=$1
  local selected=$2
  local payload
  payload=$(jq -nc --arg name "$selected" '{name: $name}')
  limactl shell --tty=false "$node_instance" -- curl -fsS --max-time 3 \
    -X PUT -H 'Content-Type: application/json' --data "$payload" \
    "http://127.0.0.1:19090/proxies/$group" >/dev/null
}

mihomo_mode() {
  local mode=$1
  local payload
  payload=$(jq -nc --arg mode "$mode" '{mode: $mode}')
  limactl shell --tty=false "$node_instance" -- curl -fsS --max-time 3 \
    -X PATCH -H 'Content-Type: application/json' --data "$payload" \
    http://127.0.0.1:19090/configs >/dev/null
}

restore_standard_config_best_effort() {
  local source_name=frpc-standard.toml
  if [ -f "$generated_root/$source_name" ] && \
     limactl shell --tty=false "$node_instance" -- sudo grep -Fxq "$owner_value" "$owner_path" >/dev/null 2>&1; then
    copy_to_guest_tmp "$node_instance" "$generated_root/$source_name" >/dev/null 2>&1 || return
    limactl shell --tty=false "$node_instance" -- sudo install -m 0600 \
      "/tmp/$source_name" /etc/vpnctl-v2-spike/tunnel/frpc.toml >/dev/null 2>&1 || true
    limactl shell --tty=false "$node_instance" -- sudo rm -f "/tmp/$source_name" >/dev/null 2>&1 || true
    limactl shell --tty=false "$node_instance" -- sudo systemctl restart "$node_client_unit" >/dev/null 2>&1 || true
  fi
}

transport_cleanup() {
  restore_auth_state_best_effort
  set_node_active true >/dev/null 2>&1 || true
  restore_standard_config_best_effort || true
  if [ -n "$saved_mihomo_mode" ]; then
    if [ -n "$saved_restricted_selector" ]; then
      mihomo_select RESTRICTED "$saved_restricted_selector" >/dev/null 2>&1 || true
    fi
    if [ -n "$saved_udp_selector" ]; then
      mihomo_select RESTRICTED-UDP "$saved_udp_selector" >/dev/null 2>&1 || true
    fi
    if [ -n "$saved_global_selector" ]; then
      mihomo_select GLOBAL "$saved_global_selector" >/dev/null 2>&1 || true
    fi
    mihomo_mode "$saved_mihomo_mode" >/dev/null 2>&1 || true
  fi
  capture_clear >/dev/null 2>&1 || true
  if [ "$restricted_started_by_tunnel" = true ]; then
    "$repository_root/scripts/v2restricted-spike.sh" stop >/dev/null 2>&1 || true
  fi
  if [ -n "$probe_pid" ] && kill -0 "$probe_pid" >/dev/null 2>&1; then
    kill "$probe_pid" >/dev/null 2>&1 || true
  fi
  transport_cleanup_armed=false
}

unit_oom_kills() {
  local instance=$1
  local unit=$2
  local control_group
  control_group=$(limactl shell --tty=false "$instance" -- systemctl show "$unit" -p ControlGroup --value)
  if [ -z "$control_group" ]; then
    echo "missing cgroup for active unit: $unit" >&2
    return 1
  fi
  limactl shell --tty=false "$instance" -- sudo awk '$1 == "oom_kill" {print $2}' "/sys/fs/cgroup$control_group/memory.events"
}

verify() {
  local evidence_dir=${1:-"$artifact_root/evidence-$(date -u +%Y%m%dT%H%M%SZ)"}
  local gateway_ip initial_pid reload_pid direct_connections gateway_connections
  local login_before login_after untrusted_before untrusted_after
  local new_proxy_rejected stale_proxy_rejected controller_rejected_before controller_rejected_after
  local reconnect_seconds revoke_seconds revoke_bound
  local direct_packets direct_protected_packets restricted_direct_packets restricted_packets
  local restricted_local_connections
  local gateway_mem_available node_mem_available minimum_mem
  local gateway_auth_oom gateway_server_oom node_client_oom node_backend_oom
  local attempt recovered=false revoked=false
  mkdir -p "$evidence_dir"
  chmod 0700 "$evidence_dir"
  assert_lab_instance "$gateway_instance"
  assert_lab_instance "$node_instance"
  if ! limactl shell --tty=false "$gateway_instance" -- sudo grep -Fxq "$owner_value" "$owner_path" || \
     ! limactl shell --tty=false "$node_instance" -- sudo grep -Fxq "$owner_value" "$owner_path"; then
    echo "tunnel spike is not owner-prepared" >&2
    exit 3
  fi
  gateway_ip=$(lab_ip "$gateway_instance")
  render_configs "$gateway_ip"
  transport_cleanup_armed=true
  trap 'transport_cleanup' EXIT
  set_node_active true
  apply_client_config "$generated_root/frpc-standard.toml"
  apply_proxy_file "$fixture_root/proxies-one.toml"
  wait_initial_tunnel
  probe_gateway 18111 backend-one
  initial_pid=$(node_frpc_pid)
  direct_connections=$(direct_control_connections)
  gateway_connections=$(gateway_control_connections)
  if [ "$direct_connections" -ne 1 ] || [ "$gateway_connections" -ne 1 ]; then
    echo "initial frp control connection is not exactly one per node" >&2
    exit 1
  fi

  apply_proxy_file "$fixture_root/proxies-two.toml"
  wait_gateway_port 18112 open
  probe_gateway 18112 backend-two
  reload_pid=$(node_frpc_pid)
  if [ "$reload_pid" != "$initial_pid" ] || [ "$(direct_control_connections)" -ne 1 ]; then
    echo "dynamic expose add replaced or multiplied the persistent frpc connection" >&2
    exit 1
  fi

  limactl shell --tty=false "$gateway_instance" -- \
    /usr/local/libexec/vpnctl-v2-spike/tunnel-probe \
    --target 127.0.0.1:18111=backend-one \
    --target 127.0.0.1:18112=backend-two \
    --streams-per-target "$(manifest_value '.load.streams_per_expose')" \
    --hold-seconds "$(manifest_value '.load.hold_seconds')" \
    --timeout 3 > "$evidence_dir/concurrent-streams.json" &
  probe_pid=$!
  sleep 1
  direct_connections=$(direct_control_connections)
  gateway_connections=$(gateway_control_connections)
  if [ "$direct_connections" -ne 1 ] || [ "$gateway_connections" -ne 1 ]; then
    kill "$probe_pid" >/dev/null 2>&1 || true
    echo "concurrent expose streams created more than one persistent tunnel connection" >&2
    exit 1
  fi
  wait "$probe_pid"
  probe_pid=
  jq -e --argjson expected "$((2 * $(manifest_value '.load.streams_per_expose')))" \
    '.status == "passed" and .streams == $expected' "$evidence_dir/concurrent-streams.json" >/dev/null

  apply_proxy_file "$fixture_root/proxies-one.toml"
  wait_gateway_port 18112 closed
  probe_gateway 18111 backend-one
  if [ "$(node_frpc_pid)" != "$initial_pid" ] || [ "$(direct_control_connections)" -ne 1 ]; then
    echo "dynamic expose removal disturbed the persistent tunnel" >&2
    exit 1
  fi

  apply_proxy_file "$fixture_root/proxies-malicious.toml"
  wait_gateway_port 18112 closed
  probe_gateway 18111 backend-one
  plugin_metrics > "$evidence_dir/metrics-after-malicious.json"
  new_proxy_rejected=$(jq -r '.requests.NewProxy.rejected' "$evidence_dir/metrics-after-malicious.json")
  if [ "$new_proxy_rejected" -lt 1 ] || \
     ! jq -e '.last_by_operation.NewProxy.reason == "mapping_mismatch"' "$evidence_dir/metrics-after-malicious.json" >/dev/null; then
    echo "authorization plugin did not reject the unregistered mapping" >&2
    exit 1
  fi

  apply_proxy_file "$fixture_root/proxies-stale-generation.toml"
  wait_gateway_port 18112 closed
  probe_gateway 18111 backend-one
  plugin_metrics > "$evidence_dir/metrics-after-stale-mapping.json"
  stale_proxy_rejected=$(jq -r '.requests.NewProxy.rejected' "$evidence_dir/metrics-after-stale-mapping.json")
  if [ "$stale_proxy_rejected" -le "$new_proxy_rejected" ] || \
     ! jq -e '.last_by_operation.NewProxy.reason == "mapping_mismatch"' "$evidence_dir/metrics-after-stale-mapping.json" >/dev/null; then
    echo "authorization plugin did not reject the stale mapping generation" >&2
    exit 1
  fi

  apply_proxy_file "$fixture_root/proxies-one.toml"
  wait_gateway_port 18112 closed
  controller_rejected_before=$(plugin_metrics | jq -r '.requests.NewProxy.rejected')
  hide_auth_state
  apply_proxy_file "$fixture_root/proxies-two.toml"
  for attempt in $(seq 1 40); do
    plugin_metrics > "$evidence_dir/metrics-after-controller-unavailable.json"
    controller_rejected_after=$(jq -r '.requests.NewProxy.rejected' "$evidence_dir/metrics-after-controller-unavailable.json")
    if [ "$controller_rejected_after" -gt "$controller_rejected_before" ]; then
      break
    fi
    sleep 0.25
  done
  wait_gateway_port 18112 closed
  if [ "$controller_rejected_after" -le "$controller_rejected_before" ] || \
     ! jq -e '.last_by_operation.NewProxy.reason == "controller_error"' "$evidence_dir/metrics-after-controller-unavailable.json" >/dev/null; then
    echo "authorization plugin did not fail closed with unavailable controller state" >&2
    exit 1
  fi
  restore_auth_state
  apply_proxy_file "$fixture_root/proxies-one.toml"
  apply_proxy_file "$fixture_root/proxies-two.toml"
  wait_gateway_port 18112 open

  untrusted_before=$(metric_total Login)
  run_rejected_client "$generated_root/frpc-untrusted-server.toml"
  untrusted_after=$(metric_total Login)
  if [ "$untrusted_after" -ne "$untrusted_before" ]; then
    echo "untrusted TLS server attempt reached Login metadata authorization" >&2
    exit 1
  fi
  login_before=$untrusted_after
  run_rejected_client "$generated_root/frpc-old-generation.toml"
  login_after=$(metric_total Login)
  plugin_metrics > "$evidence_dir/metrics-after-old-generation.json"
  if [ "$login_after" -le "$login_before" ] || \
     ! jq -e '.last_by_operation.Login.reason == "generation_mismatch"' "$evidence_dir/metrics-after-old-generation.json" >/dev/null; then
    echo "old tunnel credential generation was not rejected at Login" >&2
    exit 1
  fi
  login_before=$login_after
  run_rejected_client "$generated_root/frpc-pool-negative.toml"
  login_after=$(metric_total Login)
  plugin_metrics > "$evidence_dir/metrics-after-pool-negative.json"
  if [ "$login_after" -le "$login_before" ] || \
     ! jq -e '.last_by_operation.Login.reason == "pool_input_not_one"' "$evidence_dir/metrics-after-pool-negative.json" >/dev/null; then
    echo "unexpected frp Login pool input was not rejected" >&2
    exit 1
  fi

  SECONDS=0
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl stop "$gateway_server_unit"
  wait_gateway_port 18111 closed
  if ! limactl shell --tty=false "$node_instance" -- systemctl is-active --quiet "$node_client_unit"; then
    echo "frpc exited instead of retrying while frps was unavailable" >&2
    exit 1
  fi
  sleep 3
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl start "$gateway_server_unit"
  wait_gateway_port 18111 open
  wait_gateway_port 18112 open
  reconnect_seconds=$SECONDS
  if [ "$(node_frpc_pid)" != "$initial_pid" ]; then
    echo "frps restart required a node frpc process restart" >&2
    exit 1
  fi
  probe_gateway 18111 backend-one
  probe_gateway 18112 backend-two

  revoke_bound=$(manifest_value '.transport.revoke_bound_seconds')
  SECONDS=0
  set_node_active false
  for attempt in $(seq 1 $((revoke_bound * 4))); do
    if [ "$(direct_control_connections)" -eq 0 ] && \
       ! gateway_port_open 18111 && ! gateway_port_open 18112; then
      revoked=true
      break
    fi
    sleep 0.25
  done
  revoke_seconds=$SECONDS
  if [ "$revoked" != true ]; then
    echo "frp Ping authorization did not close the revoked node within ${revoke_bound}s" >&2
    exit 1
  fi
  sleep 2
  plugin_metrics > "$evidence_dir/metrics-after-revoke.json"
  if ! jq -e '((.last_by_operation.Login.reason == "revoked") or (.last_by_operation.Ping.reason == "revoked")) and (.requests.Login.rejected + .requests.Ping.rejected) > 0' \
    "$evidence_dir/metrics-after-revoke.json" >/dev/null; then
    echo "revoked tunnel reconnect was not rejected" >&2
    exit 1
  fi
  set_node_active true
  wait_gateway_port 18111 open
  wait_gateway_port 18112 open
  probe_gateway 18111 backend-one

  ensure_restricted_transport
  saved_mihomo_mode=$(mihomo_get /configs | jq -er '.mode')
  saved_global_selector=$(mihomo_get /proxies/GLOBAL | jq -er '.now')
  saved_restricted_selector=$(mihomo_get /proxies/RESTRICTED | jq -er '.now')
  saved_udp_selector=$(mihomo_get /proxies/RESTRICTED-UDP | jq -er '.now')

  capture_start
  apply_client_config "$generated_root/frpc-standard.toml"
  wait_gateway_port 18111 open
  probe_gateway 18111 backend-one
  sleep 1
  capture_snapshot "$evidence_dir/standard-transport.nft"
  direct_packets=$(capture_packets "$evidence_dir/standard-transport.nft" direct-frp)
  direct_protected_packets=$(capture_packets "$evidence_dir/standard-transport.nft" restricted-shadowtls)
  if [ "${direct_packets:-0}" -eq 0 ] || [ "${direct_protected_packets:-0}" -ne 0 ]; then
    echo "standard tunnel path was not isolated as direct gateway TCP/17000" >&2
    exit 1
  fi

  mihomo_select RESTRICTED RESTRICTED-VALID
  mihomo_select GLOBAL RESTRICTED
  mihomo_mode global
  apply_client_config "$generated_root/frpc-restricted.toml"
  wait_gateway_port 18111 open
  wait_gateway_port 18112 open
  restricted_local_connections=$(local_proxy_connections)
  if [ "$restricted_local_connections" -ne 1 ]; then
    echo "restricted tunnel did not establish exactly one frpc-to-Mihomo connection" >&2
    exit 1
  fi
  capture_clear
  capture_start
  probe_gateway 18111 backend-one
  probe_gateway 18112 backend-two
  sleep 1
  capture_snapshot "$evidence_dir/restricted-transport.nft"
  restricted_direct_packets=$(capture_packets "$evidence_dir/restricted-transport.nft" direct-frp)
  restricted_packets=$(capture_packets "$evidence_dir/restricted-transport.nft" restricted-shadowtls)
  jq -n \
    --argjson direct_packets "${restricted_direct_packets:-0}" \
    --argjson shadowtls_packets "${restricted_packets:-0}" \
    --argjson local_proxy_connections "$restricted_local_connections" \
    '{direct_packets: $direct_packets, shadowtls_packets: $shadowtls_packets, local_proxy_connections: $local_proxy_connections}' \
    > "$evidence_dir/restricted-transport.json"
  if [ "${restricted_direct_packets:-0}" -ne 0 ] || [ "${restricted_packets:-0}" -eq 0 ] || \
     [ "$restricted_local_connections" -ne 1 ]; then
    echo "restricted tunnel switch did not use exactly one frpc-to-Mihomo connection and ShadowTLS outer TCP" >&2
    exit 1
  fi
  plugin_metrics > "$evidence_dir/metrics-after-transport-switch.json"
  if ! jq -e '.last_by_operation.Login.outcome == "allowed"' "$evidence_dir/metrics-after-transport-switch.json" >/dev/null; then
    echo "transport switch did not preserve an authorized tunnel identity" >&2
    exit 1
  fi

  transport_cleanup
  trap - EXIT
  wait_gateway_port 18111 open
  wait_gateway_port 18112 open
  probe_gateway 18111 backend-one
  if [ "$(direct_control_connections)" -ne 1 ]; then
    echo "standard tunnel did not recover after restricted transport cleanup" >&2
    exit 1
  fi

  gateway_mem_available=$(limactl shell --tty=false "$gateway_instance" -- awk '$1 == "MemAvailable:" {print $2}' /proc/meminfo)
  node_mem_available=$(limactl shell --tty=false "$node_instance" -- awk '$1 == "MemAvailable:" {print $2}' /proc/meminfo)
  minimum_mem=$(manifest_value '.load.minimum_mem_available_kib')
  gateway_auth_oom=$(unit_oom_kills "$gateway_instance" "$gateway_auth_unit")
  gateway_server_oom=$(unit_oom_kills "$gateway_instance" "$gateway_server_unit")
  node_client_oom=$(unit_oom_kills "$node_instance" "$node_client_unit")
  node_backend_oom=$(unit_oom_kills "$node_instance" "$node_backend_unit")
  if [ "$gateway_mem_available" -lt "$minimum_mem" ] || [ "$node_mem_available" -lt "$minimum_mem" ] || \
     [ "$gateway_auth_oom" -ne 0 ] || [ "$gateway_server_oom" -ne 0 ] || \
     [ "$node_client_oom" -ne 0 ] || [ "$node_backend_oom" -ne 0 ]; then
    echo "tunnel spike exceeded the minimum-host resource gate" >&2
    exit 1
  fi
  "$repository_root/scripts/v2lab.sh" report "$evidence_dir/resources"
  plugin_metrics > "$evidence_dir/plugin-metrics-final.json"
  limactl shell --tty=false "$gateway_instance" -- systemctl show \
    "$gateway_auth_unit" "$gateway_server_unit" \
    -p Id -p ActiveState -p MainPID -p MemoryCurrent -p MemoryPeak -p CPUUsageNSec > "$evidence_dir/gateway-units.txt"
  limactl shell --tty=false "$node_instance" -- systemctl show \
    "$node_client_unit" "$node_backend_unit" \
    -p Id -p ActiveState -p MainPID -p MemoryCurrent -p MemoryPeak -p CPUUsageNSec > "$evidence_dir/node-units.txt"
  jq -n \
    --arg status passed \
    --arg frp_version "$(manifest_value '.frp.version')" \
    --argjson streams_per_expose "$(manifest_value '.load.streams_per_expose')" \
    --argjson control_connections "$direct_connections" \
    --argjson reconnect_seconds "$reconnect_seconds" \
    --argjson revoke_seconds "$revoke_seconds" \
    --argjson direct_packets "${direct_packets:-0}" \
    --argjson restricted_packets "${restricted_packets:-0}" \
    --argjson gateway_mem_available_kib "$gateway_mem_available" \
    --argjson node_mem_available_kib "$node_mem_available" \
    '{
      schema_version: 1,
      status: $status,
      provider: {name: "frp", version: $frp_version, wire_protocol: "v1", tls_verified: true},
      multiplexing: {tcp_mux: true, pool_count: 0, persistent_connections: $control_connections, exposes: 2, streams_per_expose: $streams_per_expose},
      dynamic_mapping: {add_without_restart: true, remove_without_restart: true, malicious_rejected: true, stale_generation_rejected: true},
      authorization: {login_generation_rejected: true, unexpected_pool_input_rejected: true, login_pool_rewritten_to_zero: true, controller_unavailable_rejected: true, untrusted_tls_reached_login: false, revoke_reconnect_rejected: true},
      lifecycle: {reconnect_without_frpc_restart: true, reconnect_seconds: $reconnect_seconds, revoke_seconds: $revoke_seconds},
      transport_switch: {standard_direct_packets: $direct_packets, restricted_shadowtls_packets: $restricted_packets, logical_identity_preserved: true},
      resources: {gateway_mem_available_kib: $gateway_mem_available_kib, node_mem_available_kib: $node_mem_available_kib, oom_kills: 0}
    }' > "$evidence_dir/summary.json"
  if rg -l --fixed-strings "$TUNNEL_TOKEN" "$evidence_dir" >/dev/null 2>&1 || \
     rg -l --fixed-strings "$BOOTSTRAP_TOKEN" "$evidence_dir" >/dev/null 2>&1 || \
     rg -l --fixed-strings "$ADMIN_PASSWORD" "$evidence_dir" >/dev/null 2>&1; then
    echo "secret value entered tunnel evidence" >&2
    exit 1
  fi
  printf 'frp tunnel spike evidence: %s\n' "$evidence_dir/summary.json"
}

status() {
  local instance unit
  for instance in "$gateway_instance" "$node_instance"; do
    assert_lab_instance "$instance"
  done
  for unit in "$gateway_auth_unit" "$gateway_server_unit"; do
    limactl shell --tty=false "$gateway_instance" -- systemctl show "$unit" \
      -p Id -p LoadState -p ActiveState -p SubState -p MainPID -p MemoryCurrent
  done
  for unit in "$node_client_unit" "$node_backend_unit"; do
    limactl shell --tty=false "$node_instance" -- systemctl show "$unit" \
      -p Id -p LoadState -p ActiveState -p SubState -p MainPID -p MemoryCurrent
  done
  limactl shell --tty=false "$gateway_instance" -- sudo ss -H -ltn \
    \( sport = :17000 or sport = :18111 or sport = :18112 or sport = :19091 \)
  limactl shell --tty=false "$node_instance" -- sudo ss -H -ltn \
    \( sport = :17400 or sport = :18121 or sport = :18122 \)
  if capture_exists; then
    echo "node capture table present: inet $capture_table"
  else
    echo "node capture table absent"
  fi
}

stop() {
  assert_lab_instance "$gateway_instance"
  assert_lab_instance "$node_instance"
  limactl shell --tty=false "$node_instance" -- sudo systemctl stop \
    "$node_client_unit" "$node_backend_unit" >/dev/null 2>&1 || true
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl stop \
    "$gateway_server_unit" "$gateway_auth_unit" >/dev/null 2>&1 || true
  capture_clear >/dev/null 2>&1 || true
  echo "tunnel spike units stopped; temporary frp logging opt-in is closed"
}

uninstall_instance() {
  local instance=$1
  local role=$2
  if ! limactl shell --tty=false "$instance" -- sudo test -e /etc/vpnctl-v2-spike/tunnel; then
    return
  fi
  if ! limactl shell --tty=false "$instance" -- sudo grep -Fxq "$owner_value" "$owner_path"; then
    echo "refusing to uninstall unowned tunnel path on $instance" >&2
    exit 3
  fi
  case "$role" in
    gateway)
      limactl shell --tty=false "$instance" -- sudo systemctl stop \
        "$gateway_server_unit" "$gateway_auth_unit" >/dev/null 2>&1 || true
      limactl shell --tty=false "$instance" -- sudo rm -f \
        "/etc/systemd/system/$gateway_server_unit" \
        "/etc/systemd/system/$gateway_auth_unit" \
        /usr/local/libexec/vpnctl-v2-spike/frps \
        /usr/local/libexec/vpnctl-v2-spike/tunnel-auth-plugin \
        /usr/local/libexec/vpnctl-v2-spike/tunnel-probe
      limactl shell --tty=false "$instance" -- sudo rm -rf /var/lib/vpnctl-v2-spike-tunnel-auth
      ;;
    node)
      limactl shell --tty=false "$instance" -- sudo systemctl stop \
        "$node_client_unit" "$node_backend_unit" >/dev/null 2>&1 || true
      limactl shell --tty=false "$instance" -- sudo rm -f \
        "/etc/systemd/system/$node_client_unit" \
        "/etc/systemd/system/$node_backend_unit" \
        /usr/local/libexec/vpnctl-v2-spike/frpc \
        /usr/local/libexec/vpnctl-v2-spike/tunnel-backend \
        /usr/local/libexec/vpnctl-v2-spike/tunnel-probe \
        /tmp/frpc-standard.toml \
        /tmp/frpc-restricted.toml \
        /tmp/frpc-old-generation.toml \
        /tmp/frpc-untrusted-server.toml \
        /tmp/frpc-pool-negative.toml \
        /tmp/proxies-one.toml \
        /tmp/proxies-two.toml \
        /tmp/proxies-malicious.toml \
        /tmp/proxies-stale-generation.toml \
        /tmp/capture.nft
      ;;
    *)
      echo "unknown tunnel uninstall role: $role" >&2
      exit 2
      ;;
  esac
  limactl shell --tty=false "$instance" -- sudo rm -rf /etc/vpnctl-v2-spike/tunnel
  limactl shell --tty=false "$instance" -- sudo rmdir /usr/local/libexec/vpnctl-v2-spike >/dev/null 2>&1 || true
  limactl shell --tty=false "$instance" -- sudo systemctl daemon-reload
  limactl shell --tty=false "$instance" -- sudo systemctl reset-failed >/dev/null 2>&1 || true
}

uninstall() {
  assert_lab_instance "$gateway_instance"
  assert_lab_instance "$node_instance"
  capture_clear >/dev/null 2>&1 || true
  uninstall_instance "$node_instance" node
  uninstall_instance "$gateway_instance" gateway
  echo "owner-checked tunnel spike resources removed; ignored cache/evidence retained"
}

command=${1:-}
case "$command" in
  fetch)
    [ "$#" -eq 1 ] || { usage >&2; exit 2; }
    fetch_frp
    printf 'pinned frp cache ready: %s, %s\n' "$frps_binary" "$frpc_binary"
    ;;
  prepare)
    [ "$#" -eq 1 ] || { usage >&2; exit 2; }
    prepare
    ;;
  verify)
    [ "$#" -le 2 ] || { usage >&2; exit 2; }
    verify "${2:-}"
    ;;
  status)
    [ "$#" -eq 1 ] || { usage >&2; exit 2; }
    status
    ;;
  stop)
    [ "$#" -eq 1 ] || { usage >&2; exit 2; }
    stop
    ;;
  uninstall)
    [ "$#" -eq 1 ] || { usage >&2; exit 2; }
    uninstall
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
