#!/bin/bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
fixture_root="$repository_root/test/v2lab/ingress"
manifest="$fixture_root/manifest.json"
artifact_root="$repository_root/artifacts/v2lab/ingress-spike"
gateway_instance=vpnctl-v2-gateway
node_instance=vpnctl-v2-node
ingress_unit=vpnctl-v2-spike-ingress.service
webhook_unit=vpnctl-v2-spike-webhook.service
owner_value=vpnctl-v2-ingress-spike-v1
owner_path=/etc/vpnctl-v2-spike/ingress/.owner
package_state_path=/etc/vpnctl-v2-spike/ingress/package.env
lab_image_digest=sha256:53fdde898feed8b027d94baa9cfe8229867f330a1d9c49dc7d84465ee7f229f7
nginx_masked=false

usage() {
  cat <<'EOF'
Usage:
  scripts/v2ingress-spike.sh prepare <manual-public-ip-for-lab>
  scripts/v2ingress-spike.sh verify [evidence-directory]
  scripts/v2ingress-spike.sh status
  scripts/v2ingress-spike.sh stop
  scripts/v2ingress-spike.sh uninstall
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
  if ! instance_json "$gateway_instance" | jq -e '
    any(.config.portForwards[]?;
      .guestPort == 443 and
      .guestIP == "0.0.0.0" and
      .guestIPMustBeZero == false and
      .proto == "any" and
      .ignore == true
    )
  ' >/dev/null; then
    echo "refusing to expose ingress spike port 443 through Lima host forwarding" >&2
    exit 3
  fi
}

lab_ip() {
  limactl shell --tty=false "$1" -- ip -4 -o address show scope global | awk '$4 ~ /^192[.]168[.]104[.]/ {sub(/\/.*/, "", $4); print $4; exit}'
}

validate_public_ip() {
  local public_ip=$1
  python3 -c 'import ipaddress,sys; value=ipaddress.ip_address(sys.argv[1]); assert value.version == 4' "$public_ip" 2>/dev/null || {
    echo "manual public IP must be a valid IPv4 address" >&2
    exit 2
  }
}

assert_owned_or_absent() {
  if limactl shell --tty=false "$gateway_instance" -- sudo test -e /etc/vpnctl-v2-spike/ingress; then
    if ! limactl shell --tty=false "$gateway_instance" -- sudo grep -Fxq "$owner_value" "$owner_path"; then
      echo "refusing to overwrite unowned ingress spike path" >&2
      exit 3
    fi
  elif limactl shell --tty=false "$gateway_instance" -- dpkg-query -W nginx >/dev/null 2>&1; then
    echo "refusing to co-own a pre-existing nginx package" >&2
    exit 3
  fi
}

assert_port_free_or_owned() {
  local port=$1
  local output
  if limactl shell --tty=false "$gateway_instance" -- systemctl is-active --quiet "$ingress_unit"; then
    return
  fi
  output=$(limactl shell --tty=false "$gateway_instance" -- sudo ss -H -ltn "sport = :$port")
  if [ -n "$output" ]; then
    echo "refusing to claim occupied gateway TCP port $port" >&2
    exit 3
  fi
}

copy_to_guest_tmp() {
  local instance=$1
  shift
  limactl copy --backend=scp "$@" "$instance:/tmp/"
}

cleanup_package_mask() {
  if [ "$nginx_masked" = true ]; then
    limactl shell --tty=false "$gateway_instance" -- sudo systemctl unmask nginx.service >/dev/null 2>&1 || true
    nginx_masked=false
  fi
}

install_nginx_package() {
  local expected_version installed_version candidate_version
  expected_version=$(manifest_value '.nginx.version')
  if limactl shell --tty=false "$gateway_instance" -- dpkg-query -W nginx >/dev/null 2>&1; then
    installed_version=$(limactl shell --tty=false "$gateway_instance" -- dpkg-query -W '-f=${Version}' nginx)
    if [ "$installed_version" != "$expected_version" ] || \
       ! limactl shell --tty=false "$gateway_instance" -- sudo grep -Eq '^NGINX_INSTALLED_BY_SPIKE=(pending|true)$' "$package_state_path"; then
      echo "installed nginx is not the owner-pinned ingress spike package" >&2
      exit 3
    fi
    limactl shell --tty=false "$gateway_instance" -- sudo systemctl disable --now nginx.service >/dev/null 2>&1 || true
    limactl shell --tty=false "$gateway_instance" -- sudo sh -c \
      "printf '%s\n' 'NGINX_INSTALLED_BY_SPIKE=true' 'NGINX_VERSION=$expected_version' > '$package_state_path'"
    limactl shell --tty=false "$gateway_instance" -- sudo chmod 0600 "$package_state_path"
    return
  fi

  if limactl shell --tty=false "$gateway_instance" -- sudo test -e /etc/systemd/system/nginx.service; then
    echo "refusing to replace an existing nginx.service override" >&2
    exit 3
  fi
  limactl shell --tty=false "$gateway_instance" -- sudo apt-get update
  candidate_version=$(limactl shell --tty=false "$gateway_instance" -- apt-cache policy nginx | awk '/Candidate:/ {print $2}')
  if [ "$candidate_version" != "$expected_version" ]; then
    echo "pinned nginx version is unavailable: expected $expected_version, candidate $candidate_version" >&2
    exit 3
  fi
  limactl shell --tty=false "$gateway_instance" -- sudo sh -c \
    "printf '%s\n' 'NGINX_INSTALLED_BY_SPIKE=pending' 'NGINX_VERSION=$expected_version' > '$package_state_path'"
  limactl shell --tty=false "$gateway_instance" -- sudo chmod 0600 "$package_state_path"
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl mask nginx.service
  nginx_masked=true
  trap 'cleanup_package_mask' EXIT
  limactl shell --tty=false "$gateway_instance" -- sudo env DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends -y "nginx=$expected_version"
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl disable --now nginx.service >/dev/null 2>&1 || true
  cleanup_package_mask
  trap - EXIT
  limactl shell --tty=false "$gateway_instance" -- sudo sh -c \
    "printf '%s\n' 'NGINX_INSTALLED_BY_SPIKE=true' 'NGINX_VERSION=$expected_version' > '$package_state_path'"
  limactl shell --tty=false "$gateway_instance" -- sudo chmod 0600 "$package_state_path"
  installed_version=$(limactl shell --tty=false "$gateway_instance" -- dpkg-query -W '-f=${Version}' nginx)
  if [ "$installed_version" != "$expected_version" ] || \
     limactl shell --tty=false "$gateway_instance" -- systemctl is-enabled --quiet nginx.service || \
     limactl shell --tty=false "$gateway_instance" -- systemctl is-active --quiet nginx.service; then
    echo "nginx package post-install state violates the spike contract" >&2
    exit 3
  fi
}

ensure_certificate() {
  local public_ip=$1
  if limactl shell --tty=false "$gateway_instance" -- sudo test -e /etc/vpnctl-v2-spike/ingress/gateway.key; then
    if ! limactl shell --tty=false "$gateway_instance" -- sudo openssl x509 \
      -in /etc/vpnctl-v2-spike/ingress/gateway.crt -noout -subject -ext subjectAltName | \
      grep -Fq "$public_ip"; then
      echo "existing ingress certificate belongs to another public IP" >&2
      exit 3
    fi
    return
  fi
  limactl shell --tty=false "$gateway_instance" -- sudo openssl req \
    -x509 -newkey rsa:2048 -sha256 -nodes -days "$(manifest_value '.certificate.validity_days')" \
    -subj "/CN=$public_ip" -addext "subjectAltName=IP:$public_ip" \
    -keyout /etc/vpnctl-v2-spike/ingress/gateway.key.tmp \
    -out /etc/vpnctl-v2-spike/ingress/gateway.crt.tmp
  limactl shell --tty=false "$gateway_instance" -- sudo chmod 0600 /etc/vpnctl-v2-spike/ingress/gateway.key.tmp
  limactl shell --tty=false "$gateway_instance" -- sudo chmod 0644 /etc/vpnctl-v2-spike/ingress/gateway.crt.tmp
  limactl shell --tty=false "$gateway_instance" -- sudo mv \
    /etc/vpnctl-v2-spike/ingress/gateway.key.tmp /etc/vpnctl-v2-spike/ingress/gateway.key
  limactl shell --tty=false "$gateway_instance" -- sudo mv \
    /etc/vpnctl-v2-spike/ingress/gateway.crt.tmp /etc/vpnctl-v2-spike/ingress/gateway.crt
}

prepare() {
  local public_ip=${1:?manual public IP is required}
  local gateway_ip
  validate_public_ip "$public_ip"
  assert_lab_instance "$gateway_instance"
  assert_lab_instance "$node_instance"
  assert_forward_ignored
  assert_owned_or_absent
  assert_port_free_or_owned 443
  assert_port_free_or_owned 18081
  gateway_ip=$(lab_ip "$gateway_instance")
  if [ "$public_ip" != "$gateway_ip" ]; then
    echo "the local spike requires the manually supplied IP to equal the reachable gateway lab IP: $gateway_ip" >&2
    exit 2
  fi

  limactl shell --tty=false "$gateway_instance" -- sudo install -d -m 0700 /etc/vpnctl-v2-spike/ingress
  limactl shell --tty=false "$gateway_instance" -- sudo sh -c "printf '%s\n' '$owner_value' > '$owner_path'"
  limactl shell --tty=false "$gateway_instance" -- sudo chmod 0600 "$owner_path"
  install_nginx_package
  ensure_certificate "$public_ip"

  copy_to_guest_tmp "$gateway_instance" \
    "$fixture_root/nginx.conf" \
    "$fixture_root/telegram_webhook_gate.py" \
    "$fixture_root/webhook_receiver.py" \
    "$fixture_root/systemd/$ingress_unit" \
    "$fixture_root/systemd/$webhook_unit"
  limactl shell --tty=false "$gateway_instance" -- sudo install -d -m 0755 /usr/local/libexec/vpnctl-v2-spike
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0755 \
    /tmp/webhook_receiver.py /usr/local/libexec/vpnctl-v2-spike/webhook-receiver
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0755 \
    /tmp/telegram_webhook_gate.py /usr/local/libexec/vpnctl-v2-spike/telegram-webhook-gate
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0600 \
    /tmp/nginx.conf /etc/vpnctl-v2-spike/ingress/nginx.conf
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0644 "/tmp/$ingress_unit" "/etc/systemd/system/$ingress_unit"
  limactl shell --tty=false "$gateway_instance" -- sudo install -m 0644 "/tmp/$webhook_unit" "/etc/systemd/system/$webhook_unit"
  limactl shell --tty=false "$gateway_instance" -- sudo install -d -m 0750 /run/vpnctl-v2-spike-ingress
  limactl shell --tty=false "$gateway_instance" -- sudo /usr/sbin/nginx \
    -t -p /etc/vpnctl-v2-spike/ingress/ -c nginx.conf
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl daemon-reload
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl restart "$webhook_unit" "$ingress_unit"
  echo "IP-only ingress spike prepared for manually supplied lab IP $public_ip"
}

wait_for_services() {
  local attempt
  for attempt in $(seq 1 20); do
    if limactl shell --tty=false "$gateway_instance" -- systemctl is-active --quiet "$webhook_unit" && \
       limactl shell --tty=false "$gateway_instance" -- systemctl is-active --quiet "$ingress_unit"; then
      return
    fi
    sleep 1
  done
  echo "ingress spike services did not become ready" >&2
  exit 4
}

node_http_request() {
  local http_version=$1
  local public_ip=$2
  local response_file=$3
  local version
  version=$(limactl shell --tty=false "$node_instance" -- curl -fsS \
    "--http$http_version" \
    --cacert /tmp/vpnctl-v2-ingress-gateway.crt \
    -H 'Content-Type: application/json' \
    --data-binary @/tmp/vpnctl-v2-ingress-update.json \
    --output "/tmp/vpnctl-v2-ingress-response-$http_version.json" \
    --write-out '%{http_version}' \
    "https://$public_ip/telegram/webhook")
  limactl shell --tty=false "$node_instance" -- cat "/tmp/vpnctl-v2-ingress-response-$http_version.json" > "$response_file"
  printf '%s\n' "$version"
}

verify() {
  local evidence_dir=${1:-"$artifact_root/evidence-$(date -u +%Y%m%dT%H%M%SZ)"}
  local public_ip http11_version http2_version unknown_status certificate_seconds requests_before requests_after
  mkdir -p "$evidence_dir"
  chmod 0700 "$evidence_dir"
  assert_lab_instance "$gateway_instance"
  assert_lab_instance "$node_instance"
  assert_forward_ignored
  wait_for_services
  public_ip=$(lab_ip "$gateway_instance")

  limactl shell --tty=false "$gateway_instance" -- sudo cat /etc/vpnctl-v2-spike/ingress/gateway.crt > "$evidence_dir/gateway.crt"
  chmod 0644 "$evidence_dir/gateway.crt"
  copy_to_guest_tmp "$node_instance" "$evidence_dir/gateway.crt" "$fixture_root/telegram-update.json"
  limactl shell --tty=false "$node_instance" -- mv /tmp/gateway.crt /tmp/vpnctl-v2-ingress-gateway.crt
  limactl shell --tty=false "$node_instance" -- mv /tmp/telegram-update.json /tmp/vpnctl-v2-ingress-update.json
  trap 'limactl shell --tty=false "$node_instance" -- rm -f /tmp/vpnctl-v2-ingress-gateway.crt /tmp/vpnctl-v2-ingress-update.json /tmp/vpnctl-v2-ingress-response-1.1.json /tmp/vpnctl-v2-ingress-response-2.json >/dev/null 2>&1 || true' EXIT

  limactl shell --tty=false "$gateway_instance" -- sudo /usr/sbin/nginx -V > "$evidence_dir/nginx-version.txt" 2>&1
  grep -Fq "nginx/$(manifest_value '.nginx.version' | sed 's/-.*//')" "$evidence_dir/nginx-version.txt"
  grep -Fq -- '--with-http_v2_module' "$evidence_dir/nginx-version.txt"
  limactl shell --tty=false "$gateway_instance" -- sudo /usr/sbin/nginx \
    -t -p /etc/vpnctl-v2-spike/ingress/ -c nginx.conf > "$evidence_dir/nginx-validation.txt" 2>&1

  openssl x509 -in "$evidence_dir/gateway.crt" -noout -subject -nameopt RFC2253 -dates -ext subjectAltName > "$evidence_dir/certificate-summary.txt"
  openssl x509 -in "$evidence_dir/gateway.crt" -noout -text > "$evidence_dir/certificate-text.txt"
  grep -Fq "subject=CN=$public_ip" "$evidence_dir/certificate-summary.txt"
  grep -Fq "IP Address:$public_ip" "$evidence_dir/certificate-summary.txt"
  grep -Fq 'Public-Key: (2048 bit)' "$evidence_dir/certificate-text.txt"
  grep -Fq 'Signature Algorithm: sha256WithRSAEncryption' "$evidence_dir/certificate-text.txt"
  openssl verify -CAfile "$evidence_dir/gateway.crt" -verify_ip "$public_ip" "$evidence_dir/gateway.crt" > "$evidence_dir/certificate-verify.txt"
  certificate_seconds=$(limactl shell --tty=false "$gateway_instance" -- sudo sh -c '
    start=$(openssl x509 -in /etc/vpnctl-v2-spike/ingress/gateway.crt -noout -startdate | cut -d= -f2-)
    end=$(openssl x509 -in /etc/vpnctl-v2-spike/ingress/gateway.crt -noout -enddate | cut -d= -f2-)
    printf "%s\n" "$(( $(date -u -d "$end" +%s) - $(date -u -d "$start" +%s) ))"
  ')
  if [ "$certificate_seconds" -ne $((1825 * 86400)) ]; then
    echo "ingress certificate validity is not exactly 1825 days" >&2
    exit 1
  fi

  limactl shell --tty=false "$node_instance" -- openssl s_client \
    -connect "$public_ip:443" -CAfile /tmp/vpnctl-v2-ingress-gateway.crt \
    -verify_ip "$public_ip" -verify_return_error -tls1_2 -brief < /dev/null > "$evidence_dir/tls12.txt" 2>&1
  grep -Fq 'Protocol version: TLSv1.2' "$evidence_dir/tls12.txt"
  limactl shell --tty=false "$node_instance" -- openssl s_client \
    -connect "$public_ip:443" -CAfile /tmp/vpnctl-v2-ingress-gateway.crt \
    -verify_ip "$public_ip" -verify_return_error -tls1_3 -brief < /dev/null > "$evidence_dir/tls13.txt" 2>&1
  grep -Fq 'Protocol version: TLSv1.3' "$evidence_dir/tls13.txt"

  requests_before=$(limactl shell --tty=false "$gateway_instance" -- curl -fsS http://127.0.0.1:18081/__vpnctl_probe/status | jq -er '.accepted_requests')
  http11_version=$(node_http_request 1.1 "$public_ip" "$evidence_dir/http11-response.json")
  http2_version=$(node_http_request 2 "$public_ip" "$evidence_dir/http2-response.json")
  requests_after=$(limactl shell --tty=false "$gateway_instance" -- curl -fsS http://127.0.0.1:18081/__vpnctl_probe/status | jq -er '.accepted_requests')
  if [ $((requests_after - requests_before)) -ne 2 ]; then
    echo "loopback receiver did not accept exactly two synthetic webhook requests" >&2
    exit 1
  fi
  [ "$http11_version" = '1.1' ]
  [ "$http2_version" = '2' ]
  for response in "$evidence_dir/http11-response.json" "$evidence_dir/http2-response.json"; do
    jq -e '.ok == true and .body_valid == true and .forwarded_proto == "https" and .host_is_ip == true' "$response" >/dev/null
  done
  unknown_status=$(limactl shell --tty=false "$node_instance" -- curl -sS \
    --http1.1 --cacert /tmp/vpnctl-v2-ingress-gateway.crt --output /dev/null \
    --write-out '%{http_code}' "https://$public_ip/not-exposed")
  [ "$unknown_status" = 404 ]

  limactl shell --tty=false "$gateway_instance" -- sudo ss -H -ltn 'sport = :443' > "$evidence_dir/gateway-443-tcp.txt"
  limactl shell --tty=false "$gateway_instance" -- sudo ss -H -lun 'sport = :443' > "$evidence_dir/gateway-443-udp.txt"
  test -s "$evidence_dir/gateway-443-tcp.txt"
  test ! -s "$evidence_dir/gateway-443-udp.txt"
  limactl shell --tty=false "$gateway_instance" -- systemctl show "$ingress_unit" "$webhook_unit" \
    -p Id -p ActiveState -p MainPID -p MemoryCurrent -p CPUUsageNSec > "$evidence_dir/services.txt"
  "$repository_root/scripts/v2lab.sh" report "$evidence_dir/resources"

  jq -n \
    --arg public_ip "$public_ip" \
    --arg nginx_version "$(manifest_value '.nginx.version')" \
    --arg http11 "$http11_version" \
    --arg http2 "$http2_version" \
    --argjson certificate_validity_days "$(manifest_value '.certificate.validity_days')" \
    '{
      schema_version: 1,
      status: "local-development-passed",
      public_identity: {type: "IPv4", value: $public_ip, san: true, cn: true},
      certificate: {key: "RSA-2048", signature: "SHA-256", validity_days: $certificate_validity_days, private_key_exported: false},
      nginx: {version: $nginx_version, source: "Ubuntu 24.04 apt", default_service_active: false},
      protocols: {tls: ["1.2", "1.3"], http: [$http11, $http2]},
      webhook_proxy: {synthetic_post_http11: true, synthetic_post_http2: true, accepted_request_delta: 2, unknown_path_status: 404},
      listeners: {tcp_443: true, udp_443: false, host_forwarded_by_vpnctl_lab: false},
      telegram: {set_webhook_executed: false, real_request_received: false, gate: "requires manually supplied public gateway and hidden bot token"},
      production_ready: false
    }' > "$evidence_dir/summary.json"
  limactl shell --tty=false "$node_instance" -- rm -f \
    /tmp/vpnctl-v2-ingress-gateway.crt /tmp/vpnctl-v2-ingress-update.json \
    /tmp/vpnctl-v2-ingress-response-1.1.json /tmp/vpnctl-v2-ingress-response-2.json
  trap - EXIT
  printf 'IP-only ingress spike evidence: %s\n' "$evidence_dir/summary.json"
}

status() {
  assert_lab_instance "$gateway_instance"
  limactl shell --tty=false "$gateway_instance" -- systemctl status --no-pager "$ingress_unit" "$webhook_unit"
}

stop_spike() {
  assert_owned_or_absent
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl stop "$ingress_unit" "$webhook_unit"
}

uninstall_spike() {
  assert_lab_instance "$gateway_instance"
  if ! limactl shell --tty=false "$gateway_instance" -- sudo grep -Fxq "$owner_value" "$owner_path"; then
    echo "refusing to uninstall unowned ingress spike" >&2
    exit 3
  fi
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl stop "$ingress_unit" "$webhook_unit"
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl clean --what=state "$ingress_unit" "$webhook_unit" >/dev/null 2>&1 || true
  limactl shell --tty=false "$gateway_instance" -- sudo rm -f \
    "/etc/systemd/system/$ingress_unit" "/etc/systemd/system/$webhook_unit" \
    /usr/local/libexec/vpnctl-v2-spike/webhook-receiver \
    /usr/local/libexec/vpnctl-v2-spike/telegram-webhook-gate
  if limactl shell --tty=false "$gateway_instance" -- sudo grep -Eq '^NGINX_INSTALLED_BY_SPIKE=(pending|true)$' "$package_state_path"; then
    limactl shell --tty=false "$gateway_instance" -- sudo env DEBIAN_FRONTEND=noninteractive \
      apt-get purge -y nginx nginx-common
  fi
  limactl shell --tty=false "$gateway_instance" -- sudo rm -f \
    /etc/vpnctl-v2-spike/ingress/nginx.conf \
    /etc/vpnctl-v2-spike/ingress/gateway.crt \
    /etc/vpnctl-v2-spike/ingress/gateway.key \
    "$package_state_path" "$owner_path"
  limactl shell --tty=false "$gateway_instance" -- sudo rmdir /run/vpnctl-v2-spike-ingress 2>/dev/null || true
  limactl shell --tty=false "$gateway_instance" -- sudo rmdir /etc/vpnctl-v2-spike/ingress /etc/vpnctl-v2-spike 2>/dev/null || true
  limactl shell --tty=false "$gateway_instance" -- sudo rmdir /usr/local/libexec/vpnctl-v2-spike 2>/dev/null || true
  limactl shell --tty=false "$gateway_instance" -- sudo systemctl daemon-reload
}

command=${1:-}
case "$command" in
  prepare) prepare "${2:-}" ;;
  verify) verify "${2:-}" ;;
  status) status ;;
  stop) stop_spike ;;
  uninstall) uninstall_spike ;;
  *) usage >&2; exit 2 ;;
esac
