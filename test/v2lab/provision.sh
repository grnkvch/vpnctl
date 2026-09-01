#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

swap_path=/var/lib/vpnctl-v2-lab.swap
if ! swapon --noheadings --show=NAME | grep -Fxq "$swap_path"; then
  if [ ! -f "$swap_path" ]; then
    install -d -m 0755 /var/lib
    fallocate -l 1G "$swap_path"
    chmod 0600 "$swap_path"
    mkswap "$swap_path"
  fi
  swapon "$swap_path"
fi
if ! grep -Fq "$swap_path none swap sw 0 0" /etc/fstab; then
  printf '%s\n' "$swap_path none swap sw 0 0" >> /etc/fstab
fi

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  dnsutils \
  iproute2 \
  iputils-ping \
  jq \
  netcat-openbsd \
  nftables \
  openssl \
  procps \
  wireguard-tools
rm -rf /var/lib/apt/lists/*
