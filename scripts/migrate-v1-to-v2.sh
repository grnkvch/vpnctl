#!/bin/sh
set -eu

if ! command -v vpnctl-v1-migrate >/dev/null 2>&1; then
  echo "vpnctl-v1-migrate is required in PATH" >&2
  exit 127
fi

exec vpnctl-v1-migrate "$@"
