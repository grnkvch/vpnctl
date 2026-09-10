#!/bin/sh
set -eu

umask 077

version="${1:-}"
if [ -z "$version" ]; then
	echo "usage: VPNCTL_MIHOMO_ARCHIVE=<path> VPNCTL_FRP_ARCHIVE=<path> scripts/release.sh <version>" >&2
	exit 2
fi
case "$version" in
	v?*)
		case "$version" in
			*[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-]*) echo "version must be a safe v-prefixed tag, for example v2.0.0" >&2; exit 2 ;;
		esac
		;;
	*) echo "version must be a safe v-prefixed tag, for example v2.0.0" >&2; exit 2 ;;
esac

if [ -z "${VPNCTL_MIHOMO_ARCHIVE:-}" ]; then echo "error: VPNCTL_MIHOMO_ARCHIVE is required" >&2; exit 2; fi
if [ -z "${VPNCTL_FRP_ARCHIVE:-}" ]; then echo "error: VPNCTL_FRP_ARCHIVE is required" >&2; exit 2; fi

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dist_dir="$root_dir/dist"
mkdir -p "$dist_dir"
work_dir=$(mktemp -d "$dist_dir/.vpnctl-release.XXXXXX")
cleanup() {
	rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM HUP

binary="$work_dir/vpnctl-linux-amd64.input"
output="$work_dir/output"
mkdir -m 0700 "$output"

cd "$root_dir"
(
	umask 022
	go test ./...
)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
	-trimpath \
	-buildvcs=false \
	-ldflags "-s -w -X github.com/vgrinkevich/vpnctl/internal/cli.version=$version" \
	-o "$binary" \
	./cmd/vpnctl

go run ./cmd/vpnctl-release \
	-version "$version" \
	-vpnctl "$binary" \
	-mihomo "$VPNCTL_MIHOMO_ARCHIVE" \
	-frp "$VPNCTL_FRP_ARCHIVE" \
	-output-dir "$output"

for asset in vpnctl-linux-amd64 vpnctl-v2-linux-amd64.bundle release-checksums.txt; do
	mv -f "$output/$asset" "$dist_dir/$asset"
done

echo "checksum-governed v2 release artifacts:"
echo "  $dist_dir/vpnctl-linux-amd64"
echo "  $dist_dir/vpnctl-v2-linux-amd64.bundle"
echo "  $dist_dir/release-checksums.txt"
echo
echo "upload all three files to the matching GitHub release"
