#!/bin/sh
set -eu

version="${1:-}"
if [ -z "$version" ]; then
	echo "usage: scripts/release.sh <version>" >&2
	exit 2
fi

case "$version" in
	v*) ;;
	*)
		echo "version must start with v, for example v0.1.0" >&2
		exit 2
		;;
esac

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dist_dir="$root_dir/dist"
work_dir="$dist_dir/vpnctl_linux_amd64"
binary="$work_dir/vpnctl"
archive="$dist_dir/vpnctl_linux_amd64.tar.gz"
checksums="$dist_dir/checksums.txt"

rm -rf "$work_dir" "$archive" "$checksums"
mkdir -p "$work_dir"

cd "$root_dir"
go test ./...

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
	-trimpath \
	-ldflags "-s -w -X github.com/vgrinkevich/vpnctl/internal/cli.version=$version" \
	-o "$binary" \
	./cmd/vpnctl

cp README.md "$work_dir/README.md"
cp docs/CLI_SPEC.md "$work_dir/CLI_SPEC.md"

(
	cd "$dist_dir"
	tar -czf "$(basename "$archive")" "$(basename "$work_dir")"
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$(basename "$archive")" >"$(basename "$checksums")"
	else
		shasum -a 256 "$(basename "$archive")" >"$(basename "$checksums")"
	fi
)

echo "release artifacts:"
echo "  $archive"
echo "  $checksums"
echo
echo "create a GitHub release and upload both files, for example:"
echo "  gh release create $version $archive $checksums --title $version --notes-file <notes.md>"
