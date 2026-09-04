#!/bin/sh
set -eu

repo="${VPNCTL_REPO:-vgrinkevich/vpnctl}"
version="${VPNCTL_VERSION:-latest}"
install_dir="${VPNCTL_INSTALL_DIR:-/usr/local/bin}"
binary_name="${VPNCTL_BINARY:-vpnctl}"
asset="vpnctl_linux_amd64.tar.gz"
checksum_file="checksums.txt"

need_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "error: required command not found: $1" >&2
		exit 1
	fi
}

need_cmd curl
need_cmd tar

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)

case "$os/$arch" in
	linux/x86_64|linux/amd64)
		;;
	*)
		echo "error: unsupported platform: $os/$arch; vpnctl release installer currently supports linux/amd64" >&2
		exit 1
		;;
esac

if [ "$version" = "latest" ]; then
	base_url="https://github.com/$repo/releases/latest/download"
else
	base_url="https://github.com/$repo/releases/download/$version"
fi

tmp_dir=$(mktemp -d)
cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

archive_path="$tmp_dir/$asset"
checksums_path="$tmp_dir/$checksum_file"

echo "downloading vpnctl $version from github.com/$repo"
curl -fsSL "$base_url/$asset" -o "$archive_path"
curl -fsSL "$base_url/$checksum_file" -o "$checksums_path"

(
	cd "$tmp_dir"
	checksum_line=$(grep "  $asset\$" "$checksum_file" || true)
	if [ -z "$checksum_line" ]; then
		echo "error: checksum file does not contain $asset" >&2
		exit 1
	fi
	if command -v sha256sum >/dev/null 2>&1; then
		printf '%s\n' "$checksum_line" | sha256sum -c -
	elif command -v shasum >/dev/null 2>&1; then
		printf '%s\n' "$checksum_line" | shasum -a 256 -c -
	else
		echo "error: neither sha256sum nor shasum is available for checksum verification" >&2
		exit 1
	fi
)

tar -xzf "$archive_path" -C "$tmp_dir"
extracted="$tmp_dir/vpnctl_linux_amd64/vpnctl"
if [ ! -f "$extracted" ]; then
	echo "error: archive did not contain vpnctl binary" >&2
	exit 1
fi

mkdir -p "$install_dir"
install_path="$install_dir/$binary_name"
cp "$extracted" "$install_path"
chmod 0755 "$install_path"

echo "installed $install_path"
"$install_path" version
