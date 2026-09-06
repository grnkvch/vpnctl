#!/bin/sh
set -eu

umask 077
LC_ALL=C
export LC_ALL

repo="${VPNCTL_REPO:-vgrinkevich/vpnctl}"
version="${VPNCTL_VERSION:-latest}"
binary_asset="vpnctl-linux-amd64"
bundle_asset="vpnctl-v2-linux-amd64.bundle"
checksums_asset="release-checksums.txt"
maximum_binary_bytes=134217728
maximum_bundle_bytes=537460736

die() {
	echo "error: $*" >&2
	exit 1
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

for command_name in awk cmp grep sed wc tr cp mv rm rmdir mkdir chmod mktemp dirname uname id; do
	need_cmd "$command_name"
done
if command -v sha256sum >/dev/null 2>&1; then
	checksum_command=sha256sum
elif command -v shasum >/dev/null 2>&1; then
	checksum_command=shasum
else
	die "neither sha256sum nor shasum is available"
fi

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$os/$arch" in
	linux/x86_64|linux/amd64) ;;
	*) die "unsupported platform: $os/$arch; vpnctl v2 supports Ubuntu linux/amd64" ;;
esac

case "$repo" in
	""|/*|*/|*/*/*|*[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-]*) die "VPNCTL_REPO must be owner/name" ;;
esac
case "$version" in
	latest) ;;
	v?*)
		case "$version" in
			*[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-]*) die "VPNCTL_VERSION must be latest or a safe v-prefixed release tag" ;;
		esac
		;;
	*) die "VPNCTL_VERSION must be latest or a safe v-prefixed release tag" ;;
esac

release_asset_dir="${VPNCTL_RELEASE_ASSET_DIR:-}"
if [ -n "$release_asset_dir" ]; then
	case "$release_asset_dir" in
		/*) ;;
		*) die "VPNCTL_RELEASE_ASSET_DIR must be absolute" ;;
	esac
	[ ! -L "$release_asset_dir" ] && [ -d "$release_asset_dir" ] || die "release asset directory must be a real directory"
	base_url=""
else
	need_cmd curl
	if [ -n "${VPNCTL_RELEASE_BASE_URL:-}" ]; then
		base_url=${VPNCTL_RELEASE_BASE_URL%/}
	else
		if [ "$version" = "latest" ]; then
			base_url="https://github.com/$repo/releases/latest/download"
		else
			base_url="https://github.com/$repo/releases/download/$version"
		fi
	fi
	case "$base_url" in
		https://*) ;;
		*) die "release base URL must use HTTPS" ;;
	esac
fi

install_root="${VPNCTL_INSTALL_ROOT:-}"
if [ -n "$install_root" ]; then
	case "$install_root" in
		/*) ;;
		*) die "VPNCTL_INSTALL_ROOT must be absolute" ;;
	esac
	while [ "$install_root" != "/" ] && [ "${install_root%/}" != "$install_root" ]; do
		install_root=${install_root%/}
	done
	[ ! -L "$install_root" ] && [ -d "$install_root" ] || die "VPNCTL_INSTALL_ROOT must be a real directory"
	[ "$install_root" != "/" ] || install_root=""
elif [ "$(id -u)" != "0" ]; then
	die "installer must run as root"
fi

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/vpnctl-install.XXXXXX")
chmod 0700 "$temporary_root"
download_binary="$temporary_root/$binary_asset"
download_bundle="$temporary_root/$bundle_asset"
download_checksums="$temporary_root/$checksums_asset"

mutation_started=0
install_complete=0
binary_existed=0
bundle_existed=0
checksums_existed=0
usr_created=0
usr_local_created=0
binary_dir_created=0
usr_local_lib_created=0
vpnctl_lib_created=0
release_dir_created=0
binary_stage=""
bundle_stage=""
checksums_stage=""

binary_dir="$install_root/usr/local/bin"
release_dir="$install_root/usr/local/lib/vpnctl/release"
binary_path="$binary_dir/vpnctl"
bundle_path="$release_dir/vpnctl.bundle"
checksums_path="$release_dir/checksums.txt"

restore_target() {
	target=$1
	backup=$2
	existed=$3
	if [ "$existed" = "1" ]; then
		restore_stage=$(mktemp "$(dirname "$target")/.vpnctl-restore.XXXXXX") || return 1
		if ! cp -p "$backup" "$restore_stage"; then
			rm -f "$restore_stage"
			return 1
		fi
		if ! mv -f "$restore_stage" "$target"; then
			rm -f "$restore_stage"
			return 1
		fi
	else
		rm -f "$target" || return 1
	fi
}

cleanup() {
	status=$1
	trap - EXIT INT TERM HUP
	rollback_failed=0
	if [ "$mutation_started" = "1" ] && [ "$install_complete" != "1" ]; then
		restore_target "$binary_path" "$temporary_root/previous.binary" "$binary_existed" || rollback_failed=1
		restore_target "$bundle_path" "$temporary_root/previous.bundle" "$bundle_existed" || rollback_failed=1
		restore_target "$checksums_path" "$temporary_root/previous.checksums" "$checksums_existed" || rollback_failed=1
	fi
	for stage in "$binary_stage" "$bundle_stage" "$checksums_stage"; do
		[ -z "$stage" ] || rm -f "$stage"
	done
	[ "$release_dir_created" = "0" ] || rmdir "$release_dir" 2>/dev/null || true
	[ "$vpnctl_lib_created" = "0" ] || rmdir "$install_root/usr/local/lib/vpnctl" 2>/dev/null || true
	[ "$usr_local_lib_created" = "0" ] || rmdir "$install_root/usr/local/lib" 2>/dev/null || true
	[ "$binary_dir_created" = "0" ] || rmdir "$binary_dir" 2>/dev/null || true
	[ "$usr_local_created" = "0" ] || rmdir "$install_root/usr/local" 2>/dev/null || true
	[ "$usr_created" = "0" ] || rmdir "$install_root/usr" 2>/dev/null || true
	rm -rf "$temporary_root"
	if [ "$rollback_failed" = "1" ]; then
		echo "error: installer rollback was incomplete; inspect the three standard vpnctl release paths" >&2
		exit 1
	fi
	exit "$status"
}
trap 'cleanup $?' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

download() {
	asset=$1
	target=$2
	if [ -n "$release_asset_dir" ]; then
		source="$release_asset_dir/$asset"
		[ ! -L "$source" ] && [ -f "$source" ] || die "release asset is missing or not a regular file: $asset"
		cp "$source" "$target"
	else
		curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
			"$base_url/$asset" --output "$target"
	fi
}

download "$binary_asset" "$download_binary"
download "$bundle_asset" "$download_bundle"
download "$checksums_asset" "$download_checksums"

[ "$(wc -l <"$download_checksums" | tr -d '[:space:]')" = "4" ] || die "release checksum metadata framing is invalid"
[ "$(sed -n '1p' "$download_checksums")" = "vpnctl-release-checksums-v1" ] || die "release checksum metadata header is invalid"
version_record=$(sed -n '2p' "$download_checksums")
printf '%s\n' "$version_record" | grep -Eq '^version  v[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-]+$' || die "release version record is invalid"
verified_version=${version_record#version  }
if [ "$version" != "latest" ] && [ "$version" != "$verified_version" ]; then
	die "release version $verified_version does not match requested $version"
fi
binary_record=$(sed -n '3p' "$download_checksums")
bundle_record=$(sed -n '4p' "$download_checksums")
printf '%s\n' "$binary_record" | grep -Eq "^[0-9a-f]{64}  [1-9][0-9]*  $binary_asset\$" || die "standalone binary checksum record is invalid"
printf '%s\n' "$bundle_record" | grep -Eq "^[0-9a-f]{64}  [1-9][0-9]*  $bundle_asset\$" || die "bundle checksum record is invalid"
canonical_checksums="$temporary_root/canonical-$checksums_asset"
printf '%s\n%s\n%s\n%s\n' "vpnctl-release-checksums-v1" "$version_record" "$binary_record" "$bundle_record" >"$canonical_checksums"
cmp -s "$download_checksums" "$canonical_checksums" || die "release checksum metadata is not canonical"
binary_checksum=$(printf '%s\n' "$binary_record" | awk '{print $1}')
binary_size=$(printf '%s\n' "$binary_record" | awk '{print $2}')
bundle_checksum=$(printf '%s\n' "$bundle_record" | awk '{print $1}')
bundle_size=$(printf '%s\n' "$bundle_record" | awk '{print $2}')
[ "$binary_size" -le "$maximum_binary_bytes" ] || die "standalone binary exceeds the installer bound"
[ "$bundle_size" -le "$maximum_bundle_bytes" ] || die "release bundle exceeds the installer bound"
[ "$(wc -c <"$download_binary" | tr -d '[:space:]')" = "$binary_size" ] || die "standalone binary size does not match checksum metadata"
[ "$(wc -c <"$download_bundle" | tr -d '[:space:]')" = "$bundle_size" ] || die "release bundle size does not match checksum metadata"

file_checksum() {
	if [ "$checksum_command" = "sha256sum" ]; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}
[ "$(file_checksum "$download_binary")" = "$binary_checksum" ] || die "standalone binary checksum does not match checksum metadata"
[ "$(file_checksum "$download_bundle")" = "$bundle_checksum" ] || die "release bundle checksum does not match checksum metadata"
chmod 0700 "$download_binary"
"$download_binary" __release-verify-bundle "$download_bundle" "$verified_version" "$binary_checksum" "$binary_size" >/dev/null 2>&1 || \
	die "release bundle structure or production manifest is invalid"
chmod 0600 "$download_binary"

for existing_path in "$install_root/usr" "$install_root/usr/local" "$binary_dir" "$install_root/usr/local/lib" "$install_root/usr/local/lib/vpnctl" "$release_dir"; do
	if [ -L "$existing_path" ] || { [ -e "$existing_path" ] && [ ! -d "$existing_path" ]; }; then
		die "install directory conflict: $existing_path"
	fi
done
for existing_path in "$binary_path" "$bundle_path" "$checksums_path"; do
	if [ -L "$existing_path" ] || { [ -e "$existing_path" ] && [ ! -f "$existing_path" ]; }; then
		die "install target conflict: $existing_path"
	fi
done

if [ ! -d "$install_root/usr" ]; then mkdir -m 0755 "$install_root/usr"; usr_created=1; fi
if [ ! -d "$install_root/usr/local" ]; then mkdir -m 0755 "$install_root/usr/local"; usr_local_created=1; fi
if [ ! -d "$binary_dir" ]; then mkdir -m 0755 "$binary_dir"; binary_dir_created=1; fi
if [ ! -d "$install_root/usr/local/lib" ]; then mkdir -m 0755 "$install_root/usr/local/lib"; usr_local_lib_created=1; fi
if [ ! -d "$install_root/usr/local/lib/vpnctl" ]; then mkdir -m 0755 "$install_root/usr/local/lib/vpnctl"; vpnctl_lib_created=1; fi
if [ ! -d "$release_dir" ]; then mkdir -m 0700 "$release_dir"; release_dir_created=1; fi

if [ -f "$binary_path" ]; then cp -p "$binary_path" "$temporary_root/previous.binary"; binary_existed=1; fi
if [ -f "$bundle_path" ]; then cp -p "$bundle_path" "$temporary_root/previous.bundle"; bundle_existed=1; fi
if [ -f "$checksums_path" ]; then cp -p "$checksums_path" "$temporary_root/previous.checksums"; checksums_existed=1; fi

binary_stage=$(mktemp "$binary_dir/.vpnctl-install.XXXXXX")
bundle_stage=$(mktemp "$release_dir/.bundle-install.XXXXXX")
checksums_stage=$(mktemp "$release_dir/.checksums-install.XXXXXX")
cp "$download_binary" "$binary_stage"
chmod 0755 "$binary_stage"
cp "$download_bundle" "$bundle_stage"
chmod 0600 "$bundle_stage"
cp "$download_checksums" "$checksums_stage"
chmod 0600 "$checksums_stage"

published=0
maybe_fail_for_test() {
	if [ "${VPNCTL_TESTING:-}" = "1" ] && [ -n "$install_root" ] && [ "${VPNCTL_TEST_FAIL_AFTER_INSTALL:-}" = "$published" ]; then
		die "injected installer publication failure"
	fi
}

mutation_started=1
mv -f "$bundle_stage" "$bundle_path"; bundle_stage=""; published=$((published + 1)); maybe_fail_for_test
mv -f "$checksums_stage" "$checksums_path"; checksums_stage=""; published=$((published + 1)); maybe_fail_for_test
mv -f "$binary_stage" "$binary_path"; binary_stage=""; published=$((published + 1)); maybe_fail_for_test
install_complete=1

echo "installed $binary_path"
echo "stored verified release bundle at $bundle_path"
echo "verified release version $verified_version"
