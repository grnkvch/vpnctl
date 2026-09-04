# Signed v2 installation

The v2 bootstrap installs one role-neutral binary and retains the complete
release bundle locally. The role is still selected only by the subsequent
`vpnctl init --gateway` or `vpnctl init --node` command.

## Trust and release assets

Every GitHub release publishes exactly four Linux/amd64 assets:

```text
vpnctl-linux-amd64
vpnctl-v2-linux-amd64.bundle
release-checksums.txt
release-checksums.txt.sig
```

`release-checksums.txt` is canonical metadata containing the signed release
version plus the exact size and SHA-256 of both payloads. The raw 64-byte
Ed25519 signature covers the domain `vpnctl-release-checksums-v1\0` followed by
the exact metadata bytes. The curl bootstrap embeds the same release public key
as the signed handshake-host list. Its raw-key ID is:

```text
sha256:9e061dd425ff7766f826911dec3502d6b8f1494705432da049ffed3c0fbe20bc
```

The private signing key is not stored in this repository. The maintainer-side
builder accepts only one mode-`0600`, regular, non-symlink PKCS#8 Ed25519 key
whose public half matches that trust anchor. Provider archives are supplied as
local inputs and must match the pinned Mihomo/frp sizes and SHA-256 values; the
release process never downloads an unpinned provider artifact.

## Online bootstrap

Run the installer as root on Ubuntu 24.04 amd64:

```sh
curl -fsSL https://raw.githubusercontent.com/vgrinkevich/vpnctl/master/scripts/install.sh | sudo sh
```

For an explicit signed version:

```sh
curl -fsSL https://raw.githubusercontent.com/vgrinkevich/vpnctl/master/scripts/install.sh \
  | sudo VPNCTL_VERSION=v2.0.0 sh
```

The script downloads all four files to a private temporary directory using
HTTPS with TLS 1.2 or newer. It verifies the metadata signature first, requires
an explicit requested tag to equal the signed version, then verifies both
sizes and checksums. A download, signature, metadata, size, or checksum failure
occurs before an installation directory or target is changed.

## Offline `scp` bootstrap

Download all four assets and `scripts/install.sh` on a connected machine, then
copy them to one private directory on the VPS. The same verifier can consume
that directory without curl:

```sh
scp scripts/install.sh vpnctl-linux-amd64 vpnctl-v2-linux-amd64.bundle \
  release-checksums.txt release-checksums.txt.sig root@SERVER:/root/vpnctl-release/

ssh root@SERVER \
  'VPNCTL_RELEASE_ASSET_DIR=/root/vpnctl-release /bin/sh /root/vpnctl-release/install.sh'
```

The local directory and every asset must be regular and non-symlink. This path
is self-contained for vpnctl-managed binaries; later role initialization can
still need configured Ubuntu repositories for its signed apt requirements.

## Standard layout and failure behavior

The verified bootstrap publishes support files first and the executable last:

```text
/usr/local/bin/vpnctl                              0755
/usr/local/lib/vpnctl/release/                     0700
/usr/local/lib/vpnctl/release/vpnctl.bundle        0600
/usr/local/lib/vpnctl/release/checksums.txt         0600
/usr/local/lib/vpnctl/release/checksums.txt.sig     0600
```

All new bytes are staged on the destination filesystem. Existing regular files
are copied to the private transaction directory before publication. If a later
publication step fails, the previous four files are restored and directories
created by that invocation are removed only when empty. Symlink/non-regular
targets and symlink/non-directory parents are conflicts. Reinstalling the same
signed release is safe.

During `init`, vpnctl reads the retained bundle from the standard path,
re-verifies its internal signed manifest and every artifact without staging or
mutation during planning, and repeats verification during apply. It installs
only vpnctl + Mihomo + `frps` for a gateway or vpnctl + Mihomo + `frpc` for a
node, then stores the signed component manifest in authoritative state. A
bundle changed between plan and apply is rejected before the role layout is
created.

The older unsigned v1 artifact flow is retained only as
`scripts/install-v1.sh` and `scripts/release-v1.sh` for migration/regression;
it is not the v2 installation path.
