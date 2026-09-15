# Checksum-verified v2 installation

The v2 bootstrap installs one role-neutral binary and retains the complete
release bundle locally. The role is selected only by the subsequent
`vpnctl init --gateway` or `vpnctl init --node` command.

## Trust and release assets

Every GitHub release publishes exactly three Linux/amd64 assets:

```text
vpnctl-linux-amd64
vpnctl-v2-linux-amd64.bundle
release-checksums.txt
```

`release-checksums.txt` is canonical metadata containing the release version
plus the exact size and SHA-256 of both binary assets. The release builder
accepts only local provider archives whose sizes and SHA-256 values match the
pinned Mihomo/frp versions; it never downloads an unpinned provider artifact.

v2.0 deliberately does not publish or verify a release signature. SHA-256
detects corruption when `release-checksums.txt` is trusted, but cannot detect
an attacker who replaces both an artifact and its checksum metadata. For an
online install, HTTPS and the GitHub account/release are the publisher trust
boundary. For an offline install, obtain the files on a trusted machine and
copy them over trusted SSH/`scp`. Signed releases, release-key rotation and
recovery are tracked in [`../BACKLOG.md`](../BACKLOG.md).

This limitation applies only to release delivery. Enrollment transcripts,
control PKI, encrypted backups, public ingress TLS, tunnel credentials, and the
independently signed handshake-host document keep their existing signatures
and authentication checks.

## Online bootstrap

Run the installer as root on Ubuntu 24.04 amd64:

```sh
curl -fsSL https://raw.githubusercontent.com/vgrinkevich/vpnctl/master/scripts/install.sh | sudo sh
```

For an explicit version:

```sh
curl -fsSL https://raw.githubusercontent.com/vgrinkevich/vpnctl/master/scripts/install.sh \
  | sudo VPNCTL_VERSION=v2.0.0 sh
```

The script downloads all three files to a private temporary directory using
HTTPS with TLS 1.2 or newer. It strictly parses the checksum metadata, requires
an explicit requested tag to equal its version, and verifies both sizes and
SHA-256 values. Before the first filesystem mutation, the checksum-verified
vpnctl binary invokes its private bootstrap verifier over the bundle. That
verifier requires the exact production manifest, standalone-binary identity,
target platform, canonical framing, every internal size/SHA-256, and exact EOF.
A download, metadata, size, checksum, or bundle-structure failure occurs before
an installation directory or target is changed. The verifier command is an
installer protocol and is intentionally absent from the public CLI/help.

## Offline `scp` bootstrap

Download the three assets and `scripts/install.sh` on a trusted connected
machine, then copy them to one private directory on the VPS:

```sh
scp scripts/install.sh vpnctl-linux-amd64 vpnctl-v2-linux-amd64.bundle \
  release-checksums.txt root@SERVER:/root/vpnctl-release/

ssh root@SERVER \
  'VPNCTL_RELEASE_ASSET_DIR=/root/vpnctl-release /bin/sh /root/vpnctl-release/install.sh'
```

The local directory and every consumed asset must be regular and non-symlink.
This path is self-contained for vpnctl-managed binaries. Role initialization
uses the configured Ubuntu repositories for only the APT packages declared for
that role by the verified bundle. It resolves and installs an exact compatible
version; it does not run a general upgrade, autoremove unrelated packages, or
install Gateway-only nginx resources on a Node.

## Standard layout and failure behavior

The verified bootstrap publishes support files first and the executable last:

```text
/usr/local/bin/vpnctl                              0755
/usr/local/lib/vpnctl/release/                     0700
/usr/local/lib/vpnctl/release/vpnctl.bundle        0600
/usr/local/lib/vpnctl/release/checksums.txt         0600
```

All new bytes are staged on the destination filesystem. Existing regular files
are copied to the private transaction directory before publication. If a later
publication step fails, the previous three files are restored and directories
created by that invocation are removed only when empty. Symlink/non-regular
targets and symlink/non-directory parents are conflicts. Reinstalling the same
checksum-verified release is safe.

During `init`, vpnctl reads the retained bundle from the standard path, checks
its canonical manifest, target platform, framing, exact EOF, and every internal
artifact without mutation during planning, then repeats verification during
apply. It installs vpnctl + Mihomo + `frps` for a gateway or vpnctl + Mihomo +
`frpc` for a node and stores the component manifest in authoritative state. A
bundle changed between plan and apply is rejected before role layout creation.

The same init transaction installs missing role-selected Ubuntu packages from
the bundle's compatibility records. Gateway init temporarily prevents the
distro nginx unit from starting with its default configuration, publishes the
vpnctl-owned service drop-in and baseline immutable ingress tree, then enables
and starts nginx. Success means the empty-expose Gateway already serves its
IP-only certificate and reserved health/enrollment namespace on TCP 443. APT,
version, ownership, activation, listener, or health failures are visible init
failures; rerunning init against its own incomplete authoritative state repairs
only that same bootstrap instead of creating a new identity.

Installation success proves only the three release files above. It does not
claim that a role has been initialized or that its network path is healthy.
After `init` and any returned new-session watchdog confirmation, use the
following boundaries in order:

```text
sudo vpnctl status --all       # passive; no network probe or mutation
sudo vpnctl plan               # read-only desired/applied/observed comparison
sudo vpnctl doctor ingress     # active bounded Gateway probe
sudo vpnctl repair --dry-run   # read-only repair preview, only when plan shows drift
sudo vpnctl repair             # explicit confirmed mutation
```

A repair that changes the network can return a new transaction ID and still
requires `vpnctl confirm <transaction-id>` from a genuinely new SSH session.
There is no permanent bootstrap-recovery or offline-update command. The one
unpublished incomplete `v2.0.0` candidate has a separately hash-bound,
one-time maintainer procedure in
[`RELEASE_RECOVERY_PLAN.md`](RELEASE_RECOVERY_PLAN.md); it is not part of a
normal installation and must not be generalized to another host or artifact.

The separately versioned v1 maintenance operation, including its qualification,
rollback, acceptance, and retirement boundary, is documented in
[`V1_MIGRATION.md`](V1_MIGRATION.md). Its executable is not a product release
asset.
