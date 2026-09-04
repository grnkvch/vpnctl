# Self-contained release bundle

Task 14.2 defines the reproducible local delivery unit consumed by gateway and
node installation. The signed online/offline bootstrap and standard retained
bundle path are defined in [`INSTALLATION.md`](INSTALLATION.md); the role
boundary accepts only an explicit absolute path to a regular, non-symlink
local file.

## Deterministic format

The bundle is a timestamp-free binary stream. Integer fields are unsigned
big-endian values and artifacts appear exactly once in the canonical order of
the signed manifest:

```text
"VPNCTLBUNDLE\0\1"
uint32 signed_manifest_length
bytes  signed_manifest
repeat for every signed artifact:
  uint16 path_length
  bytes  path
  uint64 artifact_size
  bytes  artifact
EOF
```

The format deliberately does not use outer tar metadata, so file owners,
modes, mtimes, host filesystem order, and build directory names cannot change
the result. Equal manifest, signing key, and artifact bytes produce equal
bundle bytes.

The signed manifest remains the only source of truth. The outer path and size
framing must match the next signed artifact exactly; reordered, missing,
duplicate, truncated, appended, or oversized data is rejected. The current
hard bounds are 1 MiB for the signed envelope, 256 MiB per artifact, 512 MiB
for all artifact payloads, and the bounded framing overhead.

## Verification and installation

Installation is fail-closed and completes all bundle verification before
creating a target directory or file:

1. Require a bounded local regular file and reject symlinks.
2. Validate magic and signed-envelope length.
3. Verify the canonical Ed25519 envelope with the caller-supplied trusted key.
4. Require the observed host to match signed Ubuntu `24.04`/`amd64`.
5. Stream every artifact into a private temporary stage while checking its
   signed order, path, byte size, and SHA-256.
6. Require exact EOF, then safely extract only the selected role's binaries.
7. Preflight every final path before creating anything. An existing exact
   mode-`0755` file is idempotent; any different file, symlink, or non-directory
   parent is a conflict.
8. Install absent files without replacement and roll back every file and empty
   directory created by a failed invocation.

The installer returns the signed, role-filtered Ubuntu package compatibility
records to the init/update layer. It neither invokes apt nor downloads from an
upstream project. Consequently an `scp`-transferred bundle contains all
vpnctl-managed binaries, but v2.0 does not claim fully air-gapped OS setup:
nginx, nftables, and wireguard-tools can still require configured Ubuntu apt
repositories.

## Role layout

| Target | Gateway | Node | Bundle source |
| --- | --- | --- | --- |
| `/usr/local/bin/vpnctl` | yes | yes | exact vpnctl artifact |
| `/usr/local/libexec/vpnctl/mihomo` | yes | yes | pinned Mihomo gzip payload |
| `/usr/local/libexec/vpnctl/frps` | yes | no | pinned frp archive member |
| `/usr/local/libexec/vpnctl/frpc` | no | yes | pinned frp archive member |

Both provider archives are still verified in full before role selection. A
gateway never installs `frpc`, and a node never installs `frps`. Normal
`init`, `apply`, and `repair` have no upstream-download path for these bundled
components; replacement is a release/update concern.

For offline transfer, the operator copies the four signed release assets and
installer with `scp`. The bootstrap stores the verified bundle at
`/usr/local/lib/vpnctl/release/vpnctl.bundle`; the subsequent role init consumes
that exact local file.
