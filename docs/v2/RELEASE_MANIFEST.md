# Canonical release manifest

Task 14.1 defines the internal validation boundary consumed by the bundle
builder, installer, updater, rollback, and v1 migrator. It does not create or
publish a release archive.

Each bundle starts with one canonical JSON manifest. It binds:

- the vpnctl version and exact binary SHA-256;
- the current and optional immediately previous control-protocol major/minor;
- the readable state-schema range;
- exact Ubuntu `24.04` and `amd64` target values;
- the independently signed handshake-host document version;
- whether the release's state migrations are backward reversible;
- every bundled component's version, capabilities, archive path, exact byte
  size, SHA-256, and gateway/node role scope;
- every apt-provided component's selected version, source, capabilities,
  compatible inclusive minimum/exclusive maximum package versions, and role
  scope.

The v2 constructor takes the build-specific vpnctl version/checksum/byte size
and explicit migration-reversibility decision. It imports the same Mihomo, frp,
and nginx pins enforced by runtime adapters. The current production contract
includes bundled vpnctl, Mihomo `v1.19.30`, and frp `0.69.0`, plus Ubuntu
compatibility ranges for nginx, nftables, and wireguard-tools.

Validation precedes installation:

1. Bound manifest size and strict-decode it, rejecting unknown/duplicate fields
   and non-canonical JSON.
2. Validate every cross-reference, sort order, role, path, capability,
   checksum, compatibility field, protocol window, and state range.
3. Compare an explicitly observed host to Ubuntu `24.04`/`amd64`.
4. Stream-hash every artifact and compare its exact byte size and SHA-256 to
   the manifest before role selection or installation.
5. Return role-filtered Ubuntu package compatibility records to init/update
   preflight. Bundle installation itself never invokes apt.

Artifact paths are canonical relative slash paths: absolute paths,
backslashes, dot paths, traversal, duplicate paths, and multiple artifacts for
one component are rejected. The vpnctl binary must serve both roles. Every
bundled component has exactly one artifact and every apt-provided component one
compatibility record.

The manifest is not signed and does not authenticate its publisher. Complete
bundle size/SHA-256 is checked against `release-checksums.txt`, whose trusted
delivery boundary is HTTPS or SSH/`scp` for v2.0. An attacker able to replace
both files is outside this checksum-only guarantee. This exception does not
apply to the independently signed handshake-host document or any other vpnctl
cryptographic trust domain.

The public schema and deliberately non-installable example are under
`docs/v2/schemas/`. The deterministic framing, local-only boundary, and
role-specific layout are defined in [`RELEASE_BUNDLE.md`](RELEASE_BUNDLE.md).
The outer three-asset bootstrap transaction is defined in
[`INSTALLATION.md`](INSTALLATION.md).
