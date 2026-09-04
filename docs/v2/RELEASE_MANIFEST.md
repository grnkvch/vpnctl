# Signed release manifest

Task 14.1 defines the verification boundary consumed by the bundle builder,
installer, and updater. It does not create or publish a release archive.

Each release has a canonical JSON payload inside a strict Ed25519 envelope.
The signature covers the exact payload bytes with the domain
`vpnctl-release-manifest-v1`. The verifier receives an already trusted public
key from the installer/updater; the envelope `key_id` is only the SHA-256
identity of that key and can never select or replace trust.

The signed payload binds:

- the vpnctl version and exact binary SHA-256;
- the current and optional immediately previous control-protocol major/minor;
- the readable state-schema range;
- exact Ubuntu `24.04` and `amd64` target values;
- the handshake-host list version;
- whether the release's state migrations are backward reversible;
- every bundled component's version, capabilities, archive path, exact byte
  size, SHA-256, and gateway/node role scope;
- every apt-provided component's selected version, source, capabilities,
  compatible inclusive minimum/exclusive maximum package versions, and role
  scope.

The v2 constructor takes the build-specific vpnctl version/checksum/byte size
and the explicit migration-reversibility decision. It imports the same Mihomo,
frp, and nginx pins enforced by their runtime adapters. The current production
contract includes bundled vpnctl, Mihomo `v1.19.30`, and frp `0.69.0`, plus
Ubuntu compatibility ranges for nginx, nftables, and wireguard-tools.

Verification order is fail-closed and precedes installation:

1. Bound envelope size and strict-decode it, rejecting unknown/duplicate
   fields and non-canonical base64url.
2. Match the trusted Ed25519 key ID and verify the domain-separated signature.
3. Strict-decode the canonical payload and validate every cross-reference,
   sort order, role, path, capability, checksum, compatibility field, protocol
   window, and state range.
4. Compare an explicitly observed host to Ubuntu `24.04`/`amd64`.
5. Stream-hash every artifact and compare its exact byte size and SHA-256 to
   the signed values before role selection or installation.
6. Return the role-filtered signed Ubuntu package compatibility records to the
   init/update preflight. Bundle installation itself never invokes apt.

Artifact paths are canonical relative slash paths: absolute paths,
backslashes, dot paths, traversal, duplicate paths, and multiple artifacts for
one component are rejected. The vpnctl binary must be assigned to both roles.
Every bundled component must have exactly one artifact and every apt-provided
component exactly one compatibility record.

The public schemas and deliberately non-installable example are under
`docs/v2/schemas/`. Production private signing material is not stored in this
repository; tests generate ephemeral keys and retain no key files.

The deterministic framing, verification order, local-only boundary, and
role-specific filesystem layout are defined in
[`RELEASE_BUNDLE.md`](RELEASE_BUNDLE.md).
