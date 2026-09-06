# 0022: Use Checksum-Only Release Delivery for v2.0

Status: Accepted for v2.0; cryptographically signed releases are deferred to
the backlog.

## Context

The original v2 design required a production Ed25519 release key and detached
signatures for both outer checksum metadata and the internal bundle manifest.
No production signing-key lifecycle exists yet. Requiring it blocks release
and real-machine testing, while the v1 release already uses a simpler SHA-256
delivery model.

v2 still needs a self-contained bundle because gateway and node roles install
different pinned Mihomo/frp binaries. A single v1-style tarball is therefore
not sufficient.

## Decision

Publish exactly three Linux/amd64 assets:

- `vpnctl-linux-amd64`;
- `vpnctl-v2-linux-amd64.bundle`;
- `release-checksums.txt`.

The checksum file canonically binds the release version and exact size/SHA-256
of both binary assets. The bundle contains a canonical manifest followed by
strictly framed artifacts in manifest order. Installer, init, update,
rollback, release verification, and v1 migration validate the applicable
sizes, hashes, framing, platform, component pins, and exact EOF before
mutation.

No release signing key, detached `.sig` asset, signed manifest envelope, or
embedded release trust anchor exists in v2.0. HTTPS GitHub delivery or trusted
SSH/`scp` supplies publisher-channel trust.

This decision changes only release delivery. Enrollment transcripts, control
PKI, encrypted backups, public ingress TLS, tunnel credentials, and the
independently signed handshake-host document remain authenticated as before.

## Consequences

SHA-256 detects accidental corruption and modification when checksum metadata
is trusted. It cannot detect an attacker who can replace both an artifact and
`release-checksums.txt`; documentation and release-gate output must not claim
publisher authentication.

The maintainer release command no longer needs private key material, which
allows reproducible release artifacts to be built for real-machine tests.
Signed publishing, key storage/rotation/revocation/recovery, CI integration,
offline verification, downgrade/replay protection, and migration from
checksum-only installs are explicit backlog work.

## Alternatives considered

- Keeping the release blocked until a production signing-key lifecycle existed
  was rejected for v2.0 because it prevents the accepted resource-constrained
  delivery trade-off and real deployment testing.
- Disabling signature verification while retaining signature fields was
  rejected because it would create a misleading security contract.
- Reusing one tarball exactly like v1 was rejected because role-scoped pinned
  Mihomo/frp installation requires the deterministic v2 bundle manifest.
