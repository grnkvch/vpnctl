# Backlog

This backlog records features and ideas that are intentionally not required for
the first server-local MVP.

## Future Features

### Remote SSH Apply

Run `vpnctl` on the operator machine and apply changes to the VPS over SSH.

Requires:

- SSH execution abstraction
- safe upload of rendered config
- remote validation
- privilege handling for root or sudo
- rollback or recovery strategy

### Non-Root Server Mode

Support running `vpnctl` as a normal user with explicit `sudo` escalation.

Requires:

- sudo capability detection
- clear privilege error messages
- careful command boundaries

### Additional Linux Distributions

Support server-local apply on distributions other than Ubuntu 24.04 LTS x64.

Candidates:

- Debian
- newer Ubuntu LTS versions
- Arch Linux

Requires:

- OS detection
- package/layout differences
- service management differences
- firewall/routing differences

### Automatic System Upgrade

Optionally run broader package upgrades during setup.

Candidate:

```text
vpnctl setup --upgrade
```

This is out of MVP because `apt upgrade -y` is a broad system mutation and can
restart services or change unrelated packages.

### Binary Install And Update Flow

Provide a convenient way to install `vpnctl` onto the server.

Candidates:

- local cross-compile plus `scp`
- release artifacts on GitHub
- install script
- package manager formula later

### Web-Based Config Delivery

Priority: required after MVP.

Provide an iPhone-friendly way to import generated configs without manually
copying files through `scp` and AirDrop/iCloud/Files.

Candidates:

- temporary HTTP server
- one-time download links
- signed URLs
- QR code that opens a temporary config URL

Requires a new ADR covering:

- expiration
- authentication
- one-time access
- revocation
- logging
- network binding and firewall behavior
- secret exposure risk

### Link-Based Config Delivery

Support temporary links, signed URLs, or one-time links for client configs.

Requires a new ADR covering:

- expiration
- authentication
- revocation
- logging
- secret exposure risk

### Multiple Servers

Manage more than one VPN server from a single state repository.

Requires:

- server selection in commands
- per-server address allocation
- per-server generated configs

### Encrypted Secret Storage

Encrypt private keys at rest instead of relying only on filesystem permissions.

Candidates:

- age
- GPG
- platform keychain integration

### IPv6 Support

Support IPv6 WireGuard addressing and routing.

Requires:

- IPv6 subnet allocation
- client config rendering
- server forwarding and firewall behavior

### Split Tunnel Client Routing

Support client configs that route only selected networks through WireGuard.

Candidates:

- `vpnctl client create vm --route-mode split`
- `vpnctl client create phone --allowed-ips 10.66.0.0/24`
- platform-specific defaults for Linux VMs

Requires:

- route mode in state
- client renderer support
- clear warnings for full tunnel on remote Linux clients

### Full Tunnel Clash Mi Routing

Support a Clash Mi route mode that sends all Clash-handled traffic through VPN.

Candidate output:

- final rule `MATCH,VPN`

Requires:

- route mode in state
- explicit user selection
- clear explanation that unrelated traffic will no longer go direct

### Server Config Render Command

Expose a public command that renders the desired WireGuard server config without
applying it.

Candidate:

```text
vpnctl server render
```

Requires:

- clear secret handling policy
- no accidental server private key leakage
- distinction from `vpnctl apply --dry-run`

### Explicit Regenerate Config Command

Add a batch command for regenerating generated artifacts without exporting them
directly.

Candidate:

```text
vpnctl client regenerate-config <client-id> --type all
```

In MVP, `vpnctl client export` regenerates the requested artifact from state.

### Explicit Ruleset Validate Command

Add a manual validation command for operators who edit ruleset files directly.

Candidate:

```text
vpnctl ruleset validate [<ruleset-id>]
```

In MVP, rulesets are validated automatically when shown, written, or used for
Clash export.

### Clash/Mihomo Advanced Rules

Improve routing policy management beyond the basic Clash Mi profile required by
the MVP.

Candidates:

- additional ruleset types such as `domain`, `domain-keyword`, `ip-cidr`, and
  `geoip`
- remote ruleset providers
- per-client profiles
- DNS policy templates
- platform-specific defaults

### Existing Server Import

Import an existing WireGuard server configuration into vpnctl state.

Requires:

- parser for existing `wg0.conf`
- mapping peers to client records
- safe handling of existing private keys

### Release Automation

Build and publish reproducible binaries.

Requires:

- build matrix for Linux amd64 and arm64
- checksums
- version injection
- release notes

### Separate Release Integrity from Authenticity

Architecturally separate two independent release-verification layers so that
adding or removing publisher authentication does not require cross-cutting
changes to bundle parsing, installation, update snapshots, rollback, or
migration orchestration:

- **integrity (required baseline):** canonical checksum metadata, exact asset
  sizes and SHA-256 values, canonical bundle manifest, strict framing and
  ordering, internal artifact verification, platform/component constraints,
  and exact EOF;
- **authenticity (optional policy layer):** an Ed25519 signature over the exact
  canonical checksum metadata, verified against an explicitly configured or
  pinned publisher trust root before the integrity-verified artifacts may be
  used.

Define one shared release-verification abstraction composed by install, local
init, update/rollback, and one-time migration. The integrity verifier must not
depend on signing keys or signature assets. The authenticity verifier must add
publisher identity without duplicating or weakening integrity checks, and its
absence must remain an explicit checksum-only policy rather than an implicit
verification bypass.

Future authenticity work includes Ed25519 key generation and protected
storage, rotation, revocation and compromise recovery, trust-root migration,
CI/release integration, optional signature publication, and consistent policy
enforcement in install, update, rollback, and migration. This is an
architectural backlog item only and is not implemented in the current
iteration.

### Cryptographically Signed Release Delivery

Replace the v2.0 checksum-only publisher trust boundary with authenticated
release artifacts. The current SHA-256 metadata detects corruption only when
the metadata is obtained through trusted HTTPS or SSH/`scp`; it cannot detect
replacement of both an artifact and its checksum file.

The future design must cover:

- a canonical, domain-separated signature over release checksum metadata and
  the self-contained bundle manifest;
- offline verification after `scp` without contacting an external key server;
- release signing-key generation, protected storage, rotation, revocation, and
  recovery after suspected compromise;
- an embedded or otherwise pinned trust-root update strategy;
- CI/release tooling that publishes and verifies the exact signed asset set;
- enforcement by curl installation, local init, update/rollback, and the
  one-time migration workflow;
- downgrade, replay, mirror, and simultaneous artifact-plus-metadata
  substitution threat tests;
- a migration path from existing checksum-only v2.0 installations.

This backlog item applies only to release publishing. The existing enrollment,
control PKI, backup authentication, public ingress TLS, tunnel credentials, and
signed handshake-host document remain in scope and must not be weakened.
