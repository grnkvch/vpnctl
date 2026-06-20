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
