## Purpose

Defines multi-device personal VPN identities and safe export flows that preserve v1 WireGuard and Clash/Mihomo use cases while making policy assignment explicit.

## ADDED Requirements

### Requirement: Explicit client creation
`vpnctl client add <name> [preset...]` SHALL create a unique immutable client identity and allocate the next free address from the client pool. It SHALL assign no presets unless they are explicitly supplied; supplied preset names SHALL be validated and assigned atomically with creation. Duplicate names and unknown presets SHALL fail without creating an identity.

#### Scenario: Selective iPhone client
- **WHEN** the operator runs `vpnctl client add iphone telegram openai anthropic`
- **THEN** one client is created with exactly those three preset assignments

#### Scenario: Full-tunnel client without presets
- **WHEN** the operator runs `vpnctl client add steamdeck`
- **THEN** one client identity is created with an empty selective preset assignment

### Requirement: Multiple isolated clients
The gateway SHALL support at least five concurrent personal client identities with unique credentials and stable overlay addresses. Client traffic SHALL be isolated from other clients and private nodes, and clients SHALL use the gateway only for permitted gateway services and internet egress.

#### Scenario: Client lateral connection attempt
- **WHEN** one active client attempts to connect to another client's overlay address
- **THEN** the gateway firewall blocks the connection

### Requirement: Client inspection without secrets
`client list` SHALL show active and revoked client records and omit deleted records; `client show <name-or-id>` SHALL expose non-secret identity, address, assignment, generation, export-staleness, and health metadata. Neither command SHALL reveal keys or secret-bearing profiles.

#### Scenario: Revoked client listing
- **WHEN** a client has been revoked but not deleted
- **THEN** it remains visible with revoked state and without credentials

### Requirement: Managed client export
`vpnctl client export <name-or-id> <clash|wireguard> [--output <path>] [--force]` SHALL write a profile to a file and MUST NOT print its content to stdout. Default artifacts SHALL be `/var/lib/vpnctl/exports/clients/<name>.clash.yaml` or `<name>.wireguard.conf`, with directory mode `0700` and file mode `0600`. The human result SHALL show the path and a ready `scp` command; JSON SHALL contain metadata and path only.

#### Scenario: Default Clash export
- **WHEN** the operator exports an active client as `clash` without an output override
- **THEN** vpnctl atomically writes the managed YAML file, records policy and credential generations, and prints only its path and copy hint

#### Scenario: Existing custom output
- **WHEN** a custom output file already exists and `--force` is absent
- **THEN** export refuses to overwrite it and leaves the existing file unchanged

### Requirement: Profile behavior
A `wireguard` export SHALL provide the v1-compatible standard full-tunnel profile and SHALL not depend on preset assignments. A `clash` export SHALL compile the client's explicit presets and equivalent split-DNS policy and MAY contain both standard and restricted alternatives, but the device user SHALL choose between transports manually. Capability mismatch in a target client SHALL be reported during validation/export and MUST NOT silently weaken policy.

#### Scenario: WireGuard after policy edit
- **WHEN** client presets change after a full-tunnel WireGuard export
- **THEN** that WireGuard export remains semantically current because its behavior does not depend on presets

### Requirement: Policy replacement and export staleness
Gateway client policy commands SHALL address an explicit client. `policy set <preset>... --client <client>` SHALL atomically replace the complete assignment, `policy clear --client <client>` SHALL explicitly empty it, and an empty `set` or unknown preset SHALL fail. A changed assignment SHALL mark the latest Clash export stale and return `requires_action: re-export`; it SHALL not modify a profile already copied to a device.

#### Scenario: Client policy replacement
- **WHEN** the operator replaces a client's assignments from `telegram openai` to `anthropic`
- **THEN** authoritative state contains only `anthropic` and the last Clash artifact is marked stale

### Requirement: Client revocation and deletion
`client revoke` SHALL require confirmation, immediately invalidate gateway acceptance of the client's credentials, and SHALL not support deferred execution. `client delete` SHALL require prior revocation and confirmation, remove the gateway record and stored exports, and acknowledge that vpnctl cannot remove profiles from external devices.

#### Scenario: Lost device revocation
- **WHEN** the operator revokes a lost device
- **THEN** its existing exported profile can no longer establish a new accepted connection

### Requirement: Client credential rotation
`client rotate` SHALL preserve client name, immutable ID, and overlay IP while issuing new credentials. It SHALL require confirmation, mark prior exports stale, and require a fresh export and manual device-profile replacement.

#### Scenario: Rotated Clash client
- **WHEN** a client rotation completes
- **THEN** old credentials are no longer accepted after the rollout boundary and the result requires re-export

### Requirement: Export delivery boundary
Client profile delivery in v2.0 SHALL be local file export followed by operator-controlled copying such as `scp`. QR codes, stdout profile piping, URLs, temporary links, and subscription links SHALL not be provided.

#### Scenario: Successful export output
- **WHEN** export succeeds in human or JSON mode
- **THEN** no QR, hosted URL, subscription endpoint, or profile secret is emitted
