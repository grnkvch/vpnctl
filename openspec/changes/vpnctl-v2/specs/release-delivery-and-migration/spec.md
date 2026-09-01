## Purpose

Defines reproducible software delivery, manual compatible upgrades, portable gateway recovery, v1 migration, and the complete release gates for the minimum supported VPS.

## ADDED Requirements

### Requirement: Signed self-contained release bundle
Each release SHALL provide one signed, checksummed bundle containing the vpnctl binary, a manifest, and pinned third-party data-plane binaries needed by both roles. Initialization SHALL install only the selected role's components from the local bundle. Normal apply and repair MUST NOT download replacement binaries from upstream projects. Ubuntu packages such as nftables, WireGuard tools, and the selected reverse proxy SHALL come from configured Ubuntu repositories and be version/compatibility reported.

#### Scenario: Offline-transferred bundle
- **WHEN** an operator downloads a bundle elsewhere, copies it to the VPS with `scp`, and initializes a role
- **THEN** vpnctl verifies the bundle and installs its pinned role components without fetching those binaries from their upstream repositories

### Requirement: Installer verification boundary
The official curl installer SHALL verify release metadata and checksums before installing the vpnctl binary. Offline bundle transfer SHALL be supported, but v2.0 SHALL not claim a fully air-gapped OS setup because required Ubuntu packages can still need configured apt repositories.

#### Scenario: Bundle checksum mismatch
- **WHEN** the downloaded or copied release bundle does not match its signed manifest
- **THEN** installation or update stops before replacing any installed component

### Requirement: Manual gateway-first updates
`vpnctl update`, `vpnctl update <version>`, and `vpnctl update rollback` SHALL be manual operations; no background update check, beta/nightly channel, or automatic remote-node update SHALL exist. An update SHALL verify all artifacts, show version and state-migration diff, fleet compatibility, affected services, expected interruption, and rollback capability before confirmed mutation. Updates SHALL proceed gateway before nodes.

#### Scenario: Latest stable update
- **WHEN** the operator explicitly runs `vpnctl update`
- **THEN** vpnctl checks the latest stable release, presents the verified plan, and waits for confirmation without updating nodes remotely

### Requirement: Update isolation and rollback
Before update, vpnctl SHALL preserve the prior binary/component bundle and a state snapshot. Unchanged healthy data-plane components SHALL not restart; changed components SHALL update sequentially with health checks and per-service rollback. `update rollback` SHALL restore the prior release and state only when migration compatibility permits. An irreversible migration SHALL be disclosed before apply and require separate confirmation.

#### Scenario: Updated component fails health check
- **WHEN** one changed data-plane component fails its post-update health check
- **THEN** vpnctl restores the compatible previous component/configuration and reports the failed update without unnecessarily restarting unchanged components

### Requirement: Update availability expectations
Single-gateway zero downtime SHALL not be promised. Update plans SHALL disclose possible transport reconnect, temporary ingress `503`, active-request interruption, and routing-engine fail-closed interruption. A management version mismatch MUST NOT tear down a compatible working data plane; unsupported mutations SHALL return an upgrade-required action without configuration change.

#### Scenario: Controller-only compatible update
- **WHEN** an update changes only the controller and CLI while data-plane manifest entries are identical
- **THEN** healthy data-plane processes continue without restart

### Requirement: Encrypted portable gateway backup
`vpnctl backup [archive-path]` SHALL create a passphrase-encrypted, atomically written mode-`0600` gateway archive containing authoritative state, presets, gateway identities/certificates, client secrets/exports, and gateway-side material required to preserve trust with existing nodes. The passphrase SHALL be entered and confirmed through hidden interactive prompts and MUST NOT be accepted as a command-line argument or retained on the gateway. Existing targets SHALL not be overwritten silently.

#### Scenario: Default backup
- **WHEN** the operator completes `vpnctl backup` with matching hidden passphrases
- **THEN** a timestamped encrypted archive is atomically created under `/var/lib/vpnctl/backups/` and status can report its age

### Requirement: Node and application data exclusion from backup
Gateway backup MUST NOT contain private-node private keys, portable node identity, or user application data. v2.0 SHALL not provide private-node cloning or portable restore; a lost node SHALL be replaced by revoking its identity and joining a new machine.

#### Scenario: Gateway archive inspection after decryption
- **WHEN** a valid backup is inspected by its owner
- **THEN** it contains no node-side private key or application payload data

### Requirement: Validated non-merging gateway restore
`vpnctl restore <archive-path> --public-ip <IPv4> [--replace]` SHALL require an explicit current public IP even if unchanged. On a clean installed host it SHALL establish the gateway role without prior init after fully decrypting, validating, and preflighting before mutation. It SHALL never merge states. An initialized gateway SHALL require `--replace`, a complete impact plan, and an emergency snapshot before atomic replacement.

#### Scenario: Restore to clean host with same endpoint
- **WHEN** a valid archive is restored to a compatible clean host using the original public IP
- **THEN** existing node trust and client profiles remain usable after gateway services converge

#### Scenario: Invalid archive
- **WHEN** archive authentication, schema, or host preflight fails
- **THEN** restore performs no system mutation

### Requirement: Restore endpoint change actions
Restore to a new public IP SHALL be supported with downtime but SHALL not claim seamless continuity. The result SHALL list required node rebind, client re-export, webhook URL/certificate update, and other external actions.

#### Scenario: Restore to new public IP
- **WHEN** a gateway archive is restored using a different public IPv4 address
- **THEN** state is restored consistently and every stale external or node artifact is identified in `requires_action`

### Requirement: One-time v1 migration
Migration from v1 SHALL be supplied as a separate one-time script rather than a permanent vpnctl command. It SHALL preserve client private/public keys, allocated `10.66.0.x` addresses, and exportable profiles as technically possible, translate v1 rulesets/state into validated v2 state, and handle v1 UFW configuration without leaving conflicting firewall ownership. A documented maintenance window with downtime SHALL be acceptable.

#### Scenario: Migrate existing v1 clients
- **WHEN** the migration script processes a valid v1 installation
- **THEN** migrated clients retain their identities, keys and addresses where compatible and can pass v2 client acceptance tests after convergence

### Requirement: Minimum capacity target
v2.0 SHALL support a gateway with 1 vCPU, 512 MB RAM, and 10 GB disk for one primary private node serving Telegram webhook/API traffic for several hundred users and up to five personal clients. Shared native daemons SHALL be used where behavior permits, idle controller memory SHALL target no more than approximately 20 MiB, and benchmark results SHALL be recorded as release evidence.

#### Scenario: Minimum-host benchmark
- **WHEN** the complete v2 stack runs the defined idle and representative Telegram/client workload on the minimum host
- **THEN** it remains stable within documented CPU, memory, disk, connection, and latency acceptance bounds

### Requirement: Full non-backlog release gate
v2.0 SHALL not be declared complete until every requirement in all capabilities of this change is implemented, all mandatory restricted-transport, ingress, reverse-tunnel, firewall/control, resource, and security spikes pass, actual supported Clash Mi passes its manual acceptance suite against an actually deployed service, v1 behavior is preserved or deliberately migrated, and the full unit/integration/E2E/resource/migration suite passes. Internal vertical slices and automated development-candidate gates SHALL be ordering and risk-reduction milestones only and MUST NOT reduce or waive the v2.0 scope.

#### Scenario: Vertical slice passes before remaining capabilities
- **WHEN** one node, restricted Telegram egress, and one webhook expose pass E2E but other non-backlog requirements remain incomplete
- **THEN** the build is treated as an internal milestone and not a completed v2.0 release

### Requirement: Explicit v2.0 exclusions
v2.0 SHALL exclude multi-gateway mesh/failover/load balancing, node-to-node networking, automatic transport selection/fallback, multiple steady-state node transports, process/container-scoped policy, raw Mihomo config passthrough, public or remote management UI/API, Docker/Kubernetes deployment, generic ingress, full IPv6, domain/ACME, URL/subscription/QR delivery, scheduled remote backups/external secret stores, portable node backup/cloning, invite files, and user applications on the gateway.

#### Scenario: Request for excluded capability
- **WHEN** an operator attempts to configure an explicitly excluded v2.0 capability
- **THEN** vpnctl rejects it as unsupported without weakening an existing security or routing guarantee
