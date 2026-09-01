## Purpose

Defines secure private-node bootstrap and the complete identity lifecycle from one-time enrollment through rotation, revocation, deletion, and same-node emergency recovery.

## ADDED Requirements

### Requirement: Explicit one-time invite
`vpnctl invite <node-name>` SHALL run on the gateway, require a unique node name, and reveal one opaque token exactly once through an interactive human output flow. The token SHALL expire after 15 minutes, be single-use, and carry the control protocol version, public gateway endpoint, stable gateway identity fingerprint, invite ID, one-time secret, node name, and expiration. The gateway SHALL store only a hash of the invite secret plus metadata and state.

#### Scenario: Invite expires unused
- **WHEN** a node presents an invite more than 15 minutes after issuance
- **THEN** enrollment is rejected, no node state is created, and the invite remains unusable

### Requirement: Invite inspection and cancellation
Active unexpired invites SHALL appear in general status without their secrets. `vpnctl invite cancel <invite-id>` SHALL immediately and idempotently invalidate an unused invite without confirmation. If the invite has already been consumed, cancellation SHALL direct the operator to node revocation.

#### Scenario: Repeated invite cancellation
- **WHEN** the operator cancels the same unused invite more than once
- **THEN** it remains invalid and the repeated command returns a non-destructive successful result

### Requirement: Separate node initialization and join
`vpnctl init --node` SHALL initialize only the host role. `vpnctl join <standard|restricted> [preset...]` SHALL be permitted only on an initialized, not-yet-joined node, SHALL require an explicit initial active transport, and SHALL assign only the explicitly listed presets. The invite token SHALL be read through hidden interactive input and MUST NOT be accepted as a command-line argument or file in v2.0.

#### Scenario: Minimal restricted join
- **WHEN** an initialized node runs `vpnctl join restricted telegram` and supplies a valid token
- **THEN** it enrolls with restricted active, standard standby, and only the `telegram` preset assigned

#### Scenario: Unknown initial preset
- **WHEN** join includes a preset unknown to the gateway
- **THEN** join fails atomically, local node identity is not committed, and the invite remains unused

### Requirement: Token-gated public enrollment
Bootstrap SHALL use a token-gated HTTPS endpoint under the reserved `/.well-known/vpnctl/` path on gateway `443/TCP`, sharing the HTTPS listener with managed ingress by path routing. On successful enrollment, the invite SHALL become invalid immediately and subsequent management SHALL move to the private internal mTLS control channel.

#### Scenario: Invite replay
- **WHEN** a second host submits a token after the first enrollment successfully consumed it
- **THEN** the gateway rejects the replay and creates no second identity

### Requirement: Node-owned private keys
During join, the node SHALL generate its control Ed25519 private key and all other node private keys locally and SHALL send only the public material or CSR needed by the gateway. Node private keys MUST NOT be generated on or transferred from the gateway.

#### Scenario: Enrollment artifact inspection
- **WHEN** a completed enrollment exchange and gateway state are inspected
- **THEN** no plaintext node private key is present on the gateway

### Requirement: Join atomicity and readiness
Successful join SHALL create one immutable node identity, assign an overlay IP, issue separate control, standard, restricted, and reverse-tunnel credentials, apply and health-check both sides, and mark exactly one transport active. Invalid tokens or failed validation SHALL leave both hosts without a partially joined node. Repeating join on a joined node SHALL make no change and direct the operator to transport switching.

#### Scenario: Post-stage health failure
- **WHEN** enrollment credentials are staged but mandatory transport or control health checks fail before commit
- **THEN** the new node is not activated and no partial policy or expose state becomes authoritative

### Requirement: Node identity listing and names
The gateway SHALL provide `node list` and `node show <name-or-id>` without revealing secrets. A node name SHALL be unique among existing records, while the immutable ID SHALL remain canonical across renames-independent lifecycle actions, credential rotation, and recovery.

#### Scenario: Duplicate node name
- **WHEN** an invite is requested with a name already held by an existing node record
- **THEN** the gateway rejects it before issuing a token

### Requirement: Immediate node revocation and subsequent deletion
`node revoke` SHALL be a confirmed, immediate gateway-only security action that invalidates the node's control, transport, and tunnel credentials, closes its connections, and disables all exposes while retaining its record and diagnostic context. It SHALL not support deferred application. `node delete` SHALL require confirmation and SHALL be permitted only after revocation, removing remaining gateway-side node resources without assuming access to the private VPS.

#### Scenario: Compromised offline node
- **WHEN** the operator revokes an offline node on the gateway
- **THEN** its old credentials cannot reconnect when the node later returns, and its exposes remain disabled

### Requirement: Full-set online credential rotation
`vpnctl node rotate` SHALL run only on the private node and SHALL rotate the control key, WireGuard key, restricted-transport credentials, and reverse-tunnel token as one atomic credential generation while preserving node ID, name, overlay IP, policies, and exposes. The node SHALL generate new secrets locally. A parallel rollout SHALL verify new control, transports, and tunnel before switching and draining the old generation; failure before commit SHALL leave the old generation fully active.

#### Scenario: Rotation succeeds
- **WHEN** all new credential paths pass health checks
- **THEN** the gateway and node atomically activate the new generation and revoke the old generation after bounded drain

#### Scenario: Rotation validation fails
- **WHEN** any mandatory member of the new credential set fails before final commit
- **THEN** no member is partially committed and the old generation remains usable

### Requirement: Same-node break-glass recovery
If normal mTLS rotation is impossible because the node certificate expired, `vpnctl node recover <name-or-id>` on the gateway SHALL, after confirmation, issue a one-time 15-minute recovery invite bound to an existing active immutable node ID. `vpnctl node recover` on that same private node SHALL accept the token via hidden input, generate a complete new credential set locally, and atomically replace credentials while preserving name, ID, overlay IP, policies, and exposes. Recovery SHALL use a reserved public HTTPS path and MUST NOT reactivate revoked or deleted nodes, clone identities, or move identity to another machine.

#### Scenario: Expired certificate recovery
- **WHEN** the original active node with an expired certificate presents a valid recovery token within 15 minutes
- **THEN** a full new credential generation is activated for the same logical node without re-creating policies or exposes

#### Scenario: Revoked node recovery attempt
- **WHEN** a recovery token is requested or used for a revoked node
- **THEN** the operation is rejected and the node remains revoked
