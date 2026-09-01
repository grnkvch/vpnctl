## Purpose

Defines secure outbound-only, per-node multiplexed reverse connectivity that lets one gateway ingress route reach many explicit private-node applications without public node listeners.

## ADDED Requirements

### Requirement: One multiplexed tunnel per node
Each joined private node SHALL maintain one persistent multiplexed reverse-tunnel connection for all of its exposes and SHALL not create one daemon, persistent connection, or permanent secret per expose. The selected provider SHALL keep its pre-created work-connection pool effectively zero and create expose streams on demand within the multiplexed connection. The gateway SHALL share server-side tunnel infrastructure across nodes while preserving node identity boundaries.

#### Scenario: Add second expose
- **WHEN** a node with one healthy expose creates another
- **THEN** the new mapping uses the existing node tunnel rather than establishing a second permanent tunnel connection

### Requirement: Outbound-only private-node connection
The reverse tunnel SHALL originate from the private node through its active transport to an internal gateway endpoint. Creating an expose SHALL not open a new inbound public port or firewall allowance on the private node, and tunnel server interfaces or dashboards MUST NOT be publicly exposed.

#### Scenario: Private node behind inbound firewall
- **WHEN** the private node allows the tunnel's outbound connection but no new inbound connection
- **THEN** the gateway can still publish a valid expose through that tunnel

### Requirement: Independent per-node tunnel identity
Every node SHALL receive a unique random 256-bit tunnel credential independent of its WireGuard, restricted-transport, and control credentials. The credential SHALL be root-only and MUST NOT appear in human/JSON status, client exports, application logs, or unencrypted backups. Transport switching SHALL preserve logical tunnel identity; full node credential rotation SHALL replace it as part of the atomic set.

#### Scenario: Transport switch
- **WHEN** a node switches from standard to restricted
- **THEN** its reverse tunnel reconnects through the target transport without creating a new logical tunnel identity or changing expose ownership

### Requirement: Gateway authorization of connections and mappings
The gateway SHALL authenticate every tunnel connection as an active immutable node ID and validate its credential generation. It SHALL authorize every announced mapping against authoritative expose state, including node owner, mapping name/type, and assigned loopback endpoint. A node MUST NOT announce another node's mapping or an unregistered endpoint.

#### Scenario: Unauthorized mapping announcement
- **WHEN** an authenticated node announces a proxy name or endpoint absent from its authoritative expose list
- **THEN** the gateway rejects that mapping while preserving the node's valid mappings

### Requirement: Stable managed gateway endpoint per expose
Each expose SHALL receive a collision-checked internal TCP endpoint stable for its lifetime and bound only to gateway loopback. The endpoint SHALL not be user input or public API and SHALL never be opened by the firewall. Allocation exhaustion SHALL fail before route publication. Restore SHALL preserve a free saved allocation or atomically remap it together with ingress configuration before publication.

#### Scenario: Internal allocation collision on restore
- **WHEN** a restored expose's previous internal port is unavailable
- **THEN** vpnctl assigns a new collision-free port and activates tunnel and ingress configuration atomically so no route points to the wrong service

### Requirement: Tunnel connection security
The internal tunnel connection SHALL use TLS and verify gateway identity even when carried inside another encrypted transport. Authentication metadata SHALL be protected in transit and the gateway-side authorization interface SHALL be local-only.

#### Scenario: Untrusted tunnel server
- **WHEN** a node reaches an endpoint presenting an untrusted tunnel certificate
- **THEN** it refuses to authenticate or disclose its tunnel credential

### Requirement: Reconnect and readiness
After disconnection, the node tunnel process SHALL retry indefinitely with bounded exponential backoff and jitter using only the current active transport. It MUST NOT try standby autonomously. A connection SHALL become ready only after authentication, configuration-generation agreement, mapping validation, and local-upstream checks; until then all node exposes SHALL be degraded and return `503`, and new requests SHALL resume automatically after readiness.

#### Scenario: Gateway restarts tunnel service
- **WHEN** the persistent connection drops and later successfully reauthenticates with the current generation
- **THEN** new expose requests resume without manual enable or service restart

### Requirement: Mapping activation and removal ordering
Expose creation SHALL make tunnel and local-upstream readiness available before publishing the public path. Removal SHALL stop new ingress routing first, allow a bounded stream drain, remove the mapping, and then release its internal endpoint. Tunnel or mapping changes SHALL be atomically rendered and validated before activation.

#### Scenario: New mapping upstream is unavailable
- **WHEN** an expose is registered but its local upstream cannot pass readiness
- **THEN** it is visible as degraded and no request is forwarded to an unintended endpoint

### Requirement: Revocation closes node tunnel
Node revocation SHALL immediately invalidate the node's tunnel credential, terminate its active tunnel connection, and disable all of its mappings. Reconnecting with the revoked generation SHALL be rejected even if the credential has not cryptographically expired.

#### Scenario: Revoked tunnel reconnect
- **WHEN** a revoked node retries its persistent tunnel connection
- **THEN** authentication fails and all of that node's public routes remain unavailable

### Requirement: Reverse-tunnel acceptance gate
The chosen tunnel implementation SHALL pass prototypes for multiplexing, dynamic mapping add/remove, per-node authorization, reconnect, transport switch, and resource use on Ubuntu 24.04 with 1 vCPU/512 MB before v2.0 release. A failing candidate SHALL be replaceable without changing the public expose contract.

#### Scenario: Candidate creates a connection per expose
- **WHEN** a tunnel candidate cannot multiplex multiple expose streams over one persistent node connection
- **THEN** it fails the v2.0 acceptance gate and is not adopted as the implementation
