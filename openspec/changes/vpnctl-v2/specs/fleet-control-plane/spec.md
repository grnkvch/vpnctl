## Purpose

Defines the authoritative, authenticated, versioned control relationship between a dedicated gateway and multiple private nodes while keeping management failures isolated from the data plane.

## ADDED Requirements

### Requirement: Gateway-authoritative desired state
The gateway controller SHALL be the sole writer of authoritative fleet state and SHALL serialize mutations. Gateway-local CLI operations SHALL use a local Unix socket; private-node CLI operations SHALL submit intent to the gateway. A private node SHALL NOT maintain an offline mutation queue, and `--defer` SHALL still require a reachable gateway to record pending desired state.

#### Scenario: Node command while gateway is unavailable
- **WHEN** a private-node CLI attempts a mutation while the gateway controller is unreachable
- **THEN** the command changes neither local nor gateway desired state and reports an unavailable result

### Requirement: Data-plane independence
The controller and data plane SHALL have independent lifecycles. Controller failure or restart MUST NOT stop already applied transports, routing, DNS, reverse tunnels, or HTTPS ingress. After restart, the controller SHALL load authoritative state but SHALL NOT automatically apply pending changes or repair drift; explicit `apply` or `repair` is required.

#### Scenario: Controller restart during active forwarding
- **WHEN** the gateway controller restarts while applied data-plane processes remain healthy
- **THEN** existing forwarding continues and healthy data-plane processes are not restarted solely because of the controller restart

### Requirement: Private internal control endpoint
Post-enrollment node management SHALL use bounded short-lived HTTPS/1.1 JSON RPC connections with mutual TLS. The endpoint SHALL listen only on the vpnctl internal overlay and MUST NOT be exposed on public interfaces. Each request and response SHALL undergo strict schema, size, and timeout validation, and transport encryption alone MUST NOT substitute for mTLS identity.

#### Scenario: Public control access attempt
- **WHEN** an unauthenticated client connects to the gateway public address outside the reserved enrollment or recovery paths
- **THEN** no post-enrollment management endpoint is reachable

### Requirement: Independent control PKI
Gateway initialization SHALL create an internal control CA distinct from the public ingress certificate. The CA SHALL default to ten-year validity; gateway server and node client leaf certificates SHALL default to five years. The CA private key SHALL remain root-only on the gateway, SHALL never be exported plaintext, and SHALL appear only inside encrypted gateway backups.

#### Scenario: Public certificate rotation
- **WHEN** the operator rotates the public ingress certificate
- **THEN** node mTLS identities and trust remain unchanged

### Requirement: Control certificate lifecycle
The gateway server leaf SHALL automatically reissue under the same control CA 180 days before expiration without node action. Node leaf certificates SHALL not auto-renew; status and doctor SHALL require `vpnctl node rotate` beginning 180 days before expiration. Control CA rotation SHALL be manual and staged with a period in which affected nodes trust both old and new CAs.

#### Scenario: Gateway leaf renewal
- **WHEN** the gateway control leaf enters its 180-day renewal window
- **THEN** a new leaf is activated under the same CA without changing the public ingress certificate or requiring node re-enrollment

### Requirement: Immutable authenticated node identity
Each node client certificate SHALL bind an immutable node ID in a URI SAN. The gateway SHALL validate the CA chain, the active node record, and the current credential generation for every request; a mutable display name MUST NOT be used as the authorization identity.

#### Scenario: Revoked certificate remains cryptographically valid
- **WHEN** a revoked node presents an otherwise unexpired CA-valid certificate
- **THEN** the controller rejects the request because the node record or credential generation is inactive

### Requirement: Independent control protocol version
The control protocol SHALL carry a `major.minor` version independent of binary release versions and SHALL also include that version in invites. Minor changes SHALL be additive and backward-compatible; breaking semantics SHALL increment the major. A gateway release SHALL support the current and immediately previous protocol major for at least one stable release.

#### Scenario: Rolling gateway-first update
- **WHEN** the gateway is updated while nodes still use the immediately previous supported protocol major
- **THEN** those nodes remain manageable during the compatibility window

#### Scenario: Incompatible node mutation
- **WHEN** a node and gateway have no mutually supported control protocol major
- **THEN** the mutation is rejected as a conflict with an upgrade action and the applied data plane remains unchanged

### Requirement: Gateway-first update compatibility
A node update SHALL preflight gateway compatibility before mutation and SHALL reject a node-newer-than-gateway combination. A gateway update SHALL by default stop when any active node falls outside its promised compatibility window. Management incompatibility MUST NOT tear down an otherwise working data plane.

#### Scenario: Node update against older gateway
- **WHEN** the requested node release requires a protocol unsupported by the current gateway
- **THEN** the update stops before changing node binaries, state, or services

### Requirement: Generation-guarded idempotent mutations
Every control-plane mutation SHALL have a unique locally persisted `request_id` and `expected_state_generation`. The gateway SHALL serialize the mutation, store its result and resulting generation, return the stored result on a retry with the same ID, and reject a stale expected generation before mutation. vpnctl MUST NOT silently create a new request ID to retry a stale or uncertain mutation.

#### Scenario: Response lost after commit
- **WHEN** the node loses the response after the gateway committed a mutation and retries the same request ID
- **THEN** the gateway returns the previously stored result without repeating the effect

#### Scenario: Concurrent stale mutation
- **WHEN** a mutation carries a generation older than authoritative state
- **THEN** the gateway returns a conflict and performs no part of the requested change

### Requirement: Bounded idempotency history
The gateway SHALL retain mutation idempotency records for no more than 30 days and no more than 1024 latest mutations per node, whichever bound is reached first. Records SHALL contain only request ID, operation type, result status/hash, and state generation and MUST NOT contain request bodies, secrets, or sensitive paths. An uncertain request whose record was evicted SHALL be reconciled against resource state and generation rather than blindly replayed.

#### Scenario: Very old uncertain request
- **WHEN** a node retries an uncertain mutation after its idempotency record was evicted
- **THEN** vpnctl compares current resource state and generation and returns a determined result or conflict without blind mutation

### Requirement: Fleet isolation
The gateway SHALL support multiple private nodes and personal clients with unique credentials and identities. Firewall and authorization policy SHALL deny client-to-client, client-to-node, and node-to-node connectivity; peers SHALL reach only required gateway data-plane services and the internet through allowed paths.

#### Scenario: Node attempts another node mapping
- **WHEN** one authenticated node attempts to manage or announce a resource owned by another node
- **THEN** the gateway rejects the operation without affecting either node's valid resources
