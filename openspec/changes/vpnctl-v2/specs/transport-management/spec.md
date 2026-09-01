## Purpose

Defines the standard and DPI-resistant data-plane choices, their manual lifecycle, and the invariant that vpnctl never changes transport or weakens selected-traffic policy automatically.

## ADDED Requirements

### Requirement: Two named transport behaviors
v2.0 SHALL provide `standard` as a WireGuard-compatible transport and `restricted` as a DPI-resistant transport. Gateway initialization SHALL keep both listeners configured and ready on fixed ports `51820/UDP` and `8443/TCP`. Restricted traffic MUST NOT use `8443/UDP`, and HTTP path routing on `443/TCP` MUST NOT be used to multiplex the restricted protocol.

#### Scenario: Gateway listener inspection
- **WHEN** an initialized gateway is healthy
- **THEN** standard is available on `51820/UDP`, restricted is available on `8443/TCP`, and no restricted listener is open on UDP

### Requirement: Manual transport selection only
Every node SHALL have exactly one active transport in steady state and one configured standby. Initial transport SHALL be selected explicitly during join; subsequent selection SHALL occur only through a user-requested switch. vpnctl MUST NOT automatically detect restrictions, fail over, switch, or keep multiple transports active in steady state.

#### Scenario: Active transport outage
- **WHEN** a node's active transport becomes unreachable
- **THEN** vpnctl reports degradation and preserves the operator's selected transport instead of silently activating standby or sending selected traffic direct

### Requirement: Shared transport choice for node paths
In steady state, the node's active transport SHALL carry all node-to-gateway selected egress, internal control, and reverse-tunnel traffic. Ordinary unmatched node traffic SHALL remain outside the transport. Independently selecting different transports for control, tunnel, and egress SHALL not be supported in v2.0.

#### Scenario: Node uses restricted active
- **WHEN** restricted is active and healthy
- **THEN** selected egress, control RPCs, and the reverse tunnel use restricted while unmatched application flows stay direct

### Requirement: Restricted selected UDP uses DPI-resistant TCP path
Restricted selected UDP SHALL be encapsulated with UDP-over-TCP inside the same DPI-resistant TCP-protected path used by selected TCP. vpnctl SHALL attempt this path for every selected UDP flow when restricted is active. If UoT capability or health validation fails, restricted SHALL be considered not ready and the UDP flow SHALL be blocked; native restricted UDP and direct fallback are prohibited.

#### Scenario: Restricted UoT probe fails
- **WHEN** UDP-over-TCP validation fails for the restricted transport
- **THEN** `transport test restricted` fails, restricted cannot become active, and selected UDP is not sent through native UDP or direct

#### Scenario: Restricted UDP is healthy
- **WHEN** UoT and the restricted transport pass validation
- **THEN** a selected UDP flow is carried through the protected TCP transport rather than blocked by policy choice

### Requirement: Transport test is non-mutating
`vpnctl transport test <standard|restricted>` SHALL run on a private node, temporarily establish the target transport, verify control connectivity, reverse-tunnel viability, and selected TCP and UDP probes, and then remove the test connection. It SHALL not change production routing, active transport, pending target, or credential generations.

#### Scenario: Test standby restricted transport
- **WHEN** standard is active and the operator runs `transport test restricted`
- **THEN** the restricted probes return a result and standard remains active regardless of test success or failure

### Requirement: Manual make-before-break switch
`vpnctl transport switch <standard|restricted>` SHALL run on a private node and require confirmation. It SHALL establish and validate the target connection, move control and reverse-tunnel readiness, switch selected traffic, allow bounded drain of old work, and only then deactivate the previous transport. A failed switch SHALL leave the previous transport active. Switching to the already active target SHALL be idempotent and perform a health check.

#### Scenario: Successful switch to standby
- **WHEN** all target transport, control, tunnel, TCP, and UDP checks pass
- **THEN** target becomes the sole active transport after bounded drain and the previous transport becomes standby

#### Scenario: Target cannot reach gateway
- **WHEN** a target transport fails validation during switch
- **THEN** the switch is aborted and the original transport continues serving production traffic

### Requirement: Deferred switch remains explicit
`transport switch ... --defer` SHALL register a pending target with a reachable gateway and SHALL not alter active connections until a later node-local `vpnctl apply`. An unavailable current transport does not authorize automatic standby activation; a manual switch can succeed only after the node establishes authenticated gateway connectivity through the requested target.

#### Scenario: Deferred target
- **WHEN** the operator defers a switch from standard to restricted
- **THEN** status shows restricted pending and standard remains active until explicit apply

### Requirement: Restricted transport acceptance contract
The selected restricted implementation SHALL pass live end-to-end tests against an actually deployed gateway and node with an actual supported Clash Mi client for selected TCP, DNS, and UDP-over-TCP. It SHALL pass resource tests on Ubuntu 24.04 with 1 vCPU/512 MB and security validation of strict DPI-resistant mode before v2.0 release. Automated gateway/Linux-node spikes MAY qualify a candidate for continued implementation, but MUST NOT satisfy or waive the deployed-client release gate. Until those gates pass, a candidate stack SHALL not be described as production-ready restricted transport.

#### Scenario: Candidate fails Clash Mi UDP test
- **WHEN** the pinned restricted stack cannot carry selected UDP through Clash Mi without policy leakage
- **THEN** the v2.0 restricted acceptance gate fails and release cannot proceed with that stack

### Requirement: Versioned pinned handshake-host selection
If the restricted implementation requires an external TLS handshake host, the release SHALL contain a versioned ordered candidate list. Gateway init SHALL test reachability, TLS 1.3 capability, and latency and persist the first passing candidate as authoritative state. The host SHALL be delivered to nodes and Clash exports, remain pinned after init, and MUST NOT be rotated or failed over automatically at runtime.

#### Scenario: First candidate unavailable during init
- **WHEN** the first bundled host fails validation and the second passes
- **THEN** the second host is persisted and all generated restricted configurations use it

### Requirement: Handshake-host degradation and manual replacement
Status and doctor SHALL validate the pinned handshake host and mark restricted degraded with a required action if it fails. Replacement SHALL be a manually prepared, validated, impact-listed, and separately committed staged operation with permitted short downtime and one active host at a time. After commit, old restricted node configurations and Clash exports SHALL be stale until updated; a bounded rollback snapshot SHALL support an explicit rollback.

#### Scenario: Pinned host later fails
- **WHEN** the saved handshake host no longer completes required validation
- **THEN** vpnctl reports restricted as degraded without changing the host or switching transport automatically

### Requirement: Emergency handshake-host recovery
If the old restricted path is unusable, an operator with SSH access to the private node SHALL be able to apply the explicitly selected new gateway handshake host locally without rejoining or changing node identity. The host SHALL not be treated as a secret, and this flow MUST NOT create a public management API.

#### Scenario: Restricted control path is blocked
- **WHEN** the active handshake host fails and normal control RPC cannot traverse restricted
- **THEN** the operator can use the documented local recovery flow over SSH to align the node with the manually chosen host

### Requirement: Personal client transport choice
A Clash/Mihomo export SHALL be able to include standard and restricted alternatives, but vpnctl SHALL leave the active choice to the client user and MUST NOT provide remote or automatic client switching. A WireGuard export SHALL use only standard transport.

#### Scenario: Clash profile contains alternatives
- **WHEN** an eligible client is exported as Clash
- **THEN** the profile presents supported standard and restricted choices without an automatic fallback policy
