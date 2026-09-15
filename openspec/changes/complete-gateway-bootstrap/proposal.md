## Why

The first real Gateway-to-Node enrollment attempt proved that a Gateway can
finish initialization and report healthy while nginx, the managed ingress tree,
and public TCP 443 are entirely absent. This violates the dedicated-host
bootstrap contract and makes the primary private-node scenario unusable despite
passing component and release gates.

## What Changes

- Make Gateway initialization consume and verify every role-specific Ubuntu
  package requirement from the verified release bundle instead of discarding
  that contract.
- Make fresh Gateway initialization render, activate, and health-check the
  baseline nginx generation containing the reserved public enrollment routes
  before initialization may succeed.
- Compile the shipped editable `telegram`, `openai`, and `anthropic` sources as
  generation-1 effective presets during fresh Gateway initialization, so the
  documented first client or Node can explicitly select them without a hidden
  import/bootstrap command.
- Extend passive status, convergence planning, doctor, and confirmed repair so
  a missing or unhealthy mandatory nginx package, unit, managed tree, or public
  listener cannot be reported as a healthy clean Gateway.
- Provide a bounded recovery path for the already deployed unpublished
  `v2.0.0` candidate: a one-time hash-bound prerequisite installs only its
  missing pinned nginx package, the normal manifest/SHA-aware same-version
  update installs the corrected product, and confirmed repair publishes the
  missing ingress without changing existing WireGuard client identity.
- Classify public enrollment reachability/TLS failures as actionable
  unavailable errors while preserving atomic, secret-free Node join failure;
  give the first-join Gateway readiness transaction one fixed 45-second
  end-to-end response budget instead of the generic five-second RPC timeout.
- Treat a retained nginx generation as current when its rendered semantic
  inputs still match authoritative state, so metadata-only state changes such
  as invite issue/cancel do not manufacture ingress or status drift.
- Include the candidate active-identity firewall in the same pre-commit join
  transaction as Gateway services and convergence metadata, retaining an exact
  owned-table rollback until the invite and Node commit together.
- Preserve the actual most-specific main-table path to the public Gateway
  endpoint when the joined Node installs its recovery route, instead of
  replacing an explicit host route with the default next hop.
- Retry the complete joined-Node routing and tunnel readiness contract inside
  the fixed 20-second activation window before publishing active convergence,
  so a transient post-start race does not leave healthy services compared
  against the staged inactive baseline.
- Bind FRP client readiness to exactly one matching `frpc` control connection
  rather than to exclusive use of the Gateway endpoint by every local process,
  because selected Mihomo traffic may legitimately share that destination.
- Normalize Linux JSON IPv4 host-route destinations to their exact `/32` prefix
  before retaining the Node routing-guard snapshot, so owner-scoped cleanup can
  restore the explicit Gateway endpoint route instead of rejecting it.
- Prove both fresh bootstrap and incomplete-candidate recovery manually on the
  existing Lima pair before adding one focused Gateway-enrollment E2E check.
- Keep migration implementation, capacity policy, release-gate orchestration,
  evidence/fingerprint infrastructure, VM topology, public ports, and public
  command shape unchanged.

## Capabilities

### New Capabilities

- `gateway-bootstrap-readiness`: Complete role-package installation, baseline
  HTTPS enrollment ingress, observable health and drift, confirmed recovery,
  safe same-version candidate remediation, and focused end-to-end acceptance.

### Modified Capabilities

None. The original `vpnctl-v2` capability set is still an unarchived active
change; this correction adds the missing integrated readiness contract without
duplicating or broadening its remaining feature scope.

## Impact

- Affected product areas: Gateway init, initial routing-preset state and release-bundle consumption, Ubuntu
  package management, nginx rendering/activation, convergence/status/doctor/
  repair observation, and Node join error mapping.
- Affected tests: focused lifecycle/controller/CLI contracts plus one existing-
  topology Lima happy-path/recovery E2E after manual proof.
- Affected operations: the unreleased production candidate receives one
  separately rehearsed, journaled, hash-bound recovery/update procedure; no
  production action occurs during implementation or primary debugging.
- Compatibility: no public CLI removal or port/configuration change; first
  public release remains `v2.0.0`, identified by its final commit and SHA-256.
