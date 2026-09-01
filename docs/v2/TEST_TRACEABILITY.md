# VPNCTL v2 requirement-to-test traceability

This table is the release traceability source for every requirement scenario in the ten v2 capability specs.
Verification assignments name the required test layers; task coverage points to the implementation-plan tasks that must supply those checks.
The regression test fails when a spec scenario is added, removed, or renamed without updating this table.

| Capability | Requirement | Scenario | Verification | Task coverage |
| --- | --- | --- | --- | --- |
| `desired-state-and-operations` | Immediate, dry-run, and deferred mutations | Dry-run expose | integration, e2e | 4.1-4.6, 13.1-13.11, 16.7, 16.11 |
| `desired-state-and-operations` | Distinct status, doctor, plan, apply, and repair | Drift conflicts with apply | integration, e2e | 4.1-4.6, 13.1-13.11, 16.7, 16.11 |
| `desired-state-and-operations` | Transactional local convergence | Generated configuration is invalid | integration, e2e | 4.1-4.6, 13.1-13.11, 16.7, 16.11 |
| `desired-state-and-operations` | Convergent cross-host operations | Response lost during cross-host activation | integration, e2e | 4.1-4.6, 13.1-13.11, 16.7, 16.11 |
| `desired-state-and-operations` | Durable versioned JSON state | Process exits during state write | integration, e2e | 4.1-4.6, 13.1-13.11, 16.7, 16.11 |
| `desired-state-and-operations` | Default status view and exit behavior | Healthy state with expiring certificate warning | integration, e2e | 4.1-4.6, 13.1-13.11, 16.7, 16.11 |
| `desired-state-and-operations` | Bounded active doctor probes | Explicit user probe URL | integration, e2e | 4.1-4.6, 13.1-13.11, 16.7, 16.11 |
| `desired-state-and-operations` | Bounded active doctor probes | Probe needs unknown external service | integration, e2e | 4.1-4.6, 13.1-13.11, 16.7, 16.11 |
| `desired-state-and-operations` | Consistent human and JSON CLI contract | Automation output with diagnostics | integration, e2e | 4.1-4.6, 13.1-13.11, 16.7, 16.11 |
| `desired-state-and-operations` | Impact-based confirmation | Non-interactive destructive JSON command | integration, e2e | 4.1-4.6, 13.1-13.11, 16.7, 16.11 |
| `desired-state-and-operations` | Logging is disabled by default | Logging session expires during restart | integration, e2e | 4.1-4.6, 13.1-13.11, 16.7, 16.11 |
| `desired-state-and-operations` | Logging destinations and redaction | Trace ingress logging | integration, e2e | 4.1-4.6, 13.1-13.11, 16.7, 16.11 |
| `desired-state-and-operations` | No telemetry or hidden calls | Idle gateway | integration, e2e | 4.1-4.6, 13.1-13.11, 16.7, 16.11 |
| `fleet-control-plane` | Gateway-authoritative desired state | Node command while gateway is unavailable | integration, e2e | 6.1-6.9, 13.11, 16.4, 16.7, 16.8 |
| `fleet-control-plane` | Data-plane independence | Controller restart during active forwarding | integration, e2e | 6.1-6.9, 13.11, 16.4, 16.7, 16.8 |
| `fleet-control-plane` | Private internal control endpoint | Public control access attempt | integration, e2e | 6.1-6.9, 13.11, 16.4, 16.7, 16.8 |
| `fleet-control-plane` | Independent control PKI | Public certificate rotation | integration, e2e | 6.1-6.9, 13.11, 16.4, 16.7, 16.8 |
| `fleet-control-plane` | Control certificate lifecycle | Gateway leaf renewal | integration, e2e | 6.1-6.9, 13.11, 16.4, 16.7, 16.8 |
| `fleet-control-plane` | Immutable authenticated node identity | Revoked certificate remains cryptographically valid | integration, e2e | 6.1-6.9, 13.11, 16.4, 16.7, 16.8 |
| `fleet-control-plane` | Independent control protocol version | Rolling gateway-first update | integration, e2e | 6.1-6.9, 13.11, 16.4, 16.7, 16.8 |
| `fleet-control-plane` | Independent control protocol version | Incompatible node mutation | integration, e2e | 6.1-6.9, 13.11, 16.4, 16.7, 16.8 |
| `fleet-control-plane` | Gateway-first update compatibility | Node update against older gateway | integration, e2e | 6.1-6.9, 13.11, 16.4, 16.7, 16.8 |
| `fleet-control-plane` | Generation-guarded idempotent mutations | Response lost after commit | integration, e2e | 6.1-6.9, 13.11, 16.4, 16.7, 16.8 |
| `fleet-control-plane` | Generation-guarded idempotent mutations | Concurrent stale mutation | integration, e2e | 6.1-6.9, 13.11, 16.4, 16.7, 16.8 |
| `fleet-control-plane` | Bounded idempotency history | Very old uncertain request | integration, e2e | 6.1-6.9, 13.11, 16.4, 16.7, 16.8 |
| `fleet-control-plane` | Fleet isolation | Node attempts another node mapping | integration, e2e | 6.1-6.9, 13.11, 16.4, 16.7, 16.8 |
| `host-bootstrap-and-lifecycle` | Supported host contract | Unsupported virtualized host | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | Explicit immutable host role | Idempotent gateway initialization | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | Explicit immutable host role | Accidental role change | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | Gateway initialization inputs and port contract | Minimal gateway initialization | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | Gateway initialization inputs and port contract | Missing public IP | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | Role-scoped component installation | Node initialization | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | Host ownership boundaries | Existing gateway reverse proxy | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | Host ownership boundaries | Foreign nftables table | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | Gateway firewall baseline | Public listener audit | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | Fail-closed SSH listener detection | Ambiguous SSH listeners | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | Independent lockout watchdog | Successful reconnect confirmation | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | Independent lockout watchdog | New SSH login fails | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | Independent lockout watchdog | Expired confirmation | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | System-owned installation layout and permissions | Invocation from another directory | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | Low-memory swap offer | Operator accepts swap | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | Uninstall and purge separation | Recoverable uninstall | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | Uninstall and purge separation | Purge preserving archives | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `host-bootstrap-and-lifecycle` | Node uninstall coordinates revocation | Offline local cleanup | unit, integration, e2e | 5.1-5.11, 14.11-14.12, 16.2, 16.7 |
| `managed-https-ingress` | IP-only HTTPS endpoint | Telegram webhook endpoint | spike, integration, e2e, manual-compatibility | 2.5-2.6, 12.1-12.11, 16.6, 16.11 |
| `managed-https-ingress` | Private-node expose creation | Port shorthand | spike, integration, e2e, manual-compatibility | 2.5-2.6, 12.1-12.11, 16.6, 16.11 |
| `managed-https-ingress` | Private-node expose creation | Non-loopback without opt-in | spike, integration, e2e, manual-compatibility | 2.5-2.6, 12.1-12.11, 16.6, 16.11 |
| `managed-https-ingress` | Exact paths by default | Overlapping prefix | spike, integration, e2e, manual-compatibility | 2.5-2.6, 12.1-12.11, 16.6, 16.11 |
| `managed-https-ingress` | Stable public ingress certificate | Export public certificate | spike, integration, e2e, manual-compatibility | 2.5-2.6, 12.1-12.11, 16.6, 16.11 |
| `managed-https-ingress` | Public certificate inspection and manual rotation | Rotate certificate with active webhooks | spike, integration, e2e, manual-compatibility | 2.5-2.6, 12.1-12.11, 16.6, 16.11 |
| `managed-https-ingress` | TLS and HTTP protocol boundary | Obsolete TLS client | spike, integration, e2e, manual-compatibility | 2.5-2.6, 12.1-12.11, 16.6, 16.11 |
| `managed-https-ingress` | Forwarding header safety | Spoofed client address header | spike, integration, e2e, manual-compatibility | 2.5-2.6, 12.1-12.11, 16.6, 16.11 |
| `managed-https-ingress` | Bounded proxy limits | Expose exceeds hard body limit | spike, integration, e2e, manual-compatibility | 2.5-2.6, 12.1-12.11, 16.6, 16.11 |
| `managed-https-ingress` | Streaming stateless forwarding | Tunnel fails after upstream starts response | spike, integration, e2e, manual-compatibility | 2.5-2.6, 12.1-12.11, 16.6, 16.11 |
| `managed-https-ingress` | Observable ingress outcomes | Application is stopped | spike, integration, e2e, manual-compatibility | 2.5-2.6, 12.1-12.11, 16.6, 16.11 |
| `managed-https-ingress` | Application responsibility boundary | Expose created for Telegram | spike, integration, e2e, manual-compatibility | 2.5-2.6, 12.1-12.11, 16.6, 16.11 |
| `managed-https-ingress` | Expose inspection and removal | Remove one of several exposes | spike, integration, e2e, manual-compatibility | 2.5-2.6, 12.1-12.11, 16.6, 16.11 |
| `node-enrollment-and-identity` | Explicit one-time invite | Invite expires unused | unit, integration, e2e | 9.1-9.9, 16.2, 16.5, 16.7 |
| `node-enrollment-and-identity` | Invite inspection and cancellation | Repeated invite cancellation | unit, integration, e2e | 9.1-9.9, 16.2, 16.5, 16.7 |
| `node-enrollment-and-identity` | Separate node initialization and join | Minimal restricted join | unit, integration, e2e | 9.1-9.9, 16.2, 16.5, 16.7 |
| `node-enrollment-and-identity` | Separate node initialization and join | Unknown initial preset | unit, integration, e2e | 9.1-9.9, 16.2, 16.5, 16.7 |
| `node-enrollment-and-identity` | Token-gated public enrollment | Invite replay | unit, integration, e2e | 9.1-9.9, 16.2, 16.5, 16.7 |
| `node-enrollment-and-identity` | Node-owned private keys | Enrollment artifact inspection | unit, integration, e2e | 9.1-9.9, 16.2, 16.5, 16.7 |
| `node-enrollment-and-identity` | Join atomicity and readiness | Post-stage health failure | unit, integration, e2e | 9.1-9.9, 16.2, 16.5, 16.7 |
| `node-enrollment-and-identity` | Node identity listing and names | Duplicate node name | unit, integration, e2e | 9.1-9.9, 16.2, 16.5, 16.7 |
| `node-enrollment-and-identity` | Immediate node revocation and subsequent deletion | Compromised offline node | unit, integration, e2e | 9.1-9.9, 16.2, 16.5, 16.7 |
| `node-enrollment-and-identity` | Full-set online credential rotation | Rotation succeeds | unit, integration, e2e | 9.1-9.9, 16.2, 16.5, 16.7 |
| `node-enrollment-and-identity` | Full-set online credential rotation | Rotation validation fails | unit, integration, e2e | 9.1-9.9, 16.2, 16.5, 16.7 |
| `node-enrollment-and-identity` | Same-node break-glass recovery | Expired certificate recovery | unit, integration, e2e | 9.1-9.9, 16.2, 16.5, 16.7 |
| `node-enrollment-and-identity` | Same-node break-glass recovery | Revoked node recovery attempt | unit, integration, e2e | 9.1-9.9, 16.2, 16.5, 16.7 |
| `personal-client-management` | Explicit client creation | Selective iPhone client | unit, integration, e2e, manual-compatibility | 1.1, 7.7-7.12, 16.1, 16.4-16.5, 16.11 |
| `personal-client-management` | Explicit client creation | Full-tunnel client without presets | unit, integration, e2e, manual-compatibility | 1.1, 7.7-7.12, 16.1, 16.4-16.5, 16.11 |
| `personal-client-management` | Multiple isolated clients | Client lateral connection attempt | unit, integration, e2e, manual-compatibility | 1.1, 7.7-7.12, 16.1, 16.4-16.5, 16.11 |
| `personal-client-management` | Client inspection without secrets | Revoked client listing | unit, integration, e2e, manual-compatibility | 1.1, 7.7-7.12, 16.1, 16.4-16.5, 16.11 |
| `personal-client-management` | Managed client export | Default Clash export | unit, integration, e2e, manual-compatibility | 1.1, 7.7-7.12, 16.1, 16.4-16.5, 16.11 |
| `personal-client-management` | Managed client export | Existing custom output | unit, integration, e2e, manual-compatibility | 1.1, 7.7-7.12, 16.1, 16.4-16.5, 16.11 |
| `personal-client-management` | Profile behavior | WireGuard after policy edit | unit, integration, e2e, manual-compatibility | 1.1, 7.7-7.12, 16.1, 16.4-16.5, 16.11 |
| `personal-client-management` | Policy replacement and export staleness | Client policy replacement | unit, integration, e2e, manual-compatibility | 1.1, 7.7-7.12, 16.1, 16.4-16.5, 16.11 |
| `personal-client-management` | Client revocation and deletion | Lost device revocation | unit, integration, e2e, manual-compatibility | 1.1, 7.7-7.12, 16.1, 16.4-16.5, 16.11 |
| `personal-client-management` | Client credential rotation | Rotated Clash client | unit, integration, e2e, manual-compatibility | 1.1, 7.7-7.12, 16.1, 16.4-16.5, 16.11 |
| `personal-client-management` | Export delivery boundary | Successful export output | unit, integration, e2e, manual-compatibility | 1.1, 7.7-7.12, 16.1, 16.4-16.5, 16.11 |
| `release-delivery-and-migration` | Signed self-contained release bundle | Offline-transferred bundle | unit, integration, e2e, manual-compatibility | 1.1, 14.1-14.12, 15.1-15.6, 16.8-16.11 |
| `release-delivery-and-migration` | Installer verification boundary | Bundle checksum mismatch | unit, integration, e2e, manual-compatibility | 1.1, 14.1-14.12, 15.1-15.6, 16.8-16.11 |
| `release-delivery-and-migration` | Manual gateway-first updates | Latest stable update | unit, integration, e2e, manual-compatibility | 1.1, 14.1-14.12, 15.1-15.6, 16.8-16.11 |
| `release-delivery-and-migration` | Update isolation and rollback | Updated component fails health check | unit, integration, e2e, manual-compatibility | 1.1, 14.1-14.12, 15.1-15.6, 16.8-16.11 |
| `release-delivery-and-migration` | Update availability expectations | Controller-only compatible update | unit, integration, e2e, manual-compatibility | 1.1, 14.1-14.12, 15.1-15.6, 16.8-16.11 |
| `release-delivery-and-migration` | Encrypted portable gateway backup | Default backup | unit, integration, e2e, manual-compatibility | 1.1, 14.1-14.12, 15.1-15.6, 16.8-16.11 |
| `release-delivery-and-migration` | Node and application data exclusion from backup | Gateway archive inspection after decryption | unit, integration, e2e, manual-compatibility | 1.1, 14.1-14.12, 15.1-15.6, 16.8-16.11 |
| `release-delivery-and-migration` | Validated non-merging gateway restore | Restore to clean host with same endpoint | unit, integration, e2e, manual-compatibility | 1.1, 14.1-14.12, 15.1-15.6, 16.8-16.11 |
| `release-delivery-and-migration` | Validated non-merging gateway restore | Invalid archive | unit, integration, e2e, manual-compatibility | 1.1, 14.1-14.12, 15.1-15.6, 16.8-16.11 |
| `release-delivery-and-migration` | Restore endpoint change actions | Restore to new public IP | unit, integration, e2e, manual-compatibility | 1.1, 14.1-14.12, 15.1-15.6, 16.8-16.11 |
| `release-delivery-and-migration` | One-time v1 migration | Migrate existing v1 clients | unit, integration, e2e, manual-compatibility | 1.1, 14.1-14.12, 15.1-15.6, 16.8-16.11 |
| `release-delivery-and-migration` | Minimum capacity target | Minimum-host benchmark | unit, integration, e2e, manual-compatibility | 1.1, 14.1-14.12, 15.1-15.6, 16.8-16.11 |
| `release-delivery-and-migration` | Full non-backlog release gate | Vertical slice passes before remaining capabilities | unit, integration, e2e, manual-compatibility | 1.1, 14.1-14.12, 15.1-15.6, 16.8-16.11 |
| `release-delivery-and-migration` | Explicit v2.0 exclusions | Request for excluded capability | unit, integration, e2e, manual-compatibility | 1.1, 14.1-14.12, 15.1-15.6, 16.8-16.11 |
| `reverse-tunnel` | One multiplexed tunnel per node | Add second expose | spike, integration, e2e | 2.7, 11.1-11.9, 16.4, 16.6-16.7 |
| `reverse-tunnel` | Outbound-only private-node connection | Private node behind inbound firewall | spike, integration, e2e | 2.7, 11.1-11.9, 16.4, 16.6-16.7 |
| `reverse-tunnel` | Independent per-node tunnel identity | Transport switch | spike, integration, e2e | 2.7, 11.1-11.9, 16.4, 16.6-16.7 |
| `reverse-tunnel` | Gateway authorization of connections and mappings | Unauthorized mapping announcement | spike, integration, e2e | 2.7, 11.1-11.9, 16.4, 16.6-16.7 |
| `reverse-tunnel` | Stable managed gateway endpoint per expose | Internal allocation collision on restore | spike, integration, e2e | 2.7, 11.1-11.9, 16.4, 16.6-16.7 |
| `reverse-tunnel` | Tunnel connection security | Untrusted tunnel server | spike, integration, e2e | 2.7, 11.1-11.9, 16.4, 16.6-16.7 |
| `reverse-tunnel` | Reconnect and readiness | Gateway restarts tunnel service | spike, integration, e2e | 2.7, 11.1-11.9, 16.4, 16.6-16.7 |
| `reverse-tunnel` | Mapping activation and removal ordering | New mapping upstream is unavailable | spike, integration, e2e | 2.7, 11.1-11.9, 16.4, 16.6-16.7 |
| `reverse-tunnel` | Revocation closes node tunnel | Revoked tunnel reconnect | spike, integration, e2e | 2.7, 11.1-11.9, 16.4, 16.6-16.7 |
| `reverse-tunnel` | Reverse-tunnel acceptance gate | Candidate creates a connection per expose | spike, integration, e2e | 2.7, 11.1-11.9, 16.4, 16.6-16.7 |
| `selective-routing-and-dns` | Separate IPv4 address pools | Pool collision at init | spike, unit, integration, e2e | 2.8-2.9, 7.1-7.6, 10.1-10.11, 16.1, 16.3, 16.7 |
| `selective-routing-and-dns` | Explicit selective-routing policy | Empty node assignment | spike, unit, integration, e2e | 2.8-2.9, 7.1-7.6, 10.1-10.11, 16.1, 16.3, 16.7 |
| `selective-routing-and-dns` | Editable versioned preset documents | User deletes an unassigned built-in preset | spike, unit, integration, e2e | 2.8-2.9, 7.1-7.6, 10.1-10.11, 16.1, 16.3, 16.7 |
| `selective-routing-and-dns` | Preset validation and activation | Invalid manual edit | spike, unit, integration, e2e | 2.8-2.9, 7.1-7.6, 10.1-10.11, 16.1, 16.3, 16.7 |
| `selective-routing-and-dns` | Deterministic preset composition | Cross-preset include and exclude | spike, unit, integration, e2e | 2.8-2.9, 7.1-7.6, 10.1-10.11, 16.1, 16.3, 16.7 |
| `selective-routing-and-dns` | Atomic policy replacement | Deferred node policy | spike, unit, integration, e2e | 2.8-2.9, 7.1-7.6, 10.1-10.11, 16.1, 16.3, 16.7 |
| `selective-routing-and-dns` | Host-wide private-node classification | Application process matches Telegram selector | spike, unit, integration, e2e | 2.8-2.9, 7.1-7.6, 10.1-10.11, 16.1, 16.3, 16.7 |
| `selective-routing-and-dns` | Fail-closed selected traffic | Gateway becomes unreachable | spike, unit, integration, e2e | 2.8-2.9, 7.1-7.6, 10.1-10.11, 16.1, 16.3, 16.7 |
| `selective-routing-and-dns` | Routing-engine crash guard | Routing engine crashes | spike, unit, integration, e2e | 2.8-2.9, 7.1-7.6, 10.1-10.11, 16.1, 16.3, 16.7 |
| `selective-routing-and-dns` | IPv4 support and IPv6 leak prevention | Selected hostname returns IPv6 | spike, unit, integration, e2e | 2.8-2.9, 7.1-7.6, 10.1-10.11, 16.1, 16.3, 16.7 |
| `selective-routing-and-dns` | Split DNS modes | Gateway DNS outage | spike, unit, integration, e2e | 2.8-2.9, 7.1-7.6, 10.1-10.11, 16.1, 16.3, 16.7 |
| `selective-routing-and-dns` | Configurable independent DNS paths | Reset node direct DNS | spike, unit, integration, e2e | 2.8-2.9, 7.1-7.6, 10.1-10.11, 16.1, 16.3, 16.7 |
| `selective-routing-and-dns` | Managed host DNS integration | Node uninstall restores DNS | spike, unit, integration, e2e | 2.8-2.9, 7.1-7.6, 10.1-10.11, 16.1, 16.3, 16.7 |
| `selective-routing-and-dns` | Classification limitations are explicit | Application uses an unselected hardcoded address | spike, unit, integration, e2e | 2.8-2.9, 7.1-7.6, 10.1-10.11, 16.1, 16.3, 16.7 |
| `transport-management` | Two named transport behaviors | Gateway listener inspection | spike, unit, integration, e2e, manual-compatibility | 2.2-2.4, 8.1-8.10, 16.3, 16.11 |
| `transport-management` | Manual transport selection only | Active transport outage | spike, unit, integration, e2e, manual-compatibility | 2.2-2.4, 8.1-8.10, 16.3, 16.11 |
| `transport-management` | Shared transport choice for node paths | Node uses restricted active | spike, unit, integration, e2e, manual-compatibility | 2.2-2.4, 8.1-8.10, 16.3, 16.11 |
| `transport-management` | Restricted selected UDP uses DPI-resistant TCP path | Restricted UoT probe fails | spike, unit, integration, e2e, manual-compatibility | 2.2-2.4, 8.1-8.10, 16.3, 16.11 |
| `transport-management` | Restricted selected UDP uses DPI-resistant TCP path | Restricted UDP is healthy | spike, unit, integration, e2e, manual-compatibility | 2.2-2.4, 8.1-8.10, 16.3, 16.11 |
| `transport-management` | Transport test is non-mutating | Test standby restricted transport | spike, unit, integration, e2e, manual-compatibility | 2.2-2.4, 8.1-8.10, 16.3, 16.11 |
| `transport-management` | Manual make-before-break switch | Successful switch to standby | spike, unit, integration, e2e, manual-compatibility | 2.2-2.4, 8.1-8.10, 16.3, 16.11 |
| `transport-management` | Manual make-before-break switch | Target cannot reach gateway | spike, unit, integration, e2e, manual-compatibility | 2.2-2.4, 8.1-8.10, 16.3, 16.11 |
| `transport-management` | Deferred switch remains explicit | Deferred target | spike, unit, integration, e2e, manual-compatibility | 2.2-2.4, 8.1-8.10, 16.3, 16.11 |
| `transport-management` | Restricted transport acceptance contract | Candidate fails Clash Mi UDP test | spike, unit, integration, e2e, manual-compatibility | 2.2-2.4, 8.1-8.10, 16.3, 16.11 |
| `transport-management` | Versioned pinned handshake-host selection | First candidate unavailable during init | spike, unit, integration, e2e, manual-compatibility | 2.2-2.4, 8.1-8.10, 16.3, 16.11 |
| `transport-management` | Handshake-host degradation and manual replacement | Pinned host later fails | spike, unit, integration, e2e, manual-compatibility | 2.2-2.4, 8.1-8.10, 16.3, 16.11 |
| `transport-management` | Emergency handshake-host recovery | Restricted control path is blocked | spike, unit, integration, e2e, manual-compatibility | 2.2-2.4, 8.1-8.10, 16.3, 16.11 |
| `transport-management` | Personal client transport choice | Clash profile contains alternatives | spike, unit, integration, e2e, manual-compatibility | 2.2-2.4, 8.1-8.10, 16.3, 16.11 |
