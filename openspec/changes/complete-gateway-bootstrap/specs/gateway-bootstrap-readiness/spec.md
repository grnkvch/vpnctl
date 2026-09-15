## Purpose

Defines when a dedicated Gateway is fully bootstrapped, observable, repairable,
and ready to accept public private-node enrollment before a release is accepted.

## ADDED Requirements

### Requirement: Complete role-specific package bootstrap
Gateway initialization SHALL derive its Ubuntu package requirements from the
verified local release bundle, show every required package action in dry-run,
install only the Gateway role's missing packages from configured Ubuntu 24.04
repositories, and verify every installed version against the bundle's declared
compatibility interval before committing initialized state. It MUST NOT run a
general OS upgrade, silently continue with an absent package, or install
Gateway-only packages during Node initialization.

#### Scenario: Clean Gateway has no nginx package
- **WHEN** the operator applies `vpnctl init --gateway` on a compatible clean host whose configured repository offers the declared nginx version range
- **THEN** the plan installs nginx without a general OS upgrade and initialization cannot succeed until its installed version is verified compatible

#### Scenario: Package acquisition is unavailable
- **WHEN** a required Gateway package cannot be acquired, the package-manager lock remains unavailable, or the repository candidate is outside the declared range
- **THEN** initialization fails with an actionable package/bootstrap result, does not publish initialized authoritative state, and restores any runtime or package changes made solely by the failed invocation

#### Scenario: Node role remains minimal
- **WHEN** the operator initializes a private Node from the same release bundle
- **THEN** no Gateway-only nginx package, service, configuration, or listener is installed or activated

### Requirement: Baseline HTTPS ingress is an initialization postcondition
A successful Gateway initialization SHALL render and atomically activate a
vpnctl-owned baseline nginx generation, enable and start its owned runtime,
serve the Gateway public-IP certificate on TCP 443, and route the reserved
health and enrollment paths to their bounded loopback upstreams. This baseline
MUST NOT require a user expose, domain, or public HTTP listener, and a failed
activation or health check MUST NOT be reported as successful initialization.

#### Scenario: Fresh Gateway becomes enrollment-ready
- **WHEN** Gateway initialization completes on a host with no prior nginx installation or managed ingress tree
- **THEN** nginx is active with a valid owned configuration, TCP 443 serves the expected IP-only TLS identity, the reserved enrollment route reaches the loopback enrollment service, and no user expose exists

#### Scenario: Baseline activation fails
- **WHEN** nginx validation, activation, TLS health, reserved-route health, or public-listener verification fails during initialization
- **THEN** initialization returns a failed/degraded result, restores the pre-invocation serving and package state where the outcome is known, and never reports the Gateway healthy

#### Scenario: Public listener is occupied
- **WHEN** unmanaged state already owns TCP 443 or conflicts with the required nginx service/configuration
- **THEN** preflight rejects initialization before overwriting, stopping, or deleting the unmanaged resource

### Requirement: Shipped presets are selectable after fresh initialization
A fresh Gateway initialization SHALL compile the exact shipped editable
`telegram`, `openai`, and `anthropic` source documents into generation-1
effective preset snapshots in authoritative state. Their source hashes,
selectors and application timestamp SHALL match the files created by that same
initialization. Repeated initialization MUST NOT silently apply later source
edits or recreate an operator-deleted source.

#### Scenario: First Node selects a shipped preset
- **WHEN** a freshly initialized Gateway has not run any separate preset command and a Node joins with the explicit `telegram` preset
- **THEN** enrollment resolves the generation-1 effective snapshot and commits the selected policy instead of rejecting the shipped preset as unknown

#### Scenario: Source changes after initialization
- **WHEN** the operator edits or deletes an unassigned built-in source after successful initialization and repeats the same init command
- **THEN** init leaves both the editable source and previously committed effective snapshot unchanged until an explicit preset workflow is used

### Requirement: Mandatory Gateway readiness is observable
Gateway `status` SHALL passively include the required nginx service and managed
ingress generation, `plan` SHALL expose missing or drifted owned ingress state,
and `doctor ingress` SHALL actively test the public-IP TLS and reserved health
path with bounded probes. A missing package, unloaded/inactive service, absent
or drifted tree, invalid configuration, or absent TCP 443 listener MUST prevent
an overall healthy/clean readiness result. An active tree whose provenance
generation is older than authoritative state SHALL remain ready only when
rendering the current semantic ingress inputs at that retained generation
produces its exact tree hash. A newer provenance or changed semantic input MUST
remain drift. Status SHALL detect collection races by rereading authoritative
state, not by requiring convergence material generation to equal a later
metadata-only state generation.

#### Scenario: nginx was removed after initialization
- **WHEN** a Gateway has valid authoritative state but its nginx package/unit and public listener are absent
- **THEN** status is degraded with a stable required action, plan reports the owned readiness gap, and doctor ingress reports the unavailable public edge without mutation

#### Scenario: Complete Gateway is healthy
- **WHEN** the package, service, owned generation, TLS listener, reserved routes, and existing vpnctl role services match the committed generation
- **THEN** status reports healthy, plan reports no drift or pending change, and doctor ingress passes its bounded readiness probes

### Requirement: Confirmed repair restores the complete owned edge
Gateway repair SHALL preview and, after explicit confirmation, reconcile missing
compatible packages, owned nginx service state, baseline configuration, and
public-listener health in addition to existing vpnctl role services and network
state. It MUST preserve unknown external resources, active WireGuard clients,
client addresses and keys, and the last healthy serving generation. An
incompatible pre-existing package or unmanaged listener/configuration SHALL
remain a conflict rather than being silently replaced or downgraded.
Package-manager, system-wide ingress, and committed network-watchdog changes MUST run only in the
short-lived privileged CLI transaction after it acquires the same root-only
cross-process mutation lock used by the controller. The resident controller
MUST NOT gain APT, dpkg, nginx-tree, or system-unit write paths for bootstrap
repair. The approved plan and authoritative generation MUST be revalidated
after lock acquisition.
The resident Gateway controller SHALL admit IPv4, Unix, and netlink address
families so its existing pre-commit `wg`/`ip` readiness observers can inspect
the staged candidate. It MUST NOT add IPv6 or package/nginx/system-unit write
authority for this purpose.

#### Scenario: Repair an initialized Gateway missing nginx
- **WHEN** confirmed repair runs against valid Gateway state whose nginx package and managed ingress generation are absent and no unmanaged conflict exists
- **THEN** the short-lived root CLI acquires the shared mutation lock, installs a compatible package, activates the baseline generation and TCP 443, preserves every existing WireGuard client, and reports the exact changed resources without routing package mutation through the resident controller

#### Scenario: Concurrent controller mutation overlaps bootstrap repair
- **WHEN** bootstrap repair owns the shared Gateway mutation lock and another command requests a controller mutation
- **THEN** the controller rejects that mutation as busy before runtime or authoritative-state mutation, while passive observation remains available

#### Scenario: Repair encounters foreign ingress ownership
- **WHEN** TCP 443, nginx configuration, or a target path is owned by an unrecognized external resource
- **THEN** repair reports a conflict and does not stop, replace, delete, or adopt that resource

#### Scenario: Repair activation fails
- **WHEN** a confirmed repair changes package or ingress state but cannot establish the required health postcondition
- **THEN** it restores the prior known package/service/configuration generation, reports any uncertain residue explicitly, and does not weaken the working WireGuard data plane

### Requirement: Unpublished same-version candidate recovery is hash-bound
The one already deployed unpublished `v2.0.0` candidate MAY use a one-time
recovery prerequisite that installs only the exact missing pinned nginx package
needed to unblock its existing updater. The recovery plan SHALL identify the
installed candidate commit/artifact hashes, expected absent package and ingress
state, exact package version, and rollback boundary; SHALL require confirmation;
and SHALL be rehearsed outside production. The subsequent same-version update
MUST recognize manifest/component SHA differences, replace only verified release
artifacts, preserve state and clients, and leave final installed metadata equal
to the eventual public `v2.0.0` assets. Confirmed repair by the updated product
SHALL then publish and verify the missing managed ingress.

#### Scenario: Recover the incomplete deployed candidate
- **WHEN** the guarded prerequisite installs the pinned nginx package on the recorded old `v2.0.0` candidate, the operator applies the final `v2.0.0` update, and then confirms repair
- **THEN** nginx readiness is restored, existing WireGuard clients remain usable, the final binary/bundle/checksum hashes match the new candidate, and the old candidate remains distinguishable in the audit journal

#### Scenario: Recovery identity or precondition is ambiguous
- **WHEN** the expected installed binary/bundle/checksum metadata, old manifest, package/listener baseline, target package version, or documented commit/hash binding does not match
- **THEN** recovery stops before package, service, state, firewall, or release-file mutation

### Requirement: Public enrollment failures are actionable and atomic
Node join SHALL classify public TCP/TLS/HTTP enrollment unavailability separately
from an internal software error, return a stable safe required action, retain an
unconsumed invite, and leave the Node unjoined without staged credentials or
active services. Diagnostics MUST NOT expose the invite token, token hash,
private keys, authorization data, or sensitive configuration.
The public handler transaction, loopback response writer, reserved nginx proxy,
and Node response-header wait SHALL share a fixed 45-second first-join response
budget while shorter bounded TCP/TLS and request admission limits remain in
effect. A written request whose outcome is not proven before that budget MUST
retain the existing uncertain-outcome semantics.
Post-restart Gateway candidate readiness SHALL retry the complete unchanged
health contract every 100 milliseconds for no more than 20 seconds inside the
shared response budget. Exhaustion SHALL restore the exact prior runtime and
return fixed `503 unavailable`; it MUST NOT be classified as an invalid invite.
The pre-commit candidate SHALL atomically replace only the existing vpnctl-owned
Gateway firewall with the candidate active identities before readiness is
observed. Until authoritative invite/Node commit, it SHALL retain and restore
the exact prior owned table on readiness, convergence, credential, or state
failure; a committed join SHALL retain the candidate table.
After the Node commits a valid assignment, each Node role unit SHALL create the
shared private runtime directory through systemd and the local activator SHALL
retry the current unit's start/readiness for no more than 20 seconds before
advancing. Exhaustion MUST retain activation-pending semantics and MUST NOT
disable the fail-closed routing boundary.
After all units report active, the activator SHALL retry the complete unchanged
Node routing and FRP readiness contract for no more than the same fixed
20-second bound before publishing the active convergence generation. A failed
or exhausted check MUST retain activation-pending semantics and MUST NOT
publish an active baseline for an unverified runtime.
FRP client readiness SHALL require exactly one established connection from the
expected `frpc` process to the candidate Gateway endpoint. Endpoint connections
owned by other processes MUST be ignored; zero or multiple matching `frpc`
connections MUST remain unhealthy.
The Node recovery table SHALL preserve the unique most-specific usable
main-table route to the public Gateway IPv4 endpoint, using the unique
best-metric default only as a fallback. Equal-priority ambiguity or an invalid
next hop MUST fail before local activation rather than guessing a route.
When Linux reports an owned IPv4 host-route destination as a bare address, the
snapshot boundary SHALL normalize it to the exact `/32` prefix before
validation and restoration. Malformed, IPv6, or cross-family destinations MUST
remain invalid and MUST NOT broaden the owner-scoped cleanup surface.
After Node services stop for owner-scoped cleanup, restoration SHALL omit the
retained rp-filter value only for the exact product WireGuard interface when
that interface is positively absent. Host-level and underlay-interface sysctls
MUST still be restored, and an unavailable or ambiguous interface observation
MUST fail closed.

#### Scenario: Gateway public HTTPS edge is absent
- **WHEN** an initialized Node attempts join with a valid unexpired invite but the Gateway TCP 443 enrollment edge cannot be reached
- **THEN** join reports enrollment unavailable with `changed=false`, the Gateway does not consume the invite, and the Node remains cleanly unjoined

#### Scenario: End-to-end enrollment succeeds
- **WHEN** a freshly initialized Gateway and Node use the final candidate, the operator creates an invite, and the Node joins with an explicit transport and preset
- **THEN** the shipped preset resolves without a separate import command, the invite is consumed exactly once, the Node commits its identity and selected policy, mandatory services become healthy, and a selected test request traverses the Gateway

#### Scenario: Minimum Gateway needs more than the generic RPC timeout
- **WHEN** a valid first join completes its synchronous Gateway staging and readiness after more than five seconds but within the fixed 45-second enrollment budget
- **THEN** nginx, the loopback handler, and the Node client keep the single request alive through the same bounded transaction and join is not reported as uncertain solely because it exceeded the generic RPC timeout

#### Scenario: Service activation precedes candidate readiness
- **WHEN** systemd reports the staged Gateway services started before WireGuard or a required listener reaches the exact candidate state
- **THEN** join retries the complete readiness report for at most 20 seconds, commits only an exact healthy result, and otherwise rolls back and reports enrollment unavailable

#### Scenario: Candidate Node becomes an active firewall identity
- **WHEN** Gateway join stages a valid Node before consuming the invite
- **THEN** the candidate Node address is present in the owned active-identity firewall during readiness, successful commit retains it, and any rejected join restores the exact prior owned table

#### Scenario: Node runtime or routing guard is transiently unavailable
- **WHEN** a joined Node boots without a pre-existing `/run/vpnctl` directory or the routing guard's first start races the WireGuard interface
- **THEN** systemd recreates the private runtime directory, activation retries that same unit within the fixed bound, and success is reported only after every required Node unit is active

#### Scenario: Active Node services precede complete readiness
- **WHEN** all joined Node units report active but the first complete routing or FRP readiness observation is not yet healthy
- **THEN** activation retries the complete readiness contract inside the fixed 20-second bound and publishes active convergence only after an exact healthy result

#### Scenario: Selected transit shares the FRP endpoint
- **WHEN** one healthy `frpc` control connection and one or more non-frpc transit connections target the same Gateway endpoint
- **THEN** FRP readiness counts only the single matching `frpc` connection and does not reject the Node because unrelated processes share the destination

#### Scenario: Public Gateway has an explicit host route
- **WHEN** the Node main table contains both a default route and a more-specific route to the public Gateway endpoint
- **THEN** the recovery table copies the more-specific route's interface and next hop so the active transport remains reachable after the routing guard starts

#### Scenario: Owner-scoped cleanup snapshots a Linux host route
- **WHEN** Linux JSON route output represents the owned Gateway endpoint route as a bare IPv4 address
- **THEN** the snapshot retains it as the exact `/32` route and uninstall or purge can validate and restore it without accepting malformed or non-IPv4 input

#### Scenario: Product WireGuard interface ends before network restoration
- **WHEN** owner-scoped Node cleanup stops the standard transport and positively observes that `vpnctl-wg` no longer exists
- **THEN** restoration omits only that interface's retained rp-filter value, restores every host and underlay value, and does not fail on a kernel path removed with the product interface

### Requirement: Focused acceptance precedes the full release gate
The final candidate SHALL first pass fast focused tests, then manual fresh and
incomplete-candidate scenarios on the existing fixed Lima pair, and only then
one focused automated Gateway-enrollment check. The focused check SHALL use the
actual candidate binary and bundle from a clean no-nginx Gateway baseline,
restore the fixtures to their prior stopped clean state, and remain independent
of capacity, migration, and general release-gate orchestration.

#### Scenario: Candidate enters final release validation
- **WHEN** both manual scenarios and the focused automated check pass for one frozen source commit
- **THEN** the existing fast and resumable VM release gates may run once for that exact commit while capacity remains an explicit on-demand measurement

#### Scenario: Focused scenario fails
- **WHEN** fresh bootstrap, recovery, public join, request flow, or owner-scoped cleanup fails
- **THEN** the candidate remains ineligible for the full release gate and the next iteration runs only focused tests until the defect is corrected
