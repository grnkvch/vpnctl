## 1. Baseline and Public Contracts

- [x] 1.1 Capture v1 golden fixtures for WireGuard full-tunnel export, Clash Mi selective export, client keys/IPs, rulesets, installer artifacts, and UFW setup; verify current `go test ./...` plus fixture replay passes before v2 refactoring.
- [x] 1.2 Build a requirement-to-test traceability table covering every requirement and scenario in all ten v2 specs; verify no spec requirement lacks an assigned unit, integration, E2E, spike, or manual compatibility check.
- [x] 1.3 Finalize the v2 command tree from the accepted happy paths, removing redundant role/target arguments without changing behavior; verify a checked-in CLI contract lists role availability, arguments, consent class, `--dry-run`/`--defer` support, and examples for every command.
- [x] 1.4 Freeze numeric exit codes for success, validation, conflict, unavailable/degraded, and internal error; verify table-driven CLI tests map every result category to the documented code.
- [x] 1.5 Define versioned JSON Schemas for common result envelopes and each command result, including `schema_version`, identifiers, status, warnings, and `requires_action`; verify all examples validate and sensitive fields are schema-forbidden.
- [x] 1.6 Define TTY/stdin rules for hidden invite/recovery tokens, backup passphrases, yes/no prompts, typed confirmations, and `--yes`; verify golden tests cover interactive and non-interactive refusal paths.
- [x] 1.7 Create the v2 Go package skeleton and dependency-direction checks described in design.md; verify `go list ./...`, static analysis, and the existing v1 tests pass without production behavior changes.

## 2. Blocking Technical Spikes

- [x] 2.1 Create a reproducible Ubuntu 24.04 amd64 test environment constrained to 1 vCPU, 512 MB RAM, and 10 GB disk with network-fault controls; verify a documented command boots gateway/node fixtures and records CPU, RSS, disk, sockets, and latency.
- [x] 2.2 Prototype pinned Mihomo with Shadowsocks + ShadowTLS v3 strict for gateway and Linux node, render and validate the Clash-compatible profile with pinned Mihomo, and verify selected TCP plus proxy-bound DNS E2E, handshake-host behavior, reconnect, and captured resource evidence; defer execution on actual Clash Mi to the deployed-service release gate.
- [x] 2.3 Extend the restricted prototype with Mihomo UDP-over-TCP and close `8443/UDP`; verify selected UDP reaches the gateway only through protected TCP and blocks without any direct/native-UDP leak when UoT is broken.
- [x] 2.4 Benchmark restricted UDP head-of-line behavior and representative Telegram plus general UDP workloads; verify the report defines supported functional bounds and explicitly records workloads with no performance guarantee.
- [x] 2.5 Prototype pinned nginx IP-only self-signed RSA ingress and a token-safe Telegram Bot API compatibility harness; verify locally TLS 1.2/1.3, five-year RSA certificate shape, SAN/CN IP identity, HTTP/1.1+HTTP/2 forwarding, public-certificate-only export, and defer the actual provider registration/request plus five-year acceptance to task 16.11 on a deployed service.
- [x] 2.6 Stress the nginx prototype for streaming without request-body disk files, hard/per-expose limits, graceful reload, concurrency, and `404`/`413`/`503`/`504`; verify measured safe defaults fit the minimum gateway or document the Caddy fallback decision.
- [x] 2.7 Prototype pinned frp with one shared frps, one frpc per node, `tcpMux`, no pool, dynamic mapping reload, local Login/NewProxy authorization, TLS, reconnect, revoke, and transport switch; verify one persistent connection carries multiple expose streams within the resource budget.
- [x] 2.8 Prototype nftables hooks, fwmark allocation, conntrack retention, policy routes, TUN readiness guard, recovery allowlist, ingress-response symmetry, and atomic rollback; verify boot/crash/restart/uninstall fault tests show no selected TCP/UDP/IPv6 direct leak and no unrelated-node traffic breakage.
- [x] 2.9 Prototype systemd-resolved integration and candidate Mihomo DNS modes with Linux applications and rendered Clash-compatible profiles validated by pinned Mihomo; verify selected/direct query separation, gateway-DNS failure, cache behavior, classic port-53 capture, and clean restoration select one documented mode, deferring actual Clash Mi DNS behavior to task 16.11.
- [x] 2.10 Prototype the Ed25519 control CA/leaf and enrollment-signature formats plus HTTPS/1.1 JSON RPC limits; verify Go/OpenSSL interoperability, URI SAN validation, renewal/overlap, signed transcript replay resistance, and bounded malformed-request behavior.
- [x] 2.11 Select and benchmark backup KDF/AEAD parameters under 512 MB RAM; verify encryption/decryption, wrong-passphrase authentication failure, corruption detection, and documented memory/time bounds.
- [x] 2.12 Consolidate spike outcomes into ADRs and a pinned component/limit manifest; verify every conditional provider and open design parameter has a development-accepted value or explicitly selected fallback and every deferred deployed-service gate is assigned to section 16 before dependent production tasks start.

## 3. Versioned Model, Store, and Secrets

- [x] 3.1 Implement versioned role, host, node, client, preset, policy, transport, expose, certificate, operation, logging, backup, and component-manifest models; verify invariant and JSON round-trip tests reject unknown/invalid states.
- [x] 3.2 Implement immutable UUID identities, unique active names, lifecycle states, credential generations, and monotonic state generation; verify property tests cover collisions, rotation preservation, revoke/delete ordering, and generation overflow/error handling.
- [x] 3.3 Implement independent `10.66.0.0/24` client and `10.67.0.0/24` node allocators with configurable pools and stable rotation assignments; verify overlap, exhaustion, release, restore, and v1-address preservation tests.
- [x] 3.4 Implement the system path resolver for `/etc/vpnctl`, `/var/lib/vpnctl`, and `/run/vpnctl` with injectable test roots; verify commands launched from different working directories resolve identical role/state paths.
- [x] 3.5 Implement validated atomic JSON writes using temp file, fsync, rename, directory fsync, and one prior generation; verify kill/fault-injection tests never accept partial state and can load the previous snapshot.
- [x] 3.6 Implement root-only secret storage with opaque references, no-follow file creation, atomic replacement, and permission repair diagnostics; verify symlink, mode, concurrent write, and secret/non-secret serialization tests.
- [x] 3.7 Implement deterministic generated-artifact manifests with content hashes, source state/policy/credential generations, and drift comparison; verify identical state renders identical non-secret output and changed input marks only affected artifacts.
- [x] 3.8 Implement bounded per-node idempotency storage with 30-day and 1024-record pruning and redacted result summaries; verify both eviction bounds and absence of bodies, paths, and secrets in persisted records.
- [x] 3.9 Implement operation records for pending/active/degraded/failed sagas and locally persisted node request IDs; verify restart and lost-response fixtures resume the same operation rather than create a duplicate.

## 4. CLI, Output, and Consent Framework

- [x] 4.1 Implement the role-aware command registry from the frozen contract; verify every command rejects unsupported host roles before state or system mutation.
- [x] 4.2 Implement the common result model and concise human renderer; verify golden output contains identifiers, warnings, required actions, and copy-ready commands without profiles or secrets.
- [x] 4.3 Implement one-document JSON stdout, stderr progress separation, schema versions, and stable exit mapping; verify every command family passes schema and stream-separation integration tests.
- [x] 4.4 Implement centralized redaction metadata and secret/sensitive-path types that cannot use ordinary formatters; verify fuzz and golden tests do not expose tokens, keys, authorization headers, bodies, or webhook paths.
- [x] 4.5 Implement impact-based consent, `--yes`, typed confirmation, hidden input, and non-interactive refusal; verify the consent matrix from task 1.3 is exhaustively tested.
- [x] 4.6 Implement common `--dry-run` and supported `--defer` plumbing without treating JSON mode as consent; verify dry-run creates neither pending state nor files and defer requires an authoritative gateway write.

## 5. Linux Host Platform and Initialization

- [x] 5.1 Implement Ubuntu/amd64/root/systemd capability discovery for TUN, kernel WireGuard, nftables, marks/policy routing, systemd-resolved, forwarding, interfaces, routes, container networks, listeners, RAM/disk, and swap; verify clean, missing-capability, and conflicting-host fixtures.
- [x] 5.2 Implement explicit public IPv4 and CIDR/interface validation with no external IP lookup; verify missing/invalid IP and overlapping pool cases fail before mutation.
- [x] 5.3 Implement fail-closed SSH port discovery from `SSH_CONNECTION` plus active listener cross-check and verified `--ssh-port`; verify non-SSH, mismatch, ambiguity, non-22, and explicit-port fixtures.
- [x] 5.4 Implement vpnctl-owned nftables table rendering with default-deny gateway inbound, established/related, loopback, SSH from `0.0.0.0/0`, fixed listeners, isolation, forwarding, and NAT; verify packet-level namespace tests and preservation of foreign tables.
- [x] 5.5 Implement preflight conflicts for UFW/firewalld, reserved ports, incompatible routes/TUN/WireGuard, and unmanaged reverse proxies while permitting non-conflicting foreign resources; verify conflicts produce actionable plans and zero mutation.
- [x] 5.6 Implement the controller-independent systemd watchdog snapshot/rollback executable and 120-second timer; verify controller/CLI kill and timeout restore only prior vpnctl rules, routes, rules, and sysctls.
- [x] 5.7 Implement `vpnctl confirm <id>` with one-time IDs and proof of a newly established post-activation SSH session; verify original-session, reused-ID, wrong-port, expired, and successful-new-session cases.
- [x] 5.8 Implement role-scoped systemd unit/config installation and `Restart=on-failure`; verify gateway and node init never install or start the other role's services.
- [x] 5.9 Implement idempotent `init --gateway` planning/application with fixed ports, default pools, explicit public IP, host ownership, presets, PKI placeholders, and lockout watchdog; verify a second identical init has no effect.
- [x] 5.10 Implement idempotent `init --node` without join or gateway services and reject role changes; verify node state is initialized but contains no enrolled identity or active tunnel.
- [x] 5.11 Implement the optional managed 1 GB swap plan, confirmed creation, status, and lifecycle ownership; verify accept, decline, existing-swap, insufficient-disk, uninstall, and purge behaviors.

## 6. Gateway Controller and Control Plane

- [x] 6.1 Implement the controller process, Unix socket permissions, serialized mutation execution, passive observation, and graceful restart; verify concurrent local mutations serialize and data-plane mock units continue through controller restart.
- [x] 6.2 Implement Ed25519 control CA, gateway leaf, enrollment identity, node CSR issuance, random serials, URI SANs, root-only storage, and distinct public ingress identity; verify certificate-chain and identity-boundary tests.
- [x] 6.3 Implement internal-overlay-only HTTPS/1.1 mTLS server/client with strict JSON schemas, deadlines, size limits, and short-lived node CLI connections; verify public binding is absent and malformed/oversized requests fail boundedly.
- [x] 6.4 Implement protocol `major.minor` negotiation independent of binary versions and current/previous-major server dispatch; verify additive-minor fixtures, breaking-major rejection, and gateway-first rolling compatibility.
- [x] 6.5 Implement request ID, expected-generation, serialized commit, stored-result replay, stale conflict, and evicted-request reconciliation; verify response-loss and concurrency fault tests produce effectively-once effects.
- [x] 6.6 Implement active node-record and credential-generation authorization on every control request; verify a cryptographically valid revoked or old-generation certificate is rejected immediately.
- [x] 6.7 Implement gateway control-leaf automatic renewal at the 180-day window without data-plane restart; verify time-travel tests preserve node trust and public ingress identity.
- [x] 6.8 Implement manual staged control-CA rotation with old/new overlap, impact reporting, node trust update, commit, and rollback; verify nodes on both accepted generations remain manageable during the window and only the new CA is trusted after commit.
- [x] 6.9 Implement unavailable/incompatible controller result behavior and node update preflight; verify failed management never mutates or tears down an already applied compatible data plane.

## 7. Presets, Policies, and Personal Clients

- [x] 7.1 Define and implement the public versioned preset YAML schema and normalized selector AST without actions/raw Mihomo fields; verify unknown types/actions/outbounds fail whole-set validation.
- [x] 7.2 Ship editable `telegram`, `openai`, and `anthropic` templates and initialize them only when absent; verify update never recreates a user-deleted preset or mutates user source implicitly.
- [x] 7.3 Implement include-minus-exclude and cross-preset union normalization with order independence; verify property tests cover reordered files/rules and cross-preset reselection.
- [x] 7.4 Implement preset list/show/validate/diff and assigned-preset deletion guard; verify manual invalid edits leave the prior effective generation active.
- [x] 7.5 Implement reviewed three-way built-in template update with user additions/exclusions preservation, immediate/deferred apply, and merge conflicts; verify safe and unsafe merge fixtures.
- [x] 7.6 Implement atomic full policy set/clear for current node and explicit client target, including unknown/empty validation and pending node policy; verify no incremental or automatic assignment path exists.
- [x] 7.7 Implement client add/list/show with immutable identity, unique name, stable address, explicit atomic initial presets, and secret-free views; verify at least five isolated clients and duplicate/unknown failures.
- [x] 7.8 Migrate the v1 WireGuard renderer into v2 deterministic full-tunnel export; verify byte/semantic golden compatibility, default DNS behavior, key/address preservation, and independence from preset changes.
- [x] 7.9 Implement Clash/Mihomo export from normalized policy and split DNS, initially with standard and later restricted alternatives; verify pinned Mihomo parses the rendered Clash-compatible profile, selected rules end in gateway-or-block semantics, and unmatched traffic ends direct, deferring import into actual Clash Mi to task 16.11.
- [x] 7.10 Implement managed/custom export paths, `0600` files, `0700` directories, atomic overwrite rules, `--force`, scp hints, generation metadata, and no stdout profile; verify file/permission/staleness/output tests.
- [x] 7.11 Implement client policy/credential staleness, rotation, immediate revoke, delete-after-revoke, and export deletion; verify old profiles stop connecting and full-tunnel WireGuard does not become stale on preset-only edits.
- [x] 7.12 Implement client/client, client/node, and node/node gateway isolation rules tied to active identities; verify packet-level lateral attempts are blocked while internet egress works.

## 8. Standard and Restricted Transports

- [x] 8.1 Implement transport provider interfaces for render, validate, test, activate, health, drain, and rollback with one active/one standby state; verify fake-provider tests enforce no automatic switch and single-active steady state.
- [x] 8.2 Implement pinned standard WireGuard gateway/node services on `51820/UDP`, overlay routes, per-identity credentials, and health observations; verify multiple clients/nodes reach permitted gateway services and internet without lateral access.
- [x] 8.3 Implement the selected restricted provider from spike results on `8443/TCP` with strict DPI-resistant mode and no UDP listener; verify rendered configuration and socket tests match the pinned manifest.
- [x] 8.4 Implement selected restricted UDP-over-TCP and mandatory readiness probes; verify broken UoT blocks activation and both TCP/UDP have no direct or native-UDP fallback.
- [x] 8.5 Implement signed versioned handshake-host bundles, init reachability/TLS1.3/latency selection, persistence, node/client delivery, and passive degradation; verify ordered selection and zero runtime auto-rotation.
- [x] 8.6 Start and supervise both gateway transport listeners while keeping exactly one active per node; verify gateway restart restores listeners and a node outage does not activate standby.
- [x] 8.7 Implement non-mutating `transport test` with isolated control, tunnel, TCP, UDP, cleanup, and bounded deadlines; verify active routing/generation is unchanged on success and failure.
- [x] 8.8 Implement confirmed make-before-break `transport switch`, idempotent active-target health check, bounded drain, rollback, and `--defer`; verify target failure preserves old production paths and successful switch moves control/tunnel/selected egress together.
- [x] 8.9 Implement staged handshake-host prepare/commit/rollback, impact/staleness reporting, and local SSH emergency alignment; verify no auto-fallback, one active host, short-downtime rollback, and identity preservation.
- [x] 8.10 Add standard/restricted alternatives to Clash export with manual client selection only; verify no health-test or fallback rule changes the user's chosen transport.

## 9. Node Enrollment and Identity Lifecycle

- [x] 9.1 Implement the versioned opaque invite codec, 256-bit secret generation, 15-minute expiry, hashed storage, one-time human display, status metadata, and idempotent cancel; verify decode, tamper, expiry, replay, cancellation, and no-secret output tests.
- [x] 9.2 Implement reserved public enrollment/recovery HTTP handlers behind `443/TCP` with bounded requests, token purpose separation, signed transcripts, and atomic secret consumption; verify scanning, replay, wrong-purpose, signature substitution, and race tests.
- [x] 9.3 Implement node-local generation of Ed25519 control, WireGuard, restricted, and tunnel private material plus CSR/public exchange; verify gateway state and packet captures contain no node private keys.
- [x] 9.4 Implement atomic `join <transport> [preset...]` across gateway/node with unique name/ID, node IP, both transport credentials, control trust, tunnel token, explicit presets, health checks, and invite consumption; verify failed health/unknown preset leaves invite unused and no partial node.
- [x] 9.5 Implement joined-node idempotency/error behavior and gateway node list/show without secrets; verify repeated join changes nothing and multiple nodes retain isolated identities/resources.
- [x] 9.6 Implement immediate gateway node revoke, connection termination, expose disable, diagnostic retention, and delete-after-revoke cleanup; verify an offline revoked node cannot reconnect through control, either transport, or tunnel.
- [x] 9.7 Implement node-local atomic full credential rotation with parallel old/new control, standard, restricted, and tunnel generations, health checks, switch, drain, and rollback; verify injected failure at every phase leaves either the complete old or complete new set active.
- [x] 9.8 Implement 180-day node certificate warnings in status/doctor and refusal of ordinary rotate after expiry; verify time-travel cases direct expired nodes to recovery.
- [x] 9.9 Implement gateway/node recovery commands with confirmed, same-node-ID, one-time 15-minute tokens and atomic full credential replacement; verify preservation of name/IP/policies/exposes and rejection of revoked, deleted, cloned, wrong-host, and replay attempts.

## 10. Host-Wide Routing and Split DNS

- [x] 10.1 Implement matcher IR compilation for node routing, nftables leak guard, gateway DNS selection, and Clash export; verify one preset fixture produces equivalent selected sets across all targets.
- [x] 10.2 Implement node routing/TUN rendering and service readiness around the selected Mihomo DNS/routing mode; verify all host processes are covered and no process/user/container scope flag exists.
- [x] 10.3 Implement nftables marks, conntrack retention, policy routes, pre-engine fail-closed guard, and minimal gateway recovery allowlist from spike values; verify boot and routing-process crash block new application egress before readiness.
- [x] 10.4 Implement standard/restricted active-outbound binding so selected TCP/UDP, control, and tunnel share one transport while unmatched flows remain direct; verify packet captures for both active modes.
- [x] 10.5 Implement selected-path failure handling with no fail-direct and continued unrelated direct traffic; verify gateway and transport outage tests for new TCP and UDP flows.
- [x] 10.6 Implement IPv6 selected-traffic leak prevention and diagnostics while retaining IPv4 as the only full data plane; verify selected AAAA/IP traffic cannot escape direct and unrelated host behavior follows documented limits.
- [x] 10.7 Implement node systemd-resolved integration, classic port-53 capture, original DNS snapshot, and uninstall restore; verify resolved and direct-socket application DNS tests plus exact restoration.
- [x] 10.8 Implement one shared gateway internal DNS forwarder and independent gateway/direct IPv4 upstream state with defaults; verify multiple nodes share it without cross-node policy leakage.
- [x] 10.9 Implement policy/direct DNS modes and show/set/reset grammar for gateway and node scopes; verify selected DNS fails closed, direct DNS continues, gateway changes need no node rewrite/export, and resets use correct sources.
- [x] 10.10 Surface DoH/DoT/hardcoded-IP classification limits in docs, status/doctor, and policy diagnostics; verify no unsupported claim or global third-party DoH block is generated.
- [x] 10.11 Add routing/DNS fault-injection tests for engine crash/restart, gateway loss, resolver loss, component update, transport switch, and uninstall; verify every selected-flow invariant and recovery path from the specs.

## 11. Multiplexed Reverse Tunnel

- [x] 11.1 Implement the implementation-neutral tunnel provider interface, expose mapping model, deterministic names, and persisted collision/exhaustion-safe loopback allocator; verify allocation/restore/remap tests.
- [x] 11.2 Package and render the selected pinned tunnel server/client with shared gateway service, one node process, multiplexing, TLS verification, no dashboard/public proxy types, and active-transport-only connectivity; verify sockets/processes/config against the manifest.
- [x] 11.3 Implement unique 256-bit per-node tunnel credentials, hashes/generations, root-only node storage, and redaction; verify credentials are absent from status/logs/exports/plain backups.
- [x] 11.4 Implement local-only Login authorization against active immutable node/generation and deny-on-controller-error behavior; verify invalid, revoked, old-generation, and cross-node logins fail.
- [x] 11.5 Implement NewProxy authorization against exact authoritative expose owner/name/type/loopback port; verify malicious or stale announcements cannot bind arbitrary gateway endpoints.
- [x] 11.6 Implement atomic node tunnel configuration and loopback-only dynamic mapping reload; verify adding/removing multiple mappings does not create additional persistent connections or interrupt unrelated streams.
- [x] 11.7 Implement bounded exponential reconnect with jitter, readiness generation checks, upstream probes, and `503` degraded state using only active transport; verify gateway/tunnel restarts recover automatically without standby attempts.
- [x] 11.8 Integrate tunnel credential rotation, transport switch, and immediate node revoke connection close; verify identity preservation on switch and rejection after revoke.
- [x] 11.9 Run provider security/resource regression from the spike in CI or a release harness; verify multiplexing, authorization, reconnect, dynamic mapping, and minimum-host budget before marking the tunnel capability complete.

## 12. Managed HTTPS Ingress

- [x] 12.1 Implement stable public RSA-2048/SHA-256 certificate generation with IP SAN/CN, five-year default, root-only key, metadata, expiry warnings, show, and public-only export; verify OpenSSL plus Telegram compatibility fixtures and no private-key export.
- [x] 12.2 Implement expose identity, unique node-local names, port shorthand normalization, loopback default, non-loopback opt-in, exact/prefix paths, high-entropy generation, reserved namespace, and overlap validation; verify parser/property tests.
- [x] 12.3 Implement implementation-neutral gateway hard limits and safe per-expose body/timeout overrides from measured defaults; verify impossible values and raw proxy directives are rejected before render.
- [x] 12.4 Implement the selected reverse-proxy renderer with TLS 1.2/1.3, HTTP/1.1+bounded HTTP/2, internal HTTP/1.1, trusted forwarding headers, no WebSocket/HTTP3, streaming, no disk body buffering, and loopback tunnel upstreams; verify config validation and directive tests.
- [x] 12.5 Implement complete generated proxy-tree staging, validation, atomic activation, graceful reload, hash drift detection, and rollback; verify invalid config and failed reload preserve the prior serving generation.
- [ ] 12.6 Implement reserved enrollment/recovery/health paths ahead of user routes and unknown-path `404`; verify user exposes cannot shadow `/.well-known/vpnctl/`.
- [ ] 12.7 Implement expose creation saga in tunnel-before-ingress order, immediate/deferred mode, degraded local-app behavior, URL/certificate/scp result, and no sensitive JSON path; verify ready and stopped-app E2E cases.
- [ ] 12.8 Implement stateless request handling with hard limits and `413`/`503`/`504`, no queue/retry/body persistence, and downstream close after partial-response failure; verify fault-injected non-idempotent request tests show no replay.
- [ ] 12.9 Implement expose list/show/remove with certificate retrieval, new-request stop, bounded drain, isolated mapping removal, port release, and webhook-removal `requires_action`; verify one-of-many removal leaves others serving.
- [ ] 12.10 Implement confirmed manual certificate rotation with affected-expose plan, bounded rollback snapshot, short downtime, no defer, and re-registration actions; verify control/enrollment identity and node trust remain unchanged.
- [ ] 12.11 Run the production ingress HTTP/1.1/2 concurrency and minimum-host proxy regression and package the token-safe Telegram registration harness; verify path/query/header/body forwarding, error statuses, memory, no body files, and readiness for the deferred real-provider gate in task 16.11.

## 13. Convergence, Diagnostics, and Temporary Logging

- [ ] 13.1 Implement deterministic discovery and planning that separates pending desired diff from vpnctl-owned drift and lists availability/destructive impact; verify no plan mutates files, state, units, or network.
- [ ] 13.2 Implement local validate-stage-activate-health-rollback transactions reusable by component adapters; verify failure injection before/after activation restores the correct generation.
- [ ] 13.3 Implement cross-host saga coordinator with unique IDs, persisted phases, public-route-last ordering, bounded drains, and generation reconciliation; verify connection loss at every phase converges without blind retry or rollback.
- [ ] 13.4 Implement `apply` for registered pending changes only and role-scoped gateway/node behavior; verify it refuses conflicting drift and does not simulate an absent node agent.
- [ ] 13.5 Implement previewed, confirmed `repair` for vpnctl-owned drift only; verify foreign resources remain unchanged and repaired hashes match desired generation.
- [ ] 13.6 Implement passive `status`, default problem-focused human view, `--all`, full JSON, invitations/log/cert/backup warnings, component versions, generations, hashes, pending/drift, and specified exit behavior; verify it emits no synthetic traffic.
- [ ] 13.7 Implement bounded role-aware `doctor` scopes for direct/gateway DNS, active transport, tunnel, ingress, local upstreams, TLS, TCP, and UDP; verify standby is skipped, real webhook paths are not called, deadlines hold, and failures map to degraded exit.
- [ ] 13.8 Implement explicit safe `--probe-url` GET and `SKIPPED` outcomes for unknown external dependencies; verify no body, credentials, hidden provider endpoint, or configuration mutation.
- [ ] 13.9 Implement persisted logging opt-ins for all scopes/levels with required duration capped at one hour, restart-safe expiry, journald default, optional `0600` bounded file, status, and disable; verify default-off and automatic expiry across restarts.
- [ ] 13.10 Apply source-level redaction to controller, transports, routing, DNS, tunnel, and ingress and disable hidden telemetry/update checks; verify canary-secret E2E scans of stdout, stderr, journal, files, state, and network captures.
- [ ] 13.11 Verify controller outage/restart leaves all applied data-plane processes and configs working while management returns unavailable; add this as a repeatable fault-injection suite.

## 14. Delivery, Backup, Update, and Removal

- [ ] 14.1 Define and implement the signed release manifest with binary/protocol/state ranges, OS/arch, pinned components/checksums/capabilities, apt compatibility, handshake-list version, and migration reversibility; verify signature, tamper, and unsupported-platform tests.
- [ ] 14.2 Build a reproducible self-contained bundle for both roles and role-scoped local installation; verify normal init/apply/repair never fetch bundled components from upstream and an scp-transferred bundle installs successfully.
- [ ] 14.3 Update the curl installer to verify signed metadata/checksums and install the standard binary/bundle layout; verify corrupt downloads leave the existing installation untouched.
- [ ] 14.4 Implement manual `update [version]` planning, latest-stable lookup only on request, gateway-first fleet compatibility, whole-bundle staging, state migration preview, component-by-component health, and expected interruption; verify no background/remote-node update occurs.
- [ ] 14.5 Implement previous-bundle/state snapshots and `update rollback`, including irreversible-migration separate confirmation; verify compatible rollback restores exact versions/state and impossible rollback is refused before update.
- [ ] 14.6 Ensure controller-only updates do not restart unchanged healthy data-plane units and changed units roll back independently; verify service restart counters and active forwarding during update tests.
- [ ] 14.7 Implement authenticated streaming gateway backup with hidden passphrase confirmation, selected KDF/AEAD, manifest/hashes, atomic `0600` output, default timestamp path, and no overwrite; verify wrong passphrase/corruption/partial-write behavior.
- [ ] 14.8 Implement a structural backup allowlist including gateway trust/client material and excluding node private keys/application data; verify archive-content tests and canary node-secret scans.
- [ ] 14.9 Implement clean-host and `--replace` non-merging restore with full prevalidation, explicit public IP, emergency snapshot, atomic convergence, and same-endpoint trust preservation; verify invalid archives make no mutation and same-IP nodes/clients reconnect.
- [ ] 14.10 Implement new-public-IP restore staleness and complete required actions for nodes, clients, webhook URLs/certificates, and external steps; verify no seamless-continuity claim and every affected resource is identified.
- [ ] 14.11 Implement recoverable `uninstall` with impact plan, gateway `--force`, node online revoke, node `--local-only`, DNS/network restoration, managed swap handling, state preservation, and binary-last removal; verify each role's online/offline cases.
- [ ] 14.12 Implement typed-confirmed `purge` with state/preset/secret/cert/export removal and separately confirmed `--include-backups`; verify portable archives remain by default and purge has no hidden recovery promise.

## 15. One-Time v1 Migration

- [ ] 15.1 Implement a read-only v1 installation inspector for cwd state, clients, keys, addresses, rulesets, generated artifacts, WireGuard, and known UFW rules; verify malformed/partial/unsupported installations yield a no-mutation report.
- [ ] 15.2 Implement deterministic conversion to a fully validated staged v2 gateway state with preserved client IDs or mapped identities, keys, `10.66.0.x` addresses, profiles, and selector presets where compatible; verify conversion golden fixtures.
- [ ] 15.3 Implement migration impact/compatibility reporting for values that cannot be preserved and required re-export; verify every dropped or transformed field is explicit before mutation.
- [ ] 15.4 Implement the standalone migration script orchestration with maintenance snapshot, signed v2 bundle verification, role setup, known-UFW translation, watchdog-protected network activation, client validation, and accepted downtime; verify repeated dry runs and interrupted phases are safe.
- [ ] 15.5 Implement a bounded migration rollback package and documented acceptance/removal step; verify injected failures before acceptance restore the v1 binary, state, WireGuard, and known UFW behavior.
- [ ] 15.6 Run migration E2E against representative v1 installations and all v1 client golden profiles; verify retained clients reconnect and v2 exports match expected semantics.

## 16. End-to-End, Security, Capacity, and Release Gate

- [ ] 16.1 Automate the one-gateway personal VPN happy paths for a selective Clash-compatible profile and full-tunnel WireGuard, including scp-only delivery; verify pinned Mihomo and WireGuard clients reach expected direct/proxied destinations, deferring actual iOS/Clash Mi execution to task 16.11.
- [ ] 16.2 Automate gateway init plus new-SSH watchdog confirmation, invite, node init, restricted join with Telegram preset, and first expose happy path; verify the accepted minimal commands work without hidden defaults.
- [ ] 16.3 Run equivalent standard-node and manual standard↔restricted test/switch/defer flows; verify no automatic fallback, one active steady-state transport, selected TCP/UDP fail-closed, and unrelated direct continuity.
- [ ] 16.4 Run multi-node, multi-client, multi-expose isolation and authorization tests; verify no lateral networking, credential reuse, mapping impersonation, or cross-resource removal.
- [ ] 16.5 Run credential lifecycle E2E for client rotation/revoke/delete and node rotation/revoke/delete/expired-certificate recovery; verify old generations fail and logical IDs/IPs/policies/exposes follow their contracts.
- [ ] 16.6 Run ingress/tunnel failure E2E for app down, tunnel reconnect, gateway controller down, proxy reload, partial response, node revoke, and expose removal; verify correct `404`/`413`/`503`/`504` or connection close with no request replay.
- [ ] 16.7 Run adversarial tests for invite/recovery replay, mTLS impersonation, stale generations, malicious tunnel mappings, symlink/permission attacks, secret redaction, firewall conflicts, IPv6/UDP/DNS leaks, and corrupt bundles/backups; verify all fail closed without foreign-resource damage.
- [ ] 16.8 Run update/rollback and backup/restore E2E for same and changed public IPs across supported protocol windows; verify data-plane compatibility, explicit interruptions, and complete required-action lists.
- [ ] 16.9 Run sustained minimum-gateway load for one Telegram node serving the defined several-hundred-user profile and five clients; verify controller idle RSS target, total memory/swap, CPU, disk, connection limits, latency, reconnect, and no OOM/deadlock.
- [ ] 16.10 Document installation, happy paths, policy/DNS classification boundary, restricted UDP limitations, webhook registration responsibility, status/doctor/logging, backup/update/removal, migration, and troubleshooting; verify every documented command is executed in docs tests and no backlog feature is advertised.
- [ ] 16.11 Re-run the requirement traceability audit, strict OpenSpec validation, full Go/unit/integration/E2E/security/resource/migration suites, and release artifact verification; against an actually deployed gateway and node, manually verify supported Clash Mi profile import, selected TCP, proxy-bound DNS, UoT, strict wrong-host rejection, no fail-direct behavior, and reconnect, then use the token-safe harness to register the IP-only five-year public certificate with Telegram, receive and validate a real webhook request, and remove only the test-created registration; verify every non-backlog requirement is green before labeling the release v2.0.
