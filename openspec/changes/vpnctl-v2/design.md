## Context

See [proposal.md](./proposal.md) for motivation and the capability specs for normative behavior. The current repository is a small Go CLI whose v1 state lives under the working directory and whose main data plane is WireGuard with generated Clash/Mihomo profiles. v2 keeps Go and reusable v1 renderers, but introduces system-owned state, two host roles, a long-running gateway controller, several independently supervised data-plane processes, cross-host operations, and security-sensitive lifecycle flows.

The target is intentionally constrained: Ubuntu 24.04 amd64, systemd, root, nftables, kernel WireGuard, `/dev/net/tun`, systemd-resolved, one dedicated gateway, and application-host private nodes. The minimum gateway has 1 vCPU, 512 MB RAM, and 10 GB disk, so process count, idle memory, reconnect behavior, and bounded proxying are architectural constraints rather than later optimization.

The v2 behavior is fixed. Blocking spikes selected Mihomo + Shadowsocks + ShadowTLS v3 for restricted transport/routing, nginx for public ingress, and frp for reverse tunneling as exact development providers. They remain replaceable internal adapters, but their fallbacks are inactive and never automatic. The versioned ADRs and `docs/v2/COMPONENT_LIMITS.v1.json` are the source of truth for dependent implementation; deployed Clash Mi, Telegram, and sustained target-capacity release gates remain in section 16.

## Goals / Non-Goals

**Goals:**

- Preserve one statically linked Go `vpnctl` entry point while separating CLI, controller, reconciliation, state, platform, and data-plane-provider boundaries.
- Make the gateway the authoritative writer without introducing a permanently running private-node management agent.
- Keep applied forwarding alive through controller restarts and make every mutation generation-guarded, idempotent, staged, and recoverable.
- Make leak prevention and SSH access recovery enforceable below the routing/controller processes that can fail.
- Use a normalized desired-state model that does not expose nginx, frp, or Mihomo syntax as public configuration.
- Prove the complete stack on the minimum VPS and actual Clash Mi before v2.0 release.

**Non-Goals:**

- A plugin SDK or user-selectable component matrix. Provider boundaries exist for maintainability and fallback, not as public configuration.
- Distributed consensus or strict two-host atomicity. The design uses a single authoritative writer and reconcilable sagas.
- Compatibility with arbitrary pre-existing gateway network stacks or user applications on the gateway.
- A long-running node control agent, remote laptop controller, public management API, or multi-tenant authorization model.
- Finalizing every low-frequency command spelling in code before a CLI-contract pass. Accepted happy paths and behavior remain fixed; the command-tree pass can shorten names without changing resource semantics.

## Decisions

### 1. Retain Go and split the repository by domain and execution boundary

The repository remains one Go module and produces one `vpnctl` binary. The same binary exposes CLI entry points and can run private internal service modes selected only by systemd unit arguments; those internal modes are not public API.

Proposed package boundaries:

```text
cmd/vpnctl                 public entry point
internal/cli               role-aware command registry, consent, human/JSON output
internal/model             versioned desired/applied domain objects and invariants
internal/store             atomic JSON state, secrets, snapshots, locks, migrations
internal/controller        gateway Unix-socket API, mutation serialization, reconcile
internal/control           HTTPS/mTLS RPC schemas, protocol negotiation, idempotency
internal/enrollment        invite, enroll, recovery and PKI workflows
internal/platform/linux    capability discovery, nftables, routes, DNS, systemd, swap
internal/render            deterministic derived configs and hash manifests
internal/transport         standard/restricted provider interfaces and health probes
internal/routing           presets, matcher IR, marks, fail-closed policy, split DNS
internal/ingress           expose model, TLS material, proxy provider and limits
internal/tunnel            tunnel provider, mapping authorization and allocation
internal/operations        plan/apply/repair sagas, watchdog transactions, diagnostics
internal/lifecycle         update, backup/restore, uninstall/purge
internal/output            redacted results, stable JSON envelopes and exit categories
```

Existing v1 WireGuard, Mihomo, state, and client code is migrated behind these boundaries rather than edited in place until it implicitly supports both models. Tests that encode v1 client behavior are retained as regression fixtures.

Alternative considered: separate `vpnctl-gateway` and `vpnctl-node` binaries. It reduces some conditional startup code but complicates one-bundle delivery and operator mental model without meaningful memory savings because only selected internal service modes run. One binary was explicitly chosen.

### 2. Use a gateway controller plus independent systemd data-plane units

Gateway CLI connects to `/run/vpnctl/control.sock`; node CLI makes a short-lived mTLS RPC over the active overlay path. Only the gateway controller writes authoritative state. Each mutation is serialized through one controller queue/lock and converted into a plan before execution.

Long-lived forwarding is owned by independent units with generated immutable-at-generation configs and `Restart=on-failure`. The exact unit set is provider-dependent, but the initial layout is:

```text
gateway:
  vpnctl-controller.service
  vpnctl-standard.service
  vpnctl-restricted.service
  vpnctl-dns.service
  vpnctl-tunnel-server.service
  nginx.service with vpnctl-owned config/override

node:
  vpnctl-routing.service
  vpnctl-standard.service
  vpnctl-tunnel-client.service
  systemd-resolved drop-in + vpnctl nftables/routes

transactional:
  vpnctl-watchdog@<transaction>.service + timer
```

The restricted node outbound and routing engine are expected to share a Mihomo process if the spike proves that arrangement safe and measurable. A controller restart reads state and observes units/config hashes; it does not restart healthy units or converge pending/drift automatically.

Alternative considered: embed reverse proxy, tunnel, DNS, routing, and transports in the controller. This reduces unit count but makes a management bug or upgrade a forwarding outage and prevents independent restart/rollback.

### 3. Separate desired state, applied observations, pending operations, and secrets

`/var/lib/vpnctl/state.json` contains a versioned envelope and normalized non-secret resources. The gateway model contains:

- host identity, role, explicit public IP, pools, interfaces, SSH source and installed component manifest;
- nodes, clients, immutable IDs, names, allocated IPs, lifecycle and credential generations;
- normalized effective presets, assignments, DNS inputs and active generation;
- active/standby transport intent, pinned handshake host, exposes and managed tunnel endpoints;
- public/control certificate metadata, pending operations, rollback snapshot metadata, logging opt-ins, backup metadata;
- per-node bounded idempotency records containing only non-sensitive result summaries.

Secrets are separate files below `/var/lib/vpnctl/secrets` and are referenced by opaque IDs. Node-local state holds role, immutable node ID, gateway endpoint/trust, last known gateway generation, pending request ID/result, local component/config hashes, original DNS state, and local secret references. Export artifacts and portable backups are not part of authoritative state and carry source-generation metadata.

Every state write follows decode → schema/invariant validation → write temporary sibling → fsync file → atomic rename → fsync directory. One prior generation and operation-scoped snapshots are retained with bounded cleanup. Config renderers are pure functions of normalized state plus secret references, and every generated artifact has a content hash used for drift detection.

Alternative considered: SQLite. It improves ad-hoc queries and transactional indexing but adds schema and backup complexity without benefit at the expected resource cardinality. Serialized JSON behind a sole writer is adequate for v2.

### 4. Model operations as generation-guarded commands and reconcilable sagas

The common mutation pipeline is:

```text
parse/authorize/consent
  → load generation and discover owned actual state
  → validate complete candidate + conflicts
  → render deterministic plan
  → persist request_id/pending operation
  → stage local and remote artifacts
  → activate in safe dependency order
  → health-check
  → commit authoritative generation
  → bounded drain/cleanup old generation
```

Local activation uses atomic file replacement, component-native validation, reload/restart only when its hash changed, and local rollback on a proven failure. Cross-host operations are sagas with per-step generation/phase records. The gateway publishes public ingress last; node rotation and transport switch keep old and new generations concurrently only during staging/drain.

If a response is lost, the node retains `request_id` until a definitive result. The gateway's idempotency entry returns the prior result. If the entry is too old, a resource-specific reconciliation compares desired generation and stable IDs instead of replaying the command. Stale expected generations return conflict and require the operator to review a fresh plan.

`--defer` writes candidate intent and pending metadata on the gateway; it is not an offline queue. `apply` only advances pending intent. `repair` constructs a separate explicit plan from desired-vs-owned actual drift. Unknown resources never enter automatic repair targets.

Alternative considered: two-phase commit across hosts. A node or network can disappear indefinitely after prepare, so it cannot guarantee atomicity and would add locks requiring manual recovery. Durable sagas match the actual failure model.

### 5. Implement lockout protection below controller lifetime

Lockout-risk plans first serialize the current vpnctl nftables table, owned routes, rules, and sysctls into a root-only transaction directory. The CLI then installs and starts a systemd watchdog service/timer whose rollback executable and input do not depend on the controller or initiating process.

The candidate nftables ruleset is loaded atomically. The transaction file records originating SSH connection identifiers and the post-change start time. `vpnctl confirm <id>` verifies it is called through an SSH connection established after activation and that its server port matches the allowed listener. Only then does it write a one-time commit marker and stop the timer. The timer restores only saved vpnctl-owned resources after 120 seconds or on explicit failed checks.

UFW/firewalld and incompatible external routing are preflight conflicts. The one-time v1 migration owns translation/removal of known v1 UFW rules; ordinary v2 apply never edits unknown UFW/firewalld state.

Alternative considered: rely on atomic nftables apply and the original SSH connection. Existing sessions can survive while all new SYN packets are blocked, so this cannot prove recoverability.

### 6. Use one matcher intermediate representation for node and client policy

Preset YAML is parsed into a versioned selector AST, validated as a complete set, normalized into order-independent include/exclude sets, and compiled into an implementation-neutral matcher IR. v2 starts with the matcher subset needed by v1 Clash exports, especially domain suffix and supported IP/CIDR selectors. The IR has no action primitive: a match always means `gateway-or-block`, while no match means direct.

The same IR feeds:

- node Mihomo routing/TUN configuration;
- nftables fail-closed sets/marks and IPv6 leak guard;
- shared gateway DNS selection metadata;
- generated Clash/Mihomo rules and split-DNS sections.

Preset source and normalized effective generation are separate. Manual edits become pending only through validate/apply. Built-in template updates use a three-way merge of embedded base, current user source, and new embedded template; unsafe merge returns conflict.

Alternative considered: raw Mihomo configuration. It exposes implementation actions capable of bypassing fail-closed guarantees and makes equivalent Linux/client compilation impossible to validate.

### 7. Build fail-closed routing from nftables marks, policy routes, TUN readiness, and a recovery allowlist

The node owns one `inet vpnctl` table and dedicated routing tables/fwmarks. The accepted internal allocation reserves only the high byte `0xff000000`: direct `0x01000000`, selected `0x02000000`, vpnctl recovery/active-outbound `0x03000000`, and ingress-response `0x04000000`; the lower 24 bits are retained in the conntrack mark. Only these exact high-byte values are restored. Route-output and prerouting hooks run at mangle priority `-150`, after conntrack association at `-200`, so local mark changes can trigger a route lookup and ingress replies can recover their gateway decision before strict reverse-path validation.

RPDB priorities `10000`, `10010`, and `10020` route recovery, ingress responses, and selected application traffic respectively. Internal tables `20001` and `20002` are the selected/TUN and gateway tables. The selected table always has an unreachable default at metric `42760`; readiness adds the managed TUN default at metric `10` before atomically switching the nftables readiness chain to ready, and switches the chain back before removing that route. These numbers are internal conflict-checked defaults, not public API.

The guard chain exists before routing-engine startup. While not ready, it permits established flows with retained direct classification and a minimal resolved gateway recovery allowlist, then drops new application egress. Once ready, selected flows are marked for the TUN/active transport; selected-path failure drops rather than reclassifies them. IPv6 is either equivalently classified and carried or rejected for selected destinations; v2 does not enable an unmanaged direct fallback.

The routing spike fixed the hook/mark allocation above and demonstrated injected rollback, boot, crash, restart, uninstall, lower-mark/foreign-table coexistence, and ingress-response symmetry. The guard is an independent systemd unit that exists before the routing engine; activation loads policy rules before nftables classification, ready transition installs the TUN route before switching the nftables chain, and teardown reverses those safety boundaries. Interaction tests with systemd-resolved remain part of the DNS-mode spike. These values remain internal and can change without changing the selector or fail-closed specs.

Alternative considered: rely solely on Mihomo TUN auto-route. If Mihomo crashes during boot or reload, kernel routing can send traffic direct before userspace restores policy.

### 8. Use Mihomo as the initial routing/restricted provider, gated by development and deployed-service tests

The initial provider uses Mihomo for node TUN classification and DNS, a native Shadowsocks listener plus ShadowTLS v3 strict wrapping on the gateway, and a Shadowsocks outbound with ShadowTLS on nodes/Clash clients. Selected UDP in restricted mode uses Mihomo UDP-over-TCP inside Shadowsocks/ShadowTLS; there is no listener on `8443/UDP`.

The provider exposes `Prepare`, `Validate`, `StartTest`, `Activate`, `Drain`, `Rollback`, and health/probe methods. Standard mode uses WireGuard and presents the same internal gateway destinations to control and tunnel clients. Both provider configs exist, but a node activation record selects one. Test creates isolated transient routes/connections and cannot mutate the production mark or tunnel generation.

The release manifest pins component versions, capabilities, and config schema. Before dependent implementation uses each candidate capability, reproducible gateway/Linux-node development spikes must prove:

- selected TCP and proxy-bound DNS end-to-end plus validation of the rendered Clash-compatible profile with the pinned Mihomo version;
- UoT end-to-end and fail-closed behavior with `8443/UDP` closed;
- ShadowTLS v3 strict behavior and handshake-host validation;
- memory/CPU/reconnect under the minimum host.

Passing the automated development gates qualifies the candidate for continued implementation, but does not make it production-ready. Before v2.0 release, the complete stack must be tested against an actually deployed gateway and node with a supported Clash Mi client for profile import, selected TCP, proxy-bound DNS, UoT, fail-closed behavior, and reconnect. If the candidate fails either gate, the transport interface and product behavior stay; another DPI-resistant provider must pass the same suite. There is no product-facing Shadowsocks or ShadowTLS configuration surface.

The task 2.4 benchmark accepts restricted UoT only as best-effort functional UDP on a healthy path. Its regression floor is one UoT association completing bounded request/response probes at 64 bytes/50 packets per second, 256 bytes/20 packets per second, and 1200 bytes/20 packets per second. These are compatibility points, not SLOs. Restricted has no latency, throughput, concurrency, or availability guarantee for voice/video, gaming, QUIC/HTTP3, bulk/high-rate UDP, adverse paths, or payloads above 1200 bytes; standard WireGuard remains the explicit manual alternative.

### 9. Treat the handshake host as pinned versioned desired state

The signed bundle carries an ordered list with stable candidate IDs and hostnames. Init probes TLS 1.3, certificate validity, reachability, and bounded latency and persists the first success. Runtime health never mutates the selection.

Replacement is a saga with `prepare` and `commit`: validate candidate, render impacted node/client generations, show impact, stage reachable nodes, then explicitly commit the single gateway host. Old configs are flagged stale; one rollback snapshot is retained. If the old path cannot carry control, the node-local SSH recovery command validates a manually provided candidate against gateway authoritative pending state before replacing only local transport configuration.

Alternative considered: automatic multi-host SNI fallback. It hides transport changes, complicates ShadowTLS demultiplexing, and conflicts with the manual-only transport contract.

### 10. Authenticate enrollment with a stable gateway identity separate from ingress TLS

Gateway init creates three independent trust domains:

1. public ingress RSA certificate/key for ordinary IP HTTPS;
2. internal control CA and leaf certificates for overlay mTLS;
3. stable enrollment signing key used to authenticate bootstrap/recovery responses.

The opaque invite is a compact versioned, base64url-encoded envelope containing public metadata plus a 256-bit random secret. It is transferred through trusted SSH and therefore does not need to hide its public fields, but it is never accepted via argv. The node connects to the reserved HTTPS endpoint and verifies the response signature against the enrollment-key fingerprint carried by the invite. HTTPS still protects passive observation using the current ingress certificate; the signed transcript prevents a substituted public certificate or proxy from impersonating the gateway. The transcript binds invite ID, endpoint, node ID, CSR hashes, requested transport/presets, expiry, and nonces.

Task 2.10 fixes the signed transcript as `vpnctl-enrollment-transcript-v1`: domain-separated, ordered length-prefixed field-name/value frames signed directly with Ed25519. It includes purpose (`enroll` or `recover`), invite ID, exact endpoint, immutable node ID, issued/expiry timestamps, independent 128-bit node and gateway nonces, requested transport, lexically normalized unique presets, sorted named SHA-256 public-key/CSR hashes, and the normalized assignment SHA-256. The JSON signature envelope carries algorithm, `sha256:<hex DER-SPKI>` enrollment-key fingerprint, and base64url-without-padding transcript/signature. Verifiers reconstruct and byte-compare the expected transcript, allow at most 120 seconds clock skew, reject expiry/context/fingerprint/signature mismatch, and atomically consume the verified transcript/signature replay key with the one-time invite. Invite secrets remain independent random 256-bit values.

After successful compare-and-consume of the invite-secret hash, the gateway returns the control CA chain, client certificate, gateway overlay address, both transport public configurations, tunnel credential material intended for the node, and signed normalized assignment. The node writes all secret material atomically before acknowledging commit. Recovery uses a distinct token purpose and binds an existing active node ID and current generation.

Alternative considered: pin the public ingress certificate fingerprint. That would couple node trust bootstrap to a certificate that must rotate independently for external webhook registrations. Alternative considered: expose the internal control CA leaf directly on public 443. It mixes trust roles and complicates a future domain/ACME frontend.

### 11. Use Ed25519 for internal identity and RSA only for public ingress compatibility

The control CA, gateway control leaf, node control keys, and enrollment signing key use Ed25519. Certificate serials are random 128-bit values; URI SANs use a versioned namespace such as `urn:vpnctl:node:<uuid>`. Public ingress remains RSA-2048/SHA-256 with IP SAN and CN for provider compatibility. Tunnel and restricted symmetric credentials use 256 bits from the kernel CSPRNG. Private-key writes use `openat`-style no-follow semantics, mode `0600`, and atomic replacement in a mode-`0700` directory.

The accepted certificate profile encodes private keys as PKCS#8 PEM and certificates/CSRs as PEM X.509/PKCS#10. Node CSRs must be signed by an Ed25519 key and request exactly one canonical `urn:vpnctl:node:<uuid>` URI SAN; the gateway rejects a mismatch and constructs the issued SAN from authoritative identity rather than trusting CN. Gateway server leaves carry the canonical `urn:vpnctl:gateway:<uuid>` URI plus the current internal-overlay IP SAN. Positive serials contain at most 128 random bits. OpenSSL 3.0.13 accepted Go-generated chains/CSRs/leaves and Ed25519 signatures in both directions.

CA and leaf validity, renewal windows, authoritative generation checks, and manual CA overlap follow the specs. Revocation is enforced from state on every new control/tunnel login rather than relying on CRLs.

Alternative considered: RSA for all PKI. It is more widely compatible but consumes more storage/CPU and is unnecessary for vpnctl-to-vpnctl TLS on the fixed platform. The public edge keeps RSA where external compatibility matters.

### 12. Version the control RPC as a small explicit operation registry

The controller exposes HTTPS/1.1 endpoints under an internal version prefix, for example `/rpc/v1/<operation>`, with one bounded JSON request and response per command. A common envelope includes protocol major/minor, request ID, expected state generation, node ID, credential generation, timestamp/nonce, operation discriminator, and typed payload. Responses include result category, authoritative generation, resource IDs, warnings, required actions, and a redacted result hash.

Task 2.10 selects TLS 1.3 only with mandatory CA validation plus exactly one canonical node URI SAN, ALPN HTTP/1.1 only, a 64 KiB request body, 256 KiB response, 8 KiB request headers, JSON nesting depth 32, two-second header timeout, five-second body/write/idle timeouts, and 16 simultaneously accepted connections. The listener binds only the configured internal-overlay address. It rejects non-POST/wrong paths or media types, unknown or duplicate fields, trailing JSON, over-limit bodies/responses, inactive node records, certificate/envelope identity mismatch, stale credential generation, and stale expected state generation before dispatch. Responses are encoded and size-checked before the first byte is written. The minimum-host spike exercised malformed and slow inputs, TLS 1.2/no-client-certificate rejection, the 17th connection, and all timeouts with a 14 MiB peak test-process RSS and zero swap.

The server negotiates only compiled supported majors and rejects unknown fields where security-sensitive semantics could be ambiguous; additive minor response fields are ignored safely by older clients. Read operations do not create idempotency records. Mutation records are pruned per node by both age and count.

Alternative considered: gRPC. The operations are rare, short-lived, and non-streaming, so HTTP/JSON is easier to inspect, fixture-test, and keep within a small static binary. Alternative considered: a custom encrypted binary protocol. mTLS already supplies a reviewed secure channel.

### 13. Use nginx as the first replaceable ingress provider

The normalized ingress model stores certificate identity, exact/prefix route, expose ID, internal endpoint, method-neutral proxy settings, body limit, upstream timeout, lifecycle, and generation. It contains no nginx directives.

The nginx provider renders one complete owned configuration tree, clears untrusted forwarding headers, sets trusted connection metadata, enables TLS 1.2/1.3 and ALPN HTTP/1.1+HTTP/2, disables disk request buffering, bounds connection/request/header/body/timeouts, maps reserved internal routes before user routes, and points each expose at a loopback-only tunnel endpoint. Activation runs nginx config validation, atomically swaps the generated tree, and requests graceful reload. A failed reload restores the prior tree.

nginx is installed from Ubuntu 24.04 apt and vpnctl owns its generated config and service override because the gateway is dedicated. A mandatory prototype verifies Telegram IP-only self-signed RSA behavior, certificate lifetime, streaming without body temp files, concurrency/body limits, and `404`/`413`/`503`/`504` outcomes at minimum resources. If it fails, a Caddy provider may replace it while preserving the normalized model and tests.

The task 2.5 development candidate pins Ubuntu `nginx 1.24.0-2ubuntu7.17` and its package checksum. RSA-2048/SHA-256 with an IPv4 SAN/CN and 1825-day lifetime passed local TLS 1.2/1.3 plus HTTP/1.1/2 proxying on the minimum fixtures, public-certificate-only export, and the token-safe provider harness contract. This qualifies nginx for continued implementation. The actual Telegram `setWebhook` certificate upload, incoming request, and five-year provider acceptance are deliberately deferred to task 16.11 against an actually deployed gateway and node; until that release gate passes, nginx is not described as production-ready.

The task 2.6 minimum-host stress gate selects 256 nginx worker connections, a hard 64 concurrent ingress requests and 64 HTTP/2 streams per gateway, and a default 40 concurrent requests per expose. The body model uses an 8 MiB gateway maximum with a 1 MiB expose default; upstream timeout uses a 15-second default with a 60-second maximum; graceful worker shutdown is bounded at 10 seconds; large request headers are bounded to four 8 KiB buffers. Every generated proxy location must compile both gateway and expose connection limits because nginx stops inheriting the parent limit when a child declares its own. Requests above concurrency limits return `503` without queueing. The gate observed a 3 MiB streaming upload reaching its upstream before completion with no body temp file, exact `404`/`413`/`503`/`504`, graceful generation handoff, about 6 MiB ingress cgroup peak, zero OOM events, and safe guest headroom. nginx therefore remains the selected development provider and the Caddy fallback is not activated.

Alternative considered: an in-process Go reverse proxy. It removes nginx but increases controller/data-plane coupling and requires vpnctl to own HTTP/2 limits, graceful reload, and edge hardening. Alternative considered: Caddy first. Its ACME strengths are outside IP-only v2 and its minimum-host resource profile is less predictable until measured.

### 14. Use frp as the first replaceable multiplexed tunnel provider

The initial tunnel provider pins frp and configures one shared internal-only `frps`, one `frpc` per node, `tcpMux` enabled, connection pooling disabled, dashboards and unused/public proxy types disabled. Each expose gets a stable loopback port from the persisted internal TCP `20000-29999` allocator; disabled exposes retain their assignment until removal. Restore preserves free saved ports and builds a complete deterministic remap plan for unavailable or legacy out-of-range ports before any tunnel or ingress generation is published.

The independently supervised gateway tunnel unit serves local-only frp `Login`, `NewProxy`, and `Ping` authorization hooks alongside its `frps` child. It starts `frps` only after the authorizer listener is ready and restarts the pair if either side fails. `Login` validates immutable node ID, current tunnel token hash/generation, and active lifecycle. `NewProxy` additionally validates the deterministic proxy name, TCP type, and exact loopback port against authoritative expose state; `Ping` revalidates current identity so revoke closes established sessions. The separate controller remains management-only, so controller outage does not remove authorization from a healthy applied reverse tunnel. `frpc` configuration uses atomic render and loopback-only dynamic reload. The tunnel has TLS server verification in addition to its active outer transport.

A mandatory prototype measures true one-connection multiplexing, dynamic add/remove, reconnect backoff, plugin behavior, immediate revoke, mapping generation validation, transport switch, and minimum-host memory. If frp fails, OpenSSH reverse forwarding is the fallback adapter, accepting more orchestration work; rathole is rejected because its current connection model does not meet required multiplexing.

Task 2.7 pins official Linux/amd64 frp `v0.69.0` at archive SHA-256 `6b90d1cd28fc661f170c0de90dde03d2c63e4fd7ce0ae2da2ca1c28014b8146e`. That release normalizes a declared client `poolCount = 0` to Login `pool_count = 1`. The version-locked local Login adapter therefore accepts exactly that input after validating node identity/generation/token, returns otherwise unchanged Login content with `pool_count = 0`, and rejects every other pool input. frps consumes the rewritten zero before it creates the control session, so no work connection is preloaded. This provider quirk is hidden behind the tunnel adapter; upgrading frp requires re-running the contract before activation.

The minimum-host gate passed with two exposes and 12 concurrent streams per expose over one persistent TLS/tcpMux connection. Mapping add/remove kept the frpc PID and control connection; an unavailable authoritative state rejected re-announced mappings as `controller_error`; reconnect after frps restart completed in 7 seconds; and revoke closed the session in 2 seconds and rejected retries. Standard transport used direct internal `17000/TCP`; after an explicit restricted switch, steady-state capture saw one frpc-to-Mihomo connection, zero direct `17000` packets, and ShadowTLS outer `8443/TCP`, without changing logical node/mapping identity. Gateway and node retained 277324/287932 KiB `MemAvailable` with zero unit OOM events. frp remains the selected development provider; OpenSSH stays an inactive manual fallback.

Alternative considered: one reverse SSH process per expose. It is operationally familiar but violates the bounded process/connection model and makes authorization/config updates more expensive.

### 15. Integrate split DNS through a shared gateway resolver and node-local managed resolver

The node routing provider runs one local resolver endpoint and installs a systemd-resolved drop-in pointing host DNS at it. Original link/global DNS state is captured before activation. Ordinary port-53 traffic is redirected within vpnctl-owned rules so applications that bypass resolved but use classic DNS follow the same classification boundary.

The local resolver evaluates normalized selector domains. In `policy` mode, selected queries use an internal gateway resolver reachable only through the active transport; other queries use saved/direct IPv4 upstreams. In compatibility `direct` mode all client lookup behavior follows the v1-compatible direct model. The gateway resolver is shared and forwards to authoritative gateway upstreams, initially `1.1.1.1` and `8.8.8.8`.

Task 2.9 selects Mihomo `policy-redir-host` as the internal policy-mode renderer and `direct-redir-host` for v1 compatibility. The pinned `v1.19.30` gate proved selected/direct query separation through direct Mihomo queries, the systemd stub, libc/NSS, and `resolvectl`; classic UDP/TCP port 53 capture; gateway-DNS failure without direct fallback; direct-query continuity; recovery; and exact restoration. A fake-IP whitelist correctly synthesized addresses only for selected domains, but was rejected because a fresh selected DNS request can receive that local synthetic answer without traversing the gateway DNS path.

The node keeps `/etc/resolv.conf` on the systemd-resolved stub, points a global `~.` route at the local Mihomo listener, disables the second resolved cache, and temporarily replaces any competing link `~.` route only after snapshotting DNS/domain/default-route state. The production routing process is deliberately host-wide and has no dedicated UID scope. Instead, its non-selectable direct-DNS outbound carries the direct socket mark, while gateway DNS carries the active outbound's recovery mark; only those two marks bypass the owned classic-port-53 redirect and avoid resolver recursion. Mihomo's pinned cache uses stale-while-revalidate: after authoritative TTL expiry, a previously gateway-validated answer may be returned with TTL `1` while refresh remains on the gateway path; an unseen selected name blocks when gateway DNS is unavailable, and selected refreshes never fall back to direct. The cache is capacity-bounded to the pinned provider default of 4096 entries, not time-bounded during an outage. Policy/mode changes restart the resolver and therefore clear this internal cache. A fake-IP range, if a future renderer needs one, must be conflict-checked rather than hard-coded because the standard `198.18.0.0/16` overlapped an observed Lima underlay resolver. Actual Clash Mi DNS behavior remains deferred to task 16.11 against the deployed service.

Alternative considered: one DNS daemon per node on the gateway. Node count is small but separate processes add memory and lifecycle cost without an isolation requirement that cannot be enforced logically.

### 16. Compile ingress and tunnel changes from a single expose resource

An expose has one immutable ID, owner node ID, optional unique name, normalized upstream, route mode/path, safe limit overrides, tunnel endpoint allocation, desired generation, and readiness. Its transaction ordering is:

```text
validate path/upstream/limits
  → allocate/stage loopback endpoint
  → authorize and activate tunnel mapping
  → verify tunnel and local upstream
  → render/validate/reload ingress route last
```

Creation can commit as `degraded` if the application is down, but the route always targets the correct unavailable mapping and returns `503`; it never points elsewhere. Removal reverses ordering: unpublish, bounded drain, remove mapping, release port. Node revoke first unpublishes all routes, invalidates tunnel/control/transport generations, and then closes connections.

### 17. Keep observability explicit, time-bounded, and redacted at the source

All components start with expanded vpnctl logging disabled. The controller persists opt-in sessions as scope, level, destinations, and absolute expiry, then renders component-specific logging configuration and timers. Journald is the default temporary destination; optional files use bounded rotation.

Redaction occurs before formatter/destination: secrets, tokens, private keys, Authorization/Cookie/provider secret headers, request/response bodies, full expose paths, and raw RPC payloads never enter a log record. Idempotency and audit summaries use stable resource IDs, operation types, generations, status, and hashes. `status` only reads cached/process metadata; `doctor` is the sole general probe runner and tags all synthetic traffic.

Alternative considered: error logging always enabled. The agreed product contract is no vpnctl expanded logging by default, so even error detail requires a bounded opt-in; service health and last exit codes remain available as passive state rather than content logs.

### 18. Deliver releases and rollback as a manifest-governed unit

The release manifest includes vpnctl version, supported control versions, state-schema range, target OS/arch, each bundled component version/hash/capabilities, compatible apt package ranges, handshake-host list version, and whether migrations are backward reversible. The self-contained bundle uses fixed versioned binary framing with no owner, timestamp, mode, or filesystem-order metadata: signed envelope followed by exact path/size/artifact records in signed order and exact EOF. The installer and updater verify the trusted signature, target platform, framing, every artifact size/hash, and provider archive structure before mutation.

Local installation consumes only an explicit regular non-symlink bundle path. It stages all signed artifacts before selecting a role, installs vpnctl and Mihomo for both roles, `frps` only for the gateway, and `frpc` only for the node. Existing byte-identical mode-`0755` targets are idempotent; any other target is a conflict, absent files are installed without replacement, and a partial invocation removes only paths it created. The installer reports the signed role-specific apt requirements but does not invoke apt or fetch upstream components. Therefore an `scp`-transferred bundle is self-contained for vpnctl-managed binaries, while Ubuntu repository access may still be required for OS packages.

The role-neutral bootstrap publishes a standalone binary plus the complete retained bundle. Its canonical checksum metadata binds the requested release version and exact size/SHA-256 of both files, and a detached Ed25519 signature covers a domain-separated exact encoding. The curl script embeds the same trust anchor as release manifests and the handshake-host list, downloads over HTTPS/TLS 1.2+, verifies everything in a private temporary directory, stages on the destination filesystem, and publishes the binary last. It also accepts an explicit local asset directory for `scp` delivery. The standard retained paths are `/usr/local/bin/vpnctl` and root-only `/usr/local/lib/vpnctl/release/{vpnctl.bundle,checksums.txt,checksums.txt.sig}`. Init inspects the complete bundle read-only during plan, repeats verification and installs role-scoped binaries during apply, and persists only its signed component manifest; a plan/apply release mismatch fails before role layout mutation.

Update downloads or consumes the full target bundle, validates fleet protocol window gateway-first, stages binaries in versioned directories, snapshots state, and atomically changes a `current` link/metadata only after preflight. Component config migrations are rendered before service changes. Rollback returns to the saved version only when the manifest marks all applied state migrations reversible.

The gateway portable backup is separate from update snapshots. The accepted `vpnctl-backup-v1` envelope starts with fixed magic and a 64-byte binary header carrying the format/KDF/AEAD identifiers and parameters. It uses Argon2id v19 with a random 16-byte salt, a 32-byte derived key, `m=65536 KiB`, `t=3`, and `p=4`, followed by XChaCha20-Poly1305 records over 1 MiB plaintext chunks. Each archive gets a random 16-byte nonce prefix and uses the big-endian 64-bit record index as the rest of the 24-byte nonce. The header hash plus the 17-byte index/final/length record header is domain-separated associated data. A zero-length authenticated final record is mandatory, records are strictly ordered, and bytes after the final record are rejected, covering header/ciphertext changes, reordering, truncation, and append attacks.

Restore parses and bounds the fixed header before running the KDF: accepted v1 resource ranges are 64-128 MiB memory, 3-6 passes, 1-4 lanes, and 64 KiB-4 MiB chunks. It streams decrypted bytes only to a mode-`0600` temporary file; wrong passphrases or any framing/authentication failure remove that file. The decrypted manifest and every entry hash are then fully authenticated/schema-validated before an atomic destination rename or any host mutation. Existing archive targets are never silently overwritten, caller-owned passphrase buffers and derived keys are wiped best-effort, and node private keys are structurally absent. Status warns when no successful portable backup exists or the latest one is at least 30 days old; this warning does not schedule, upload, rotate, or delete archives and does not change a healthy exit category.

On the 1-vCPU/512-MiB amd64 fixture, the selected KDF measured `1117.839 ms` median and `70784 KiB` peak process RSS. The full multi-failure correctness process peaked at `178528 KiB`; hard acceptance bounds are 2 seconds/128 MiB for one selected KDF operation and 256 MiB for the short-lived backup/restore CLI process. XChaCha20-Poly1305 with 1 MiB records measured approximately 68.7 MiB/s for combined seal/open traffic; the 17 MiB streaming archive completed encryption/decryption including KDF in approximately 2.38/2.88 seconds. AES-256-GCM was faster on this AES-capable fixture, but XChaCha was selected for its portable software performance and simple 128-bit-random-prefix plus counter nonce construction. The RFC 9106 64-MiB Argon2id profile was preferred to the weaker 32-MiB candidate and the higher-cost 96-MiB/custom-pass variants.

Alternative considered: download data-plane binaries independently during apply. This makes a desired generation non-reproducible and breaks offline transfer and rollback guarantees.

### 19. Treat CLI grammar and JSON schemas as generated contracts

The CLI layer uses one role-aware command registry containing availability, consent class, dry-run/defer support, arguments, result type, and exit mapping. Accepted high-frequency commands and happy paths from the specs are retained. Before feature implementation expands the surface, a dedicated CLI-contract task reviews the full tree to remove redundant role/target arguments and freezes:

- command and option names for v2.0;
- exact numeric exit codes behind the stable categories;
- per-result JSON Schema documents and `schema_version` policy;
- stdin/TTY behavior for secret and typed prompts;
- a machine-readable redaction classification for every output field.

Golden tests cover human output shape, one-document JSON stdout, stderr separation, no-secret output, role errors, consent, and idempotent aliases if any. This pass can shorten command spelling but cannot change capability behavior, accepted minimal happy paths, or security confirmation rules.

Alternative considered: let each command define output and consent ad hoc. That produces incompatible automation and is especially dangerous around hidden tokens and destructive operations.

## Risks / Trade-offs

- **[512 MB gateway may not sustain all candidate daemons]** → Run spikes before provider integration, enforce shared daemons and hard concurrency limits, measure idle and representative load, offer managed swap, and keep nginx/frp fallback adapters.
- **[UDP-over-TCP performs poorly for latency-sensitive traffic]** → Guarantee functional selected UDP and leak prevention, publish no gaming/voice performance promise, benchmark head-of-line effects, and keep standard WireGuard as the manually selected alternative.
- **[DPI-resistant candidate changes upstream syntax or behavior]** → Pin binaries/config schemas in the signed manifest, test the exact release bundle, expose only a transport behavior abstraction, and require an explicit upgrade plan.
- **[Handshake hosts are external dependencies]** → Ship a versioned ordered list, validate and pin one, report degradation, and require a staged manual replacement with SSH recovery; do not conceal changes through auto-fallback.
- **[Kernel hook ordering can leak or break unrelated node traffic]** → Make nftables/routing priority selection a blocking spike, own a single table and mark namespace, test boot/crash/uninstall and foreign-state conflicts, and fail preflight when safe coexistence cannot be proven.
- **[Control CA compromise has fleet-wide impact]** → Store root-only, exclude plaintext export, include only encrypted backups, validate active identity generations per request, support staged CA rotation, and keep public ingress identity separate.
- **[Enrollment on public 443 is exposed to scanning and replay]** → Use high-entropy single-use short-lived tokens, hashed server storage, rate/size/time bounds, signed transcripts, atomic consume, reserved paths, and no general public management endpoint.
- **[Cross-host failure leaves mixed generations]** → Persist operation phases on both sides, use stable IDs and expected generations, activate public routing last, preserve old generation until confirm, and reconcile instead of blind rollback/retry.
- **[Node without a resident control agent cannot be remotely converged]** → Keep commands node-local by product contract, make gateway state authoritative, expose pending/required actions clearly, and allow already applied data plane to survive.
- **[Self-signed IP certificate expires or is rejected by a provider]** → Gate the five-year RSA profile with live Telegram tests, warn 180 days ahead, keep rotation manual, and produce explicit re-registration actions.
- **[nginx may buffer request bodies to disk under some settings]** → Assert generated directives and verify with filesystem-observed E2E tests before acceptance; switch provider if the contract cannot be met.
- **[frp plugin failure can weaken per-node isolation]** → Keep frps internal-only, deny by default on plugin timeout/error, validate every login/mapping against generation, disable shared-token-only auth, and test malicious announcements.
- **[No default logs makes incident diagnosis harder]** → Preserve passive health/exit metadata, provide bounded doctor probes, and make scoped logging easy to enable while enforcing source redaction and automatic expiry.
- **[Manual public IP and manual external actions add operator work]** → Keep them explicit because automatic discovery and third-party credential storage would weaken correctness/ownership; return complete copy-ready commands and `requires_action` lists.
- **[Large v2 scope increases integration risk]** → Sequence implementation by risk gates and vertical slices, but retain a single release gate requiring every non-backlog capability and migration test.

## Migration Plan

1. Freeze v1 regression fixtures for client keys, addresses, WireGuard full-tunnel export, Clash selective export, rulesets, installer artifacts, and current UFW behavior.
2. Complete the restricted, nginx, frp, nftables/routing, DNS-mode, control-crypto, and minimum-host development spikes. Record chosen versions, limits, mark layout, cryptographic/KDF parameters, development-candidate acceptance evidence, and every deferred deployed-service release gate before dependent production code.
3. Introduce the v2 model/store/controller and system-owned layout behind new `init` flows without mutating v1 installations. Implement atomic state migrations and render/apply harnesses.
4. Deliver a gateway-only internal vertical foundation: preflight, watchdog-confirmed firewall, control PKI, both transport listeners, DNS, component supervision, status/doctor, and rollback.
5. Add personal-client v1 behavior through the v2 model and prove exports against golden fixtures before removing reliance on cwd state.
6. Add invite/join and one private node with standard transport, then restricted transport/UoT and fail-closed routing/DNS. Exercise lost-response, controller-down, transport-down, routing-crash, and credential-rotation cases.
7. Add authenticated multiplexed reverse tunnel and one expose, then managed HTTPS ingress/certificate/limits and multi-node/multi-expose isolation.
8. Add pending/apply/repair, logging, backup/restore, update/rollback, uninstall/purge, and all destructive/required-action flows.
9. Run the separate one-time migration tool in a maintenance window. It snapshots v1 state, validates conversion, installs v2 gateway resources with watchdog protection, preserves client identities/addresses/keys, replaces known v1 UFW ownership, verifies clients, and retains a rollback package until operator acceptance. Downtime is permitted.
10. Run the complete E2E, adversarial security, fault-injection, migration, and minimum-capacity suites. Release v2.0 only after every non-backlog spec passes.

Rollback during development and update uses the prior bundle, state snapshot, and generated configs when the manifest declares migration reversibility. The migration tool provides a separate documented v1 rollback until the operator accepts v2 and removes the migration snapshot. Purge is intentionally not rollbackable; portable encrypted backups are the recovery boundary.

## Resolved Spike Parameters and Remaining Release Gates

Task 2.12 closes the blocking-spike design parameters in three accepted ADRs and `docs/v2/COMPONENT_LIMITS.v1.json`. The consolidated manifest pins the exact component artifacts/checksums, provider/fallback status, routing/DNS internals, ingress/tunnel/control/backup limits, 30-day backup warning, numeric CLI exits, and command-tree contract. It contains no unresolved implementation parameter for dependent tasks.

Development acceptance is not release acceptance. Task 16.9 still owns sustained several-hundred-user plus five-client capacity on the minimum gateway. Task 16.11 still owns actual supported Clash Mi behavior and real Telegram IP-only certificate/webhook registration against a deployed gateway/node. These gates may reject a provider or release candidate, but they do not authorize automatic fallback or silent changes to product behavior.
