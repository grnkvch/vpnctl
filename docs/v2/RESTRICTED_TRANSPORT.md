# Restricted transport

Tasks 8.3-8.10 implement the restricted-provider foundation, mandatory
UDP-over-TCP readiness, pinned handshake-host selection and replacement,
independent gateway listener supervision, explicit testing/switching, and
node-local SSH recovery. It remains a development-gated path: testing against
a deployed gateway/node plus real Clash Mi belongs to release gate 16.11.

## Pinned provider contract

- Provider: Mihomo `v1.19.30`, Linux amd64 archive `mihomo-linux-amd64-v1.19.30.gz`.
- Archive SHA-256: `cf06ce2c7d1421bdbda14ee4a5b6046672dc35ebf8eecd8e77504ec3c0ed9a84`.
- Inner proxy: Shadowsocks `2022-blake3-aes-256-gcm`.
- DPI-resistant layer: embedded ShadowTLS v3 with strict mode on the node.
- Gateway socket: `8443/TCP` on the wildcard address. No `8443/UDP` listener is allowed.
- Provider output uses `silent` logging; transport process stdout and stderr are discarded unless a later explicit, temporary logging workflow enables them.

The gateway public IP remains an operator-supplied value. The handshake
hostname is selected from the signed list described below; every restricted
identity must agree with that authoritative state. Replacement is always a
manual staged operation.

## Signed handshake-host selection

The development release embeds list version 1 with the stable ordered
candidates `microsoft`/`www.microsoft.com`, `apple`/`www.apple.com`, and
`cloudflare`/`www.cloudflare.com`. The exact canonical JSON payload is wrapped
in a domain-separated Ed25519 signature envelope. Verification pins key ID
`sha256:9e061dd425ff7766f826911dec3502d6b8f1494705432da049ffed3c0fbe20bc`,
rejects duplicate or unknown JSON fields, rejects non-canonical base64url or
payload JSON, and requires the list version to match the installed component
manifest. Task 14 moves these same verified artifacts into the self-contained
release archive; it does not weaken this verification boundary.

Fresh gateway init verifies the bundle before host mutation and probes
candidates strictly in declared order. Each probe performs a bounded TCP/TLS
handshake with normal certificate verification, requires TLS 1.3, and must
complete within three seconds. Init persists the first passing candidate as
`{list_version, candidate_id, hostname, selected_at}` in authoritative state.
If none passes, init stops before allocating the host identity or modifying the
machine. A faster later candidate cannot displace an earlier passing one.

The persisted record is the only source used by restricted gateway rendering,
node delivery, and the client-export delivery boundary. Restricted transport
records must carry the same hostname. Repeating init does not load or probe the
candidate list again. Node enrollment will use this versioned delivery record
in task 9.4; restricted Clash exports consume it now.

Runtime observation is deliberately passive. Given an observation of the exact
pinned candidate, health reports `handshake-host-healthy` or
`handshake-host-degraded` plus a required manual action. It cannot inspect the
candidate bundle, probe another hostname, alter state, activate standby, or
rotate or fail over.

## Manual replacement and SSH recovery

`transport host prepare <host>` probes exactly the supplied canonical hostname
for reachability, a normally verified certificate, TLS 1.3, and the pinned
three-second latency bound. It never scans the signed list for another answer.
A bundled hostname retains its signed candidate ID; a valid manually supplied
hostname receives a deterministic non-secret ID. A successful prepare stores
one pending candidate and the exact affected active node/client IDs while the
old host remains the sole active selection. A second pending replacement is
rejected.

`transport host commit` requires explicit confirmation and repeats the exact
candidate probe. The gateway runtime stages and validates the candidate before
the authoritative write, then publishes it only after the single next state
generation is durable. That generation replaces the one authoritative host and
every enabled restricted transport record together; it never retains two
active host selections or chooses a fallback. A brief restricted-path outage
during listener publication is accepted by the product contract.

Commit retains one exact previous-host snapshot for 24 hours. It reports every
affected node configuration and Clash client export as stale, with explicit
`apply`/re-export actions; WireGuard exports are independent. Clash sidecars
carry a non-secret `{candidate_id, list_version}` source dependency, so the
staleness remains detectable independently of the rendered-content hash. The
dual-transport profile also embeds the host, so re-rendering changes the
restricted alternative while leaving the WireGuard export unchanged. Legacy
sidecars without that optional dependency remain readable
but are stale for a client with an enabled restricted transport.

`transport host rollback` also requires confirmation. Before expiry it stages
the previous listener, restores the exact stored selection and all restricted
records in one new generation, and reports the same node/Clash restaleness.
After expiry rollback is refused; the next explicit prepare may close that old
operation and replace its snapshot. No timer performs this transition.

If the committed change broke a node's restricted control path, the operator
logs into that private VPS over SSH and runs `transport host recover <host>`.
Recovery is node-local and requires the restricted transport to remain the
manual active selection. It renders only the requested host with the existing
node ID and credential generation, performs native validation plus authenticated
control, reverse-tunnel, selected-TCP, and selected-UDP checks against the
gateway, then activates and persists one local generation. A failed check
leaves the old host active; a post-activation failure restores the old rendered
candidate before candidate cleanup. Recovery never rejoins the node, rotates
credentials, changes its address, edits gateway state, or tests an alternative
hostname.

`transport host show` checks only the active pinned hostname and reports its
healthy/degraded observation, pending impact, and rollback availability. A
degraded observation produces a manual replacement action but cannot mutate
selection or runtime state.

## Credential boundary

The gateway owns one create-once, 256-bit Shadowsocks server key. The protocol requires that key to be shared by the listener and its node outbounds. Each enabled restricted client or node has a separate 256-bit ShadowTLS v3 password, which is the per-identity authorization and revocation boundary. An undistributed bootstrap ShadowTLS user keeps an empty gateway configuration structurally valid; it is never an export credential.

The model and public results hold only opaque secret references and generations. Renderers read secret payloads into private memory, reject malformed or reused credentials, and never expose passwords through descriptors, hashes, service failures, or CLI output.

Personal client creation provisions both transports together: standard is
active in authoritative gateway state and restricted is standby. The Clash
artifact includes both credentials, but one manual `type: select` group leaves
the device user in control; standard is listed first for compatibility. No
health test, remote controller, automatic fallback, or gateway state mutation
can change the selection stored by the client. Client credential rotation
replaces the WireGuard and ShadowTLS identity generations atomically; revoke
disables both before best-effort deletion of both secret payloads.

## Rendered artifacts

The gateway artifact defines one Shadowsocks listener named `vpnctl-restricted-in`, bound to TCP port 8443 with `udp: false`. Its ShadowTLS v3 user list contains the bootstrap user and every active, non-disabled restricted identity in deterministic order. The terminal rule is `MATCH,DIRECT` because this process terminates the protected inbound on the public gateway and performs its internet egress there.

The provider candidate contains only the outbound `VPNCTL-RESTRICTED`. It uses the manually supplied gateway IPv4 address, port 8443, ShadowTLS v3, fingerprint `chrome`, and `strict-mode: true`. Task 8.4 added UoT v2 and explicit readiness rejection. The task-10.4 production routing bundle embeds the same validated outbound in the one host-wide Mihomo TUN/DNS process, marks its outer socket for the exact recovery route, and makes it the sole member of `VPNCTL-GATEWAY`; treating `udp: false` alone as fail-closed remains forbidden by the spike evidence.

Both artifacts reject YAML aliases, anchors, merge keys, unknown fields, extra documents, an unpinned component, an invalid public IP, and inconsistent handshake hosts. They are also validated with the exact pinned Mihomo binary before use.

## Gateway service and passive health

The hidden service mode is `vpnctl __service gateway-restricted`. It reads `/etc/vpnctl/generated/gateway/restricted.yaml`, uses `/var/lib/vpnctl/restricted`, and executes `/usr/local/libexec/vpnctl/mihomo`. Before starting it requires private regular config/state paths, validates vpnctl's strict schema, verifies the exact Mihomo version token, and runs Mihomo's native `-t` validation.

`vpnctl-restricted.service` is gateway-only, restarts on failure, emits no
process logs by default, and receives a private state directory. Gateway init
atomically writes both listener configurations and their hash-bound readiness
markers before starting either role unit. Standard and restricted gateway
listeners are enabled and supervised independently across process failure and
gateway reboot. Their simultaneous availability does not select restricted for
any node and cannot trigger automatic fallback.

The restricted health observers are intentionally passive. Listener health
reports healthy only when `vpnctl-restricted.service` is active, exactly one
wildcard TCP/8443 socket is owned by Mihomo, and no UDP/8443 socket exists.
Handshake-host health evaluates only a supplied observation of the pinned
candidate. Both preserve the model's active/standby role and never probe a
standby candidate, rotate a handshake host, activate standby, or switch
transports.

## Reproducible verification

The disposable Linux gate uses only the owner-marked `vpnctl-v2-restricted` network namespace in the already provisioned `vpnctl-v2-node` fixture:

```bash
./scripts/v2restricted-test.sh status
./scripts/v2restricted-test.sh verify
./scripts/v2restricted-test.sh status
```

`verify` checks the cached archive checksum, cross-compiles the transport tests, validates both rendered artifacts with the pinned binary, starts the real listener, proves an IPv4 TCP connection, proves zero UDP sockets and a free UDP bind, stops the process, and checks that the TCP socket disappeared. Its trap removes only its namespace and owner-verified runtime. Manual recovery is:

```bash
./scripts/v2restricted-test.sh cleanup
```

The previous full restricted spike, including UoT/DNS/fail-closed/reconnect evidence and its limitations, remains documented in [spikes/RESTRICTED_TRANSPORT.md](spikes/RESTRICTED_TRANSPORT.md). Task 8.3 narrows that selected candidate into production rendering and process boundaries; it does not claim the later end-to-end gates.
