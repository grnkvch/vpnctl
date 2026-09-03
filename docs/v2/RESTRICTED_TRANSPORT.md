# Restricted transport

Tasks 8.3-8.6 implement the restricted-provider foundation, mandatory
UDP-over-TCP readiness, the pinned handshake-host lifecycle, and independent
gateway listener supervision. It remains a development-gated path: explicit
test/switch operations belong to tasks 8.7-8.8, and testing against a deployed
gateway/node plus real Clash Mi to release gate 16.11.

## Pinned provider contract

- Provider: Mihomo `v1.19.30`, Linux amd64 archive `mihomo-linux-amd64-v1.19.30.gz`.
- Archive SHA-256: `cf06ce2c7d1421bdbda14ee4a5b6046672dc35ebf8eecd8e77504ec3c0ed9a84`.
- Inner proxy: Shadowsocks `2022-blake3-aes-256-gcm`.
- DPI-resistant layer: embedded ShadowTLS v3 with strict mode on the node.
- Gateway socket: `8443/TCP` on the wildcard address. No `8443/UDP` listener is allowed.
- Provider output uses `silent` logging; transport process stdout and stderr are discarded unless a later explicit, temporary logging workflow enables them.

The gateway public IP remains an operator-supplied value. The handshake
hostname is selected from the signed list described below; every restricted
identity must agree with that authoritative state. Manual replacement remains
the separate staged task 8.9 flow.

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
candidate list again. The node-enrollment and restricted Clash consumers will
use this versioned delivery record in tasks 9.4 and 8.10 respectively.

Runtime observation is deliberately passive. Given an observation of the exact
pinned candidate, health reports `handshake-host-healthy` or
`handshake-host-degraded` plus a required manual action. It cannot inspect the
candidate bundle, probe another hostname, alter state, activate standby, or
rotate/fail over. Explicit prepare/commit/rollback and SSH recovery are task
8.9.

## Credential boundary

The gateway owns one create-once, 256-bit Shadowsocks server key. The protocol requires that key to be shared by the listener and its node outbounds. Each enabled restricted client or node has a separate 256-bit ShadowTLS v3 password, which is the per-identity authorization and revocation boundary. An undistributed bootstrap ShadowTLS user keeps an empty gateway configuration structurally valid; it is never an export credential.

The model and public results hold only opaque secret references and generations. Renderers read secret payloads into private memory, reject malformed or reused credentials, and never expose passwords through descriptors, hashes, service failures, or CLI output.

## Rendered artifacts

The gateway artifact defines one Shadowsocks listener named `vpnctl-restricted-in`, bound to TCP port 8443 with `udp: false`. Its ShadowTLS v3 user list contains the bootstrap user and every active, non-disabled restricted identity in deterministic order. The terminal rule is `MATCH,DIRECT` because this process terminates the protected inbound on the public gateway and performs its internet egress there.

The node artifact contains only the outbound `VPNCTL-RESTRICTED`. It uses the manually supplied gateway IPv4 address, port 8443, ShadowTLS v3, fingerprint `chrome`, and `strict-mode: true`. It has no listener, TUN device, DNS service, native UDP, or UDP-over-TCP in task 8.3. Shared node routing and the explicit selected-UDP reject/readiness path are added in task 8.4; treating `udp: false` alone as fail-closed is forbidden by the spike evidence.

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
