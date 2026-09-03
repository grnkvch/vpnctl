# Restricted transport

Task 8.3 implements the restricted-provider foundation. It is development-gated, not yet an activatable end-to-end node path: fail-closed UDP-over-TCP and mandatory readiness belong to task 8.4, listener supervision and restoration to task 8.6, and testing against a deployed gateway/node plus real Clash Mi to release gate 16.11.

## Pinned provider contract

- Provider: Mihomo `v1.19.30`, Linux amd64 archive `mihomo-linux-amd64-v1.19.30.gz`.
- Archive SHA-256: `cf06ce2c7d1421bdbda14ee4a5b6046672dc35ebf8eecd8e77504ec3c0ed9a84`.
- Inner proxy: Shadowsocks `2022-blake3-aes-256-gcm`.
- DPI-resistant layer: embedded ShadowTLS v3 with strict mode on the node.
- Gateway socket: `8443/TCP` on the wildcard address. No `8443/UDP` listener is allowed.
- Provider output uses `silent` logging; transport process stdout and stderr are discarded unless a later explicit, temporary logging workflow enables them.

The gateway public IP remains an operator-supplied value. The handshake hostname is taken from the selected component bundle; task 8.3 requires every restricted identity to agree on it but does not select, rotate, or replace it. Signed bundles and manual host changes belong to tasks 8.5 and 8.9.

## Credential boundary

The gateway owns one create-once, 256-bit Shadowsocks server key. The protocol requires that key to be shared by the listener and its node outbounds. Each enabled restricted client or node has a separate 256-bit ShadowTLS v3 password, which is the per-identity authorization and revocation boundary. An undistributed bootstrap ShadowTLS user keeps an empty gateway configuration structurally valid; it is never an export credential.

The model and public results hold only opaque secret references and generations. Renderers read secret payloads into private memory, reject malformed or reused credentials, and never expose passwords through descriptors, hashes, service failures, or CLI output.

## Rendered artifacts

The gateway artifact defines one Shadowsocks listener named `vpnctl-restricted-in`, bound to TCP port 8443 with `udp: false`. Its ShadowTLS v3 user list contains the bootstrap user and every active, non-disabled restricted identity in deterministic order. The terminal rule is `MATCH,DIRECT` because this process terminates the protected inbound on the public gateway and performs its internet egress there.

The node artifact contains only the outbound `VPNCTL-RESTRICTED`. It uses the manually supplied gateway IPv4 address, port 8443, ShadowTLS v3, fingerprint `chrome`, and `strict-mode: true`. It has no listener, TUN device, DNS service, native UDP, or UDP-over-TCP in task 8.3. Shared node routing and the explicit selected-UDP reject/readiness path are added in task 8.4; treating `udp: false` alone as fail-closed is forbidden by the spike evidence.

Both artifacts reject YAML aliases, anchors, merge keys, unknown fields, extra documents, an unpinned component, an invalid public IP, and inconsistent handshake hosts. They are also validated with the exact pinned Mihomo binary before use.

## Gateway service and passive health

The hidden service mode is `vpnctl __service gateway-restricted`. It reads `/etc/vpnctl/generated/gateway/restricted.yaml`, uses `/var/lib/vpnctl/restricted`, and executes `/usr/local/libexec/vpnctl/mihomo`. Before starting it requires private regular config/state paths, validates vpnctl's strict schema, verifies the exact Mihomo version token, and runs Mihomo's native `-t` validation.

`vpnctl-restricted.service` is gateway-only, restarts on failure, emits no process logs by default, and receives a private state directory. Publication of the readiness marker and orchestration that starts both gateway listeners remain task 8.6.

The task-8.3 health observer is intentionally passive. It reports healthy only when `vpnctl-restricted.service` is active, exactly one wildcard TCP/8443 socket is owned by Mihomo, and no UDP/8443 socket exists. It preserves the model's active/standby role and never probes, rotates a handshake host, activates standby, or switches transports.

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
