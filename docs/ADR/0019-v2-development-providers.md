# 0019: Select the v2 Development Providers After Blocking Spikes

Status: Accepted for dependent development; v2.0 release gates remain mandatory.

## Context

The v2 design deliberately kept three expensive choices behind replaceable adapters: DPI-resistant routing/transport, IP-only HTTPS ingress, and the multiplexed node-to-gateway reverse tunnel. Dependent production code needs one exact development baseline, while provider compatibility with a deployed Clash Mi client and Telegram cannot be proven by local Linux fixtures.

## Decision

- Select Mihomo `v1.19.30` for node routing, split DNS, Shadowsocks 2022, ShadowTLS v3 strict, and UoT v2. Pin the official amd64 asset and SHA-256 in the consolidated manifest.
- Select Ubuntu nginx `1.24.0-2ubuntu7.17` for IP-only HTTPS ingress. Pin the package source/checksum and the task 2.6 concurrency/body/timeout/streaming limits.
- Select frp `0.69.0` for one internal frps plus one frpc per node with TLS, `tcpMux`, and effective pool zero. The version-locked Login adapter must rewrite the provider's normalized pool input from one to zero after authorization.
- Keep provider selection internal. There is no plugin matrix or automatic fallback exposed to operators.
- Keep Caddy as the inactive ingress fallback and OpenSSH reverse forwarding as the inactive tunnel fallback. If Mihomo fails a future pin or deployed-client gate, a replacement DPI-resistant provider must satisfy the same adapter contract and test suite. Activating any fallback is a reviewed architecture/release change, never a runtime failover.

The exact pins and limits live in [COMPONENT_LIMITS.v1.json](../v2/COMPONENT_LIMITS.v1.json). A component-version change invalidates its acceptance evidence and requires the listed development and release gates to run again.

## Alternatives considered

- Caddy was not selected because its domain/ACME strengths do not help the IP-only v2 contract and nginx passed the smaller-resource streaming gate.
- An in-process Go reverse proxy was rejected because it couples edge forwarding to vpnctl lifecycle and expands the HTTP/2/limit hardening surface.
- One OpenSSH reverse process per expose was rejected as the default because it violates the bounded connection/process model.
- rathole was rejected because the evaluated connection model did not satisfy the required multiplexing contract.
- Automatic provider or transport fallback was rejected because it can silently change the security path and violate fail-closed/manual-switch behavior.

## Consequences

Dependent implementation may target these exact providers and internal adapter contracts. It must not describe restricted transport or nginx webhook compatibility as production-ready until task 16.11 passes against deployed services. Release capacity for the stated user profile remains blocked on task 16.9.
