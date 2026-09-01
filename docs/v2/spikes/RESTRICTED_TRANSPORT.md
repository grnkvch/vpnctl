# Restricted transport candidate — tasks 2.2 and 2.3

Status: **automated gateway/Linux-node TCP, DNS, UoT, fail-closed, and reconnect gates passed; deployed Clash Mi release gate pending**.

Tested on 2026-09-01 with two Ubuntu 24.04 amd64 fixtures constrained to 1 vCPU, 512 MiB configured RAM, 10 GiB configured disk, and 1 GiB managed swap. The candidate is Mihomo `v1.19.30` (`linux amd64`, Go 1.26.6) with Shadowsocks `2022-blake3-aes-256-gcm`, embedded ShadowTLS v3, and Shadowsocks UoT v2. The downloaded release archive matched SHA-256 `cf06ce2c7d1421bdbda14ee4a5b6046672dc35ebf8eecd8e77504ec3c0ed9a84`.

## Accepted automated evidence

- Gateway listened on `8443/TCP`; `8443/UDP` had no socket.
- Node direct access could not reach the gateway-loopback TCP probe. The same target through Mihomo returned `vpnctl-v2-shadowtls-ok`.
- A node query to its local Mihomo DNS listener returned `example.com` A records through the proxy-bound DoH upstream.
- `www.microsoft.com` completed strict TLS 1.3 validation. Selecting `www.apple.com` failed certificate validation; restoring the pinned host restored the probe.
- A SOCKS5 UDP-associate probe returned `vpnctl-v2-uot-ok` from the gateway loopback through UoT v2. The positive capture recorded 13 packets on protected `8443/TCP` and zero node-gateway, node-loopback-direct, or gateway-input native UDP packets.
- The negative outbound reported `udp=false,uot=false`. With `RESTRICTED-UDP → REJECT-DROP`, selected TCP remained healthy and recorded 17 protected packets, selected UDP timed out, and every native/direct UDP counter remained zero.
- The negative experiment also proved that `udp=false` alone is unsafe: before adding the explicit guard, Mihomo attempted one matched UDP datagram through `DIRECT`. The accepted design therefore requires both an explicit UDP reject target and the independent kernel leak guard.
- Restarting only the gateway restricted unit made the outage probe fail, then TCP and UoT both recovered on their first bounded attempt without a node Mihomo restart.
- The generated Clash-style UoT profile passed the pinned Mihomo configuration validator.
- Corrected Lima wildcard ignore rules left no development-host listener on `1053`, `8443`, `17890`, `18080`, or `19090` while guest services were active.

The final isolated snapshot measured approximately 40 MiB RSS for gateway Mihomo and 45 MiB RSS for node Mihomo. The gateway's two test-only Python probes used approximately 33 MiB combined. Total guest RSS was approximately 313 MiB on gateway and 299 MiB on node, with 453 MiB usable guest RAM and 1 GiB swap. These are point measurements, not final load limits.

Raw ignored evidence is under:

- `artifacts/v2lab/restricted-spike/uot-final-isolated/`;
- `artifacts/v2lab/restricted-spike/uot-reconnect-final-isolated/`.

## Remaining acceptance and performance work

The candidate is not production-approved until task 16.11 runs the same pinned profile against an actually deployed gateway/node and supported Clash Mi, including selected TCP, DNS, UoT, strict-host failure, fail-closed behavior, and reconnect.

UDP head-of-line behavior and representative Telegram/general UDP workloads belong to task 2.4. The broader DNS-mode choice belongs to task 2.9.

Primary references: [Mihomo v1.19.30 release](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.30), [Mihomo Shadowsocks outbound](https://wiki.metacubex.one/en/config/proxies/ss/), [Mihomo Shadowsocks listener](https://wiki.metacubex.one/en/config/inbound/listeners/ss/), [Mihomo DNS proxy selection](https://wiki.metacubex.one/en/config/dns/), and [ShadowTLS v3 strict TLS 1.3 behavior](https://github.com/ihciah/shadow-tls/blob/master/docs/protocol-v3-en.md).
