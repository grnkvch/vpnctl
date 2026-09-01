# Restricted transport candidate — task 2.2

Status: **automated gateway/Linux-node gate passed; actual Clash Mi gate pending**.

Tested on 2026-09-01 with the two Ubuntu 24.04 amd64 fixtures constrained to 1 vCPU, 512 MiB configured RAM, 10 GiB configured disk, and 1 GiB managed swap. The candidate is Mihomo `v1.19.30` (`linux amd64`, Go 1.26.6) with Shadowsocks `2022-blake3-aes-256-gcm` and embedded ShadowTLS v3. The downloaded release archive matched SHA-256 `cf06ce2c7d1421bdbda14ee4a5b6046672dc35ebf8eecd8e77504ec3c0ed9a84`.

## Accepted automated evidence

- Gateway listened on `8443/TCP`; `8443/UDP` had no socket.
- Node direct access could not reach the gateway-loopback probe. The same target through Mihomo returned `vpnctl-v2-shadowtls-ok`, proving the application connection exited through the gateway process.
- A node query to its local Mihomo DNS listener returned `example.com` A records. The temporary node journal recorded the DoH connection as `mihomo --> 1.1.1.1:443 using RESTRICTED[RESTRICTED-VALID]`.
- `www.microsoft.com` completed TLS 1.3 certificate validation from the gateway and remained the only pinned host. Selecting a client SNI of `www.apple.com` failed because the forwarded certificate was not valid for that name. Restoring the pinned selection immediately restored the TCP probe.
- Stopping the gateway restricted unit caused the probe to fail. Restarting only that unit recovered on the first bounded retry; the node Mihomo PID remained `2178`, so node restart was not required.
- The generated Clash-style profile passed the pinned Mihomo configuration validator. Its temporary guest copy was removed after validation.
- Lima forwarding isolation produced no development-host listener on `1053`, `8443`, `17890`, `18080`, or `19090`.

The post-reconnect snapshot measured approximately 38 MiB RSS for gateway Mihomo and 46 MiB RSS for node Mihomo. Total guest RSS was approximately 307 MiB and 304 MiB respectively, with 453 MiB usable guest RAM and 1 GiB swap. These are point measurements for the spike, not final capacity limits or a load benchmark.

Raw ignored evidence is under:

- `artifacts/v2lab/restricted-spike/evidence-final/`;
- `artifacts/v2lab/restricted-spike/reconnect-final/`.

## Remaining acceptance gate

The candidate is not production-approved and task 2.2 is not complete until the same pinned profile passes on an actual supported Clash Mi installation. The manual run must record the app/platform version and sanitized results for profile import, selected TCP, selected DNS, strict wrong-host rejection, and reconnect. Linux Mihomo validation is deliberately not treated as a substitute.

UDP-over-TCP behavior, head-of-line performance, and the broader DNS-mode choice belong to tasks 2.3, 2.4, and 2.9 respectively and are not inferred from this result.

Primary references: [Mihomo v1.19.30 release](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.30), [Mihomo Shadowsocks outbound](https://wiki.metacubex.one/en/config/proxies/ss/), [Mihomo Shadowsocks listener](https://wiki.metacubex.one/en/config/inbound/listeners/ss/), [Mihomo DNS proxy selection](https://wiki.metacubex.one/en/config/dns/), and [ShadowTLS v3 strict TLS 1.3 behavior](https://github.com/ihciah/shadow-tls/blob/master/docs/protocol-v3-en.md).
