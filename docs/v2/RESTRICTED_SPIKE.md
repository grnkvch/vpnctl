# Restricted transport spike

Task 2.2 tests the candidate implementation only; it does not make the restricted transport production-ready. The candidate is pinned in `test/v2lab/restricted/manifest.json`: Mihomo `v1.19.30`, Shadowsocks 2022 AES-256-GCM, and ShadowTLS v3 with strict client validation over `8443/TCP`. The official archive SHA-256 is verified before a binary is copied into either lab VM.

The spike owns only these guest resources:

- `/usr/local/libexec/vpnctl-v2-spike/mihomo`;
- `/etc/vpnctl-v2-spike/restricted/` with an ownership marker;
- `vpnctl-v2-spike-restricted-{gateway,node}.service` and `vpnctl-v2-spike-echo.service`;
- their three systemd `StateDirectory` paths;
- gateway TCP ports `8443` and loopback `18080`, plus node loopback ports `1053`, `17890`, and `19090`.

Lima forwarding for all of those ports is explicitly ignored. The orchestrator refuses a stopped/drifted fixture, a mismatched image or network, an occupied port, a missing owner marker, or a port that could be forwarded onto the development host. Host and guest mutations plus rollback are recorded in `docs/v2/HOST_CHANGELOG.md`.

Prepare the pinned candidate and run its automated TCP, DNS, strict-host, socket, and resource checks:

```bash
./scripts/v2restricted-spike.sh prepare
./scripts/v2restricted-spike.sh verify
./scripts/v2restricted-spike.sh reconnect
```

`verify` proves that the node cannot reach a gateway-loopback HTTP probe directly, can reach it through the restricted proxy, resolves `example.com` through the proxy-bound Mihomo DNS upstream, rejects a deliberately mismatched strict handshake host, restores the pinned host, and has no listener on `8443/UDP`. `reconnect` stops only the gateway spike service, requires the proxy probe to fail, restarts it, and verifies the already-running node reconnects.

The generated evidence and credentials are mode-restricted and ignored under `artifacts/v2lab/restricted-spike/`. Temporary `info` logs exist only inside the disposable fixtures for this explicit spike; production logging remains default-off.

## Actual Clash Mi gate

Mihomo-on-Linux compatibility is not accepted as evidence for Clash Mi. A reachable gateway address must be supplied manually to render a secret-bearing profile:

```bash
./scripts/v2restricted-spike.sh render-client 203.0.113.10
```

The default output is mode `0600` under the ignored artifact directory. Transfer it to an actual supported Clash Mi installation and record the app version, platform, import result, selected TCP result, selected DNS result, strict-host negative result, reconnect result, and sanitized evidence. The task remains incomplete until that manual run passes; the local rootless Lima address is not advertised as an iOS-reachable gateway.

Stop the spike without deleting evidence, or remove only owner-verified guest resources:

```bash
./scripts/v2restricted-spike.sh stop
./scripts/v2restricted-spike.sh uninstall
```
