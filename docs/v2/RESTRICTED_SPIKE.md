# Restricted transport spikes

Tasks 2.2 and 2.3 test the development candidate only; they do not make the restricted transport production-ready. The candidate is pinned in `test/v2lab/restricted/manifest.json`: Mihomo `v1.19.30`, Shadowsocks 2022 AES-256-GCM, ShadowTLS v3 strict over `8443/TCP`, and Shadowsocks UDP-over-TCP v2. The official archive SHA-256 is verified before a binary is copied into either lab VM.

The spike owns only these guest resources:

- `/usr/local/libexec/vpnctl-v2-spike/{mihomo,udp-echo,udp-probe}` as applicable to each role;
- `/etc/vpnctl-v2-spike/restricted/` with an ownership marker;
- `vpnctl-v2-spike-restricted-{gateway,node}.service`, `vpnctl-v2-spike-echo.service`, and `vpnctl-v2-spike-udp-echo.service`;
- their systemd state paths;
- gateway `8443/TCP`, loopback `18080/TCP`, and test `18080/UDP`, plus node loopback ports `1053`, `17890`, and `19090`.

Lima ignores those ports for listeners bound on any guest interface, so none is forwarded to the development host. The orchestrator refuses a stopped/drifted fixture, a mismatched image or network, an occupied port, a missing owner marker, or an incorrectly scoped forwarding rule. Host and guest mutations plus rollback are recorded in `docs/v2/HOST_CHANGELOG.md`.

Prepare the pinned candidate and run its automated TCP, DNS, UDP-over-TCP, strict-host, fail-closed, socket, resource, and reconnect checks:

```bash
./scripts/v2restricted-spike.sh prepare
./scripts/v2restricted-spike.sh verify
./scripts/v2restricted-spike.sh reconnect
```

`verify` proves all of the following:

- selected TCP reaches a gateway-loopback probe only through Shadowsocks/ShadowTLS;
- selected DNS uses the proxy-bound Mihomo upstream;
- the deliberately wrong strict handshake host fails and restoring the pinned host recovers;
- selected UDP reaches a gateway-loopback echo through Shadowsocks UoT v2;
- the outer node/gateway capture records protected `8443/TCP` and no native UDP;
- when runtime evidence says `udp=false,uot=false`, an explicit UDP readiness guard selects `REJECT-DROP`, selected TCP continues through restricted, selected UDP blocks, and no node-gateway or node-loopback direct UDP is emitted;
- `8443/UDP` has no listener.

The capture tables use the exact temporary name `inet vpnctl_v2_spike_uot_capture` and are deleted by a trap on success or failure. The generated evidence and credentials are mode-restricted and ignored under `artifacts/v2lab/restricted-spike/`. Temporary `info` logs exist only inside the disposable fixtures for this explicit spike; production logging remains default-off.

## Provider safety result

Mihomo does not by itself provide the required fail-closed behavior when a selected Shadowsocks outbound lacks UDP capability: without an explicit readiness guard, a matched UDP flow can be attempted through `DIRECT`. Production integration must therefore render an explicit selected-UDP reject path and combine it with the independent kernel leak guard. Merely setting `udp: false` is not a safety mechanism.

## Deployed Clash Mi release gate

Mihomo-on-Linux compatibility is not accepted as evidence for actual Clash Mi. A reachable deployed gateway address must be supplied manually to render a secret-bearing profile:

```bash
./scripts/v2restricted-spike.sh render-client 203.0.113.10
```

The default output is mode `0600` under the ignored artifact directory. Before v2.0, transfer it to an actual supported Clash Mi installation and record the app/platform version plus sanitized results for import, selected TCP, selected DNS, selected UoT, strict wrong-host rejection, no fail-direct behavior, and reconnect. Tasks 2.2 and 2.3 are complete on their automated development gates; the candidate remains non-production-ready until this deployed-service release gate passes.

Stop the spike without deleting evidence, or remove only owner-verified guest resources:

```bash
./scripts/v2restricted-spike.sh stop
./scripts/v2restricted-spike.sh uninstall
```
