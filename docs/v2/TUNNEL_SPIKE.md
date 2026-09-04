# Multiplexed reverse-tunnel spike

Task 2.7 tests the development tunnel provider on the minimum gateway/node fixtures. It does not install production vpnctl services or expose a public port. The provider is pinned in `test/v2lab/tunnel/manifest.json`: frp `v0.69.0`, one shared internal-only frps, one frpc per node, TLS server verification, `tcpMux`, and an effective work-connection pool of zero. The official Linux/amd64 archive SHA-256 is verified before either binary is installed.

The spike owns only these guest resources:

- `/usr/local/libexec/vpnctl-v2-spike/{frps,frpc,tunnel-auth-plugin,tunnel-backend,tunnel-probe}` as applicable to each role;
- `/etc/vpnctl-v2-spike/tunnel/` and `/var/lib/vpnctl-v2-spike-tunnel-auth/` with exact ownership markers;
- `vpnctl-v2-spike-tunnel-{auth,server,client,backend}.service` on their respective roles;
- gateway overlay `17000/TCP`, gateway loopback `18111/18112/19091`, and node loopback `17400/18121/18122`.

Lima ignores every spike port for host forwarding. The orchestrator refuses drifted VM contracts, foreign files/listeners, missing owner markers, or unexpected forwarding. Every host/guest mutation and rollback is recorded in `docs/v2/HOST_CHANGELOG.md`.

Prepare, inspect, and run the complete acceptance gate:

```bash
./scripts/v2tunnel-spike.sh prepare
./scripts/v2tunnel-spike.sh status
./scripts/v2tunnel-spike.sh verify
```

`verify` proves all of the following:

- one persistent TLS/tcpMux connection carries 12 concurrent streams for each of two exposes;
- adding and removing mappings uses loopback-only reload without replacing the frpc process or disturbing the other expose;
- the local Login/NewProxy authorizer rejects revoked/old-generation identities and malicious/stale mappings, and fails closed when unavailable;
- an untrusted TLS server never receives Login metadata;
- restarting frps reconnects without restarting frpc; revocation closes the live connection and rejects retries;
- standard transport reaches frps directly, while the manually selected restricted transport has exactly one frpc-to-Mihomo connection and sends steady-state tunnel traffic only through ShadowTLS `8443/TCP`;
- the standard transport, node identity, mapping ownership, and authorization state are restored after the switch;
- both 1-vCPU/512-MiB guests retain the manifest memory floor with zero unit OOM events.

Generated credentials and evidence are mode-restricted and ignored under `artifacts/v2lab/tunnel-spike/`. The accepted run is summarized in `evidence-20260901T220258Z/summary.json`: effective pool zero, one persistent connection, two exposes, 24 concurrent streams, controller-state failure rejection, reconnect in 7 seconds, revoke in 2 seconds, standard direct traffic, and restricted steady-state `17000 = 0` plus ShadowTLS `8443 > 0`. Temporary `info` logs exist only while the disposable spike units are intentionally active; production logging remains default-off.

## Pinned frp pool normalization

frpc `v0.69.0` normalizes a declared `transport.poolCount = 0` to Login `pool_count = 1`. The local version-locked Login adapter accepts exactly that expected input after identity validation and returns otherwise unchanged Login content with `pool_count = 0` before frps creates the control session. Every other input is rejected. This uses frp's documented plugin content-replacement mechanism and keeps the provider's effective pool at zero; negative pool values are not used.

This normalization is an internal provider-adapter detail, not part of the public expose model. A frp version change must update the pin and rerun the full contract before activation.

## Provider decision

Pinned frp `v0.69.0` is accepted as the replaceable development provider. OpenSSH reverse forwarding remains the fallback adapter if a future pinned frp version cannot pass multiplexing, authorization, no-pool, TLS, lifecycle, transport-switch, or resource gates. No fallback is activated automatically.

Stop the temporary logging/runtime without deleting evidence, or remove only owner-verified spike resources:

```bash
./scripts/v2tunnel-spike.sh stop
./scripts/v2tunnel-spike.sh uninstall
```

## Production provider release harness

Task 11.9 promotes the spike checks into a repeatable release harness without
promoting the spike implementation itself. On a clean source tree and the two
running contract-matching Lima fixtures, run:

```bash
./scripts/v2tunnel-release-gate.sh run
```

The harness first runs every `TestFRPNative*` case from the production tunnel
package against checksum-verified official frps/frpc binaries. This covers the
production renderer, TLS identity, Login/NewProxy/Ping authorization, effective
zero pool, dynamic mapping reload, reconnect/readiness, and live revoke close.
It then runs the original two-host spike regression for concurrent
multiplexing, standard/restricted path capture, and minimum-host resources.

The harness refuses an existing tunnel fixture, foreign ownership, occupied
paths/ports, drifted VM resources, a dirty source tree, or an existing evidence
directory. It records the exact source commit, provider archive hash, sanitized
native test output, fixture descriptors, and the complete spike summary below
`artifacts/v2lab/tunnel-release-gate/`. It removes its temporary binaries and
owner-created tunnel/restricted fixtures on both success and failure. A
pre-existing owner-verified restricted fixture is reused and restored by its
own transport cleanup contract rather than deleted.

This is the tunnel capability's development release gate. It does not replace
the sustained several-hundred-user capacity gate in task 16.9, deployed Clash
Mi behavior, or the real Telegram webhook gate in task 16.11.

The accepted clean-tree run is recorded in
`artifacts/v2lab/tunnel-release-gate/task-11.9-6089016/summary.json` and binds
source commit `60890165f934a610fe8e365d0a7bc071d9be96c2`. Six production native
tests passed; the spike retained one control connection for 24 concurrent
streams, reconnected in 7 seconds, revoked in 3 seconds, observed 50 standard
direct and 19 restricted ShadowTLS packets, retained 278996/304908 KiB
available on gateway/node, and recorded zero OOM kills.
