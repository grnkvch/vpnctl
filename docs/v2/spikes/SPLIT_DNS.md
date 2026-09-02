# Split DNS candidate — task 2.9

Status: **automated Linux-node and rendered-profile gate passed; deployed Clash Mi release gate pending**.

The accepted internal renderer is Mihomo `v1.19.30` with `redir-host`. Policy mode uses `nameserver-policy` so selected domains query the gateway resolver and unmatched domains query the saved node-direct resolvers. Compatibility mode uses `redir-host` with all DNS direct. No fallback list is rendered between these paths.

The fake-IP whitelist candidate was validated but rejected. It returned synthetic addresses only for selected domains, yet it could answer a fresh selected query without consulting the gateway DNS path. That is incompatible with vpnctl's literal selected-query contract even though a later connection could still fail closed.

## Host integration

The node keeps the systemd-resolved stub and installs an owned drop-in that routes global `~.` DNS to Mihomo on `127.0.0.1:1053`, clears fallback DNS, and disables resolved's cache. Existing per-link DNS, route domains, default-route state, resolver files, and the `/etc/resolv.conf` target are captured and restored exactly. If an existing link owns `~.`, vpnctl temporarily replaces only that route domain after snapshotting it so resolved cannot race the underlay server.

An owned nftables output-NAT table redirects classic TCP/UDP destination port 53 to Mihomo. Only the dedicated resolver UID and the systemd loopback stubs bypass that redirect; the resolver UID is therefore the only process allowed to contact configured upstreams without recursion. Production activation must remain behind the routing readiness guard selected by task 2.8.

## Failure and cache semantics

With gateway DNS stopped, a fresh selected name returns no address and never appears at the direct fixture, while a fresh unrelated name continues through the direct resolver. A previously gateway-validated answer follows Mihomo's pinned stale-while-revalidate behavior: after authoritative expiry it is returned with TTL `1` while refresh continues only toward the unavailable gateway. The cache is capacity-bounded to the pinned provider default of 4096 entries, but stale eviction is not time-bounded during an outage. This does not create fail-direct; every selected connection remains subject to the independent gateway-or-block routing guard. Policy/mode changes restart Mihomo and clear the internal cache.

## Reproduce and rollback

```bash
./scripts/v2dns-spike.sh prepare
./scripts/v2dns-spike.sh verify
```

`verify` owner-checks the two Lima fixtures, validates all node and Clash-compatible configs with the pinned Mihomo binary, exercises systemd-resolved/libc/direct DNS clients, TCP/UDP 53 capture, cache/outage/recovery, direct compatibility, resources, and exact restoration. Its armed EXIT trap performs a full owner-safe teardown on success or failure. Manual cleanup is:

```bash
./scripts/v2dns-spike.sh uninstall
```

The accepted ignored evidence is `artifacts/v2lab/dns-spike/evidence-20260902T033936Z/summary.json`. Import and DNS behavior on an actual supported Clash Mi build remain a deployed-service release gate in task 16.11.
