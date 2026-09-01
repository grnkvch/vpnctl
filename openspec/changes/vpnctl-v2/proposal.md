## Why

vpnctl v1 решает только одноузловой personal WireGuard VPN и не покрывает сценарий self-hoster с gateway во внешнем регионе и application VPS в ограниченном регионе. v2 превращает утилиту в opinionated gateway orchestrator, который на малой VPS безопасно совмещает personal VPN, selective fail-closed egress private nodes и IP-only HTTPS ingress для webhook/API приложений.

## What Changes

- **BREAKING**: заменить cwd-зависимую v1-модель на role-aware system-wide installation с `vpnctl init --gateway|--node`, authoritative gateway state и одним бинарником для обеих ролей.
- Сохранить personal clients v1, включая WireGuard full-tunnel и Clash/Mihomo selective profiles, но перевести их на явные preset assignments, стабильные identities и управляемый export через `scp`.
- Добавить secure enrollment нескольких private nodes, internal mTLS control plane, lifecycle credentials, revoke/delete/rotate и break-glass recovery.
- Добавить host-wide selective egress private node: явно выбранный TCP/UDP и связанный DNS идут через gateway либо блокируются; остальной IPv4 traffic остаётся direct.
- Добавить два подготовленных транспорта — WireGuard `standard` и DPI-resistant `restricted` — с только ручным выбором, test/switch flows и отсутствием fail-direct.
- Добавить managed IP-only HTTPS ingress на `443/TCP` и multiplexed reverse tunnel от gateway к явно опубликованным HTTP applications private nodes.
- Добавить transactional desired-state operations, passive status, active doctor, drift repair, lockout watchdog, temporary opt-in logging, encrypted gateway backup/restore и explicit uninstall/purge semantics.
- Добавить signed pinned release bundle, gateway-first manual updates with rollback, one-time migration from v1 и acceptance/resource gates для Ubuntu 24.04 amd64 на 1 vCPU/512 MB/10 GB.
- Явно не включать mesh/failover, node-to-node networking, automatic transport switching, process/container-scoped policy, public management API/Web UI, generic ingress, full IPv6, domain/ACME, URL/subscription/QR delivery и node cloning/portable backup.

## Capabilities

### New Capabilities

- `host-bootstrap-and-lifecycle`: role initialization, host ownership, preflight, nftables/SSH safety, filesystem/service installation, swap, uninstall and purge.
- `fleet-control-plane`: authoritative gateway controller, versioned mTLS RPC, generations, idempotency, availability and compatibility behavior.
- `node-enrollment-and-identity`: invites, join, multi-node isolation, credential lifecycle, revoke/delete/rotate and break-glass recovery.
- `personal-client-management`: client identities, explicit policy assignment, WireGuard/Clash export, revoke/delete/rotation and v1-compatible behavior.
- `selective-routing-and-dns`: editable presets, host-wide classification, split DNS, IPv4 boundary and fail-closed TCP/UDP guarantees.
- `transport-management`: standard/restricted transports, ShadowTLS handshake-host lifecycle, UDP-over-TCP, manual test/switch and standby behavior.
- `managed-https-ingress`: IP-only TLS endpoint, path-based expose resources, certificate lifecycle, bounded HTTP proxying and observable failure semantics.
- `reverse-tunnel`: per-node multiplexed outbound tunnels, authorization, reconnect, stable internal endpoints and expose mapping lifecycle.
- `desired-state-and-operations`: transactional plan/apply/repair, pending/drift semantics, status/doctor, temporary logging and state durability.
- `release-delivery-and-migration`: signed bundles, pinned dependencies, manual update/rollback, encrypted gateway backup/restore, v1 migration and release acceptance gates.

### Modified Capabilities

None. The repository has no existing OpenSpec capability specifications; v1 behavior that must remain is captured in the new v2 capabilities.

## Impact

- The current Go CLI, domain model, state storage, setup/apply paths, WireGuard and Mihomo rendering will be substantially refactored while retaining validated v1 client behavior.
- New gateway services and integrations include a vpnctl controller, nftables, WireGuard, Mihomo/Shadowsocks/ShadowTLS, nginx, a reverse-tunnel implementation, systemd-resolved integration and independent systemd data-plane units.
- Public network contract reserves `443/TCP` for HTTPS/enrollment/recovery, `8443/TCP` for restricted transport and `51820/UDP` for WireGuard; `8443/UDP` and `443/UDP` remain closed.
- System state moves to `/etc/vpnctl`, `/var/lib/vpnctl` and `/run/vpnctl`; gateway becomes vpnctl-dedicated while private nodes remain application hosts with narrowly scoped vpnctl ownership.
- Delivery and operations require signed release artifacts, pinned component manifests, a one-time v1 migration tool, compatibility windows and end-to-end/security/resource testing on the minimum target VPS.
