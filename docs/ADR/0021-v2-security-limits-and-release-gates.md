# 0021: Freeze v2 Security, Resource, and Deferred Release Gates

Status: Accepted for dependent development; listed section 16 gates block v2.0.

## Context

The blocking spikes selected concrete PKI, RPC, ingress, tunnel, DNS, and backup limits for a 1-vCPU/512-MiB/10-GiB host. Leaving those numbers scattered across fixtures would let production renderers drift. The same consolidation must distinguish development acceptance from checks that require a deployed service.

## Decision

Use [COMPONENT_LIMITS.v1.json](../v2/COMPONENT_LIMITS.v1.json) as the machine-readable development baseline. It hashes every source fixture/contract and freezes:

- public ports, address pools, routing marks/tables, DNS modes, and recovery watchdog;
- restricted-UDP functional probes without a performance SLO;
- nginx concurrency, body, header, timeout, streaming, and graceful-drain limits;
- frp topology, heartbeats, effective pool zero, and resource floor;
- Ed25519 control identity, enrollment transcript, certificate lifetimes, and bounded TLS 1.3/HTTP 1.1 RPC;
- RSA-2048/SHA-256 public ingress identity with manual IPv4 SAN/CN and five-year lifetime;
- Argon2id v19 `64 MiB/t=3/p=4` plus XChaCha20-Poly1305 1-MiB records and pre-KDF restore caps;
- no expanded logging by default, a one-hour logging opt-in maximum, 30-day/1024-record idempotency bounds, and a 30-day successful-backup warning age.

The 30-day backup warning is passive only. vpnctl does not schedule, upload, delete, or rotate portable backups, and warning status remains a successful exit category.

There are no unresolved blocking-spike implementation parameters. Public command spelling and numeric exits are already frozen in the CLI contract. Future release packaging may narrow compatible Ubuntu package/kernel ranges, but it cannot change these behavior limits without a new reviewed manifest version and the affected regression gates.

Three non-local gates remain explicit:

- task 16.9: sustained minimum-host load for the several-hundred-user Telegram-node profile plus five personal clients;
- task 16.11: actual supported Clash Mi profile/import/TCP/DNS/UoT/strict-host/fail-closed/reconnect behavior against a deployed gateway and node;
- task 16.11: real Telegram certificate registration, incoming webhook validation, and cleanup of only the test-created registration.

All three block v2.0 where applicable. They are release validation, not open permission to choose different implementation semantics.

## Alternatives considered

- Treating local Linux Mihomo and synthetic webhook requests as final provider evidence was rejected by the specs.
- Keeping an unversioned prose-only checklist was rejected because source pins and numeric limits could drift silently.
- A shorter backup warning was rejected as noisy for a manually operated personal system; a longer interval leaves too much time without a portable recovery point.

## Consequences

Dependent tasks must read the consolidated manifest or equivalent generated constants and tests. Changing a hashed source manifest intentionally fails regression until this baseline and the affected ADR are reviewed together. Development acceptance must never be presented as v2.0 release acceptance.
