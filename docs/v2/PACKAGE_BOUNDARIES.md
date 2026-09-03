# vpnctl v2 package boundaries

vpnctl remains one Go module and one binary. The v2 packages are layered inward-to-outward; an outer layer may import an inner layer, never the reverse. Provider packages expose implementation-neutral contracts, while OS and third-party details stay behind adapters.

| Tier | Packages | Responsibility |
| --- | --- | --- |
| 0 | `internal/model` | Versioned domain objects and invariants; standard library only |
| 1 | `internal/store`, `internal/platform/linux`, `internal/render`, `internal/output`, `internal/restricted` | Persistence, host primitives, deterministic artifacts, result rendering, and the restricted wire/credential contract shared by transport and client export |
| 2 | `internal/control`, `internal/transport`, `internal/routing`, `internal/ingress`, `internal/tunnel` | Protocol and data-plane capability boundaries |
| 3 | `internal/enrollment`, `internal/operations`, `internal/lifecycle` | Cross-capability workflows and sagas |
| 4 | `internal/controller` | Authoritative gateway mutation serialization and reconciliation |
| 5 | `internal/cli` | Public role-aware command registry and invocation adapters |

Packages in the same tier do not import one another. `cmd/vpnctl` only constructs and calls `internal/cli`; no internal package imports a `cmd` package. Existing v1 packages remain temporarily outside this graph and are protected by golden fixtures while behavior is moved behind v2 boundaries.

The regression dependency test parses Go imports and fails on inward-to-outward or same-tier dependencies, model imports outside the standard library, imports of `internal/cli` from another internal package, or a missing package from this table.
