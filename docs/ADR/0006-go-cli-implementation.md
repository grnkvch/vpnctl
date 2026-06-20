# 0006: Implement vpnctl As A Go CLI

## Context

vpnctl is a CLI-first tool that should run from an operator machine and manage a
small VPN infrastructure over SSH. The operator wants to minimize globally
installed dependencies.

## Decision

Implement vpnctl in Go as a single command-line binary.

## Alternatives Considered

- Python CLI
- Shell scripts
- Rust CLI

## Tradeoffs

Go provides a small operational footprint, fast tests, straightforward
cross-compilation, and simple distribution as a single binary.

The cost is that contributors unfamiliar with Go need to learn its module,
package, error handling, and testing conventions.

## Consequences

- The project uses `go.mod` for dependency management.
- The executable entrypoint lives under `cmd/vpnctl`.
- Application code lives under `internal`.
- External dependencies should be added deliberately and kept minimal.
