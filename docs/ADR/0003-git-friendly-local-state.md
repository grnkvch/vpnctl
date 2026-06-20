# 0003: Use Git-Friendly Local State As Source Of Truth

## Context

vpnctl is used by one operator and manages a small number of clients. The
architecture requires a single source of truth, Git-friendly state, idempotent
operations, and secure handling of private keys.

## Decision

Use local files as the source of truth. Store non-secret state in Git-friendly
structured files. Store secret material separately with restricted permissions.

## Alternatives Considered

- Server-side state as the source of truth
- SQLite database
- Remote API service with a database
- Encrypted Git repository for all state and secrets

## Tradeoffs

Local structured files are easy to review, diff, back up, and restore. They keep
the first implementation small and transparent.

The cost is that concurrent operators, remote reconciliation, and advanced
secret management are not solved initially.

## Consequences

- State loading and validation become core functionality.
- Generated artifacts must be reproducible from state.
- Secret files must be excluded from Git by default.
- Schema migrations should be explicit once state format changes.
