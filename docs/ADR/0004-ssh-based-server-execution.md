# 0004: Use SSH-Based Server Execution

Status: Superseded for the initial MVP by ADR 0007.

## Context

The VPS already exists and SSH access already exists. The project should avoid
unnecessary moving parts while still applying server changes safely.

## Decision

Use SSH to inspect and apply server-side changes. Do not introduce a persistent
server-side vpnctl daemon.

This remains a future direction, but it is no longer part of the initial MVP.
ADR 0007 selects a server-local execution model for the first implementation.

## Alternatives Considered

- Server-side REST API
- Agent daemon running on the VPS
- Manual copy and command instructions only
- Configuration management tools such as Ansible

## Tradeoffs

SSH-based execution uses the operator's existing trust and access model. It
keeps deployment simple and avoids maintaining a daemon.

The cost is that the CLI must carefully handle command construction, privilege
escalation, idempotency, and diagnostics.

## Consequences

- Server apply operations should support dry-run or render-before-apply.
- Remote commands must avoid printing secrets.
- The server module should be isolated behind a small execution interface.
- A daemon or API can be reconsidered only if SSH execution becomes limiting.
