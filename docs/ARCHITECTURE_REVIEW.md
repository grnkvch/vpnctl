# Architecture Review

## Scope

vpnctl is a CLI-first tool for managing a small personal WireGuard-based VPN
infrastructure over SSH.

The target scale is one operator and 1-20 clients. Simplicity, explicit state,
and recoverability are more important than generic multi-tenant flexibility.

## Current Architecture Summary

Core concepts:

- Server
- Client
- KeyPair
- WireGuardConfig
- ClashConfig
- ConfigDelivery
- Ruleset

Primary constraints:

- VPS and SSH access already exist.
- WireGuard is the VPN backend.
- Mihomo / Clash Mi is the routing layer for supported clients.
- State must be Git-friendly and act as the single source of truth.
- Operations must be idempotent.
- Private keys must not be logged.
- Linux VM usage must not break SSH access.

## Recommended Direction

Use a local CLI that owns a repository of declarative state and applies changes
to the server over SSH.

The CLI should:

- Maintain local state as versionable files.
- Generate server and client configuration from state.
- Apply server-side changes through idempotent SSH commands.
- Treat generated private keys as secrets with restricted file permissions.
- Keep delivery artifacts separate from long-lived state.

Server-side state should be derived from the local source of truth rather than
edited manually on the server.

## Assumptions To Validate

- The operator can run the CLI from a trusted machine.
- The server OS will be a Linux distribution with systemd.
- WireGuard is available through the server distribution package manager.
- The server has a stable public endpoint or DNS name.
- The tool may require root privileges on the server through SSH.
- Client IP addresses can be allocated from a single private WireGuard subnet.
- IPv6 support is optional for the first implementation.
- Multiple VPN servers are out of scope for the first implementation.

## Main Risks

- Losing SSH connectivity when applying routing or firewall changes.
- Accidental leakage of private keys through logs, generated artifacts, shell
  history, or world-readable files.
- State drift between local files and the server.
- Ambiguous client lifecycle behavior when a client is revoked, deleted, or
  rotated.
- Config delivery mechanisms extending the trusted surface area.
- Clash/Mihomo rule generation becoming more complex than the VPN lifecycle.

## Tradeoffs

Local file state is easy to inspect, review, back up, and version with Git. The
cost is that concurrent operators and remote state reconciliation are not first
class concerns.

SSH-based execution avoids a server-side API, daemon, and authentication model.
The cost is that command execution and error handling must be carefully designed
to remain idempotent and auditable.

Generated config files reduce manual configuration errors. The cost is that the
data model must be strict enough to prevent invalid or unsafe output.

## Phase 1 Outcome

Before implementation, create ADRs for the following decisions:

- WireGuard as the VPN backend.
- Mihomo / Clash Mi as the routing layer.
- Git-friendly local state as the source of truth.
- SSH-based server execution instead of a server daemon.
- Config delivery boundaries and first supported delivery modes.

After approval, proceed with a minimal implementation that can initialize state,
define a server, create a client, generate WireGuard configs, and render the
server-side desired configuration without applying it automatically.
