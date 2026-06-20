# 0009: Keep State In Workspace And Apply To System Paths

## Context

The initial MVP runs directly on the VPN server as root. It needs both
Git-friendly state and the ability to apply real system configuration for
WireGuard on Ubuntu 24.04 LTS x64.

## Decision

Use a hybrid path model:

- vpnctl state lives in the current workspace under `.vpnctl/`;
- generated review and delivery artifacts live under `.vpnctl/generated/`;
- secrets live under `.vpnctl/secrets/`;
- server apply writes system WireGuard configuration to `/etc/wireguard/`.

The primary state path is:

```text
.vpnctl/state.json
```

The expected applied WireGuard config path for the default interface is:

```text
/etc/wireguard/wg0.conf
```

## Alternatives Considered

- Store all vpnctl data in the current workspace only.
- Store vpnctl state under `/etc/vpnctl/`.
- Store everything under `/etc/wireguard/`.

## Tradeoffs

Keeping state in `.vpnctl/` makes it easier to inspect, back up, and version
with Git. Applying only the rendered server configuration to `/etc/wireguard/`
keeps the runtime system integration explicit.

The cost is that users must understand the difference between source state and
applied system configuration.

## Consequences

- `vpnctl init` creates `.vpnctl/` in the current working directory.
- `vpnctl apply` reads `.vpnctl/state.json` and writes system config only after
  explicit confirmation or dry-run review.
- `.vpnctl/secrets/` must be excluded from Git by default.
- Documentation must clearly distinguish state, generated artifacts, and
  applied system files.
