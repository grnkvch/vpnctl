# 0018: Provide One-Shot Ubuntu Server Setup

## Context

The MVP runs directly on the VPN server as root. The operator wants vpnctl to
perform the practical system setup that was previously done manually:

- install WireGuard tooling, QR support, and UFW;
- enable IPv4 forwarding;
- generate WireGuard keys;
- detect the external network interface;
- write `/etc/wireguard/wg0.conf`;
- configure NAT and forwarding;
- allow SSH and WireGuard in UFW;
- enable UFW;
- start `wg-quick@wg0`;
- verify the resulting WireGuard status.

The desired UX is one-shot server setup, with a dry-run preview before mutation.

## Decision

Add `vpnctl setup` as the primary MVP command for initial server setup.

```text
vpnctl setup --endpoint <server-public-ip-or-host>
```

`vpnctl setup --dry-run` must show planned changes without mutating the system.

For MVP, `vpnctl setup` should:

- initialize `.vpnctl/` if needed;
- store server settings in state;
- verify Ubuntu 24.04 LTS x64;
- run `apt update`;
- install `wireguard`, `qrencode`, and `ufw`;
- not run `apt upgrade -y`;
- generate server WireGuard keys with system `wg`;
- store secrets under `.vpnctl/secrets/`;
- enable IPv4 forwarding through `/etc/sysctl.d/99-vpnctl.conf`;
- detect the external interface with `ip route get 1.1.1.1` unless explicitly
  configured;
- generate `/etc/wireguard/wg0.conf`;
- include NAT and forwarding `PostUp` and `PostDown` rules;
- allow SSH in UFW using detected or configured SSH port;
- allow WireGuard UDP port in UFW;
- enable UFW by default;
- enable and start `wg-quick@wg0`;
- verify service status and `wg show`;
- never print private keys.

For later state changes, `vpnctl apply` remains the command that applies the
current state to the local system.

## Alternatives Considered

- Keep separate `vpnctl init`, `vpnctl server init`, `vpnctl server bootstrap`,
  and `vpnctl apply` steps for initial setup.
- Only generate config and keep all system changes manual.
- Automatically run `apt upgrade -y` as part of setup.
- Keep UFW disabled by default.

## Tradeoffs

One-shot setup matches the operator's real workflow and reduces the number of
manual steps needed to get a working server.

The cost is that `setup` becomes a broad system-changing command. `--dry-run`,
clear output, root checks, SSH port detection, and secret redaction are required
to keep it understandable and safe.

`apt upgrade -y` remains out of scope because it changes unrelated system
packages and can restart services outside the VPN setup boundary.

## Consequences

- `vpnctl setup` is the recommended first-run command.
- `vpnctl init` remains useful for preparing state without changing the system.
- `vpnctl apply` remains useful after client create/revoke/rotate.
- UFW is enabled by default during setup, after SSH and WireGuard allow rules are
  installed.
- Operators can opt out of UFW enablement with `--no-enable-ufw`.
- Unit tests should use command executor abstractions for package, sysctl, UFW,
  systemd, `ip`, and `wg` operations.
