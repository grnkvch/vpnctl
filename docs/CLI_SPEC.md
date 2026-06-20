# CLI Specification

Status: Draft for MVP implementation.

## Command Principles

- `vpnctl` runs locally on the VPN server for the MVP.
- Server-changing commands require `root`.
- State is read from the current working directory under `.vpnctl/`.
- Secrets are never printed in normal status, errors, or logs.
- Commands that write system files support review before mutation.
- Exit code `0` means success.
- Exit code `1` means runtime or validation failure.
- Exit code `2` means CLI usage error.

## Global Flags

```text
vpnctl [--state-dir <path>] [--yes] [--verbose] <command>
```

Flags:

- `--state-dir <path>`: use a custom state directory instead of `.vpnctl`.
- `--yes`: assume yes for confirmations.
- `--verbose`: print additional non-secret diagnostics.
- `-h`, `--help`: show help.
- `-v`, `--version`: show version.

MVP default:

```text
--state-dir .vpnctl
```

## Core Commands

### `vpnctl help`

Show help.

```text
vpnctl help
vpnctl help client export
```

### `vpnctl version`

Show version.

```text
vpnctl version
```

### `vpnctl init`

Initialize local vpnctl state in the current working directory.

```text
vpnctl init [--force]
```

Flags:

- `--force`: rewrite missing default files if state already exists.

Creates:

```text
.vpnctl/
  state.json
  rulesets/
    default.json
  secrets/
  generated/
    wireguard/
    mihomo/
    delivery/
```

Default `.vpnctl/rulesets/default.json` domains:

- `chatgpt.com`
- `openai.com`
- `claude.ai`
- `anthropic.com`

Behavior:

- idempotent when run multiple times;
- does not overwrite existing secrets;
- creates Git ignore rules for secrets and generated delivery artifacts.

## Setup Commands

### `vpnctl setup`

Perform one-shot initial setup of the local Ubuntu VPN server.

```text
vpnctl setup --endpoint <host-or-ip> [flags]
```

Flags:

- `--endpoint <host-or-ip>`: public endpoint used by clients. Required.
- `--name <name>`: server name. Default: `main`.
- `--port <port>`: WireGuard listen port. Default: `51820`.
- `--interface <name>`: WireGuard interface. Default: `wg0`.
- `--subnet <cidr>`: WireGuard subnet. Default: `10.66.0.0/24`.
- `--dns <ip-list>`: custom DNS list for generated client configs. Default:
  empty.
- `--external-interface <name>`: external network interface for NAT. Default:
  auto-detected with `ip route get 1.1.1.1`.
- `--ssh-port <port>`: SSH port to allow in UFW. Default: detected from
  `SSH_CONNECTION`, fallback `22`.
- `--no-enable-ufw`: add UFW allow rules but do not enable UFW.
- `--dry-run`: show planned setup actions without changing the system.
- `--yes`: skip confirmation.

Defaults:

```text
--name main
--port 51820
--interface wg0
--subnet 10.66.0.0/24
--dns <empty>
--external-interface <auto>
--ssh-port <auto, fallback 22>
--enable-ufw true
```

Behavior:

- requires `root`;
- initializes `.vpnctl/` if needed;
- verifies Ubuntu 24.04 LTS x64;
- runs `apt update`;
- installs `wireguard`, `qrencode`, and `ufw`;
- does not run `apt upgrade -y`;
- generates server keys through system `wg`;
- stores secrets under `.vpnctl/secrets/`;
- writes `/etc/sysctl.d/99-vpnctl.conf` with `net.ipv4.ip_forward=1`;
- applies sysctl settings;
- detects external interface unless provided;
- writes `/etc/wireguard/wg0.conf`;
- configures NAT and forwarding through WireGuard `PostUp` and `PostDown`;
- allows SSH and WireGuard in UFW;
- enables UFW unless `--no-enable-ufw` is provided;
- enables and starts `wg-quick@wg0`;
- verifies `systemctl is-active wg-quick@wg0` and `wg show`;
- never prints private keys.

`--dry-run` output should include planned package installs, sysctl changes,
external interface, UFW rules, UFW enablement, WireGuard config path, and systemd
actions.

## Server Commands

### `vpnctl server init`

Initialize server settings in local state.

```text
vpnctl server init [flags]
```

Flags:

- `--name <name>`: server name. Default: `main`.
- `--endpoint <host-or-ip>`: public endpoint used by clients. Required unless
  detection is available and succeeds.
- `--port <port>`: WireGuard listen port. Default: `51820`.
- `--interface <name>`: WireGuard interface. Default: `wg0`.
- `--subnet <cidr>`: WireGuard subnet. Default: `10.66.0.0/24`.
- `--dns <ip-list>`: custom DNS list for generated client configs. Example:
  `--dns 1.1.1.1,1.0.0.1`. Default: empty.
- `--external-interface <name>`: external network interface for NAT. Default:
  auto-detected during setup/apply.
- `--force`: replace existing server settings.

Defaults:

```text
--name main
--port 51820
--interface wg0
--subnet 10.66.0.0/24
--dns <empty>
--external-interface <auto>
```

Derived values:

- server WireGuard address: first usable IP in subnet, for example `10.66.0.1`;
- first client address: next usable IP, for example `10.66.0.2`.

Validation:

- must run on Ubuntu 24.04 LTS x64 for server-changing flows;
- must validate subnet CIDR;
- must validate DNS IP list when provided;
- must fail clearly when server settings already exist and `--force` is not set.

### `vpnctl server show`

Show non-secret server state.

```text
vpnctl server show
```

Output excludes private keys.

## Ruleset Commands

### `vpnctl ruleset list`

List local rulesets.

```text
vpnctl ruleset list
```

### `vpnctl ruleset show`

Show one ruleset.

```text
vpnctl ruleset show <ruleset-id>
```

### `vpnctl ruleset add`

Create or replace a ruleset.

```text
vpnctl ruleset add <ruleset-id> --domain <comma-separated-domains> [flags]
```

Flags:

- `--domain <domains>`: comma-separated domain list. Required.
- `--name <name>`: display name. Default: derived from ruleset ID.
- `--type <type>`: ruleset type. Default: `domain-suffix`.

MVP supported type:

```text
domain-suffix
```

Example:

```text
vpnctl ruleset add default --domain chatgpt.com,openai.com,claude.ai
```

Writes:

```text
.vpnctl/rulesets/default.json
```

Validation:

- ruleset ID must be file-name safe;
- `type` must be in the supported type whitelist;
- domains must be valid domain suffixes;
- duplicates are removed deterministically;
- rulesets are validated automatically when shown, written, or used for export.

## Client Commands

### `vpnctl client create`

Create a client and generate key material.

```text
vpnctl client create <client-id> [flags]
```

Flags:

- `--name <name>`: display name. Default: client ID.
- `--platform <platform>`: optional platform metadata.
- `--tags <tag-list>`: comma-separated tags.

MVP platform values are metadata only:

- `ios`
- `macos`
- `arch`
- `ubuntu`
- `linux-vm`
- `generic`

Defaults:

```text
--name <client-id>
--platform generic
```

Behavior:

- allocates the next available client IP from the configured subnet;
- first default-subnet client receives `10.66.0.2`;
- generates client private key and public key through system `wg`;
- stores private key under `.vpnctl/secrets/clients/`;
- does not print private keys.

### `vpnctl client list`

List clients.

```text
vpnctl client list [--all]
```

Flags:

- `--all`: include revoked and deleted clients.

### `vpnctl client show`

Show one client.

```text
vpnctl client show <client-id>
```

Output excludes private keys.

### `vpnctl client revoke`

Revoke a client.

```text
vpnctl client revoke <client-id> [--reason <text>]
```

Behavior:

- marks client as revoked;
- rendered server config excludes revoked client;
- preserves metadata and historical state.

### `vpnctl client rotate-keys`

Rotate client WireGuard keys.

```text
vpnctl client rotate-keys <client-id> [--yes]
```

Behavior:

- generates new client key material;
- updates client public key in state;
- keeps client ID and assigned IP.

### `vpnctl client delete`

Delete a client from active state.

```text
vpnctl client delete <client-id> [--yes]
```

Behavior:

- requires confirmation unless `--yes` is provided;
- prefer `revoke` for normal deactivation.

## Export Commands

### `vpnctl client export`

Export a client config.

```text
vpnctl client export <client-id> --type <type> [flags]
```

Flags:

- `--type <type>`: required. Supported: `wireguard`, `clash`.
- `--output <path>`: write to path instead of default delivery directory.
- `--qr`: render QR output. Valid for `--type wireguard`.
- `--ruleset <ruleset-id>`: ruleset for Clash export. Default: `default`.
- `--no-scp-hint`: do not print the suggested `scp` command after file export.

Default output paths:

```text
.vpnctl/generated/delivery/<client-id>.conf
.vpnctl/generated/delivery/<client-id>.clash.yaml
```

WireGuard export defaults:

- `AllowedIPs = 0.0.0.0/0`
- `PersistentKeepalive = 25`
- omit `DNS` when no custom DNS is configured
- include `DNS = ...` when `vpnctl server init --dns ...` was used

Clash export defaults:

- mode: `rule`
- proxy name: `DO-WG`
- proxy group: `VPN`
- WireGuard proxy has `udp: true`
- WireGuard proxy has `allowed-ips: ['0.0.0.0/0']`
- rules come from `.vpnctl/rulesets/<ruleset-id>.json`
- if `--ruleset` is omitted, `default` is used
- final rule is `MATCH,DIRECT`
- if no custom DNS is configured, inject fallback DNS `1.1.1.1`, `8.8.8.8`
  and print a warning

Warning when fallback DNS is used:

```text
warning: no custom DNS configured; Clash Mi profile uses default DNS servers 1.1.1.1, 8.8.8.8
```

Validation:

- referenced client must exist and be active;
- referenced ruleset must exist and pass validation;
- export must not log private keys outside the explicit config artifact.

Behavior:

- regenerates the requested artifact from current state each time it runs;
- does not rotate keys;
- writes exported files on the server;
- prints the output path;
- prints an `scp` hint unless `--no-scp-hint` is provided.

Example `scp` hint:

```text
copy from your local machine:
  scp root@198.211.99.116:/root/vpnctl-state/.vpnctl/generated/delivery/iphone.clash.yaml .
```

## Apply Commands

### `vpnctl apply`

Apply desired local server config to the system.

```text
vpnctl apply [--dry-run] [--yes]
```

Flags:

- `--dry-run`: show planned changes without writing system files.
- `--yes`: skip confirmation.

Writes by default:

```text
/etc/wireguard/wg0.conf
```

Behavior:

- requires `root`;
- renders desired server config first;
- writes NAT and forwarding `PostUp` and `PostDown` rules using detected or
  configured external interface;
- validates generated config when possible;
- writes system config safely;
- enables and starts `wg-quick@wg0`;
- applies idempotently;
- avoids routing and firewall changes that can break the active SSH session.

## MVP Workflow

```text
vpnctl setup --endpoint 198.211.99.116 --dry-run
vpnctl setup --endpoint 198.211.99.116
vpnctl client create iphone --platform ios
vpnctl client export iphone --type wireguard --qr
vpnctl client export iphone --type clash
vpnctl apply --dry-run
vpnctl apply
```

Custom subnet and DNS:

```text
vpnctl setup \
  --endpoint 198.211.99.116 \
  --subnet 10.10.10.0/24 \
  --dns 1.1.1.1,1.0.0.1
```

Custom ruleset:

```text
vpnctl ruleset add custom-ai --domain chatgpt.com,openai.com,claude.ai
vpnctl client export iphone --type clash --ruleset custom-ai
```
