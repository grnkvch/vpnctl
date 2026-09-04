# vpnctl

`vpnctl` is a small CLI for managing a personal self-hosted WireGuard VPN
server and its client configs.

The current MVP is designed for one operator, one Ubuntu VPS, and a small number
of clients. It runs directly on the server as `root`, stores source-of-truth
state in `.vpnctl/`, and applies rendered WireGuard configuration to the local
system.

## Features

- One-shot Ubuntu server setup for WireGuard, UFW, forwarding, and QR support.
- Local Git-friendly state under `.vpnctl/`.
- Secret key storage under `.vpnctl/secrets/`.
- WireGuard client creation, listing, show, revoke, key rotation, and deletion.
- Server config apply from current state.
- WireGuard client export with optional QR PNG.
- Clash/Mihomo profile export with editable domain rulesets.
- `scp` hints for copying generated client artifacts from the server.

## Supported Platform

Server target for the MVP:

- Ubuntu 24.04 LTS
- Linux amd64/x86_64
- systemd
- root execution for system-changing commands

Do not run `vpnctl setup` or `vpnctl apply` on a development laptop. They write
system files and run `systemctl`, `ufw`, `sysctl`, and WireGuard commands.

## Install

After a GitHub release has been published, install on the server with:

```sh
curl -fsSL https://raw.githubusercontent.com/vgrinkevich/vpnctl/master/scripts/install.sh | sudo sh
```

Install a specific release:

```sh
curl -fsSL https://raw.githubusercontent.com/vgrinkevich/vpnctl/master/scripts/install.sh | sudo VPNCTL_VERSION=v2.0.0 sh
```

Useful installer environment variables:

```text
VPNCTL_VERSION            Signed release tag to install. Default: latest
VPNCTL_REPO               GitHub repo. Default: vgrinkevich/vpnctl
VPNCTL_RELEASE_ASSET_DIR  Absolute local directory containing all four signed assets
```

The v2 installer verifies Ed25519-signed version/size/SHA-256 metadata before
changing the standard binary or retained bundle paths. See
[`docs/v2/INSTALLATION.md`](docs/v2/INSTALLATION.md) for the online and offline
`scp` flows. The preserved v1 scripts are named `install-v1.sh` and
`release-v1.sh`.

## Build From Source

```sh
go test ./...
GOOS=linux GOARCH=amd64 go build -o vpnctl ./cmd/vpnctl
```

For a manual/offline installation, copy the four signed v2 release assets and
run the installer with `VPNCTL_RELEASE_ASSET_DIR`; copying an unverified binary
alone is not a v2 installation.

## First Server Setup

Run these commands on the Ubuntu server as `root`.

```sh
mkdir -p ~/vpnctl-state
cd ~/vpnctl-state

vpnctl setup --endpoint SERVER_IP --dry-run
vpnctl setup --endpoint SERVER_IP
```

`--endpoint` is the public IP address or DNS name clients should use to reach
the VPN server. It is intentionally explicit because VPS networking can include
private IPs, floating IPs, NAT, IPv6, or DNS-based endpoints.

Check non-secret server state:

```sh
vpnctl server show
```

## Client Workflow

Create a client:

```sh
vpnctl client create iphone --platform ios
vpnctl client list
vpnctl client show iphone
```

Export client configs:

```sh
vpnctl client export iphone --type wireguard --qr
vpnctl client export iphone --type clash
```

Apply server-side peer changes:

```sh
vpnctl apply --dry-run
vpnctl apply
```

After export, `vpnctl` prints the generated file path and an `scp` hint for
copying the artifact from the server.

## Client Lifecycle

Revoke a client and apply the server config:

```sh
vpnctl client revoke iphone --reason "lost device"
vpnctl apply
```

Rotate client keys, then export a fresh config and apply the server config:

```sh
vpnctl client rotate-keys iphone --yes
vpnctl client export iphone --type wireguard --qr
vpnctl apply
```

Delete a client from active state:

```sh
vpnctl client delete iphone --yes
vpnctl apply
```

Deleted and revoked clients are hidden from `client list` by default. To include
them:

```sh
vpnctl client list --all
```

## Rulesets And Clash Export

The default Clash/Mihomo ruleset routes these domains through the VPN:

- `chatgpt.com`
- `openai.com`
- `claude.ai`
- `anthropic.com`

Create or replace a ruleset:

```sh
vpnctl ruleset add custom-ai --domain chatgpt.com,openai.com,claude.ai
vpnctl ruleset show custom-ai
vpnctl client export iphone --type clash --ruleset custom-ai
```

Non-matching Clash traffic stays direct via the final `MATCH,DIRECT` rule.

## Release Artifacts

Create signed v2 release artifacts locally from the already downloaded pinned
provider archives and an external mode-`0600` release signing key:

```sh
VPNCTL_RELEASE_SIGNING_KEY=/secure/vpnctl-release-key.pem \
VPNCTL_MIHOMO_ARCHIVE=/cache/mihomo-linux-amd64-v1.19.30.gz \
VPNCTL_FRP_ARCHIVE=/cache/frp_0.69.0_linux_amd64.tar.gz \
scripts/release.sh v2.0.0
```

The script runs tests, reproducibly builds `linux/amd64`, verifies pinned
provider bytes, and writes:

```text
dist/vpnctl-linux-amd64
dist/vpnctl-v2-linux-amd64.bundle
dist/release-checksums.txt
dist/release-checksums.txt.sig
```

Upload all four files to the matching GitHub release. Private signing material
is never copied into `dist/` or stored in the repository.

## State Layout

Default state directory:

```text
.vpnctl/
  state.json
  rulesets/
  secrets/
  generated/
```

Secrets and generated artifacts are ignored by Git by default.

## Development

Run the test suite:

```sh
go test ./...
```

Project documentation lives under `docs/`, including the CLI contract and ADRs.
