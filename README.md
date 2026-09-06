# vpnctl

`vpnctl` v2 manages a small self-hosted VPN deployment with one public gateway,
multiple personal devices, and multiple private VPS nodes. The gateway is a
dedicated, operator-owned Ubuntu server in the external region. It provides
internet egress, two manually selected client/node transports, and optional
IP-only HTTPS ingress for applications running on private nodes.

The v2.0 operator entry point is
[`docs/v2/OPERATIONS.md`](docs/v2/OPERATIONS.md). It contains the supported
deployment model, both installation happy paths, routing and DNS boundaries,
webhook ownership, diagnostics, backup/update/removal, migration, and
troubleshooting. The complete stable command surface is frozen in
[`docs/v2/CLI_CONTRACT.md`](docs/v2/CLI_CONTRACT.md).

## Supported host

- Ubuntu 24.04 LTS, Linux amd64/x86_64, systemd;
- root for installation and operational commands;
- one immutable role per host: `gateway` or `node`;
- dedicated host ownership for vpnctl-managed networking and listeners;
- minimum target: 1 vCPU, 512 MiB RAM, 10 GiB disk; vpnctl can offer a managed
  1 GiB swap file during initialization.

The gateway public IPv4 is always supplied manually. vpnctl does not discover
it through an external service. The fixed public listeners are `443/TCP` for
managed HTTPS, `8443/TCP` for the restricted transport, and `51820/UDP` for
standard WireGuard. `443/UDP` and `8443/UDP` remain closed.

## Checksum-verified installation

After a v2 release is published, install its binary and retained bundle
on each server:

```sh
curl -fsSL https://raw.githubusercontent.com/vgrinkevich/vpnctl/master/scripts/install.sh | sudo sh
```

Install an explicit version:

```sh
curl -fsSL https://raw.githubusercontent.com/vgrinkevich/vpnctl/master/scripts/install.sh | sudo VPNCTL_VERSION=v2.0.0 sh
```

The bootstrap verifies canonical version, size, and SHA-256 metadata before
changing the standard installation. v2.0 relies on trusted HTTPS or SSH/`scp`
delivery and does not authenticate release publisher identity with a signature.
The exact limitation and offline flow are documented in
[`docs/v2/INSTALLATION.md`](docs/v2/INSTALLATION.md). Copying an unverified
binary by itself is not a v2 installation.

## Minimal start

On the public gateway:

```sh
sudo vpnctl init --gateway --public-ip 203.0.113.10
```

If the result reports a firewall transaction, open a genuinely new SSH session
and run its exact `vpnctl confirm <transaction-id>` command within 120 seconds.

For a personal selective client:

```sh
sudo vpnctl client add iphone telegram openai
sudo vpnctl client export iphone clash
```

For a private VPS, create an invite on the gateway, then initialize and join on
the private VPS. The invite is read from a hidden terminal prompt and is never
placed in argv:

```sh
# gateway
sudo vpnctl invite bot-server

# private VPS
sudo vpnctl init --node
sudo vpnctl join restricted telegram
```

Use the emitted `scp` hints to retrieve client profiles and the public ingress
certificate. URL delivery, subscription links, and QR export are not v2.0
delivery methods.

## Development

Run the ordinary suite:

```sh
go test ./...
```

Build the Linux binary from source for development only:

```sh
GOOS=linux GOARCH=amd64 go build -o vpnctl ./cmd/vpnctl
```

The checksum-governed release builder, provider pins, reproducibility contract,
and three-asset flow are documented in
[`docs/v2/RELEASE_BUNDLE.md`](docs/v2/RELEASE_BUNDLE.md) and
[`docs/v2/RELEASE_MANIFEST.md`](docs/v2/RELEASE_MANIFEST.md). The mandatory
actual-service/Clash Mi/Telegram release procedure is
[`docs/v2/DEPLOYED_RELEASE_GATE.md`](docs/v2/DEPLOYED_RELEASE_GATE.md). The preserved v1
installer/release code exists only for migration and regression.
