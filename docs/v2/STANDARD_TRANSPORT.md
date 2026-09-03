# Standard WireGuard transport

The v2 `standard` provider uses Ubuntu 24.04 kernel WireGuard and
`wireguard-tools`. Its public gateway contract is fixed to `51820/UDP`; it
does not open TCP/51820 or any alternative UDP port. Exact compatible Ubuntu
package and kernel ranges remain release-manifest data owned by task 14.1.

## Identities and configuration

The gateway owns one generation-1 provider credential at the opaque secret
reference `wireguard-key:gateway-standard-g1`. Provisioning uses
create-if-absent storage and re-derives the public key before adopting either
an existing credential or a concurrent winner. Only the reference,
generation, and public key cross the provider boundary.

Every active client or node contributes its own standard public key and exact
overlay `/32` to the shared gateway interface. Disabled transports and
revoked/deleted identities are omitted. Duplicate public keys are rejected.
The gateway addresses are the reserved `.1` addresses of the client and node
pools. The renderer is deterministic and emits `Table = off` with no
`PostUp`/`PostDown` firewall or NAT commands: the owned `inet vpnctl` table is
the only policy/NAT authority.

A private node keeps its WireGuard private key locally and must prove that it
matches the public key in its authoritative transport record. Its config uses
the manually supplied gateway IPv4 on UDP/51820, `AllowedIPs = 0.0.0.0/0`,
and keepalive 25, while `Table = off` prevents an implicit main-table default
route. The standard service installs only the node-pool gateway `.1/32`
bootstrap route. Task 10.4 owns fail-closed selected/default routing and binds
control, reverse tunnel, and selected traffic to the active provider.

Generated role configs live at:

- `/etc/vpnctl/generated/gateway/vpnctl-wg.conf`
- `/etc/vpnctl/generated/node/vpnctl-wg.conf`

They are root-only `0600` files. The hidden `gateway-standard` and
`node-standard` service modes validate with `wg-quick strip`, reconcile a
stale `vpnctl-wg` only after its public key proves ownership, start the kernel
interface, verify the gateway listener, remain alive for systemd supervision,
and remove the interface on shutdown. Gateway init publishes both the standard
and restricted configuration plus hash-bound readiness markers before either
listener starts. Both gateway units are enabled independently and use
`Restart=on-failure`, so a process failure or gateway reboot restores both
listeners without changing any node's active/standby selection.

## Health semantics

Health observations use only `wg show` and `ip address show`. They verify the
interface public key, exact IPv4 overlay addresses, expected peer and
AllowedIPs, gateway UDP/51820 listener, and—when required—a bounded recent
handshake. They never send application probes, invoke systemd, repair state,
or inspect the restricted transport.

Runtime role and health are independent. A missing or stale handshake reports
an active standard transport as degraded without selecting standby. An
inactive standby can report unavailable while remaining the configured
standby. Provider-neutral non-mutating four-path test orchestration is in
place; manual make-before-break switching remains task 8.8.

## Packet acceptance

The disposable namespace acceptance lab creates one real gateway WireGuard
interface, five client peers, two node peers, and a synthetic internet host.
It loads firewall bytes from the production renderer and verifies:

- all seven unique identities complete real WireGuard handshakes;
- every identity reaches TCP and UDP internet services through gateway NAT;
- clients reach only shared gateway DNS, while nodes also reach internal
  control and reverse-tunnel ports;
- client/client, client/node, node/client, and node/node forwarding is blocked;
- the gateway listener remains UDP/51820 and all temporary resources are
  removed.

Run `./scripts/v2standard-test.sh status|verify|cleanup`. The wrapper refuses
an unowned runtime or a lab VM outside the pinned 1-vCPU/512-MiB/10-GiB
contract.
