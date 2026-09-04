# Public ingress certificate

vpnctl keeps the gateway's ordinary HTTPS identity separate from its internal
control CA. Gateway initialization creates the public identity once and commits
its metadata with generation 1 state; an identical later `init --gateway` is a
no-op and does not replace it.

## Certificate contract

- self-signed RSA-2048 certificate signed with SHA-256;
- the manually supplied canonical public IPv4 is the single IP SAN and the
  compatibility CN;
- exact default lifetime of 1825 days and an expiry warning from 180 days
  remaining;
- PKCS#8 private key and public certificate are retained in the root-only
  secret store; state contains only identity, validity, fingerprint, generation,
  and opaque references;
- the public ingress identity is independent from control/enrollment identities,
  so its later rotation cannot re-enroll nodes or change control trust.

`vpnctl cert show [--json]` is gateway-only and returns public metadata. It is
healthy before the warning boundary, expiring from the exact 180-day boundary,
and unavailable after expiry. Expiring and expired results identify manual
rotation as the next action.

`vpnctl cert rotate [--dry-run] [--yes]` is gateway-only and manual-only. Its
read-only plan lists every ready or degraded expose affected by the new public
identity without exposing webhook paths. Immediate application requires the
ordinary availability-impact confirmation; `--defer` is rejected. The command
creates the next generation under new opaque secret references, validates and
activates the complete ingress generation, atomically replaces the public
export, and then commits state. Short ingress downtime is permitted during the
runtime activation.

The successful state keeps the current generation and exactly one previous
public certificate/key generation as its bounded rollback snapshot. Starting a
later explicit rotation removes the superseded older snapshot before creating
the next candidate. A known pre-commit failure restores the prior runtime and
public export and removes the candidate secrets. An ambiguous state-persistence
outcome is reported as uncertain and is not blindly rolled back. Rotation
changes neither the logical public-certificate ID nor the control CA, control
server identity, enrollment signer, node records, transports, or node trust.
There is no schedule or automatic rotation.

After success, one `reregister_external_webhook` action is returned for every
affected expose. vpnctl never registers or updates a provider webhook itself;
the application owner uses the unchanged public URL and the newly exported
certificate with its provider.

`vpnctl cert export [absolute-output-path] [--json]` validates the stored PEM
against authoritative metadata and writes exactly one public certificate. The
default path is `/var/lib/vpnctl/exports/gateway.crt`; creation is atomic,
mode `0644`, idempotent for identical content, and refuses symlinks or an
existing different file. Command output reports the public `output_path`,
fingerprint, and an `scp` hint. It never reads, prints, or copies the private key.

The automated Telegram compatibility fixture checks the public upload boundary
and multipart certificate shape without a bot token or provider call. Actual
`setWebhook`, incoming request, and five-year provider acceptance remain the
deployed-service release gate in task 16.11.
