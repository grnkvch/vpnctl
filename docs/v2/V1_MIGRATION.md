# One-time v1 to v2 gateway migration

The v1 migration is a separate maintenance tool, not a permanent `vpnctl`
command. It intentionally permits gateway downtime and operates only on a
gateway host. Keep the original v1 workspace in place until v2 is explicitly
accepted.

The examples assume that the signed local v2 bundle and the standalone
`vpnctl-v1-migrate` binary were copied to the gateway with `scp`. URL delivery,
subscriptions, and QR delivery are outside v2.0.

## Inspect before the maintenance window

Run the read-only plan from the original v1 workspace:

```sh
sudo vpnctl-v1-migrate \
  --workspace /path/to/v1-workspace \
  --bundle /root/vpnctl-v2-linux-amd64.bundle \
  --public-ip 203.0.113.10 \
  --dry-run
```

`--public-ip` is always explicit. Use `--ssh-port` only when automatic
resolution cannot prove the active SSH listener. A blocking compatibility,
ownership, signature, platform, or SSH check fails before the maintenance
directory or host state is changed.

## Apply and resume

Start the accepted downtime with the same target arguments:

```sh
sudo vpnctl-v1-migrate \
  --workspace /path/to/v1-workspace \
  --bundle /root/vpnctl-v2-linux-amd64.bundle \
  --public-ip 203.0.113.10 \
  --yes
```

The tool creates a root-only maintenance package at
`/var/lib/vpnctl-v1-migration` by default. It captures the v1 binary, complete
v1 workspace, known WireGuard/sysctl/UFW files with modes, and the enabled and
active state of the v1 `wg-quick` unit. It also retains the already verified v2
bundle before the first host-role mutation. The operation journal binds these
artifacts to the original workspace and system root.

Network activation uses the ordinary independent watchdog. When instructed,
open a genuinely new SSH session and run the reported `vpnctl confirm <id>`.
Then rerun the exact migration command above. Repetition resumes the first
uncommitted phase; changed source or target inputs are a conflict.

## Validate, then choose one terminal action

Do not accept immediately. First verify every re-export action reported by the
migration and test the migrated clients that must remain usable. Acceptance is
the operator's assertion that this external validation is complete.

If v2 is correct, keep v2 and irreversibly remove the private rollback payload:

```sh
sudo vpnctl-v1-migrate \
  --workspace /path/to/v1-workspace \
  --accept --yes
```

If v2 must be abandoned before acceptance, restore v1:

```sh
sudo vpnctl-v1-migrate \
  --workspace /path/to/v1-workspace \
  --rollback --yes
```

Rollback stops only verified v2 gateway/watchdog units, restores the captured
pre-migration network snapshot, removes only verified v2 release components
and vpnctl-owned roots, restores the exact captured v1 files and binary,
restores the known UFW enabled/disabled behavior, and restores the captured
`wg-quick` enabled/active state. It finishes with an explicit action to retest
the v1 clients.

`--accept` and `--rollback` are mutually exclusive, require `--yes`, do not
accept migration target options, and are selected atomically. Either command
is resumable if interrupted, but once one action is selected the other remains
permanently rejected. The non-secret operation and terminal recovery journals
remain as the audit record after the private snapshot, stage, and recovery
bundle are removed.

Use the exact original `--workspace` and the same `--system-root` value if a
fixture root was used. A missing, changed, symlinked, incorrectly permissioned,
or foreign rollback artifact is rejected before the terminal action is selected
or a service/network mutation begins.
