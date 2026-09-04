# Temporary operational logging

vpnctl expanded operational logging is off by default. Enabling it is an
explicit, local, time-bounded diagnostic action on either an initialized
gateway or an initialized node:

```console
sudo vpnctl log enable ingress --level trace --for 10m
sudo vpnctl log status
sudo vpnctl log disable ingress
```

The accepted scopes are `control`, `transport`, `routing`, `dns`, `tunnel`,
`ingress`, and `all`; levels are `error`, `info`, `debug`, and `trace`. The
duration is required, must be a whole number of seconds, and cannot exceed one
hour. `all` cannot overlap another active opt-in, and a second opt-in for the
same scope is rejected. Different explicit scopes can be active together.

Each session is append-only authoritative state with an immutable absolute
`started_at` and `expires_at`. Components evaluate `expires_at` before every
expanded log emission, so the session stops at the original instant even if a
controller or data-plane process was restarted. Startup/mutation reconciliation
marks elapsed records `expired`; it never derives a fresh duration from restart
time. `log status` is passive and shows only currently effective opt-ins and
their remaining seconds. `log disable <scope|all>` performs an explicit early
stop.

Journald is the default destination. `--file` chooses the fixed local path
`/var/log/vpnctl/<scope>.log`; arbitrary paths and remote destinations are not
supported. The writer refuses symlinks, non-regular files, and existing files
whose mode is not `0600`. Each record is capped at 64 KiB, the current file at
8 MiB, and rotation retains exactly three 8 MiB archives. The file is created
only when an opted-in component first emits a permitted record.

Source-level redaction is mandatory regardless of level or destination:
secrets, authorization headers, bodies, and webhook paths are never eligible
log fields. Controller, standard/restricted transport, routing, DNS, tunnel,
and ingress adapters can emit only a closed set of versioned event codes plus
validated UUIDs, generations, counters, bounded durations, and SHA-256 hashes.
There is no arbitrary string, error, URL, path, header, or body field in that
API. Policy is checked before a record is formatted, and journald and file
destinations receive the same canonical JSON line.

Provider output cannot bypass this boundary: Mihomo is rendered with silent
logging and background geodata updates disabled, nginx access/error content
logs are disabled, HTTP server error logs are discarded, and Mihomo, frp, and
nginx subprocess stdout/stderr are discarded. vpnctl does not support a remote
logging destination, telemetry, an automatic update check, or a baked project
endpoint. Network activity remains limited to separately documented data-plane
and explicit operator-requested operations.
