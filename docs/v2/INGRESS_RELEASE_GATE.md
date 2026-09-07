# Managed ingress production regression

Task 12.11 packages one repeatable development gate around the production
nginx renderer and the accepted minimum-host stress fixture:

```text
scripts/v2ingress-release-gate.sh run
```

The command requires clean source and the two running, isolated Ubuntu 24.04
amd64 role-specific Lima fixtures: Gateway remains 1 vCPU/512 MiB/10 GiB and
Node is the shared 4-vCPU/2-GiB functional fixture. It refuses an
existing ingress fixture, nginx package, test path, evidence path, or occupied
owned listener instead of adopting it.

The gate compiles the production ingress package for Linux/amd64 and runs three
tests with the pinned Ubuntu nginx `1.24.0` runtime:

- exact production-tree parser validation;
- one-attempt failure/partial-response behavior;
- HTTP/1.1 and HTTP/2 production-renderer forwarding plus concurrency.

The last test verifies the unchanged method, path, raw query, authorization and
Telegram application header, streaming body length/hash, HTTP/1.1 internal hop,
and replacement of spoofed forwarding headers with connection-derived values.
It admits 32 mixed HTTP/1.1+HTTP/2 requests, enforces the exact 40-request
per-expose and 64-request gateway boundaries, observes `404`, `413`, `503`, and
`504`, samples the nginx master+worker RSS below 128 MiB, and requires zero
request/response body temp files.

The same run repeats the accepted full minimum-host spike: TLS 1.2/1.3,
HTTP/1.1/2, streaming before upload completion, exact overload counts, graceful
reload, ingress cgroup peak below 128 MiB, zero OOM events, and no body files.
It then removes only its owner-marked units, files, package, guest test tools,
and listeners. Evidence is retained under the ignored
`artifacts/v2lab/ingress-release-gate/` tree and records the source commit.

## Packaged Telegram gate

The evidence directory contains `telegram-webhook-gate.py`, its manifest, and
SHA-256 checksums. Offline tests prove that it:

- reads a token only from an explicitly opened controlling TTY, never argv,
  environment, a file, log, or JSON;
- accepts only a manually supplied global IPv4 and a bounded, regular,
  no-symlink public certificate file with no private key;
- refuses to replace a pre-existing webhook;
- runs a bounded temporary receiver only on a private-node loopback port;
- registers the fixed test route `/telegram/webhook` with the custom
  certificate and a random Telegram `secret_token` held only in process
  memory;
- accepts one structurally valid Telegram update only when the reverse proxy
  preserved that secret header, and emits neither token nor secret;
- calls `deleteWebhook` only if the provider's current URL still equals the URL
  created by this run, so it cannot knowingly remove a concurrent registration.

Task 12.11 runs only mocked/offline harness tests and never contacts Telegram.
The packaged script is reserved for task 16.11 on an actually deployed gateway
and private node. Create a temporary exact-path expose from the node to an
otherwise unused loopback port, transfer the exported public certificate and
helper to that node with `scp`, and invoke it interactively on the node:

```text
sudo vpnctl expose 18081 --name vpnctl-v2-telegram-gate \
  --path /telegram/webhook
./telegram-webhook-gate.py \
  --public-ip <manually-entered-gateway-ipv4> \
  --certificate <absolute-path-to-exported-gateway.crt> \
  --receiver-port 18081
```

The bot token is then requested through `/dev/tty`. While the helper waits,
send one update to the dedicated bot. A successful JSON result proves that the
provider accepted the five-year certificate, delivered a secret-authenticated
update through the production gateway/node route, and that the helper removed
its registration. Only then run
`sudo vpnctl expose remove vpnctl-v2-telegram-gate`. If registration
ownership or cleanup cannot be proven, the script fails with a generic message:
inspect/remove the test webhook manually before removing the expose. Passing
task 12.11 does not claim Telegram compatibility or production readiness; only
the real task-16.11 run can do that.

## Accepted task-12.11 run

The gate passed on source commit
`12d7546029ce9c3ca8018142ce82c64b4dc69b8d`. Production nginx master+worker RSS
peaked at `20,238,336` bytes; the independent systemd ingress cgroup peaked at
`6,025,216` bytes with zero OOM events. Both exact overload boundaries were
observed (`40 + 5 rejected`, `64 + 8 rejected`), all four error statuses
matched, and both body-file checks were zero. The packaged Telegram harness
SHA-256 is
`e201a087c711789a32bebeb819aab4894d64c976c01e4af481852b514ac30346`.

The retained evidence is
`artifacts/v2lab/ingress-release-gate/task-12.11-12d7546/summary.json` (ignored
from release source). Postflight found no task-owned package, unit, listener,
process, guest path, or host temporary root. `production_ready` remains false
until task 16.11.
