# Managed ingress production regression

Task 12.11 packages one repeatable development gate around the production
nginx renderer and the accepted minimum-host stress fixture:

```text
scripts/v2ingress-release-gate.sh run
```

The command requires clean source and the two running, isolated Ubuntu 24.04
amd64 Lima fixtures at 1 vCPU, 512 MiB RAM, and 10 GiB disk. It refuses an
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
- registers the fixed test route `/telegram/webhook`, confirms the custom
  certificate and one new receiver request, and emits no sensitive value;
- calls `deleteWebhook` only if the provider's current URL still equals the URL
  created by this run, so it cannot knowingly remove a concurrent registration.

Task 12.11 runs only mocked/offline harness tests and never contacts Telegram.
The packaged script is reserved for task 16.11 on an actually deployed gateway
and private-node test receiver. At that gate, invoke it interactively:

```text
./telegram-webhook-gate.py \
  --public-ip <manually-entered-gateway-ipv4> \
  --certificate <absolute-path-to-exported-gateway.crt>
```

The bot token is then requested through `/dev/tty`. If registration ownership
or cleanup cannot be proven, the script fails with a generic message and the
operator must inspect/remove the test webhook manually. Passing task 12.11 does
not claim Telegram compatibility or production readiness; only the real
registration, incoming request, and owner-checked cleanup in task 16.11 can do
that.

## Accepted task-12.11 run

The gate passed on source commit
`774c46e16b5197cddd2f2be2aef1133a6a01778c`. Production nginx master+worker RSS
peaked at `19,869,696` bytes; the independent systemd ingress cgroup peaked at
`6,135,808` bytes with zero OOM events. Both exact overload boundaries were
observed (`40 + 5 rejected`, `64 + 8 rejected`), all four error statuses
matched, and both body-file checks were zero. The packaged Telegram harness
SHA-256 is
`3c172406f861687040272214b6fc0ce7d6e90ac9e4e26ee042bede2755269b47`.

The retained evidence is
`artifacts/v2lab/ingress-release-gate/task-12.11-20260904/summary.json` (ignored
from release source). Postflight found no task-owned package, unit, listener,
process, guest path, or host temporary root. `production_ready` remains false
until task 16.11.
