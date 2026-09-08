# Deployed-service v2.0 release gate

Task 16.11 is the only gate that can turn the development candidate into a
production-ready v2.0 release. It binds all evidence to the same clean Git commit
and one explicit stable version. It does not weaken the earlier automated
gates and it never labels or publishes a release.

The gate intentionally has four explicit phases:

```text
scripts/v2deployed-release-gate.sh prepare v2.0.0
scripts/v2deployed-release-gate.sh run-fast <absolute-evidence-directory>
scripts/v2deployed-release-gate.sh run-vm <absolute-evidence-directory>
scripts/v2deployed-release-gate.sh run-automated <absolute-evidence-directory>
scripts/v2deployed-release-gate.sh run-automated --resume <absolute-evidence-directory>
scripts/v2deployed-release-gate.sh status <absolute-evidence-directory>
scripts/v2deployed-release-gate.sh finalize <absolute-evidence-directory> <absolute-release-assets-directory>
```

`prepare`, `status`, and `finalize` do not contact Telegram and do not mutate a
server. `run-fast` executes the host-only checks without resolving, inspecting,
or invoking `limactl`; it also removes the private VM timing/session variables
from every child command so nested tests cannot adopt the enclosing attempt's
output path. `run-vm` executes the Lima-backed checks only after every fast
result is reusable. `run-automated` is the backward-compatible ordered
composition of those two phases and may
start only the two exact owner-controlled role-specific fixtures. Gateway is
the 1-vCPU/512-MiB minimum-capacity host; Node is the 4-vCPU/2-GiB functional
and load-generating fixture. Each child
harness retains its existing owner checks and cleanup; the top-level gate
requires both fixtures `Stopped` before starting and restores every fixture it
starts to `Stopped` on success or failure.

The evidence directory is a new mode-`0700` direct child of
`artifacts/v2lab/deployed-release-gate/`. Its top-level JSON and checksum files
are mode `0600`, ignored by Git, and contain no credential, request body,
webhook path beyond the fixed public test route, or Clash profile. `prepare` refuses to
replace an earlier directory, creates the versioned append-only automated
attempt ledger, and copies the exact Telegram helper bound to the candidate
commit. Evidence created by the previous one-shot schema remains read-only; it
is never migrated or rewritten and cannot be resumed or finalized as a new
candidate.

## Automated phase

The preferred split workflow is:

```text
scripts/v2deployed-release-gate.sh run-fast <absolute-evidence-directory>
scripts/v2deployed-release-gate.sh run-vm <absolute-evidence-directory>
```

After a phase failure, repeat only that phase with `--resume`. The complete
compatibility command remains `run-automated [--resume]`. Both workflows run:

- requirement traceability, strict OpenSpec validation, full ordinary and race
  Go suites, and vet;
- credential lifecycle plus update/restore/migration suites;
- node transport, fleet isolation, failure, adversarial security, and sustained
  minimum-host capacity E2Es;
- personal-client, transport supervision, restricted child-process, both SSH
  watchdog paths, native reverse-tunnel, and native ingress release gates.

Every stage
creates a new
`automated-attempts/<stage>/attempt-NNNN/` containing `input.json`,
`output.log`, `child-timing.json`, and `result.json`. A completed attempt is sealed mode `0500` with
mode-`0400` files. Failed attempts are retained exactly like passing attempts;
an interrupted, unsealed attempt is retained but is never reusable. The gate
never overwrites an attempt or hides a failed measurement.

After a failure, use the exact phase-specific command printed by the gate, for
example:

```text
scripts/v2deployed-release-gate.sh run-fast --resume <absolute-evidence-directory>
scripts/v2deployed-release-gate.sh run-vm --resume <absolute-evidence-directory>
```

Resume validates the complete attempt ledger and reuses a passing result only
when the source commit, release version, stage command contract, tracked-input
SHA-256, and required Lima image digest still match. The tracked-input digest
is intentionally conservative: it covers the complete Git tree, including all
relevant scripts, fixtures, configuration, specs, and tests. A mismatching,
failed, malformed, or interrupted attempt is retained and a new numbered
attempt is appended for that stage. Unaffected matching passes are not run
again. Fresh-attempt refusal is scoped to the selected phase; a normal
`run-automated` still refuses any existing attempt, making continuation an
explicit opt-in. Neither standalone phase writes `automated.json`; the common
aggregator does so only after the complete mandatory set passes.

Each `run-vm` invocation first requires both exact fixtures `Stopped` and verifies
their resource/image/network fields plus the exact stored readiness-probe SHA-256
from `test/v2lab/fixtures.json`. This catches stale Lima metadata before creating
session evidence or starting either VM; changing only CPU/RAM metadata is not a
valid fixture migration when the probe contract changed. The invocation then creates an
append-only `automated-fixture-sessions/session-NNNN/`, starts Gateway and Node
once in the parent, atomically installs and SHA-256-verifies the two exact
topology-bound lab helpers on both fixtures, captures the initial witness, and
runs every pending VM attempt sequentially without
per-stage cold boots. The existing `transport-supervision` boot-recovery check
is the only exception: it performs and records one additional Gateway restart.
A checked-in bounded manifest and read-only witness prove the absence of every
known stage-owned path, unit, process, listener, namespace, nftables object,
network object, and package mutation before the first attempt and between
attempts. Within each fixture the witness takes one snapshot per resource
class, scans `/proc` once, and evaluates every exact manifest entry from those
snapshots. Gateway and Node are inspected concurrently because their state is
independent; VM stages themselves remain strictly sequential. Witness failure
blocks later stages; only the registered harness
owner-scoped cleanup adapter may run. Success, failure, `INT`, and `TERM` all
stop Node before Gateway and verify both exact fixtures `Stopped`.

Session `input.json`, `session.log`, any numbered witness JSON files, and
`result.json` are sealed together. A fixture-start failure can legitimately have
zero witnesses; it is still an immutable failed session, records the elapsed
startup and shutdown time, and prints its log plus the exact explicit resume
command. The same applies when versioned helper setup or verification fails
before the first witness. Attempt and session results contain
non-negative monotonic diagnostic timings for validation, execution, witness,
cleanup, boot, and shutdown where applicable. These timings never change a
product latency, reconnect, capacity, or workload acceptance result.

The VM order is versioned in
`test/v2lab/deployed-release-gate/stages.json`; inexpensive checks run first and
the unchanged 300-second capacity workload runs last. `tunnel-release` and
`ingress-release` are canonical attempts. `failure` consumes their exact
immutable result SHA-256 values and runs only its unique source failure checks,
instead of executing both complete provider release gates a second time. Its
standalone `scripts/v2failure-e2e.sh verify` behavior remains self-contained.
The expected speedup comes only from starting the two fixtures once per VM
phase and removing those duplicate provider runs. The gate records timings for
measurement, but deliberately defines neither an estimated percentage nor a
new duration threshold.

For capacity, only Gateway is the normative capacity target and it remains
strictly 1 vCPU/512 MiB/10 GiB with 1 GiB managed swap. Node runs FRPC and its
watchdog, Mihomo, the webhook backend, five synthetic WireGuard clients, both
load generators, and the resource monitor on a fixed 4-vCPU/2-GiB profile. Its
services must remain functional and OOM/crash-free, but Node CPU, memory, swap,
and disk do not inherit Gateway acceptance thresholds. Neither role is resized
inside a gate run.

Before the measured interval, the Node must successfully complete an unscored
ten-second warm-up at the same 10/s webhook and 5/s Bot API rates. This removes
fixture/TLS cold start from the separately asserted steady-state sample without
changing the measured 300 seconds or its 3,000/1,500 scheduled requests. The
unchanged per-request timeout is eight seconds. Generator pools are derived
from rate multiplied by that timeout plus 20% headroom: 96 webhook workers and
48 Bot API workers. A missing, incomplete, or unsuccessful warm-up invalidates
load generation and cannot produce a passing capacity result.

The host enters the Gateway fault command before starting the measured workload
and waits for its fixed root-only ready marker. The guest process begins its
local delay only after the host supplies a fixed trigger while the fixture is
idle; load starts immediately afterward. Opening a new Lima control connection
under load therefore cannot shift the outage toward the end of the fixed
135–175-second scheduling-sanity window. The client-observed disruption instead
starts at the first failed webhook request (`D0`) and ends at the completion of
the first five consecutive later HTTP-200 requests whose end-to-end time is at
most 2,000 ms (`D1`). That first recovery cohort freezes `D1`; a later failure
cannot enlarge the interval. Requests scheduled before `D1` and completing at
or after `D0` are affected. The disruption must be at most 11.5 seconds, derived
from the accepted 3.5-second physical-outage tolerance plus the unchanged
8-second reconnect bound.

Before publishing the ready marker, that already-open helper verifies the
normal FRPS restart policy, applies and verifies its owner-scoped temporary
`Restart=no` drop-in, and completes the required `daemon-reload`. No measured
request exists yet. At the 145-second boundary it only arms the bounded probes
and protected restart job before the hard KILL; it does not create policy files
or reload systemd under load. Existing success, failure, and signal cleanup
restores the original policy.

Webhook pre-disruption and post-recovery p95/p99 remain 1,000/2,000 ms, the
global Bot API p95/p99 remain 1,000/2,000 ms with no disruption exception, and
the fixed minimum remains 2,890 successful webhook requests. Independently,
the load generator must submit and complete every scheduled request, keep
global and pre/post webhook dispatch-lag p99 plus global Bot API dispatch-lag
p99 at or below the predeclared 1,000 ms, drain its queue after recovery, and
finish the last 30 scheduled seconds with no errors and no individual request
dispatched more than 1,000 ms late. The 1,000-ms bound equals ten
webhook scheduling periods: it permits ordinary scheduler jitter but rejects a
generator that is a full second behind the declared 10-request/s profile. It is
fixed before the next real run and must not be tuned from that result.

Schema-3 capacity evidence is split into `measurement_validity`,
`gateway_capacity`, `node_fixture_health`,
`load_generator_validity`, `fault_reconnect`, `client_disruption`, and
`steady_state_latency`. Invalid/degraded generation remains a failed attempt
and is never aggregated into `automated.json`, but is classified separately
from a demonstrated Gateway capacity failure. The two-second monitors start
before load and record busy CPU, iowait, steal, load average, and run queue on
both VMs; across the fixed fault-sanity window they also retain bounded
unit/cgroup-process/TCP-state and authenticated FRPC status without opening
another Lima control session at the fault boundary. Worker occupancy and queue lag help distinguish
Node CPU starvation, worker exhaustion from hanging requests, FRP reconnect
failure, and Gateway saturation without claiming that a heuristic is causal
proof.

Each monitor obtains authoritative restart counters in one bounded systemd
query before and after measurement. It does not spawn systemd commands inside
the measured interval: fault-window service state comes directly from each
declared system-slice cgroup's `cgroup.events`, `cgroup.procs`, and bounded
process names. Only the exact Gateway FRPS cgroup may be absent during the
declared outage; another missing or malformed required observation is retained as a sanitized
unit/offset/error-class record, collection continues, and the aggregate is
classified `invalid_measurement_evidence`. Such an attempt fails but is not
reported as proof of Gateway saturation. The managed swap contract still provisions exactly
1 GiB; its observed `SwapTotal` may be exactly 4,096 bytes lower because Linux
reserves the first `mkswap` page for metadata. No swap-use or Gateway resource
threshold is changed. The top-level release aggregate remains schema v2.

The VM topology digest covers the role contract, both templates, provisioning,
and capacity load/monitor/evaluation contracts. It is stored in each VM attempt,
fixture session, and final automated aggregate. Together with the source tree,
release version, stage contract, and Lima image digest it invalidates stale
attempts without rewriting any earlier evidence.

The gate writes schema-v2 `automated.json` only after every mandatory stage has
a matching passing attempt and both fixtures are back in `Stopped`. The final
document records the selected attempt name and result SHA-256 for all 19 stages;
`finalize` revalidates those references. The evidence directory name also
scopes each nested watchdog/tunnel/ingress attempt, so retries append new child
evidence rather than colliding with or adopting a prior attempt.

## Deployed gateway and node

Build the three checksum-governed assets from the same clean commit with the
pinned provider archives, transfer them over trusted `scp`, and install the
same version on a dedicated Ubuntu 24.04/amd64 gateway and private node.
Supply the gateway public IPv4 manually. Verify healthy role/status output,
gateway-node control, restricted transport, the assigned `telegram` preset,
the five-year RSA-2048/SHA-256 IP-SAN certificate, and default-off logging.

Fill `deployment.json` without adding secrets. Its certificate SHA-256 is the
digest of the exact exported public PEM bytes:

```text
shasum -a 256 gateway.crt
```

The temporary Telegram expose must be created from the private node and may
use only an otherwise unused loopback port:

```text
sudo vpnctl expose 18081 --name vpnctl-v2-telegram-gate \
  --path /telegram/webhook
```

Do not mark its removal as passed until provider cleanup below is proven.

## Clash Mi manual phase

Copy the candidate Clash profile through the accepted `scp` workflow and keep
the profile itself outside release evidence. Record its SHA-256, exact Clash Mi
version, iOS version, UTC test time, and only the boolean results in
`clash-mi.json`.

The same profile and deployed gateway must pass import, selected TCP,
proxy-bound DNS, selected UoT, strict wrong-host rejection, selected TCP and UDP
blocking while the gateway is unavailable, no observed fail-direct behavior,
and reconnect after the gateway returns. Restore the valid profile and healthy
service after the negative cases. This phase remains manual because
Mihomo-on-Linux is not evidence for supported Clash Mi behavior.

## Telegram manual phase

Use a dedicated bot whose current webhook URL is empty. Export only the public
gateway certificate, then copy that certificate and the prepared
`telegram-webhook-gate.py` to the private node. On the node:

```text
umask 077
./telegram-webhook-gate.py \
  --public-ip <manually-entered-gateway-ipv4> \
  --certificate <absolute-path-to-exported-gateway.crt> \
  --receiver-port 18081 > telegram.json
```

The bot token is read only from `/dev/tty`. The helper keeps a random Telegram
`secret_token` only in process memory, starts a bounded `127.0.0.1` receiver,
uploads only the public certificate, and accepts only a structurally valid
update carrying the matching `X-Telegram-Bot-Api-Secret-Token` provider header.
Send one update while it waits.
Its sanitized JSON is successful only after it re-reads the provider URL and
deletes the registration it created.

If the helper reports failure after registration, do not remove the expose:
first inspect and remove the dedicated bot webhook manually. Once cleanup is
proven, copy `telegram.json` into the evidence directory, remove only
`vpnctl-v2-telegram-gate`, and set the two expose booleans in `deployment.json`.
The helper does not make Telegram integration a vpnctl product responsibility;
it is a test-only release witness.

## Checksum-governed assets and finalization

The release asset directory must contain exactly the three outputs of `scripts/release.sh`:

- `vpnctl-linux-amd64`;
- `vpnctl-v2-linux-amd64.bundle`;
- `release-checksums.txt`.

`finalize` uses the maintainer-only `vpnctl-release-verify` command. It verifies
the canonical checksum metadata, binary and bundle sizes/digests, the complete
manifest and every bundled artifact, Ubuntu 24.04/amd64,
backward-reversible migration, the requested version, and that the standalone
vpnctl binary matches the bundle record. It rejects a detached signature or any
other fourth asset. It
also requires the Telegram certificate digest to equal the deployed certificate
digest and every automated/manual boolean to be true.

This gate detects corruption and inconsistent artifacts but does not
cryptographically authenticate the publisher. The evidence operator must obtain
the three files over a trusted HTTPS or SSH/`scp` channel.

Only then is `final-summary.json` written with `production_ready=true`. It
deliberately retains `release_labeled=false`: reviewing the private evidence,
checking the host journal, completing task 16.11, creating the Git tag, and
publishing the three assets remain separate explicit maintainer actions.
