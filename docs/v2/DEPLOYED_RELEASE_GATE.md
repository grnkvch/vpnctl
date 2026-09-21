# Deployed-service v2.0 release gate

Task 16.11 qualifies a finalized development candidate as a production-ready
v2.0 release. It is not the default development workflow and it never labels or
publishes a release. The current gate implementation binds final evidence to
the same clean Git commit and one explicit stable version; this implementation
constraint does not apply to ordinary development or exploratory VPS checks.

## Development/discovery is the default — approved 2026-09-21

Follow the repository [working rules](../../AGENTS.md). Until final acceptance
is explicitly started, aim for a working end-to-end MVP and early discovery of
material blockers, not a fully green qualification run after every edit.

- Exercise the available end-to-end path, including an authorized early VPS
  pass, before polishing isolated failures. Local gate completion is not an
  automatic prerequisite for exploratory VPS work. Verify ownership, recovery
  access, necessary backups and a safe starting state first.
- Stage numbering is not a strict execution order. Respect actual dependencies,
  safety/cleanup boundaries and separately agreed manual or publication gates;
  continue independent safe scenarios after a nonblocking failure. Record
  dependent scenarios as BLOCKED, not PASS.
- Fix immediately only a safety/data/recovery threat or a blocker preventing a
  substantial part of the path. Otherwise retain observations, classify them
  as product, fixture, environment, orchestration or unknown, and group fixes
  after the discovery pass. Deferred scope stays in the backlog; only agreed
  deferred cases are SKIP. No result is made green by changing its label.
- Git commit/hash is optional provenance for discovery, not a run prerequisite
  or a result-validity key. A clean tree, a new commit, a frozen worktree and an
  unchanged HEAD are not required merely to continue development. Keep a small
  record of the scenario, outcome, actual input artifacts/helper/configuration
  and relevant environment; retain artifact checksums and a source patch or
  snapshot when testing modified source. A binary checksum alone does not
  identify a changed test oracle.
- Review the impact of each correction and repeat affected checks. A new Git
  SHA, branch, journal entry or documentation edit alone does not require a new
  build, fixture or full rerun. Changes to the product, test predicates/helpers,
  configuration, dependencies or environment can invalidate affected results;
  unknown input equivalence cannot establish reuse.
- Keep original failures and input identities. Workarounds/hot-swaps are useful
  discovery observations when labelled and safely cleaned up, but do not
  establish the final product happy-path. Discovery coverage and release
  readiness are separate statuses in the existing checklist, not new trackers.

After the grouped fixes, freeze the final candidate and complete all mandatory
local/VPS acceptance without workarounds. Keep agreed real Telegram/iOS actions
at the end and preserve their setup until then. Publication requires separate
permission. None of these process rules grants external-operation authority.

### Development execution

Run a selected registered stage directly from the current working files:

```text
scripts/v2deployed-release-gate.sh run-dev update-restore
scripts/v2deployed-release-gate.sh run-dev node-transport
scripts/v2deployed-release-gate.sh run-dev failure
```

`run-dev <stage>` requires an initialized Git repository for file inventory,
but no commit (even the first), clean tree, fixed HEAD, prepared release
candidate, or completed fast phase. It runs only the selected command and its
registry prerequisites. For example, `failure` includes `tunnel-release` and
`ingress-release`, not the entire gate. Capacity runs only when explicitly
selected as `run-dev capacity`; it is never an implicit dependency.

Each invocation creates a fresh private directory beneath
`artifacts/v2lab/development-runs/`. It retains current tracked/untracked,
non-ignored repository inputs from the explicit source, script, test, OpenSpec,
documentation and Go-module roots in `inputs.tar`, plus their modes/checksums in
`inputs.json`. Root-local files such as `bot_token`, ignored artifacts and Python
bytecode caches are excluded. `input.json` identifies the selected commands and
snapshot hashes. The runner compares the input manifest after execution;
detected drift makes the overall observation non-passing. Do not edit the
captured inputs while a check is running. This is a small provenance snapshot,
not a hermetic build, per-stage cache or proof of an unchanged environment.
Python 3 and the existing Git/jq/hash utilities are needed on the development host.

Nested harnesses use a validated repository-scoped development context; their
legacy `source_commit` field contains the literal `development`, never a fake
Git SHA. Existing provider-archive checksums, fixture ownership/readiness,
clean-state witnesses and cleanup remain required. Host-only stages never invoke
Lima. VM stages still require authorized use of the exact stopped lab fixtures
and restore them to Stopped on success, failure or handled interruption. This
command neither connects to real VPS nor provisions/recreates the fixtures.

`development.json` records `mode: development`, `source_commit: null`, status,
exit code and `production_ready: false`. It does not create `candidate.json`,
`automated.json` or `final-summary.json`. Retry a selected stage with a new
`run-dev` invocation; there is no `--resume`, cross-run reuse or rewriting of
earlier failed attempts. After safe cleanup, another independent stage can run
without first fixing an unrelated failure. The selected harness may still build
or run its own suites: this command removes the outer qualification prerequisite,
not the actual work within that stage.

### Final automation boundary

Existing final release commands still enforce clean/same-commit and full-tree
fingerprints, including for `--resume`; they cannot resume across commits.
They discard inherited development context and reject development directories.
Use them for explicit final qualification, not as an implicit prerequisite for
the next independent discovery scenario. Preserve the separately authorized VPS
plan; `run-dev` is not a replacement for its real-host or manual checks.

Reducing the final runner's Git coupling is deferred implementation work in
[PROC-002/GATE-002](../DEVELOPMENT_PROCESS_BACKLOG.md), not a prerequisite for
discovery and not a claim that current scripts already use per-stage inputs.
OpenSpec release requirements and sealed evidence formats remain unchanged.

## Final acceptance workflow

The gate intentionally exposes separate preparation, mandatory execution,
on-demand capacity, status, and finalization commands:

```text
scripts/v2deployed-release-gate.sh prepare v2.0.0
scripts/v2deployed-release-gate.sh run-fast <absolute-evidence-directory>
scripts/v2deployed-release-gate.sh run-vm <absolute-evidence-directory>
scripts/v2deployed-release-gate.sh run-automated <absolute-evidence-directory>
scripts/v2deployed-release-gate.sh run-automated --resume <absolute-evidence-directory>
scripts/v2deployed-release-gate.sh run-capacity <absolute-evidence-directory>
scripts/v2deployed-release-gate.sh run-capacity --resume <absolute-evidence-directory>
scripts/v2deployed-release-gate.sh status <absolute-evidence-directory>
scripts/v2deployed-release-gate.sh finalize <absolute-evidence-directory> <absolute-release-assets-directory>
```

Before creating this general release evidence, the same product source and
candidate bytes must pass the deliberately separate focused enrollment check:

```text
scripts/v2gateway-enrollment-e2e.sh verify <absolute-release-assets-directory>
```

That development check proves clean no-nginx Gateway bootstrap, public Node
join, selected traffic and missing-ingress repair on the fixed stopped Lima
pair. It is not a release-gate stage, cannot resume, does not write or satisfy
`automated.json`, and never runs capacity or migration. A failure prevents final
qualification, not independent safe discovery. Diagnose the affected path and
retain the failure; do not start a new full gate merely to debug it or remain
in an unbounded fix-and-rerun loop before the first end-to-end observations.

`prepare`, `status`, and `finalize` do not contact Telegram and do not mutate a
server. `run-fast` executes the host-only checks without resolving, inspecting,
or invoking `limactl`; it also removes the private VM timing/session variables
from every child command so nested tests cannot adopt the enclosing attempt's
output path. `run-vm` executes the Lima-backed checks only after every fast
result is reusable. `run-automated` is the backward-compatible ordered
composition of those two mandatory phases. Neither command runs capacity.
`run-capacity` is the only capacity entry point and may
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
compatibility command remains `run-automated [--resume]`. Both mandatory workflows run:

- requirement traceability, strict OpenSpec validation, full ordinary and race
  Go suites, and vet;
- credential lifecycle plus update/restore/migration suites;
- node transport, fleet isolation, failure, and adversarial security E2Es;
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

The current final-gate resume implementation validates the complete attempt
ledger and reuses a passing result only when the source commit, release version,
stage command contract, tracked-input
SHA-256, and required Lima image digest still match. The tracked-input digest
is intentionally conservative: it covers the complete Git tree, including all
relevant scripts, fixtures, configuration, specs, and tests. A mismatching,
failed, malformed, or interrupted attempt is retained and a new numbered
attempt is appended for that stage. Unaffected matching passes are not run
again. Fresh-attempt refusal is scoped to the selected phase; a normal
`run-automated` still refuses any existing attempt, making continuation an
explicit opt-in. Neither standalone phase writes `automated.json`; the common
aggregator does so only after the complete mandatory automatic set passes.
Capacity attempts in the same ledger are ignored by fresh automatic-attempt
refusal and by aggregation.

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

Ingress cleanup also covers a package-manager failure immediately after its
exact owner marker is created but before either custom unit exists. It skips
only units reported as `LoadState=not-found`; a foreign owner, unexpected unit
state, or real stop failure remains fail-closed and retains the owned state for
inspection.

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
`test/v2lab/deployed-release-gate/stages.json`; inexpensive checks run first.
`tunnel-release` and
`ingress-release` are canonical attempts. `failure` consumes their exact
immutable result SHA-256 values and runs only its unique source failure checks,
instead of executing both complete provider release gates a second time. Its
standalone `scripts/v2failure-e2e.sh verify` behavior remains self-contained.
The expected speedup comes only from starting the two fixtures once per VM
phase and removing those duplicate provider runs. The gate records timings for
measurement, but deliberately defines neither an estimated percentage nor a
new duration threshold.

## On-demand capacity

Capacity is advisory for each release candidate and is never invoked by
`run-fast`, `run-vm`, `run-automated`, or `finalize`. Run it explicitly when a
new capacity measurement is useful:

```text
scripts/v2deployed-release-gate.sh run-capacity <absolute-evidence-directory>
scripts/v2deployed-release-gate.sh run-capacity --resume <absolute-evidence-directory>
```

The command does not require completed fast evidence and may run before or
after `automated.json` exists. It uses a distinct `phase=capacity` fixture
session, appends immutable numbered attempts, applies the same candidate,
source-tree, stage, topology, and Lima-image fingerprints, and restores both
fixtures stopped. A failed attempt remains visible and requires explicit
`--resume`; neither failure nor success creates, replaces, removes, or is
referenced by `automated.json`.

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
`Restart=no` drop-in, completes the required `daemon-reload`, starts both fault
workers, and establishes one validated Gateway-local TLS/HTTP connection. No
measured request exists yet. The connection receives an expected HTTP 404 from
the ingress root every fixed five seconds, below nginx's 15-second idle
timeout. Its trigger wait is derived from the fixed 145-second delay, unchanged
eight-second reconnect bound, and fixed 60-second control headroom. Both values
come from the capacity manifest and therefore invalidate old attempts when
changed. Five seconds is one third of the server idle timeout; the 60-second
headroom is the existing 30-second host readiness/trigger budget plus an equal
scheduling margin, selected before the next real run.

At the 145-second boundary the helper only arms the protected restart job,
hard-kills FRPS, and reuses that exact connection for the unavailable webhook
POST. It starts no new Lima shell, Python/TLS client, policy file, or
`daemon-reload` under load. A retained connection failure remains fatal but is
collected after the KILL, so it cannot suppress the scheduled outage. The
five-second keepalive adds a conservative unscored 0.2 request/s to the local
ingress root and does not reduce or replace the fixed measured workload.
After stable recovery, the helper verifies the exact temporary drop-in and
transfers its cleanup to the parent without changing systemd under measured
load. The parent restores the original policy with its existing owner-scoped
cleanup only after all fixed loads and monitors finish. Before that successful
transfer, any helper failure or signal restores the policy immediately. The
manifest and reconnect evidence require the fixed
`post_measurement_cleanup` phase, so a different lifecycle invalidates reuse.

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

The gate writes schema-v2 `automated.json` only after every mandatory automatic stage has
a matching passing attempt and both fixtures are back in `Stopped`. The final
document records the selected attempt name and result SHA-256 for all 18 automatic stages;
`finalize` revalidates those references. The evidence directory name also
scopes each nested watchdog/tunnel/ingress attempt, so retries append new child
evidence rather than colliding with or adopting a prior attempt.

## Deployed gateway and node

Build the three checksum-governed assets from the same clean commit with the
pinned provider archives, transfer them over trusted `scp`, and install the
same version on a dedicated Ubuntu 24.04/amd64 gateway and private node.
The builder keeps its private work and later build/package subprocesses under
`umask 077`, explicitly applies canonical output modes, and runs the mandatory
Go suite in an isolated child shell with deterministic `umask 022`;
a test failure stops before any v2 asset is published and cleans the private
temporary work directory.
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
vpnctl binary matches the bundle record. It also prepares the exact gateway and
node install candidates in private temporary roots, exercising both provider
archive extraction paths without installing onto the host. It rejects a detached signature or any
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
