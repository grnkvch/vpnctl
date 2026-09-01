# vpnctl v2 host change journal

This journal records development-host mutations made while implementing and validating vpnctl v2. Repository files and ordinary build caches under `/tmp` are excluded. Every entry names exact targets, conflict scope, verification, and rollback.

## Operating rules

1. Never modify, start, stop, or delete a host VM, service, package, network, or file that is not explicitly owned by the `vpnctl-v2` lab.
2. Lab VM names are reserved to `vpnctl-v2-gateway` and `vpnctl-v2-node`. The pre-existing `realty-front-docker-vm` is foreign and must remain untouched.
3. Before package-manager mutation, capture installed versions and disable automatic updates and cleanup (`HOMEBREW_NO_AUTO_UPDATE=1`, `HOMEBREW_NO_INSTALL_CLEANUP=1`).
4. Prefer project-local or `/tmp` tools. A host package install requires a recorded removal command and a compatibility note for upgraded shared dependencies.
5. Before every destructive rollback, resolve and verify the exact target. Never use broad Lima or Homebrew cleanup commands.
6. Generated VM evidence lives under ignored `artifacts/v2lab/`; accepted conclusions are copied into versioned ADRs. Secrets are never recorded here.

## 2026-09-01 — Lima lab bootstrap

### Failed shared-network gateway fixture

- Requested mutation: create `vpnctl-v2-gateway` from `test/v2lab/lima.yaml`.
- Observed result: Lima created a stopped instance directory, then refused to boot because `socket_vmnet` was absent.
- Cleanup performed: `limactl delete vpnctl-v2-gateway` after `limactl list --json` confirmed the exact instance was stopped.
- Verification: the named instance disappeared from `limactl list`; no `socket_vmnet` or sudoers changes were made.
- Conflict scope: none outside the deleted lab instance.
- Rollback: already complete.

### Rootless-network gateway fixture attempt

- Requested mutation: recreate `vpnctl-v2-gateway` with 1 vCPU, 512 MiB RAM, 10 GiB disk, x86_64 QEMU, and `lima:user-v2` networking.
- Observed result: a stopped exact-name instance was created; boot stopped before guest start because Lima's x86_64 guest agent was absent.
- Conflict scope: only `~/.lima/vpnctl-v2-gateway`; no foreign instance was invoked.
- Rollback: `limactl stop vpnctl-v2-gateway` if running, verify stopped state with `limactl list --json`, then `limactl delete vpnctl-v2-gateway`.

### Homebrew guest-agent installation incident

- Requested command: `brew install lima-additional-guestagents` to support an amd64 guest on an arm64 host.
- Intended changes: install `lima-additional-guestagents` and its new `json-c` dependency.
- Actual additional changes caused by Homebrew defaults:
  - auto-updated Homebrew taps;
  - upgraded Lima `2.1.3 → 2.2.0` and QEMU `9.2.2 → 11.1.1`;
  - upgraded shared dependencies including `libunistring`, `gettext`, `capstone`, `dtc`, `glib`, `ca-certificates`, `libtasn1`, `nettle`, `p11-kit`, `gnutls`, `jpeg-turbo`, `libpng`, `libslirp`, `openssl@3`, `libssh`, `libusb`, `ncurses`, `pixman`, and `snappy`;
  - Homebrew cleanup removed old formula versions and caches, auto-removed `python@3.13`, and removed a cached Clash Mi DMG (not the installed application).
- Verification: `limactl version` reports `2.2.0`; `lima-additional-guestagents 2.2.0` and QEMU `11.1.1` installed successfully.
- Conflict scope: upgraded Lima/QEMU may affect the next start of the pre-existing foreign `realty-front-docker-vm`; that VM has not been started, stopped, deleted, or edited by this work.
- Safe partial rollback: after deleting only the two lab VMs, run `HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 brew uninstall lima-additional-guestagents` if x86_64 lab support is no longer needed.
- Exact rollback limitation: Homebrew cleanup removed prior Lima/QEMU/dependency cellars, so an exact automatic rollback is not currently guaranteed. Restoring those versions would require explicit retrieval of the old signed bottles/formula revisions and a separately reviewed plan. No such rollback will be attempted implicitly.
- Prevention: all subsequent Homebrew commands must set both opt-out environment variables and record a preflight version snapshot before execution.

### Active lab creation

- Requested mutation: start `vpnctl-v2-gateway` and `vpnctl-v2-node`, downloading only the pinned Ubuntu 24.04 amd64 image digest and writing baseline reports under ignored `artifacts/v2lab/`.
- Conflict scope: the two exact lab instances, Lima's image cache, and the isolated `192.168.104.0/24` user-v2 network. No host listener or privileged socket-vmnet network is requested.
- Full lab rollback: run `./scripts/v2lab.sh down`, verify both exact names are stopped, then run `./scripts/v2lab.sh destroy`. The pinned downloaded image may remain in Lima's shared cache; cache removal is intentionally not automated because it can affect foreign instances.
- First result: both fixtures reached Lima `READY`; provisioning created the guest-local 1 GiB swap files and installed the lab packages. Helper installation then stopped without changing host state because clean Ubuntu lacked `/usr/local/libexec`.
- Corrective action: change the guest-local helper installation to `install -D`, which creates only the missing parent directory and the two owned files `/usr/local/libexec/vpnctl-v2-lab-{report,fault}`. Re-running `up` reuses the two exact fixtures.
- Corrective rollback: deleting the lab fixtures removes these guest-local files; while retaining the fixtures, remove only the two exact paths and remove `/usr/local/libexec` only if it is empty.
- Second result: helper installation succeeded on both fixtures. Baseline serialization stopped because two memory metrics contained a literal `\\n`; the zero-byte partial `artifacts/v2lab/20260901T180558Z/gateway.json` is ignored and has no host effect. The same diagnostic exposed a positional `vmstat` parser that did not account for Ubuntu's additional `gu` CPU column.
- Corrective action: emit real newlines from the two `awk` expressions and select `vmstat` fields by the `us`, `sy`, `id`, and `wa` header names. Reinstalling the exact helper paths overwrites only lab-owned files.
- Baseline result: both reports completed at `artifacts/v2lab/20260901T180732Z/summary.json`; each guest reports Ubuntu 24.04 amd64, 1 vCPU, 453 MiB usable RAM inside the 512 MiB VM limit, 1 GiB swap, a 10 GB provisioned disk (8.65 GiB filesystem), and successful peer connectivity. An escalated final Lima metadata snapshot is still pending.
- Status: fixtures running; baseline complete.

### Planned lab network-fault verification

- Requested mutation: on `vpnctl-v2-node` only, apply a 250 ms `netem` delay toward the gateway, replace it with an nftables partition limited to the gateway peer IP, then clear both controls.
- Conflict scope: guest-local `eth0` root qdisc and the dedicated guest-local `inet vpnctl_v2_lab_fault` table. Host interfaces, host firewall, and the gateway guest are not modified.
- Rollback before every transition and after the test: `./scripts/v2lab.sh fault node clear`. The helper deletes only a detected `netem` root qdisc and the exact dedicated nftables table; deleting the node fixture is the fallback full rollback.
- Verification: capture a report after latency, partition, and clear; finish only after `tc qdisc` and the dedicated nftables table are absent and peer connectivity is restored.
- Result: `artifacts/v2lab/20260901-latency-250ms/summary.json` measured 250.974–253.781 ms and 0% loss; `artifacts/v2lab/20260901-partition/summary.json` measured 100% peer loss in both directions; `artifacts/v2lab/20260901-cleared/summary.json` measured restored 0% loss and 1.152–2.451 ms latency.
- Conflict hardening: netem now uses the dedicated `1abc:` qdisc handle on only the peer-route interface, and clear refuses to remove another qdisc. Lima orchestration validates VM type, architecture, exact resource limits, image digest, and network before reusing, stopping, or deleting an exact-name instance; deletion also refuses running instances.
- Final verification: the dedicated nftables table was absent, the ordinary `fq_codel` qdisc was restored, and a second dedicated-handle cycle showed `qdisc netem 1abc:` during the fault and restored 0% loss afterward at `artifacts/v2lab/20260901-final-cleared/summary.json`.
- Final Lima metadata: both lab fixtures are `Running`, `qemu`, `x86_64`, 1 vCPU, 536870912 bytes configured RAM, and 10737418240 bytes configured disk. The foreign `realty-front-docker-vm` was observed as `Running` but was not started, stopped, edited, or otherwise targeted by any lab command.
- Current rollback: `./scripts/v2lab.sh down` stops only contract-matching lab fixtures. After their stopped state is verified, `./scripts/v2lab.sh destroy` deletes only those fixtures. The fixtures remain running for the immediately following transport spikes.
- Status: complete; no network fault remains active.
