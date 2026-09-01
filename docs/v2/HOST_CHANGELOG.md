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

## 2026-09-01 — Restricted transport spike preparation

### Planned Lima forwarding isolation

- Requested mutation: stop only `vpnctl-v2-gateway` and `vpnctl-v2-node`, add ignore rules for guest ports `1053`, `8443`, `17890`, `18080`, and `19090` to both exact instance configurations as applicable, then restart only those fixtures.
- Reason: prevent Lima's dynamic forwarder from creating development-host listeners when the guest spike starts its services.
- Conflict scope: only the two contract-matching lab instance configurations and their temporary downtime. The foreign `realty-front-docker-vm` is not a command target.
- Preflight: verify exact names, QEMU/amd64, 1 vCPU, 512 MiB, 10 GiB, pinned image digest, rootless network, and current running state before stopping or editing.
- Rollback: stop the two exact lab fixtures, remove only the five matching `portForwards` entries with a separately reviewed `limactl edit`, and restart. Keeping the ignore rules is safe and preferred because it prevents host exposure; deleting/recreating the fixtures from the versioned template produces the same isolated state.
- First stop result: no VM changed state because Lima 2.2 rejected a multi-name `stop` invocation before acting. The lab orchestrator was corrected to invoke `stop`/`delete` once per already contract-validated exact instance.
- Retry result: both exact fixtures stopped cleanly. Five `proto:any` ignore entries were added to each stopped configuration and a read-only snapshot confirmed the entries before restart.
- Boot observation: the already-created fixtures embed the original idempotent-but-networked provision script, so this restart repeats `apt update/install` and adds several minutes of amd64-emulated boot time. The versioned template now writes `/var/lib/vpnctl-v2-lab.provisioned` after success and skips package networking on subsequent boots of newly created fixtures. Existing fixtures are not edited out-of-band; they retain the old hook until safely recreated from the template.
- Restart result: both fixtures returned to `READY` and produced `artifacts/v2lab/20260901-port-isolation/summary.json`. No spike listeners exist yet; the ignore rules will be verified again after service start by checking both Lima metadata and host listeners.
- Status: complete; both fixtures running with forwarding isolation.

### Planned Mihomo/ShadowTLS candidate installation

- Requested mutation: download the official pinned Mihomo `v1.19.30` amd64 gzip into ignored `artifacts/v2lab/cache/`, verify SHA-256 `cf06ce2c7d1421bdbda14ee4a5b6046672dc35ebf8eecd8e77504ec3c0ed9a84`, and install the binary, generated configs, three systemd units, and three state directories only inside the two lab fixtures.
- Guest ownership: all paths use `vpnctl-v2-spike` names and `/etc/vpnctl-v2-spike/restricted/.owner`; existing paths without the exact marker and occupied ports are hard conflicts. Units are started but not enabled.
- Listener scope: gateway `8443/TCP` plus `127.0.0.1:18080`; node `127.0.0.1:{1053,17890,19090}`. Lima ignore rules prevent host forwarding. No `8443/UDP` listener is configured.
- External dependency: `www.microsoft.com:443`, already observed from the gateway with TLS 1.3 and valid certificate verification, is pinned for the spike. No automatic fallback is used.
- Logging: `info` is a temporary explicit opt-in inside disposable fixtures for test evidence. Credentials and generated client profiles remain mode `0600` under ignored artifacts and are not recorded in this journal.
- Rollback: `./scripts/v2restricted-spike.sh stop` stops only the exact units. `uninstall` first verifies the marker, then stops/cleans those units and removes only their exact unit, config, binary, and systemd-managed state paths. Deleting the two lab fixtures remains the full fallback. Host cache/evidence removal is manual and must target the exact ignored directory.
- Result: the official 18,868,732-byte archive was downloaded and checksum-verified; both rendered configs passed pinned `mihomo -t`; owner-marked files and three non-enabled units were installed and reached active state.
- Host isolation verification: with all guest services running, `lsof` found no development-host TCP listener on `1053`, `8443`, `17890`, `18080`, or `19090`.
- Status: installed and running inside the two fixtures; no host listener created.

### Planned restricted E2E and reconnect mutations

- Requested runtime mutations: temporarily select the deliberately wrong ShadowTLS host in the node's in-memory `RESTRICTED` group, require strict failure, restore the pinned selection, then separately stop and restart only `vpnctl-v2-spike-restricted-gateway.service` to verify node reconnect.
- Persistence/conflict scope: no generated config or desired state changes; the selection is controller-memory-only. A shell trap restores `RESTRICTED-VALID` on every exit. The reconnect trap restarts the exact gateway spike unit on every exit.
- Verification: selected TCP reaches only the gateway-loopback token, selected DNS returns through the proxy-bound DoH upstream, wrong-host strict mode fails, correct host recovers, gateway outage fails, restart recovers without node restart, and resource/socket evidence is captured under ignored artifacts.
- Rollback: restore `RESTRICTED-VALID`; start the exact gateway unit; if either cannot be confirmed, stop all three spike units with `./scripts/v2restricted-spike.sh stop` while preserving evidence.
- Automated E2E result: passed at `artifacts/v2lab/restricted-spike/evidence-final/`. The gateway-loopback token was unreachable direct and reachable through restricted; the proxy-bound DoH request returned A records; temporary `www.apple.com` selection failed certificate validation; pinned `www.microsoft.com` recovered; `8443/UDP` was absent.
- Reconnect result: passed at `artifacts/v2lab/restricted-spike/reconnect-final/`. The outage probe failed while the exact gateway unit was stopped, recovery succeeded on the first bounded attempt, gateway Mihomo changed PID `2200 → 2375`, and node Mihomo remained PID `2178`.
- Resource snapshot: gateway/node Mihomo RSS was approximately 38/46 MiB; total guest RSS approximately 307/304 MiB. Both guests retained 1 GiB swap and healthy peer connectivity.
- Cleanup verification: the in-memory selection is `RESTRICTED-VALID`; the gateway unit is running; the temporary secret-bearing `/tmp/clash-mi-lab.yaml` was removed. No fault or wrong-host selection remains active.
- Logging opt-in closure: after evidence capture, `./scripts/v2restricted-spike.sh stop` stopped all three exact spike units; `systemctl show` confirmed `ActiveState=inactive` for gateway, node, and echo. Generated configs and evidence remain for an explicit rerun; no restricted/test listener or continuing Mihomo test log remains.
- Current host state: both isolated lab VMs remain running for the next implementation step, while all restricted spike units are inactive. `./scripts/v2lab.sh down` remains the exact VM-level rollback.
- Status: automated mutations complete and left inactive. Actual Clash Mi compatibility remains a manual product gate, so OpenSpec task 2.2 is not marked complete.

## 2026-09-01 — Restricted UDP-over-TCP spike

### Planned UoT installation and fault verification

- Accepted gate change: the prior automated gateway/Linux-node evidence completes task 2.2; actual Clash Mi execution is deferred to the deployed-service v2.0 release gate and remains mandatory before production approval.
- Requested guest mutation: replace only the owner-marked restricted node/client candidate configs with pinned Mihomo UoT v2 enabled, add the exact lab-owned executables `/usr/local/libexec/vpnctl-v2-spike/{udp-echo,udp-probe}`, add `vpnctl-v2-spike-udp-echo.service`, and restart only the four spike units.
- Listener scope: the added echo service uses `18080/UDP` inside the gateway fixture. The existing Lima `proto:any` ignore rule for guest port `18080` prevents development-host forwarding. Restricted ingress remains only `8443/TCP`; no `8443/UDP` socket is configured.
- Positive verification: a SOCKS5 UDP-associate probe targets the gateway echo through Mihomo with `udp-over-tcp: true` and version 2. A temporary exact-name `inet vpnctl_v2_spike_uot_capture` table on each lab guest counts protected TCP and any node-to-gateway native UDP.
- Failure verification: select the explicitly UoT-disabled but TCP-capable negative-control outbound, require selected TCP to keep working, require the UDP probe to fail, and require both native-UDP counters to remain zero.
- Conflict scope: only the two exact contract-matching lab fixtures and the ignored evidence directory. The foreign `realty-front-docker-vm`, host firewall, host routes, and unrelated guest nftables tables are not targets.
- Automatic rollback: shell traps restore `RESTRICTED-VALID` and delete only `inet vpnctl_v2_spike_uot_capture` on either exit path. `./scripts/v2restricted-spike.sh stop` stops only the spike units and clears the same exact table. `uninstall` additionally verifies the owner marker before removing the exact unit/config/executable/state paths.
- Full rollback: stop and destroy only `vpnctl-v2-gateway` and `vpnctl-v2-node` through `scripts/v2lab.sh`; the ignored cache/evidence remains until separately reviewed for exact-path removal.
- First installation result: both pinned Mihomo configs validated and all four exact spike units reached active state. The first positive UDP probe timed out because its test destination was not in the node's selected rules and the journal showed `match Match ... using DIRECT`; the temporary gateway counter/drop guard prevented that test-only direct datagram from reaching the echo service.
- First-run rollback verification: the failure trap restored `RESTRICTED-VALID`; `inet vpnctl_v2_spike_uot_capture` was absent from both guests; all four spike services remained active for correction. Mihomo's local API reported `udp=true,uot=true` for `RESTRICTED-VALID` and `udp=false,uot=false` for the negative control.
- Corrective action: add the rendered gateway `/32` only to this spike's selected rules so the UDP test target exercises the intended restricted policy, then owner-checked reinstall and repeat the complete capture. No host or foreign-VM change is required.
- Second-run result: selected classification and UoT were confirmed on both sides, but gateway Mihomo could not send the decoded UDP datagram to its own non-loopback address and reported `netlinkrib: address family not supported by protocol`; no native UDP escaped and both capture tables were removed by the failure trap.
- Second corrective action: target the gateway loopback echo at `127.0.0.1:18080`, matching the established TCP probe topology. Add a separate node output counter for UDP to that exact loopback target so a direct fallback cannot be hidden by the topology; retain the outer gateway/native-UDP counters and closed `8443/UDP` assertion.
- Third-run result: UoT again reached gateway and was decoded with the correct `127.0.0.1:18080` target, but gateway Mihomo reported the same `netlinkrib: address family not supported by protocol` before sending to echo. Failure traps again removed both capture tables and restored the valid selector.
- Root cause: the restricted Mihomo systemd units allowed only `AF_INET`, `AF_INET6`, and `AF_UNIX`; Mihomo's UDP direct outbound performs an `AF_NETLINK` route lookup. TCP did not expose this sandbox omission.
- Corrective action: add `AF_NETLINK` only to the two restricted Mihomo units' `RestrictAddressFamilies`. Keep the echo unit unchanged and reassert that no `8443/UDP` socket exists.
- AF_NETLINK rerun result: positive UoT passed and the capture recorded protected TCP with zero native UDP. The UoT-disabled negative control exposed a Mihomo safety hazard: selecting an outbound with `udp=false,uot=false` caused one matched UDP datagram to be attempted through `DIRECT`; the dedicated loopback counter caught it and failed the run. No datagram reached gateway and both capture tables were removed by the trap.
- Corrective action: add a separate `RESTRICTED-UDP` readiness group. It selects the restricted path only after UoT validation; the broken-UoT scenario explicitly selects `REJECT-DROP` before probing while TCP remains on the working restricted outbound. Save local API evidence for both `uot=false` and the active reject guard.
- Architectural consequence: vpnctl must never rely on Mihomo's `udp=false` capability flag alone for fail-closed behavior. The production renderer/readiness transaction needs an explicit UDP reject target plus the independent kernel leak guard already required by the design.
- Explicit-guard result: passed. Positive capture recorded 13 protected TCP packets and zero native/direct UDP; the selected UDP echo returned `vpnctl-v2-uot-ok`. With runtime `udp=false,uot=false` and `RESTRICTED-UDP` set to `REJECT-DROP`, TCP remained healthy with 17 protected packets, the UDP probe timed out, and all node-gateway, node-loopback, and gateway-input leak counters remained zero.
- Reconnect result: restarting only `vpnctl-v2-spike-restricted-gateway.service` caused the outage probe to fail, then both TCP and UoT recovered on their first bounded attempts without restarting node Mihomo.
- Cleanup verification: runtime selectors were restored to `RESTRICTED-VALID` and `RESTRICTED-UDP → RESTRICTED`; the exact capture table was absent on both guests; `8443/UDP` remained closed.

### Correct wildcard forwarding isolation

- Unexpected host observation: while the spike units were active, Lima hostagent exposed `127.0.0.1:8443/TCP` and `127.0.0.1:18080/UDP` on the development host even though per-port ignore entries existed. Stopping the four exact spike units removed both listeners; all units are currently inactive.
- Root cause: the existing rendered ignore rules defaulted `guestIP` to `127.0.0.1`, while gateway spike listeners bind wildcard addresses. The running hostagent therefore did not match those rules.
- Official Lima rule selected: each exact ignored port uses `guestIP: 0.0.0.0`, explicit `guestIPMustBeZero: false`, `proto: any`, and `ignore: true`, which matches listeners bound on any guest interface under Lima 2.x semantics.
- Planned host mutation: with both exact lab VMs contract-validated and spike units inactive, stop only `vpnctl-v2-gateway` and `vpnctl-v2-node`, update only their five existing port-forward entries, restart the two lab VMs, rerun the spike, and confirm host `lsof` has no matching listeners while guest services are active.
- Rollback: stop those same two exact VMs, restore only the ten edited `guestIP`/`guestIPMustBeZero` values, and restart. The old values are known to expose local host listeners and therefore are retained only as an audit rollback, not a recommended state. Deleting/recreating the two lab VMs from the corrected versioned template is the clean full rollback.
- Applied correction: both exact lab VMs were contract-validated, stopped, and edited only at the five existing port-forward entries. Read-only metadata confirmed `guestIP=0.0.0.0`, `guestIPMustBeZero=false`, `proto=any`, and `ignore=true` on every entry before restart. The foreign VM was not a command target.
- Restart result: both lab VMs returned to `READY` and produced `artifacts/v2lab/20260901-uot-forwarding-fixed/summary.json`. The old embedded provision hook repeated inside each guest; no Homebrew or other host package mutation occurred.
- Isolation verification: after all four spike units were active and no `limactl shell` command remained, host `lsof` found no TCP or UDP listener on `1053`, `8443`, `17890`, `18080`, or `19090`.
- Final isolated E2E: `artifacts/v2lab/restricted-spike/uot-final-isolated/summary.json` passed TCP, DNS, strict-host, positive UoT, explicit broken-UoT reject, zero-leak counters, and closed `8443/UDP`. `uot-reconnect-final-isolated/summary.json` recorded TCP and UoT recovery on the first attempt.
- Logging/runtime closure: `./scripts/v2restricted-spike.sh stop` stopped the four exact units and removed the exact capture table. Both lab VMs remain running for the next spike, with spike services inactive and no development-host spike listeners.
- Status: task 2.3 complete; forwarding isolation corrected and verified.

## 2026-09-01 — Restricted UDP-over-TCP workload benchmark

### Planned benchmark mutations

- Requested guest-only mutation: owner-checked reinstall of the restricted spike adds two test executables (`udp-benchmark` and `http-benchmark`) plus a synthetic credential-free Telegram Bot API-shaped response. Only the existing four spike units and their already owned paths are restarted.
- Runtime benchmark mutation: select `RESTRICTED-VALID` and `RESTRICTED-UDP → RESTRICTED`, create only the exact temporary capture tables `inet vpnctl_v2_spike_uot_capture`, then apply a 250 ms node-to-gateway partition using the lab-owned `inet vpnctl_v2_lab_fault` table while one bounded UoT stream is active.
- Workloads: 50 sequential small API-like HTTP request/responses over selected TCP; steady request/response UDP at 64, 256, and 1200 payload bytes; an observational 1200-byte burst; and identical 256-byte UoT streams before and during the controlled 250 ms partition.
- Conflict scope: only the contract-matching `vpnctl-v2-gateway` and `vpnctl-v2-node` fixtures. No host route, host firewall, Homebrew package, foreign VM, public Telegram endpoint, credential, or real Clash Mi installation is a target. Existing Lima wildcard ignores continue to prevent host port forwarding.
- Automatic rollback: an EXIT trap terminates only its recorded background probe PID if still running, clears only the lab fault helper's exact nftables table/netem handle, deletes only the exact capture tables, and restores both runtime selectors. `./scripts/v2restricted-spike.sh stop` remains the listener/logging closure; `uninstall` remains the owner-checked guest rollback.
- Acceptance: healthy steady profiles and the post-fault probe must have no response loss; the impaired run must record at least one response over 100 ms and at least 100 ms maximum-RTT inflation over baseline. The burst is observational, not an SLA. The report must state that Telegram Bot API/webhooks are TCP/HTTPS, that the synthetic workload is shape-only, and that restricted UoT has no performance guarantee for voice, gaming, QUIC, bulk/high-rate UDP, adverse paths, or payloads above the tested 1200 bytes.
- Preflight result: both exact lab VMs were `Running`, x86_64/QEMU, 1 vCPU, 512 MiB, and 10 GiB; all four spike services were inactive; no capture/fault table and no development-host listener on the five ignored ports existed. `realty-front-docker-vm` was read only and remained outside the command target.
- Installation result: owner validation passed, both pinned Mihomo configs validated, and only the role-appropriate four spike units became active. Host `lsof` remained empty for TCP/UDP `1053`, `8443`, `17890`, `18080`, and `19090`.
- Benchmark result: the final repeat at `artifacts/v2lab/restricted-spike/benchmark-final/summary.json` passed. All healthy 64/256/1200-byte steady profiles and post-fault recovery had zero loss. The 1200-byte/1000 pps observation lost 81.4%. A 250 ms partition raised the 256-byte/100 pps stream from 67.861 to 911.094 ms p95, increased maximum RTT by 828.218 ms, and lost 12% within the bounded receive window.
- Safety/resource result: the capture counted 2535 protected TCP packets and zero native/direct UDP. Final gateway/node Mihomo RSS was approximately 44/48 MiB; total guest RSS approximately 320/282 MiB, with 453 MiB usable RAM and 1 GiB swap on each guest.
- Rollback verification: both exact capture/fault tables and the `1abc:` netem handle were absent; selectors were `RESTRICTED → RESTRICTED-VALID` and `RESTRICTED-UDP → RESTRICTED`; peer packet loss returned to zero; no benchmark port appeared on the host. The four test units remain active only until the explicit logging/runtime closure below.
- Logging/runtime closure: `./scripts/v2restricted-spike.sh stop` stopped all four exact spike units. Final `systemctl show` reported every unit inactive on both roles; the fault/capture tables and `1abc:` handle remained absent; host `lsof` remained empty for every ignored port. Both exact lab VMs remain `Running` for task 2.5, with owner-marked files retained for reproducibility and `uninstall` available as the exact guest rollback.

## 2026-09-01 — IP-only nginx ingress spike

### Planned host-forwarding isolation

- Preflight observation: neither vpnctl lab guest listened on `443/TCP`, and neither rendered lab configuration had a port-443 forwarding rule. The development host already had an unrelated `*:443` listener owned by PID 64389, whose command and cwd identify `realty-front-docker-vm`; that process, VM, and its files are read-only observations and are not targets.
- Versioned change: add one exact Lima ignore entry for guest port 443 with `guestIP: 0.0.0.0`, `guestIPMustBeZero: false`, `proto: any`, and `ignore: true`, matching the already accepted wildcard isolation contract.
- Planned metadata mutation: with every spike unit inactive, contract-check and stop only `vpnctl-v2-gateway` and `vpnctl-v2-node`, append only the exact 443 ignore entry to each stopped VM through `limactl edit`, verify the rendered metadata, and restart only those two VM instances.
- Conflict rule: refuse duplicate/non-ignore port-443 entries, drifted VM contracts, active spike units, or any command target other than the two exact x86_64/QEMU lab names. The foreign host listener may remain present throughout and must keep the same owner command.
- Rollback: stop only the two exact lab VMs, delete only their exact port-forward object whose `guestPort` is 443 and `ignore` is true, verify no other rule changed, then restart. Recreating only these lab VMs from the versioned template is the clean full rollback.
- Applied isolation: contract and inactive-unit checks passed; only the two exact lab VMs were stopped. One exact 443 ignore object was appended to each stopped VM, verified before restart, and both instances returned `Running` with evidence at `artifacts/v2lab/20260901-ingress-forwarding-isolated/summary.json`.
- Foreign-listener verification: after restart, the sole host TCP/443 listener remained PID 64389 with the `realty-front-docker-vm` hostagent command. Neither vpnctl lab hostagent created or acquired a host-443 listener.

### Planned nginx/package and certificate mutations

- Package scope: after forwarding isolation, refresh apt metadata only in `vpnctl-v2-gateway`; install the Ubuntu 24.04 nginx package only if absent. Prevent the distro `nginx.service` from starting during installation, then leave it disabled while the separately named spike unit runs the packaged binary with an owned configuration tree. Record exact before/after package versions for owner-checked uninstall. No host package manager is used.
- Guest resources: `/etc/vpnctl-v2-spike/ingress/` with its own owner marker and root-only RSA key, `/usr/local/libexec/vpnctl-v2-spike/webhook-receiver`, `vpnctl-v2-spike-ingress.service`, `vpnctl-v2-spike-webhook.service`, their exact runtime/state paths, gateway `443/TCP`, and loopback-only upstream `18081/TCP`.
- Certificate scope: generate RSA-2048/SHA-256 for the manually supplied IPv4, with IP SAN and compatibility CN, 1825-day validity, public certificate mode `0644`, and private key mode `0600`. The private key remains inside the gateway fixture and is never copied into evidence or command output.
- Test scope: validate nginx configuration; TLS 1.2 and 1.3; certificate algorithm, IP SAN/CN, and five-year window; real HTTP/1.1 and HTTP/2 POST forwarding to the loopback receiver; and unknown-path `404`. Access logging is off and the receiver records neither bodies nor paths.
- External gate: the local fixture cannot receive Telegram traffic because its address is private. A separate test-only helper may read a bot token from a hidden TTY, upload the public certificate as multipart data, validate `getWebhookInfo`, and remove the webhook, but no token may enter argv, environment, files, logs, JSON, or git. Task 2.5 remains incomplete until that flow runs against a manually supplied public gateway IP or is explicitly reassigned to the deployed-service release gate.
- Rollback: stop only the two ingress spike units, remove only owner-marked ingress files/units/state, restore prior package state if this spike installed nginx, and retain only ignored sanitized evidence. VM-level rollback remains `scripts/v2lab.sh down`; destroying the exact two lab VMs remains the full fallback.
- First prepare result: apt installed only `nginx` and `nginx-common` at pinned version `1.24.0-2ubuntu7.17`; the temporary mask prevented the distro unit from starting, and it ended disabled/inactive. RSA key/certificate and owner-marked fixtures were installed. Manual config validation then failed before either spike unit started because `/run/vpnctl-v2-spike-ingress` did not yet exist for the configured pid path.
- Failure state: `NGINX_INSTALLED_BY_SPIKE=true` records package ownership, the private key remains mode `0600` in the gateway fixture, no ingress listener started, and no Telegram/public endpoint was contacted. The package mask cleanup trap ran.
- Corrective action: create only the exact runtime directory with mode `0750` immediately before manual `nginx -t`. The systemd unit already declares the same `RuntimeDirectory`; uninstall removes the directory only if empty. Rerun must reuse the owned package and certificate rather than reinstall or rotate them.
- Second prepare result: reused the exact package and certificate, passed `nginx -t`, and started only `vpnctl-v2-spike-{webhook,ingress}.service`. Gateway listeners were wildcard `443/TCP` and loopback `18081/TCP`; `443/UDP` was absent. Distro `nginx.service` remained disabled/inactive, and the sole host TCP/443 listener retained foreign PID 64389.
- First local verify result: stopped before any TLS/HTTP request because host OpenSSL rendered the subject as `subject=CN=192.168.104.1`, while the text assertion expected spaces around `=`. Public certificate evidence was written, node temporary files were removed by the trap, services remained unchanged, and no private key was copied.
- Corrective action: request RFC2253 subject formatting explicitly and compare the exact stable `subject=CN=<manual-ip>` form. No certificate rotation, config reload, package, listener, or external request is needed.
- Final local E2E: `artifacts/v2lab/ingress-spike/evidence-local-final/summary.json` passed nginx validation, RSA-2048/SHA-256, exact 1825-day lifetime, IPv4 SAN/CN verification, TLS 1.2 and 1.3, HTTP/1.1 and HTTP/2 synthetic POST forwarding, unknown-path `404`, `443/TCP`, and closed `443/UDP`.
- Resource point: final gateway nginx master/worker RSS was approximately 8/8 MiB and the test-only Python receiver approximately 20 MiB; total gateway/node guest RSS was approximately 285/284 MiB. Both peer checks had zero loss. This is not the task 2.6 load result.
- Secret/isolation verification: evidence contains the public PEM only; scans found no private-key PEM. All exact node `/tmp/vpnctl-v2-ingress-*` files were absent. While guest nginx was active, host TCP/443 remained solely foreign PID 64389.
- Logging/runtime closure: `./scripts/v2ingress-spike.sh stop` stopped only the two ingress units. Both custom units and distro `nginx.service` are inactive/disabled; guest `443` and `18081` listeners are absent. Pinned packages and owner-marked certificate/config remain for a repeat or exact `uninstall`; the external Telegram gate has not run.
- External-gate preparation: installed the test-only `telegram-webhook-gate` in the owner path and added a loopback-only accepted-request counter. The helper requires a global manual IPv4, reads the bot token with a hidden TTY, refuses an existing webhook, uploads only public PEM, observes a real counter increase, and deletes only its own registration. Static tests forbid argv/env/file token inputs and sensitive output.
- Final local rerun: updated receiver/helper files were installed without package or certificate rotation; local TLS/HTTP verification passed again with `accepted_request_delta=2`; `stop` then left every nginx/ingress unit inactive and both guest listeners absent. No real Telegram API call or external bot state mutation occurred.
- Uninstall verification: owner check passed; only `nginx` and `nginx-common` version `1.24.0-2ubuntu7.17` were purged; exact ingress units, config, certificate/key, receiver/helper, and empty runtime path were removed. Restricted spike ownership/files remained intact, both lab VMs remained `Running` with the 443 ignore contract, and foreign host PID 64389 remained the sole TCP/443 listener. Apt metadata and sanitized ignored evidence were intentionally retained.
- Final lab state: task 2.5 local runtime is fully rolled back and inactive. A future local rerun or task 2.6 will reinstall from the pinned manifest; the real Telegram gate requires an actually deployed endpoint and has not run.
