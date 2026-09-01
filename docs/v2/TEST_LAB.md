# vpnctl v2 minimum-host test lab

The mandatory v2 spikes run in two pinned Ubuntu 24.04 amd64 Lima/QEMU VMs named `vpnctl-v2-gateway` and `vpnctl-v2-node`. Each VM has exactly 1 vCPU, 512 MiB RAM, a 10 GiB root disk, and a managed 1 GiB swap file. The dated Ubuntu cloud image and SHA-256 digest are pinned in `test/v2lab/lima.yaml`.

All development-host mutations and rollback instructions are recorded in `docs/v2/HOST_CHANGELOG.md`. Do not operate on similarly named or pre-existing Lima instances.

Requirements on the development host are Lima 2.0+ with QEMU. On an arm64 development host, install Lima's x86_64 agent bundle with `brew install lima-additional-guestagents`. Both fixtures use Lima's built-in rootless `lima:user-v2` network, so they can communicate on an isolated `192.168.104.0/24` segment without installing `socket_vmnet` or changing host sudoers.

Boot both fixtures and immediately capture baseline evidence:

```bash
./scripts/v2lab.sh up
```

The command validates the template, creates or starts both VMs, installs the lab helpers, and writes timestamped JSON under `artifacts/v2lab/`. `summary.json` contains OS/architecture, vCPU and memory limits, swap, disk capacity, CPU/load sample, total and top-process RSS, listening/connected TCP+UDP sockets, guest addresses, peer latency, and packet loss. Re-run measurement without recreating the VMs with:

Package provisioning records `/var/lib/vpnctl-v2-lab.provisioned` only after a successful install. Fixtures created from the current template therefore skip network package work on later boots.

```bash
./scripts/v2lab.sh report
```

Network faults are always explicit and role-scoped:

```bash
# Add 250 ms on the node path toward the gateway.
./scripts/v2lab.sh fault node latency 250

# Add 10 percent packet loss on the gateway path toward the node.
./scripts/v2lab.sh fault gateway loss 10

# Block only gateway/node communication while leaving their other networking intact.
./scripts/v2lab.sh fault node partition

# Remove nftables and netem faults from the selected VM.
./scripts/v2lab.sh fault node clear
```

The latency/loss helper owns the dedicated `1abc:` qdisc handle on the peer-route interface; partitioning owns only the `inet vpnctl_v2_lab_fault` table. `clear` removes those exact controls. Before any existing exact-name VM is started, inspected, stopped, or deleted, the orchestrator verifies QEMU/amd64, resource limits, pinned image digest, and rootless network. A mismatch exits as a conflict instead of operating on the instance.

Use `./scripts/v2lab.sh shell gateway` or `shell node` for an interactive guest shell, `down` to stop both persistent fixtures, and explicit `destroy` to delete them. Generated evidence is intentionally untracked; accepted spike results are summarized in versioned ADRs and manifests.
