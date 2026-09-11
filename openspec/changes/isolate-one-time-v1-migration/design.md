## Context

The current `feat/vpnctl-v2` tree contains the standalone migrator command, its orchestration, v1 conversion/recovery code, tests, and documentation. Although the normal v2 release publishes only three product assets, the release gate fingerprints the whole tracked source commit and `release.sh` runs `go test ./...`; therefore a migration-only fix creates a new product candidate and repeats expensive unrelated verification.

Two real maintenance attempts have already shown the other problem. The first found an official-FRP-archive shape missed by synthetic tests. The second reached shared nftables activation and found a first-install validation error. Both failures rolled back correctly, but the production Gateway was acting as the first realistic systemd/nftables integration fixture.

The migrator runs as root and owns a rollback boundary, so an unversioned script outside VCS is not acceptable. The design instead separates product and operation lineage while binding them cryptographically by commit and SHA-256 metadata.

## Goals / Non-Goals

**Goals:**

- keep migration-only corrections out of the permanent v2 product commit and its release-evidence loop;
- discover migration defects on a disposable native fixture before the production maintenance window;
- preserve exact source, artifact, evidence, rollback, and host-change traceability;
- distinguish a shared product defect from a migration-only defect;
- retire the executable after its one intended use without erasing its history.

**Non-goals:**

- weakening the current product release gate, `release.sh` verification, or capacity policy;
- publishing the migrator as a fourth v2 release asset or permanent public command;
- supporting arbitrary v1 fleets or making the one-time operation a general migration framework;
- automatically connecting to or mutating the production Gateway from the test gate;
- rewriting prior release or migration evidence.

## Decisions

### 1. Use a product base commit plus an operational descendant

The maintained v2 line ends at a clean product commit `P` with no migration-only executable or implementation. The operational branch `ops/v1-to-v2-migration` is created from `P` and adds only allowlisted migration paths, producing migration commit `M`:

```text
product history ─────────────── P
                                \
operational migration line       M1 ── M2 ── Mfinal ── immutable tag/ref
```

The existing migration files are removed from the product line and reintroduced on the operational descendant. A machine-readable contract records `P`, `M`, the allowlisted path set, release version, bundle checksum, and fixture checksum. The operation build refuses a dirty tree, a non-descendant relation, or a diff from `P` touching a non-allowlisted path.

Examples of migration-only paths are the standalone command, explicitly named `internal/lifecycle/v1_*` files, the migration build/gate scripts, the dedicated fixture, and the operational runbook. Shared release parsing, installer, nftables, systemd, runtime lifecycle, and normal vpnctl behavior are not allowlisted. A fix there first lands on the product line and necessarily produces a new `P` and bundle.

This repository cannot make a remote branch or tag immutable by itself. The workflow therefore verifies the local ancestry and candidate metadata; after successful production acceptance the maintainer pushes an annotated archival tag and may delete the active operational branch. Cryptographic tag signing remains outside this change, consistent with the current checksum-only release policy.

### 2. Keep product release and migration qualification independent

The product pipeline remains:

```text
P → product release gate → exact v2 bundle B
```

The operational pipeline consumes, but does not rebuild, that result:

```text
P + B → M → migration fast gate → native lifecycle gate → migrator binary H
```

A change confined to the operational allowlist creates a new `M` and `H`; it reruns migration qualification but reuses the unchanged `P` evidence and `B`. If the change affects shared product code, the ancestry/diff check fails and sends the fix back through the product pipeline. `release.sh` keeps its autonomous `go test ./...` check for product builds. Stage-specific product fingerprints are deliberately not introduced here.

The normal three-asset release verifier also gains a focused regression assertion that no migrator is accepted in the product asset directory. It does not consume migration evidence.

### 3. Provide fast and native migration commands

One migration-oriented entrypoint exposes a small maintainer CLI:

```text
scripts/v1migration-gate.sh prepare <version> <absolute-product-bundle>
scripts/v1migration-gate.sh run-fast <evidence-directory>
scripts/v1migration-gate.sh run-native [--resume] <evidence-directory>
scripts/v1migration-gate.sh status <evidence-directory>
scripts/v1migration-gate.sh build <evidence-directory>
```

`prepare` creates, never replaces, a private evidence directory and canonical candidate metadata. `run-fast` covers branch ancestry/path isolation, checksums and manifest binding, CLI/plan/recovery contracts, official archive installability, nft first-install regression, shell syntax, focused Go tests, and strict OpenSpec validation without Lima. `run-native` owns the disposable fixture and writes numbered append-only attempts. `build` requires reusable passing fast and native results and emits the exact migrator plus checksum/candidate metadata for SCP; it never emits or republishes the product bundle.

Resume is intentionally limited: it may reuse only a matching passing fast attempt and matching completed native substage from the same candidate contract. Failed attempts remain immutable. A final `migration.json` aggregate is created only after both phases pass and the fixture postcondition is proven.

### 4. Use a dedicated disposable native fixture

The fixture is separate from `vpnctl-v2-gateway` and `vpnctl-v2-node`, with a distinct exact owner marker and fixed name such as `vpnctl-v1-migration`. It uses the pinned Ubuntu 24.04 amd64 Lima image, 1 vCPU, 512 MiB RAM, 10 GiB disk, and 1 GiB managed swap to reproduce the real Gateway shape. It is not a capacity benchmark and defines no performance threshold.

Provisioning installs only prerequisites. Each native attempt builds a representative v1 installation from the checked-in v1 release/tag and regression fixtures, including systemd, WireGuard, UFW/nftables state, clients, and a reachable probe namespace. It then executes:

1. baseline v1 service and traffic checks;
2. dry-run plus filesystem/service/firewall immutability comparison;
3. apply until the watchdog confirmation boundary;
4. confirmation from a separate fixture SSH session and v2 convergence checks;
5. retained client identity/address/key and traffic checks;
6. explicit rollback and exact v1 service/firewall/traffic restoration;
7. a second dry-run/apply/confirm cycle;
8. explicit acceptance, rollback-payload removal, and final v2 health;
9. removal or stopped-clean verification of the owned fixture.

The gate accepts no host/address argument and invokes Lima only by its fixed, contract-checked fixture name. This prevents accidental use of the production Gateway as a development target. Fixture creation/start/stop/deletion and recovery are recorded in both attempt evidence and `docs/v2/HOST_CHANGELOG.md`; generated evidence itself stays under the ignored artifact tree.

### 5. Make evidence and deployment inputs explicit

Candidate metadata contains at least:

- schema version, release version, product commit, and migration commit;
- clean-tree and ancestry/path-isolation witnesses;
- product bundle path at preparation time, exact size, SHA-256, and embedded manifest identity;
- migrator size/SHA-256 after build;
- hashes of the operational source allowlist, gate command contract, fixture template/provisioner, v1 seed fixture, and Lima image;
- creation timestamp and expected production architecture/OS.

Every stage attempt contains input and output checksums, timestamps, exit status, diagnostics, cleanup result, and its candidate fingerprint. Directories become read-only when an attempt closes. The aggregate references attempts and their hashes; it does not copy mutable success flags from logs.

The production runbook produces one-line commands for SCP and on-host checksum verification, dry-run, apply/resume, confirmation, validation, rollback, acceptance, and final helper removal. It appends concrete mutations and rollback instructions to the existing host journal. Secrets, WireGuard keys, bundle contents, and raw service configuration are excluded from evidence and command output.

### 6. Retire active migration code but retain the audit trail

After the real migration is accepted, the helper and staging copy are removed from the Gateway under their ownership contract. The private rollback payload is already removed by migrator acceptance. The maintainer records the terminal result, migrator and bundle hashes, product/migration commits, and evidence path, creates an annotated archival ref, and can delete the active operational branch.

The product line retains only the behavioral requirement, a short historical/operational pointer, and shared v2 fixes. The exact executed source remains reachable through the archival ref; “delete the migrator” means remove it from active product development and the host, not erase the only reproducible source record.

## Risks / Trade-offs

- **Two source lines can drift.** Exact ancestry, an allowlisted diff, and bundle/commit binding fail closed; shared changes require a new product base.
- **Reintroducing migration files after product cleanup can omit a dependency.** The operational build and native gate must start from the clean product base and compile/test the complete helper before any production use.
- **A native fixture is slower than unit tests.** It is still much shorter and safer than repeating the full product release gate or discovering defects on the real Gateway, and it runs only on explicit request.
- **Lima is not the production hypervisor/network.** The gate targets Linux service/firewall semantics and client continuity, while the final dry-run and operator validation remain required on the real host.
- **An unsigned archival tag does not authenticate the publisher.** Commit and SHA-256 metadata provide reproducibility under the repository/SSH trust boundary; signed source/release authenticity remains backlog work.
