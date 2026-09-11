## 1. Shared Product Correction

- [x] 1.1 Reproduce the absent-table `nft --check` failure in the shared Linux gateway activation path and add a regression test that distinguishes first install from replacement; verify the focused platform/lifecycle test fails before the correction.
- [x] 1.2 Correct shared nftables validation without weakening rollback, ownership, or existing-table replacement behavior; verify focused firewall, init, migration, and failure-injection tests pass.
- [x] 1.3 Record the source-only correction and its rollback boundary in `docs/v2/HOST_CHANGELOG.md`; verify no Lima fixture or production host was touched.

## 2. Clean Product Source Line

- [x] 2.1 Define and test the canonical migration-only path allowlist, including rejection of shared release/install/network/service paths; verify representative allowed and forbidden diffs are classified correctly.
- [ ] 2.2 Remove the standalone migrator command, wrapper, migration-only lifecycle source/tests, native migration fixture, and executable migration runbook from the maintained product tree while retaining the v2 behavior requirement and a short archival-operation pointer; verify `rg` finds no buildable migrator in the product tree.
- [ ] 2.3 Add a product release regression that accepts exactly the existing three canonical v2 assets and rejects a fourth migrator asset; verify release builder/verifier tests and `release.sh` contract tests pass without changing its autonomous `go test ./...` behavior.
- [ ] 2.4 Run focused product tests, the complete Go suite, vet, shell syntax, traceability, and strict OpenSpec validation; verify the cleaned product tree remains releasable before fixing the product base commit `P`.

## 3. Operational Source Line

- [ ] 3.1 Create `ops/v1-to-v2-migration` as a descendant of the exact clean product base `P`, restore only the migration implementation from its recorded pre-extraction source, and record both commits; verify ancestry and the allowlisted diff mechanically.
- [ ] 3.2 Add canonical operational metadata and validation for product commit, migration commit, clean tree, release version, bundle size/SHA-256, embedded manifest, source contract, fixture contract, and Lima image digest; verify missing, mismatched, dirty, non-descendant, and forbidden-path candidates fail closed.
- [ ] 3.3 Build the standalone migrator only on the operational line with embedded product/migration identity and canonical checksum metadata; verify deterministic rebuilds match and no product release asset is created or replaced.

## 4. Fast Migration Gate and Immutable Evidence

- [ ] 4.1 Implement the minimal `prepare`, `run-fast`, `run-native [--resume]`, `status`, and `build` CLI in `scripts/v1migration-gate.sh`; verify parser/usage tests reject legacy evidence, unsafe paths, replacement, and ambiguous arguments.
- [ ] 4.2 Implement append-only numbered attempts and final aggregation bound to all relevant fingerprints; verify failed and interrupted attempts remain immutable, mismatched passes are invalidated, retries append, and `migration.json` appears only after every required result passes.
- [ ] 4.3 Compose the no-VM fast suite from branch/path isolation, checksum/manifest/installability, migrator CLI/plan/recovery, first-install nft regression, shell syntax, focused Go tests, and strict OpenSpec validation; verify a contract test proves `run-fast` never invokes Lima or the full product release gate.
- [ ] 4.4 Make `build` require reusable passing fast and native evidence and emit only the migrator, candidate metadata, and checksum metadata; verify it refuses incomplete/invalid evidence and verifies every emitted byte before publication.

## 5. Disposable Native Migration Gate

- [ ] 5.1 Add a dedicated pinned Ubuntu 24.04 amd64 Lima fixture at 1 vCPU, 512 MiB RAM, 10 GiB disk, and 1 GiB managed swap with a unique ownership contract; verify template/image/resource fingerprints and rejection of foreign fixture collisions.
- [ ] 5.2 Build a representative released-v1 seed from the recorded v1 tag and regression fixtures, including real systemd, WireGuard, UFW/nftables state, retained clients, and an isolated traffic peer; verify its baseline service, state, firewall, identity, and traffic witnesses before migration.
- [ ] 5.3 Implement native dry-run immutability, apply/watchdog/confirm, v2 convergence, retained-client traffic, exact rollback to working v1, second apply, explicit acceptance, rollback-payload removal, and final v2 health; verify each lifecycle boundary has a direct witness and injected failure.
- [ ] 5.4 Restrict the native gate to its fixed owner-scoped Lima fixture with no arbitrary host/SSH target and implement bounded recovery plus stopped-or-absent postconditions; verify interruption and foreign-residue tests never touch an unowned VM or path.
- [ ] 5.5 Record fixture create/start/mutate/stop/delete actions, timings, diagnostics, and rollback instructions in append-only evidence and `docs/v2/HOST_CHANGELOG.md`; verify output excludes credentials, WireGuard private keys, raw configs, and other private host data.

## 6. Operational Runbook and Retirement

- [ ] 6.1 Create the operational Russian runbook with one-line SCP/checksum/dry-run/apply/resume/confirm/validate/rollback/accept/remove commands, explicit SSH-key placeholders, and host-journal steps; verify all local command forms execute through parser or dry-run tests and outputs are safe to share.
- [ ] 6.2 Document the decision boundary for migration-only versus shared product fixes, reuse of product evidence, production-host prohibition in the gate, and post-acceptance retirement; verify test traceability maps every `one-time-migration-operations` scenario to a test or manual witness.
- [ ] 6.3 Add the archival procedure that records `P`, `Mfinal`, bundle/migrator hashes, evidence path, and an annotated immutable ref before the active operational branch may be deleted; verify the procedure never claims cryptographic publisher authentication.

## 7. Qualification and Handoff

- [ ] 7.1 Run the complete fast migration gate and focused contract/model regression suite on the final operational candidate; verify all reusable evidence matches the exact candidate fingerprint.
- [ ] 7.2 Run the full native migration lifecycle on the disposable fixture without contacting the production Gateway; verify passing aggregate evidence and the stopped-or-absent clean fixture postcondition.
- [ ] 7.3 Run final diff checks and strict OpenSpec validation, create separate product and operational commits, and synchronize the completed spec/task record back to the product line without migration source; verify both branch diffs and hashes match the documented topology.
- [ ] 7.4 Prepare but do not execute the next production migration step: emit the exact qualified artifacts and one next manual command, restore the user's pre-existing untracked deployment file, and verify no release was labeled or published and no production host changed.
