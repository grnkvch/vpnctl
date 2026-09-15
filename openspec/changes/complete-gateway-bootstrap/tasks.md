## 1. Lock the regression contract with fast tests

- [x] 1.1 Add focused failing tests that reproduce a Gateway initialized without its manifest-declared nginx package, managed ingress tree, service, and TCP 443 listener; verify the tests demonstrate that current status/plan can incorrectly report healthy/clean before implementation.
- [x] 1.2 Add package-lifecycle fake and contract tests for role filtering, exact compatible-version selection, dry-run rows, package-manager lock/unavailable failures, nginx masking, idempotence, and known/uncertain rollback outcomes; verify the suite runs without APT, root, network, or VM access.
- [x] 1.3 Add baseline-ingress orchestration tests covering clean Gateway bootstrap, Node role exclusion, occupied TCP 443, foreign drop-in/tree ownership, validation/start/health failures, retained-generation rollback, and retry after persisted-but-incomplete initialization; verify existing authoritative identity and client state remain unchanged across retry and compensation.

## 2. Implement role package bootstrap

- [x] 2.1 Implement a package planner that accepts only the verified bundle's role-selected `APTPackageCompatibility` records and reports installed version, allowed interval, resolved exact version, and action; verify unit tests reject undeclared packages, incompatible candidates, and Gateway packages on a Node.
- [x] 2.2 Implement the bounded Ubuntu package transaction with package-manager serialization, conditional metadata refresh, exact `package=version` installation, nginx service masking, a private transaction journal, post-install verification, and conservative compensation; verify fake command traces contain no general upgrade, autoremove, silent downgrade, or unrelated package mutation.
- [x] 2.3 Split immutable host preflight from package-provided capability checks and rediscover the complete host after package application; verify dry-run reports missing declared tools as planned work while wrong OS/architecture, kernel gaps, unsafe ownership, and unmanaged port conflicts still fail before authoritative mutation.
- [x] 2.4 Compose the package transaction into Gateway init and repair while leaving Node init free of Gateway-only nginx resources; verify human and JSON output expose package changes and actionable bootstrap failures without leaking repository credentials or command transcripts.

## 3. Make baseline HTTPS ingress an init postcondition

- [x] 3.1 Implement the owned nginx systemd drop-in adapter with strict path/content ownership checks, atomic publication, daemon reload, captured enable/active state, and rollback; verify tests preserve foreign resources and restore the exact known prior service state.
- [x] 3.2 Compose the existing certificate, nginx renderer, validator, immutable-tree activation, loopback enrollment service, firewall watchdog, and bounded readiness checks in the specified Gateway init order; verify a fresh empty-expose Gateway cannot commit success until IP-only TLS, TCP 443, and the reserved routes are healthy.
- [x] 3.3 Merge the nginx drop-in, active generation/hash, service expectation, packages and listeners into the effective convergence readiness projection while retaining their dedicated repair adapters; verify repeated successful init is idempotent and repeated incomplete init plans and repairs the missing work instead of returning a no-op.
- [x] 3.4 Exercise expose, revoke, restore, update, and uninstall tests against the shared baseline ingress identity; verify user routes retain the reserved enrollment paths, update preserves the serving generation, and uninstall removes only vpnctl-owned runtime/configuration rather than Ubuntu package dependencies.
- [x] 3.5 Compile the three shipped editable preset sources into fresh Gateway generation-1 effective state; verify exact source/hash/selector identity, immediate first-join selection, and repeated-init preservation of later operator edits/deletions.

## 4. Unify Gateway readiness, planning, and repair

- [x] 4.1 Implement the bounded read-only Gateway readiness inspector for declared package versions, owned drop-in/tree, nginx load/enable/active/runtime state, TCP 443, and the loopback enrollment listener; verify it performs no package refresh, network request, service control, or filesystem mutation.
- [x] 4.2 Feed the shared readiness projection into convergence, passive status, and plan; verify removal of nginx or drift of any mandatory ingress component makes status degraded and plan non-clean with stable required actions, while a complete Gateway remains healthy/clean.
- [x] 4.3 Advance the repair contract to bind the observed package baseline, drop-in, candidate tree hash, service expectation, and existing watchdog inputs; verify stale confirmation, incompatible packages, foreign ownership, and unmanaged listeners fail closed before mutation.
- [x] 4.4 Implement confirmed repair of missing compatible packages and owned ingress state using the same lifecycle adapters as init; verify activation failure restores known prior package/service/tree state and successful repair preserves every WireGuard client address, key, peer, and working data plane.
- [x] 4.5 Extend `doctor ingress` with the loopback enrollment readiness probe while retaining its bounded public-IP TLS and reserved health probes; verify missing public ingress is distinguished from a healthy loopback controller.
- [x] 4.6 Keep package/bootstrap and committed network-watchdog mutation out of the resident controller sandbox: execute that system-wide repair in the confirmed short-lived root CLI under one shared cross-process mutation lock, revalidate plan/state after acquisition, and verify concurrent controller mutation is rejected before side effects.

## 5. Make Node join failures actionable and atomic

- [x] 5.1 Add a dedicated enrollment-unavailable error for bounded dial, timeout, TLS identity/trust, and Gateway 502/503/504 failures; verify malformed, expired, or rejected invites keep their existing validation/authentication categories.
- [x] 5.2 Map enrollment unavailability to stable CLI human/JSON output with a safe Gateway status/doctor action; verify output excludes invite tokens and hashes, private keys, authorization data, endpoint transcripts, and sensitive configuration.
- [x] 5.3 Add join atomicity tests for an absent Gateway TCP 443 edge and a successful end-to-end adapter flow; verify failure returns `changed=false`, leaves the invite unconsumed and Node unjoined with no credentials/services, while success consumes the invite exactly once.
- [x] 5.4 Give the public handler, loopback response writer, reserved nginx proxy, and Node response-header wait one fixed 45-second first-join budget while preserving shorter admission limits and uncertain-outcome semantics; verify the numerical contracts stay equal and bounded.
- [x] 5.5 Make ingress readiness retain an older active generation when current semantic inputs render to its exact hash, and make passive status detect races by authoritative-state reread; verify invite-only generation changes stay healthy while a semantic ingress change remains drift.
- [x] 5.6 Retry complete post-restart Gateway join readiness every 100 ms for at most 20 seconds inside the fixed enrollment budget, and map exhausted readiness to public `503 unavailable`; verify a transient identity mismatch converges while a persistent health failure rolls back and is not misclassified as invalid credentials.
- [x] 5.7 Permit `AF_NETLINK` in the resident Gateway controller's address-family sandbox for its existing read-only `wg`/`ip` candidate observers while retaining no IPv6 or package/nginx/system-unit write path; verify the rendered unit contract exactly binds the three permitted families.
- [x] 5.8 Make every Node role unit create the shared private `/run/vpnctl` runtime directory and retry each unit's start/readiness within one fixed bounded activation window before advancing; verify a transient routing-guard startup race converges while a persistent failure keeps the join result activation-pending and fail-closed.
- [x] 5.9 Include the candidate active-identity firewall in the pre-commit Gateway join transaction; verify it atomically replaces only the existing owned table, is retained on commit, and restores the exact prior table on readiness, convergence, or state failure.
- [x] 5.10 Preserve the unique most-specific main-table route to the public Gateway endpoint when compiling the Node recovery table, with the best default only as fallback; verify explicit host-route selection and ambiguous/invalid fail-closed behavior.
- [x] 5.11 Retry the complete unchanged joined-Node routing and FRP readiness contract inside the fixed 20-second activation bound before publishing active convergence; verify a transient post-start failure converges while persistent failure retains activation-pending and fail-closed state.
- [x] 5.12 Scope FRP client connection cardinality to matching `frpc` process lines at the exact Gateway endpoint; verify unrelated Mihomo/transit sessions are ignored while zero or multiple frpc matches remain unhealthy.
- [x] 5.13 Normalize bare IPv4 host-route destinations from Linux JSON snapshots to exact `/32` prefixes; verify owner-scoped Node cleanup retains the route while malformed, IPv6 and cross-family destinations remain rejected.
- [x] 5.14 During Node cleanup, omit only the retained rp-filter sysctl for a positively absent product WireGuard interface; verify host/underlay values remain mandatory and ambiguous interface probes fail closed.

## 6. Complete the no-VM verification checkpoint

- [x] 6.1 Run the focused package, init, ingress, convergence, repair, update, uninstall, and join suites plus all repository contract tests; verify they pass without Lima and record any intentionally deferred real-host assertions in the change notes.
- [x] 6.2 Run formatting, `git diff --check`, the complete Go test suite, targeted race tests for changed concurrent lifecycle/controller packages, `go vet ./...`, and strict OpenSpec validation; verify no failure is deferred to a VM merely because it is inconvenient to model locally.

## 7. Prove both scenarios manually on the existing Lima pair

- [x] 7.1 Verify the existing `vpnctl-v2-gateway` and `vpnctl-v2-node` fixture identity, image, resource profile, ownership, and stopped clean state, then journal every host/VM mutation in `docs/v2/HOST_CHANGELOG.md`; verify no production host and no old evidence directory is touched.
- [ ] 7.2 Build a non-release candidate and run the fresh scenario from a clean no-nginx Gateway through Gateway init, Node init, invite creation, public join, and one selected request; verify nginx/package/readiness postconditions, single invite consumption, and final service/firewall health before owner-scoped cleanup returns both fixtures to stopped state.
- [ ] 7.3 Recreate the exact incomplete unpublished-candidate shape with a retained WireGuard client, rehearse the hash-bound pinned-nginx prerequisite and same-version manifest/SHA transition, then run confirmed repair; verify final artifact hashes, client continuity, public join, readiness, audit distinction, reversal boundary, and stopped owner-clean fixture state.
- [ ] 7.4 Save only redacted diagnostics and an explicit manual result for each scenario without changing immutable historical evidence; verify no token, token hash, private key, authorization header, or secret configuration appears in tracked files or logs.

## 8. Add one narrow automated enrollment check

- [ ] 8.1 Add a single focused Gateway-enrollment E2E entrypoint for the fixed existing Lima topology and actual candidate binary/bundle, covering clean no-nginx bootstrap/join plus missing-ingress repair; verify its contract explicitly excludes resume, fingerprints, capacity, migration, and release-stage registry integration.
- [ ] 8.2 Implement owner/image/resource/stopped-state preflight, root-only transient invite handling, bounded diagnostics, owner-scoped cleanup, and restoration of the fixtures' initial stopped state; verify cleanup and secret-redaction behavior with fast orchestration tests before invoking Lima.
- [ ] 8.3 Run the focused E2E against the same frozen source commit used in both manual scenarios; verify both modes pass and a failed mode remains in the focused loop rather than triggering any general release gate.

## 9. Freeze and validate the final candidate once

- [ ] 9.1 Update release, recovery, installation, readiness, repair, and troubleshooting documentation, including the one-time unpublished-candidate recovery boundary; verify examples distinguish passive status, active doctor, confirmed repair, and the absence of any permanent recovery command.
- [ ] 9.2 Re-run the complete source verification on the frozen commit and inspect the full diff for package, service, state, secret, and rollback boundaries; verify the commit is pushed before creating new release evidence.
- [ ] 9.3 Run the existing fast and resumable VM release gates once for that exact frozen commit, leaving capacity as an explicit on-demand measurement; verify automated aggregation accepts no failed/invalid mandatory stage and preserves all attempt evidence.
- [ ] 9.4 Prepare but do not execute the production handoff: exact final `v2.0.0` hashes, guarded nginx prerequisite, normal same-version update, confirmed repair, fresh invite/join, Telegram API/webhook verification, rollback points, and migration-artifact cleanup; verify each host-changing command is journaled and will be presented to the operator one line at a time.
