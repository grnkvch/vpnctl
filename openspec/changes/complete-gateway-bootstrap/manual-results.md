# Manual Lima results

Date: 2026-09-15

Scope: disposable `vpnctl-v2-gateway` and `vpnctl-v2-node` Lima fixtures only.
No production host, SSH credential, published release, or historical evidence
directory was accessed or changed.

## 7.2 Fresh no-nginx bootstrap

Result: **PASS**

- Frozen source: `375e4a4404085a96b8bb3721a5aeee071f703250`.
- Verified non-release candidate SHA-256: binary
  `eb4894dc582bbad4f4c889d501d190018e05a9e2d5cc49cd2d20814aff827105`,
  bundle `bcc9ba7b0f9fca5d8e25bed95d8ea7f91bc1ed984478c60f34c582b79878c10e`,
  checksum metadata
  `648b23b64550b654ee955a3c07c4bcb916626514525a3eb4ef8b05df345ff684`.
- A clean Gateway without nginx completed `init --gateway`, installed only the
  declared compatible nginx package, published baseline IP-only HTTPS ingress,
  and passed new-session watchdog confirmation. A clean Node completed
  `init --node`.
- One invite was consumed exactly once by one public `join` invocation. The
  Node activated standard transport, routing guard, routing and tunnel client.
- A selected Telegram DNS/HTTPS request succeeded and WireGuard aggregate
  counters increased. Gateway and Node validation/plan/readiness, role services,
  active identity firewall membership and public health passed.
- Public owner-scoped purge, package/TEST-NET reversal and final checks returned
  both fixtures to a stopped clean state.

## 7.3 Unpublished-candidate recovery

Result: **PASS**, with the cleanup-attribution limitation below retained.

- Incomplete candidate identity: source
  `04606fd1c24e78749ef6039e3cb430a7d68f4f4e`, binary SHA-256
  `9c1503321ccafcc9126fbf2c9913323ebc9b00469f29726917f753e46dc26fd9`,
  bundle `6537daba4ca4f4f773ae517b4b3b0bd2ec2ebc06a4302c580d7da3c6ddfb6e1e`,
  and checksum metadata
  `fa70e3e7a3fa95ab66395af75918e0fa9f61cb42b2d86309cb8325a710257132`.
- The hash-bound prerequisite, script SHA-256
  `4347c0e037cf5ca77d21654a34f0c30a34e66b94945f63b627e1f560c359239c`,
  accepted only that old identity and exact retained-client/no-ingress shape. It
  installed only nginx `1.24.0-2ubuntu7.18`, left it masked/inactive, and
  recorded an exact package reversal boundary.
- A same-version manifest/SHA update and confirmed repair installed the final
  matching candidate from source
  `c23bf3dcf595e8c237ee49d9b98fd940a5ca6095`: binary SHA-256
  `76aed6c6d96b31ca2e07ed568d457913fc1b3e05f0be741923281f1a4e373160`,
  bundle `d0cef3c7add4d35c5730c088b4802c914dcbb597b66ebba31879e0234d257372`,
  and checksum metadata
  `d7e8d20e3f3d0775fd84cdc278b70d3b72d483422f66bb125a8958b399f714d7`.
- The retained client kept its ID, name, `10.66.0.2` address, credential
  generation, root-only export and exact `/32` peer. Live WireGuard handshake,
  DNS and internet traffic passed before the transition and passed again after
  the initial final-candidate transition. The last two code-only updates
  restarted services; a second private-profile transfer was deliberately not
  performed. Final counters were zero, so no later live transfer is claimed.
- Public Node join succeeded and consumed its invite. Both roles then passed
  validation, clean plan, expected readiness, service, firewall, FRP and public
  ingress checks. The update rollback dry-run bound the exact old same-version
  snapshot and was not applied.
- Final owner-scoped cleanup removed product runtime/state/network/package and
  all task-owned temporary material, retained only the verified installer cache,
  `nginx-common` and fixture swap, and stopped both exact VM profiles.

Cleanup-attribution limitation: a piped typed-prompt invocation and a later
interactive invocation overlapped ambiguously. The latter returned a safe
`changed=false` failure after cleanup had already completed. Independent
postconditions prove an owner-scoped public purge completed, and a focused CLI
result-contract check passed, but the exact winning invocation was not retained.
Both attempts remain disclosed in `docs/v2/HOST_CHANGELOG.md`; this is not used
as evidence of an additional product behavior.

## Redaction and evidence boundary

- The manual record contains only public artifact hashes, stable resource IDs,
  package versions, bounded status facts and aggregate counters.
- Invite values, invite-derived hashes, private keys, authorization headers,
  certificate keys, client profile contents and secret configuration are absent.
- Temporary token, transcript, TLS, client-fixture, helper and result paths were
  removed after bounded checks. Binary-blob marker matches were treated as
  non-text false positives; task-owned textual files had no secret-marker match.
- Immutable historical evidence was neither migrated, rewritten nor deleted.
