# Local component transactions

Task 13.2 defines one reusable transaction boundary for generated files,
systemd units, and owned network state. Component-specific code implements
opaque handles; the common coordinator sees only component name, generation,
presence, revision SHA-256, and runtime SHA-256.

The normal sequence is:

```text
inspect expected generation
  → validate complete candidate
  → stage candidate
  → atomically activate
  → verify exact candidate generation
  → component health check
  → outer authoritative state commit
  → finalize old-generation cleanup
```

`PrepareLocalTransaction` stops after staging. `Activate` switches and checks
the candidate but deliberately retains the prior generation. The caller may
then commit matching authoritative state. A failed or uncertain state write
must call `Rollback`, which uses the activation receipt and verifies the exact
previous generation before reporting success. Only after a durable state commit
may the caller invoke `Commit` to let the adapter remove its rollback snapshot.

`RunLocalTransaction` is the convenience path for a candidate whose
authoritative intent is already durable; workflows that still need a state
write use the explicit prepare/activate/rollback/commit methods.

## Failure rules

- Validation failure cannot create a staged handle and must leave current
  generation unchanged.
- Staging or activation may return an opaque handle together with an error. The
  coordinator then discards or rolls back that exact handle. An error without a
  handle promises no corresponding stage/switch survived.
- A bad stage/activation descriptor, an observed generation other than the
  candidate, or a failed health check is treated as a transaction failure and
  restores the previous generation.
- Discard and rollback ignore cancellation of the initiating operation and use
  their own bounded timeout. Successful rollback is accepted only after a fresh
  observation exactly matches the previous presence, generation, and hashes.
- Rollback failure is explicitly `uncertain`; the coordinator never claims the
  prior generation was restored.
- `Commit` is called only after authoritative state is durable. Its cleanup
  failure therefore leaves the desired generation active and reports
  `cleanup_pending`; rolling runtime back at that point would contradict state.
- Exact no-op candidates validate but do not stage, activate, run health, or
  finalize anything.

The coordinator never formats opaque candidates, staged objects, activation
receipts, configuration bytes, or secrets into results and errors.
