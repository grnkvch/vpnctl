# Cross-host saga coordination

Task 13.3 defines the recoverable coordination boundary for a change that
spans the authoritative gateway and one private node. The coordinator is
operation-neutral: task 13.4 and resource-specific workflows provide the
state store and component adapter.

The gateway-backed store is a compare-and-swap boundary. It must durably
persist the full saga record, including its unique operation ID, distinct
request ID, record revision, current phase, both expected/current/desired host
generations, readiness flags, and drain deadline. A create or save call may
commit and lose its acknowledgement; callers therefore resume by stable ID
instead of treating an error as proof that no write occurred.

## Fixed phase order

| Persisted phase | Required effect before advancing | State after advance |
| --- | --- | --- |
| `validate` | Read-only complete-candidate and generation validation | `staging` |
| `stage` | Stage gateway and node candidates without publication | `staging` |
| `activate-private` | Activate the private-side candidate | `staging` |
| `confirm-private` | Confirm tunnel/component readiness by exact generation | `staging` |
| `publish-public` | Publish the public gateway route | `active` |
| `drain` | Drain the superseded generation until the persisted deadline | `active` |
| `finalize` | Remove old generation resources and reach desired generations | `completed` |
| `complete` | Terminal, no further effect | `completed` |

The receipt invariants make public publication impossible before the private
candidate is confirmed ready. A publication receipt supplies the effective
gateway time. The coordinator persists `effective_at + drain` as an absolute
deadline, with `drain` limited to ten seconds. A restart never starts a fresh
drain window; once that deadline has passed the coordinator records drain
completion without invoking another wait.

## Resume-first execution

Every side-effect phase follows the same rule:

1. Load and validate the latest CAS record.
2. Reconcile the stable operation ID, phase, and both host generations.
3. Advance without execution when evidence is `applied`.
4. Execute exactly once only after positive `not_applied` evidence.
5. Persist `degraded` and stop when evidence is `unknown`, a response is lost,
   or persistence acknowledgement is uncertain.

The adapter deliberately has no rollback method. After uncertainty, passive
`status` can surface the persisted phase; a later `apply` loads the operation
again and reconciles actual generations before taking another effect. This
prevents both blind replay and blind rollback. A definitive
expected-generation conflict returned by the read-only validation phase is
instead persisted as terminal `failed`.

Adapter receipts are non-secret, operation-bound evidence. They may advance a
host generation only within the persisted current-to-desired range. Finalize
must report both exact desired generations. Invalid, early-publication, stale,
or cross-operation receipts cannot advance the saga.

## Integration boundary

The task-13.4 `apply` adapter must preserve these properties:

- the authoritative gateway remains the sole durable writer;
- a node process is contacted for node effects rather than simulated locally;
- every remote command is idempotent by operation ID and phase;
- reconciliation reads exact applied generations and stable resource IDs;
- CAS conflicts cause a fresh load/resume, never an unguarded repeat;
- serialized records and errors contain no candidate bytes or secrets.

Validation and phase actions have bounded contexts. A caller deadline may
shorten a step, but no step may extend the persisted drain deadline.
