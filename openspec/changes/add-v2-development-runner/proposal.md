## Why

The approved discovery policy is currently documentation-only: both the parent
release gate and several child harnesses still require a clean committed tree.
Developers need a real selected-stage entry point without creating commits or
requalifying the whole release after each edit.

## What Changes

- Add `run-dev <stage>` to the deployed-gate entry point, using current working
  files and only the selected registered stage plus its actual prerequisites.
- Retain a private input snapshot, content checksums and non-release results;
  Git HEAD and clean-tree state do not authorize or invalidate development runs.
- Propagate an explicit repository-scoped development context to child harnesses
  that currently enforce clean Git source, without relaxing fixture ownership,
  clean-state witnesses, package hashes or cleanup.
- Keep final preparation, resume, aggregation and finalization strict and unable
  to consume development evidence. No cross-run cache or automatic result reuse.

## Capabilities

### New Capabilities

- `development-test-execution`: uncommitted selected-stage development execution
  with content-bound, clearly non-release evidence.

### Modified Capabilities

None. Existing final release qualification remains unchanged.

## Impact

Gate orchestration, a small shared source-context helper, affected child
harnesses, deterministic host-only regression fixtures, and process docs.
No product routing change, VM/VPS run, Telegram/iOS interaction or release
publication is part of implementing this change.
