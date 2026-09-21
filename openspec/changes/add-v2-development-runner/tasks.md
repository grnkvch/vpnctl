## 1. Development execution

- [x] 1.1 Add a private current-input snapshot and source-context helper; verify dirty/unborn source and exact helper bytes with host-only regressions.
- [x] 1.2 Add selected-stage `run-dev` execution using existing registry, prerequisites and cleanup; verify selection, failure and stopped-fixture outcomes with fake commands/Lima.
- [x] 1.3 Integrate nested source checks without weakening final mode; verify real child entry points, inherited-context isolation and rejection of development evidence.

## 2. Verification and handoff

- [x] 2.1 Cover HEAD changes, input drift, invalid selection and immutable earlier observations; run focused development/final gate regression tests and shell syntax checks.
- [ ] 2.2 Update AGENTS, release guide and backlog to describe implemented behavior and limitations; validate OpenSpec, review the scoped diff and update PR #1.
