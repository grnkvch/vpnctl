# 0008: Use JSON For MVP State Files

## Context

vpnctl needs a Git-friendly local state file that can be loaded, validated, and
saved by the Go CLI. The project also prefers minimizing dependencies,
especially early in the implementation.

## Decision

Use JSON for the initial MVP state file.

The primary state file is:

```text
.vpnctl/state.json
```

## Alternatives Considered

- YAML
- TOML
- SQLite

## Tradeoffs

JSON is supported by the Go standard library, so it avoids adding a parser
dependency for the initial state model. It is strict, predictable, and easy to
test.

The cost is that JSON is less pleasant to edit manually than YAML and does not
support comments.

## Consequences

- The MVP state package should use Go's standard `encoding/json` package.
- State files should be formatted deterministically for readable diffs.
- If manual editing becomes painful, YAML or another format can be reconsidered
  in a future ADR.
