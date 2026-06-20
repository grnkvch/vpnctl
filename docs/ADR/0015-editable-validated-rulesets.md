# 0015: Use Editable Validated JSON Rulesets

## Context

Clash Mi profiles need domain rules. The operator wants a convenient default
ruleset and the ability to edit rulesets manually as files. Manual editing means
vpnctl must validate rulesets strictly before using them.

## Decision

Store rulesets as editable JSON files under:

```text
.vpnctl/rulesets/
```

The MVP creates a built-in editable `default` ruleset during `vpnctl init`:

```text
.vpnctl/rulesets/default.json
```

Ruleset domains can be provided as a comma-separated list:

```text
vpnctl ruleset add default --domain chatgpt.com,openai.com,claude.ai
```

The MVP supports only this ruleset type:

```text
domain-suffix
```

Example file:

```json
{
  "id": "default",
  "name": "Default",
  "type": "domain-suffix",
  "domains": [
    "chatgpt.com",
    "openai.com",
    "claude.ai",
    "anthropic.com"
  ]
}
```

## Alternatives Considered

- Store rulesets inside `.vpnctl/state.json`.
- Use YAML ruleset files.
- Allow arbitrary Clash rule types in MVP.
- Require domains only through command flags without editable files.

## Tradeoffs

Separate JSON ruleset files are easy to inspect, edit, diff, and reuse. Keeping
the MVP type whitelist to `domain-suffix` avoids accepting invalid or unsupported
rule types.

The cost is that more Clash rule types require future schema and renderer work.

## Consequences

- `vpnctl init` should create `.vpnctl/rulesets/default.json`.
- `vpnctl ruleset add <id> --domain <comma-separated-domains>` should create or
  update a ruleset file.
- Rulesets must be validated both when written by commands and when loaded from
  disk.
- Invalid `type` values must produce clear errors and stop export.
- Clash Mi export should default to the `default` ruleset unless another
  ruleset is specified.
