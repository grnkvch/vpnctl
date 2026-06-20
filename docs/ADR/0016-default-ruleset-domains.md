# 0016: Use Minimal Built-In Default Ruleset Domains

## Context

The MVP creates an editable `default` ruleset for Clash Mi domain routing. The
default domain list should be useful immediately while avoiding unnecessary
duplicates.

The MVP ruleset type is `domain-suffix`, so a rule for `openai.com` also covers
subdomains such as `api.openai.com` and `ios.chat.openai.com`.

## Decision

Create the built-in `default` ruleset with this default domain list:

```text
chatgpt.com
openai.com
claude.ai
anthropic.com
```

Do not include `api.openai.com` by default because it is already covered by
`openai.com` with `domain-suffix` matching.

## Alternatives Considered

- Include `api.openai.com` explicitly.
- Include auxiliary app domains such as Sentry, RevenueCat, or Apple services.
- Start with an empty ruleset.

## Tradeoffs

The minimal list is clear and avoids duplicate generated rules. It keeps the
built-in default ruleset focused on AI services.

The cost is that auxiliary domains used by client apps may still go direct
unless the operator adds them manually.

## Consequences

- `vpnctl init` should create `.vpnctl/rulesets/default.json` with the four
  default domains.
- Generated Clash rules should include one `DOMAIN-SUFFIX` rule per default
  domain.
- Clash client exports should use the `default` ruleset when `--ruleset` is not
  provided.
- This default applies to all Clash/Mihomo client exports. WireGuard exports do
  not use rulesets.
- The operator can edit `.vpnctl/rulesets/default.json` or use
  `vpnctl ruleset add` to extend the list.
