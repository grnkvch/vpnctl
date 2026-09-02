# vpnctl preset document v1

Files under `/etc/vpnctl/presets.d/*.yaml` use the public
[`preset-v1.schema.json`](schemas/preset-v1.schema.json) contract. A complete
example is [`preset-v1.example.yaml`](schemas/preset-v1.example.yaml).

The root contains exactly `schema_version`, `name`, `include`, and
`exclude`. Both arrays are required and `include` must contain at least one
selector. Supported selector types are:

- `domain`: one exact canonical lower-case DNS name;
- `domain-suffix`: the canonical lower-case suffix and its subdomains;
- `ip-cidr`: one canonical IPv4 or IPv6 prefix; use `/32` or `/128` for
  one IP.

The parser rejects unknown fields and types, duplicate selectors in the same
array, non-canonical values, YAML aliases/anchors, and multiple YAML documents.
It sorts selectors into a provider-neutral AST, so source order has no effect.

There is intentionally no action, outbound, proxy name, Mihomo rule, or raw
provider field. An included match can only mean selected traffic that must use
the gateway or block; an unmatched flow remains direct. Exclusion/composition
semantics and policy activation are handled separately from this source schema.

Fresh `vpnctl init --gateway` creates editable `telegram.yaml`, `openai.yaml`,
and `anthropic.yaml` sources with mode `0644`. These files become user state at
creation: repeat initialization and ordinary binary/component updates neither
restore a deleted source nor overwrite an edited one. A later built-in template
revision must be introduced only through the explicit reviewed preset-update
flow.

The initial Telegram template intentionally contains stable DNS suffixes rather
than a frozen data-center address list. Telegram clients obtain DC addresses at
runtime and those addresses may change; an operator who needs hardcoded-IP
classification can add reviewed `ip-cidr` selectors before applying the preset.

Composition keeps preset boundaries. Each preset first evaluates its own
`include − exclude` set with exclusions taking precedence; assigned presets are
then unioned. An explicit include in one preset can therefore reselect a domain
or IP excluded by another preset. Source rule order and preset file order do not
change the normalized composition.
