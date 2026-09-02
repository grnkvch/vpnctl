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

## Source inspection and pending changes

The gateway treats files in `presets.d` as a candidate source set and the
presets stored in authoritative state as the last active effective generation.
The read-only `preset list`, `preset show`, `preset validate`, and `preset diff`
operations compare those two views; they never publish state or rewrite source
files.

Validation always covers the complete source set. Each `*.yaml` entry must be a
bounded regular file rather than a symlink, its document name must equal its
filename, and all documents must form one valid composition. A validation
failure rejects the candidate set as a whole, so `diff` returns issues without
a partial change plan and the previous effective generation remains active.

Diffs distinguish a raw source change from a normalized selector change. A
comment-only edit is therefore visible and reviewable without being reported as
a routing-semantic change. Added and removed selectors, presets, and affected
node/client assignments are returned in deterministic order.

Deleting an unassigned YAML source is a valid pending deletion. Deleting a
preset that is still assigned to any node or client is a whole-set validation
error until every assignment is explicitly removed. There is no separate
public `preset delete` command; source creation, editing, and deletion remain
explicit filesystem operations followed by the reviewed apply flow.

## Reviewed built-in template updates

Built-in sources carry a comment-only marker such as
`# vpnctl built-in-template: telegram@1`. The marker does not add a YAML field
or broaden the public selector schema. Marker-less sources are accepted only as
the legacy revision-1 base; a malformed, duplicated, unknown, or stale revision
cannot be guessed and makes template update return a conflict. Releases retain
the embedded adjacent base revisions needed for an offline three-way merge;
there is no remote ruleset or background fetch.

The merge compares the embedded base, the current user source, and the next
embedded template by logical `(selector type, value)` matcher. Disjoint
upstream changes and operator additions/exclusions are preserved. If both sides
change the same matcher's include/exclude membership incompatibly, the source
is left byte-identical and the conflicting matchers are reported. A successful
merge is rendered back into canonical selector order with the next revision
marker; comments and formatting other than the managed header are intentionally
not semantic and may be normalized after review.

Planning is read-only and binds the review to the complete source-set hash and
authoritative state generation. Apply rejects a stale plan if any preset source
or state generation changed after review. A deleted built-in remains absent
until an explicit update, which restores the latest embedded revision.

Immediate update atomically replaces only the selected source and publishes a
new effective generation for that preset and its assigned policies. Other valid
manual edits remain pending for the general `vpnctl apply` flow; invalid files
anywhere still reject the complete candidate before mutation. Deferred update
atomically replaces only the YAML and leaves authoritative/effective state
unchanged. A state-write failure proven to have left the old generation active
restores the exact prior YAML (or removes an explicitly restored file); an
uncertain/committed write is reported without attempting a destructive blind
rollback.
