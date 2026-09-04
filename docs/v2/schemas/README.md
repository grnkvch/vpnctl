# vpnctl v2 JSON result schemas

The v2 CLI emits schema version `1` for the lifetime of the v2 major version. Additive optional fields may be introduced without changing that number; removing, renaming, changing the type of a field, or making an optional field required needs a new result schema version.

`common-result-v1.schema.json` defines the mandatory envelope. Files in `results/` constrain the command IDs and `data` shape for every JSON-capable command listed in `docs/v2/CLI_CONTRACT.md`. `examples-v1.json` contains one validating result for every such registry row.

The schemas intentionally reject unknown top-level fields and sensitive field names recursively. Tokens, secrets, private keys, authorization material, passphrases, request/response bodies, and sensitive webhook/probe URLs are never JSON result fields. Commands that must reveal or consume a secret use the separate TTY flow.

`preset-v1.schema.json` is the public JSON Schema for editable YAML preset
documents rather than a CLI result schema. `preset-v1.example.yaml` is its
canonical example; parser-level checks additionally enforce canonical DNS/IP
values, one YAML document, and the absence of aliases or anchors.

`release-manifest-v1.schema.json` defines the canonical payload signed for a
release, while `signed-release-manifest-v1.schema.json` defines its Ed25519
envelope. The checked-in `release-manifest-v1.example.json` is deliberately
non-installable: its vpnctl checksum is illustrative. Runtime verification
also enforces cross-field component/artifact/apt references, deterministic
ordering, canonical JSON/base64url, signature authenticity, exact artifact
SHA-256, and the observed Ubuntu/architecture boundary.
