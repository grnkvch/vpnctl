# vpnctl v2 TTY and stdin contract

This contract separates consent from secret input. `--json` changes output rendering only; it never grants consent and never changes how secrets are read or displayed.

## Input channels

- Interactive input and one-time secret output use the controlling terminal (`/dev/tty`), not ordinary stdin/stdout.
- Redirected stdin, pipes, environment variables, argv flags, and token/passphrase files are not secret-input sources in v2.0.
- If a required controlling terminal is unavailable, vpnctl returns validation exit code `2` before authoritative state or system mutation.
- SIGINT, EOF, an empty required value, exhausted attempts, or a confirmation mismatch aborts before mutation.
- `--dry-run` skips consent, but still reads a hidden token or restore passphrase when it is required to authenticate and validate the proposed operation. A dry-run never creates or displays a new invite/recovery token and never asks for a new backup passphrase.

## Input matrix

| Input | Commands | TTY behavior | Non-TTY behavior | Effect of `--yes` | Effect of `--dry-run` |
| --- | --- | --- | --- | --- | --- |
| Yes/no consent | consent class `confirm`; destructive branch of `conditional` | Visible prompt, default `no`; accepts case-insensitive `y/yes/n/no` | Refuse unless `--yes` is present | Proceeds after the complete impact plan | Consent is skipped |
| Typed purge consent | `purge` | Exact case-sensitive `purge gateway` or `purge node` | Refuse | None | Consent is skipped |
| Typed backup deletion | `purge --include-backups` | After purge consent, exact case-sensitive `delete backups` | Refuse | None | Consent is skipped |
| Typed irreversible migration | `update` when the plan marks migration irreversible | After normal update consent, exact case-sensitive `accept irreversible migration` | Refuse | Satisfies only the normal yes/no step | Consent is skipped |
| Invite token | node `join` | One hidden value, up to three input attempts; consumed only by successful join commit | Refuse | None | Still required for remote validation, never consumed |
| Recovery token | node `node recover` | One hidden value, up to three input attempts; consumed only by successful recovery commit | Refuse | None | Still required for remote validation, never consumed |
| New backup passphrase | gateway `backup` | Two hidden entries must match; up to three pairs | Refuse | None | Not requested because no archive is created |
| Existing backup passphrase | `restore` | One hidden value, up to three input attempts | Refuse | None | Still required to decrypt and fully validate the archive |
| One-time secret display | gateway `invite` and gateway `node recover` | Written once directly to the TTY before the success JSON document | Refuse before token activation | None | Suppressed because no token is created |

`--yes` may be combined with non-interactive execution only when no secret input, typed consent, or one-time secret display is required. In JSON mode, secret-issuing commands keep stdout as one schema-valid document and send the token only to the controlling TTY.
