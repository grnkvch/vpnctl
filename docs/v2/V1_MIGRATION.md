# One-time v1 migration

The standalone v1-to-v2 migrator is deliberately not maintained in the vpnctl
v2 product source line and is not a release asset or permanent command. Its
versioned source, executable runbook, disposable Ubuntu qualification gate, and
immutable evidence live only on the operational
`ops/v1-to-v2-migration` source line based on the exact product commit and
release bundle being installed.

Before using that operation, require matching passing fast and native migration
evidence, verify the recorded product/migration commits and bundle/migrator
SHA-256 values, and copy artifacts over trusted SSH/SCP. The real Gateway is
never a development fixture. Downtime remains accepted, and the existing
snapshot, watchdog, rollback, client-validation, and explicit-acceptance
contract remains mandatory.

After acceptance, remove the deployed helper and its staging copy, retain the
non-secret host journal and evidence, and preserve the exact executed source as
an archival ref. The active operational branch may then be deleted; the
reproducible source record must not be erased.
