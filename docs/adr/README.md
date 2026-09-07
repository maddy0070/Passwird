# Architecture Decision Records

Short, dated records of decisions that are expensive to reverse. Format: context →
decision → consequences (including the bad ones).

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-aead-selection.md) | AES-256-GCM with per-write HKDF-derived message keys | Accepted |
| [0002](0002-random-vek-key-slots.md) | Random VEK wrapped by independent key slots | Accepted |
| [0003](0003-drive-visible-folder.md) | Visible `drive.file` folder, not `appDataFolder` | Accepted |
| [0004](0004-whole-vault-sync-unit.md) | Sync the whole vault as one blob, merge after decryption | Accepted |
| [0005](0005-no-telemetry.md) | No analytics or crash reporting of any kind | Accepted |
| [0006](0006-no-sharing.md) | No vault sharing in any form | Accepted |
| [0007](0007-no-certificate-pinning.md) | No certificate pinning for Drive | Accepted |
| [0008](0008-no-wipe-on-failed-unlock.md) | Backoff, never wipe, on failed unlock | Accepted |
