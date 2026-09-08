# Passwird — Testing Strategy

**Status:** v1 · **Last updated:** 2026-09-07

## 1. Principle

> **Every security claim in `02-threat-model.md` §4 must have a test that fails if the
> claim stops being true.**

A threat model without executable tests is a wish list. The tests below are the
enforcement mechanism for the claims we make to users.

## 2. Why the architecture is shaped the way it is

The modules `core:crypto`, `core:model`, `core:vault`, `core:search` and `core:sync`
are **pure Kotlin/JVM** — no Android, no Google. This is a testability decision as much
as a layering one: it means the entire security core, the merge algorithm and the
conflict matrix run in CI in seconds, with no emulator, on every commit.

Android-dependent code is confined to `platform:secure`, `data:drive` and `app`, and is
kept as thin as possible — ideally holding no logic worth testing, only bindings to
platform APIs.

| Layer | Type | Runs in CI without a device |
|---|---|---|
| `core:*` | JVM unit + property tests | **Yes** |
| `platform:secure`, `data:drive` | Instrumented | No (needs device/emulator) |
| `app` | Compose UI tests | No |

## 3. Security tests (the ones that matter most)

Every row names something that **exists and runs**. Rows for work not yet done are in §3.1,
kept separate on purpose: a test list is a safety argument, and a safety argument that
quietly includes tests nobody has written is worse than a short one.

| Test | Asserts |
|---|---|
| `CiphertextOnlyTest` | Serialises a vault populated with sentinel values, then scans every byte handed to the transport for **any** of them. Fails the build on a single hit. This is the test that backs the central product claim. |
| `TamperDetectionTest` | Every single-bit flip across header and payload is rejected. Also covers truncation at any offset, appended trailing bytes, foreign files, and over-long declared header/payload lengths — rejected on the declared length, before allocation. |
| `HeaderAadTest` | Mutating any header field — KDF cost, slot, version, chain — breaks the tag. |
| `KeyCommitmentTest` | Wrong passphrase yields `WrongSecret` before any unwrap; a crafted file cannot open under two keys. |
| `RollbackGuardTest` | A remote version below the watermark is refused and never adopted. |
| `HashChainTest` | A rewritten history fails chain validation. |
| `DowngradeRejectionTest` | Below-floor KDF parameters and out-of-range format versions are refused. |
| `NoSecretsInLogsTest` | A full lifecycle — seal, unlock, recover, wrong passphrase, truncated file, corrupted file — writes no sentinel to stdout or stderr. Includes a planted leak, so the harness cannot pass vacuously. |
| `RedactedToStringTest` | Every `Secret`-bearing type redacts in `toString()`. |
| `SearchIndexLeakTest` | The serialised index contains no plaintext secrets. |
| `NoGoogleKeyPathTest` | Structural: no Google/Android/platform type is on the crypto module's classpath or named in any signature or field within it, and no unseal entry point accepts anything identifying a user. Plus a full unlock cycle with the identity layer absent. |
| `DeviceSlotTest` | A device slot unlocks without the passphrase, is rejected if found in a vault file, and is invalidated by VEK rotation. |
| `RecoveryKeyTest` | The recovery key round-trips, tolerates real transcription mistakes, and detects >97% of single typos and transpositions before Argon2id runs. |
| `KdfFloorTest` | Parameters below floor are never used, and are upgraded after unlock. |
| `scripts/scan-secrets.sh` | 15 static checks: no key material in source, no Google or Android imports in core, no vault data in `SharedPreferences`, no analytics SDK. |
| `scripts/check-contrast.py` | 56 token pairs meet the WCAG floors in `08-design-system.md` §2.3. |

### 3.1 Named but **not yet written**

> **Corrected 2026-09-08.** An audit compared every test name appearing in these documents
> against the classes that actually exist. Eleven names did not resolve. Most were real
> coverage recorded under the wrong name and have been corrected above
> (`RollbackProtectionTest` → `RollbackGuardTest`; `TruncationTest` and `VaultFileTest` →
> `TamperDetectionTest` and `HeaderAadTest`; `NoHardcodedKeysTest` → `scan-secrets.sh`;
> `ContrastTest` → `check-contrast.py`). `NoGoogleKeyPathTest` and `NoSecretsInLogsTest`
> were genuinely missing and have now been written. The three below are genuinely missing
> and remain so.

| Test | Would assert | Why it does not exist yet |
|---|---|---|
| `PreferencesLeakTest` | Nothing vault-derived reaches `SharedPreferences`. | Needs an instrumented run. `scan-secrets.sh` covers the static half (no vault type is written to preferences in source); the runtime half is unverified. |
| `ClipboardPolicyTest` | Clipboard auto-clear fires, and `EXTRA_IS_SENSITIVE` is set. | Needs a device. The policy is implemented but **has never been executed**. |
| `AtomicPublishTest` | A Drive upload interrupted at any step never leaves the vault unreadable or absent. | Needs a fake Drive. The behaviour **is** implemented (`DriveTransport.upload` stages, reads back, archives, re-checks and renames) but has never been run, and the review identifies a window between the delete and the rename where no live vault exists. |

## 4. Property-based tests

Where the input space is too large to enumerate, we assert invariants instead. These
catch the merge bugs that destroy vaults.

| Property | Statement |
|---|---|
| **Data-loss invariant** | No record present in `local` or `remote` is ever absent from the merge result unless a tombstone explicitly covers it. *The single most valuable test in the repository.* |
| Merge commutativity | `merge(base, l, r) ≡ merge(base, r, l)` |
| Merge idempotence | `merge(base, m, m) ≡ m` |
| Convergence | Any ordering of a change-set across three devices reaches the same state |
| Crypto round-trip | `decrypt(encrypt(x)) == x` for arbitrary payloads including empty, huge, and adversarial Unicode |
| Padding | Round-trips exactly; bucket boundaries never mis-strip |
| Generator uniformity | Character distribution within statistical bounds; no modulo bias |
| Serialisation | Unknown fields survive a decode/encode round-trip (the cross-version data-loss guard) |

## 5. Functional coverage

**Crypto/vault:** create, unlock (passphrase / recovery / device slot), wrong secret,
change passphrase, add/remove slot, VEK rotation, parameter upgrade, schema migration
against frozen fixtures, migration failure is non-destructive.

**Sync:** the full `{none, edit, delete, create}²` matrix with and without a base;
concurrent same-field edits; tombstone-vs-edit both directions; three-device chains;
interrupted upload/download; corrupt remote; generation mismatch; offline queue and
replay; rollback and fork.

**Domain:** generator (length, classes, ambiguity exclusion, passphrase mode, exact
entropy), strength estimation, search (ranking, prefix, fuzzy, unicode, 10k-item
performance), reuse/weak/age detection.

**Android (instrumented):** Keystore wrap/unwrap, StrongBox present and absent,
biometric success/failure/lockout, key invalidation on new enrolment, auto-lock across
timeouts and backgrounding, `FLAG_SECURE`, clipboard auto-clear, Drive transport
against a fake server for every error mapping in `06-drive-integration.md` §6.

**UI:** onboarding to first credential; unlock paths; retrieve-and-copy critical path;
add/edit/delete with undo; conflict review; every error state renders; 200% text scale;
reduced motion; TalkBack traversal of the critical path.

## 6. Test data

- **Frozen fixtures** for every historical schema version, committed as binary. Never
  regenerated — regenerating a fixture defeats its purpose.
- Sentinel values (`SENTINEL_PW_a7f3…`) used throughout so leak scans have something
  unambiguous to search for.
- Adversarial corpus: truncated files, flipped bits, oversized length prefixes,
  duplicate slots, hostile JSON (deep nesting, huge strings, dupe keys), zero-length
  payloads.

## 7. CI gates

Every PR: build all JVM modules · run all `core:*` tests · property tests · secret scan
· contrast test over the token table · design-token grep gates (`08-design-system.md`
§10) · dependency review.

**Merge is blocked if:** any security test fails, coverage of `core:crypto` or
`core:sync` drops below 90%, or a new outbound network call appears without a
corresponding update to `11-privacy-model.md` §2.

## 8. Honest limitations

- Instrumented and UI tests **cannot run in this development container** (no Android
  SDK). They are written to run on a device or emulator in a full CI environment; here
  they are unexecuted. This is stated rather than papered over.
- Memory zeroisation is best-effort on the JVM (GC may copy) and cannot be fully
  asserted by a test.
- We do not test against a real Google Drive in CI; the transport is exercised against
  a fake implementing the same contract, with a small manual matrix before release.
