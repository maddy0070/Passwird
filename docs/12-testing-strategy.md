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

| Test | Asserts |
|---|---|
| `CiphertextOnlyTest` | Serialises a vault populated with sentinel values, then scans every byte handed to the transport for **any** of them. Fails the build on a single hit. This is the test that backs the central product claim. |
| `TamperDetectionTest` | Every single-bit flip across header and payload is rejected. |
| `HeaderAadTest` | Mutating any header field — KDF cost, slot, version, chain — breaks the tag. |
| `KeyCommitmentTest` | Wrong passphrase yields `WrongSecret` before any unwrap; a crafted file cannot open under two keys. |
| `RollbackProtectionTest` | A remote version below the watermark is refused and never adopted. |
| `HashChainTest` | A rewritten history fails chain validation. |
| `DowngradeRejectionTest` | Below-floor KDF parameters and out-of-range format versions are refused. |
| `TruncationTest` | Truncated, over-long and malformed length prefixes are rejected without allocation blow-ups. |
| `NoSecretsInLogsTest` | A full lifecycle with a captured log sink contains no sentinel values. |
| `RedactedToStringTest` | Every `Secret`-bearing type redacts in `toString()`. |
| `PreferencesLeakTest` | Nothing vault-derived reaches `SharedPreferences`. |
| `SearchIndexLeakTest` | The serialised index contains no plaintext secrets. |
| `NoHardcodedKeysTest` + `scripts/scan-secrets.sh` | No key material in source or build output. |
| `NoGoogleKeyPathTest` | A complete unlock/decrypt cycle runs with the Google layer absent. |
| `KdfFloorTest` | Parameters below floor are never used, and are upgraded after unlock. |

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
