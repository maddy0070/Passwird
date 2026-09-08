# Passwird — Implementation Roadmap

**Status:** v1 · **Last updated:** 2026-09-07

Ordered so that the security foundation is provable before anything is built on it.
Each phase has an exit criterion; a phase is not "done" because the code exists.

---

## Phase 0 — Foundation ✔

Repository, Gradle multi-module structure, version catalog, CI skeleton, and the
sixteen specification documents in `docs/`.

**Exit:** architecture agreed, security decisions recorded as ADRs.

---

## Phase 1 — Cryptographic core *(highest risk, therefore first)*

`core:crypto` — Argon2id with calibration and floor, HKDF domain registry, AES-256-GCM
with per-write derived message keys, key commitment, LUKS-style key slots, `SecretBytes`
with zeroisation, the `PWVAULT` v1 container with authenticated header, size-bucket
padding, and a hostile-input-hardened parser.

**Exit:** every test in `12-testing-strategy.md` §3 that applies to the format passes,
including tamper, truncation, downgrade, commitment and ciphertext-only.
*Nothing is built on top of this until it is green.*

---

## Phase 2 — Domain model

`core:model` — item envelope and the eleven content types, `Secret`, tombstones,
revision/origin ordering, per-field revisions, folders, tags, device records; the
migration framework with a frozen v1 fixture; codec with unknown-field preservation.

**Exit:** round-trip and unknown-field-preservation properties pass; migration
framework demonstrated with a synthetic v1→v2 migration.

---

## Phase 3 — Vault services

`core:vault` — repository over the encrypted store, CRUD with revision bookkeeping,
auto-lock state machine (platform-free, so it is testable), password generator, honest
strength/entropy model, reuse/weak/age analysis.
`core:search` — offline index, ranking, prefix and fuzzy matching.

**Exit:** generator uniformity and entropy properties pass; search returns correct
ranked results over a 10k-item corpus within budget; no plaintext in the serialised
index.

---

## Phase 4 — Sync engine

`core:sync` — state machine, three-way record merge with tombstones, field-level merge
with conflict preservation, rollback watermark, hash-chain validation, `VaultTransport`
interface, `FakeTransport`, pre-merge safety snapshots.

**Exit:** the full conflict matrix passes; the **data-loss invariant**, commutativity,
idempotence and three-device convergence properties pass.

---

## Phase 5 — Android platform layer

`platform:secure` — Keystore/StrongBox key management, `BiometricPrompt` with
`CryptoObject`, invalidation handling, encrypted local store, clipboard policy,
`FLAG_SECURE` and background masking, auto-lock wiring.
`data:drive` — OAuth lifecycle, `drive.file` folder layout, temp-verify-swap upload,
generation checks, backup rotation, error mapping.

**Exit:** instrumented tests pass on a device; a manual Drive matrix is walked; the
bytes uploaded are verified to be ciphertext.

---

## Phase 6 — Design system

`design:tokens` and `design:components` — every token from `08-design-system.md` as
typed Kotlin; the full component inventory with all states; the generated-mark
renderer; motion and reduced-motion; contrast tests; token grep gates in CI.

**Exit:** state-coverage previews exist for every component; contrast tests pass; no
Material component ships in default dress.

---

## Phase 7 — Application

All 47 screens. Onboarding, unlock, vault, item detail, editor, generator, security,
settings, sync and every exceptional state.

**Exit:** critical path ≤ 4s on a mid-range device; every error state in
`10-error-matrix.md` reachable and rendered; full function at 200% text scale; TalkBack
traversal of the critical path.

---

## Phase 8 — Hardening and audit

Static secret scan, R8 rules, `allowBackup=false` and extraction rules, debug-build
guards, dependency review, and a security review against `02-threat-model.md` claim by
claim.

**Exit:** every claim in §4 of the threat model maps to a passing test; every item in
§5 is reflected in user-facing copy.

---

## Phase 9 — Polish

Motion timing on real hardware, haptics, empty and loading states, copy review of every
string against the rules in `10-error-matrix.md`, icon set completion, performance on a
low-end device with a 5k-item vault.

---

## Post-v1

| Version | Item | Why not v1 |
|---|---|---|
| v1.1 | **Android Autofill Service** | Very high value; large surface with its own leak paths. Deserves a dedicated security review. Seams prepared in `core:vault`. |
| v1.1 | Import from 1Password / Bitwarden / LastPass / KeePass / Chrome | Migration is a trust moment; needs care and a lot of fixtures. |
| v1.2 | Wear OS companion, tablet layouts | — |
| v2 | Passkeys via Credential Manager | Requires being a system credential provider and a considered position on syncing private key material. |
| v2 | Breach check, opt-in, default off | Real if small leakage; must be user-consented with exact disclosure. |
| v2 | Reproducible builds + published artefact hashes | Closes the supply-chain gap named in the threat model §5. |
| v3 | Second sync backend (WebDAV / local network) | Proves Drive is genuinely swappable — the `VaultTransport` interface exists for this. |
| **Never** | Cloud account, telemetry, sharing, key escrow | Each is a documented structural security decision, not a backlog item. |

---

## Status of this build

Stated precisely, because "done" means different things for code that runs here and code
that does not.

| Phase | State | Verified how |
|---|---|---|
| 0 Foundation | Complete | 16 documents + 8 ADRs |
| 1 Crypto core | **Complete** | 69 tests |
| 2 Domain model | **Complete** | 22 tests |
| 3 Vault services | **Complete** | 46 tests |
| 3 Search | **Complete** | 18 tests |
| 4 Sync engine | **Complete** | 59 tests, incl. 5 randomised properties over 400 scenarios each |
| 5 Android platform | Written, **not compiled** | - |
| 5 Drive adapter | Written, **not compiled** | - |
| 6 Design system | Tokens, icons, components written, **not compiled** | Fonts bundled and licence-attributed |
| 7 Application | Core screens written, **not compiled** | - |
| 8 Hardening | **Complete for what runs here** | 15 static checks, each verified to fail on a planted violation |
| 9 Polish | Ongoing | - |

**214 JVM tests pass.** The security core, the domain model, the generator, search and the
entire merge and rollback engine are compiled and executed on every commit.

### The honest caveat

The development container has a JDK and Gradle but **no Android SDK and no emulator**.
Everything under `platform/`, `data/`, `design/` and `app/` is therefore written but has
never been compiled or run. It is reviewed code, not verified code, and this table says so
rather than implying otherwise.

That limitation is also *why* the architecture looks the way it does. Pushing the crypto,
the schema, the merge algorithm and the rollback defence into pure Kotlin/JVM modules was a
layering decision first and a testability decision second - but the effect is that the
parts where a bug is most expensive are the parts that are actually proven, and the
unproven parts are mostly thin bindings to platform APIs.

`settings.gradle.kts` detects the missing SDK and configures only the JVM modules, so
`./gradlew test` is green in this container while a full checkout on a machine with the SDK
builds the complete app.

### What a reviewer should check first

1. `./scripts/scan-secrets.sh` - 15 checks, including the architectural boundaries that
   make the central claim true.
2. `./gradlew test` - 214 tests.
3. `core/sync/src/test/.../MergePropertiesTest.kt` - the data-loss invariant. It is the
   single most valuable test in the repository.
4. `core/crypto/src/test/.../SecurityPropertiesTest.kt` - `CiphertextOnlyTest`, which backs
   the product's central promise on the exact bytes handed to the transport.
