# Passwird — Documentation Index

> A private vault that happens to synchronise.

An offline-first, end-to-end encrypted password manager for Android. The vault lives on
the device. Google Drive holds a sealed copy and is treated as **hostile by default**.

---

## Reading order

**Start here** if you want the product:

1. [`01-product-spec.md`](01-product-spec.md) — positioning, ranked principles, scope
   decisions and what we deliberately refused to build
2. [`09-ux-flows.md`](09-ux-flows.md) — information architecture, the critical path,
   first-run flow, and the 47-screen inventory
3. [`08-design-system.md`](08-design-system.md) — “Quiet Precision”: tokens, type, motion
   and the rules that keep it coherent

**Start here** if you want the security:

4. [`02-threat-model.md`](02-threat-model.md) — assets, adversaries, what we protect
   against **and what we cannot**
5. [`03-encryption-architecture.md`](03-encryption-architecture.md) — primitives, key
   hierarchy, and the normative `PWVAULT` file format
6. [`04-key-management.md`](04-key-management.md) — key slots, biometrics, recovery,
   rotation, and the authentication/encryption separation
7. [`05-sync-architecture.md`](05-sync-architecture.md) — merge algorithm, rollback
   defence, conflict handling
8. [`06-drive-integration.md`](06-drive-integration.md) — scopes, layout, concurrency,
   and what Google can and cannot see

**Supporting:**

9. [`07-data-model.md`](07-data-model.md) — schema, item types, migrations
10. [`10-error-matrix.md`](10-error-matrix.md) — 32 error states with exact copy
11. [`11-privacy-model.md`](11-privacy-model.md) — every network call the app makes
12. [`12-testing-strategy.md`](12-testing-strategy.md) — how each security claim is proven
13. [`13-roadmap.md`](13-roadmap.md) — phases and current build status
14. [`research/competitive-notes.md`](research/competitive-notes.md) — findings and the
    decisions they produced
15. [`adr/`](adr/README.md) — ten decision records

**Read these two first if you are assessing what actually works:**

16. [`14-production-readiness-review.md`](14-production-readiness-review.md) — every
    subsystem classified as verified / reviewed-but-unverified / partial / missing / risk,
    with the recovery and multi-device recommendations and the exact implementation order.
    **The JVM core is tested; no Android code has ever been compiled.** This document is the
    honest account of that gap.
17. [`15-autofill-design.md`](15-autofill-design.md) — the security and privacy design that
    must be accepted before any Autofill code is written. Deferred deliberately.
18. [`17-android-verification-gate.md`](17-android-verification-gate.md) — the first real
    Android build: what compiled, the seven defects it found, the APK it produced, and what
    still cannot be verified without a device.

---

## The five decisions that define this product

| Decision | Where | Why it matters |
|---|---|---|
| **Google is not in the key hierarchy** | [`04`](04-key-management.md) §1 | Authentication and encryption are fully separate. Total Google account takeover yields ciphertext. |
| **The store is assumed hostile** | [`02`](02-threat-model.md) §2 | Rollback, fork and downgrade defences that the Feb 2026 ETH Zürich study showed most shipped managers lack. |
| **Merges never destroy data** | [`05`](05-sync-architecture.md) §5 | Conflicting edits are kept, not resolved. Enforced by a property test, not by care. |
| **No server, no telemetry, no sharing** | [`adr/0005`](adr/0005-no-telemetry.md), [`adr/0006`](adr/0006-no-sharing.md) | Three entire attack classes removed by construction rather than mitigated. |
| **Honest, or silent** | [`01`](01-product-spec.md) §7 | Entropy with a stated attacker model instead of a five-bar meter. Limits stated in the product, not buried. |

---

## What Google can and cannot see

| Can see | Cannot see |
|---|---|
| A `Passwird` folder exists | Any password, username, note, URL or card number |
| The encrypted file's padded size | How many items the vault holds |
| When the file changed | Which items changed |
| That the account uses this app | The passphrase or the recovery key |

The right-hand column is enforced by `CiphertextOnlyTest`, which fails the build if any
known plaintext value appears in the bytes handed to the transport.

---

## Module map

```
core/crypto     KDF, key hierarchy, key slots, PWVAULT format     pure JVM · tested here
core/model      schema, item types, migrations                    pure JVM · tested here
core/vault      repository, generator, strength, auto-lock         pure JVM · tested here
core/search     offline index and ranking                          pure JVM · tested here
core/sync       state machine, three-way merge, rollback defence   pure JVM · tested here
platform/secure Keystore, biometrics, clipboard, FLAG_SECURE       Android · needs SDK
data/drive      OAuth + Drive transport                            Android · needs SDK
design/*        tokens and components                              Android · needs SDK
app             screens and navigation                             Android · needs SDK
```

The `core:*` modules are deliberately free of Android and Google dependencies. That is a
layering decision *and* a testability one: the entire security core and the full conflict
matrix run in CI in seconds without an emulator.
