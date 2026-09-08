# Passwird — Production-Readiness Review

**Status:** v1 · **Date:** 2026-09-08 · **Reviewer:** architecture/security review pass
**Scope:** the gap between a verified JVM core and an Android application that has never been built.

---

## 0. The honesty rule this document follows

One sentence governs everything below:

> **No Android code in this repository has ever been compiled or executed.**

There is no Android SDK in the development environment. `settings.gradle.kts` detects this
and configures only the pure-JVM modules, which is why `./gradlew test` is green. That green
covers `core:crypto`, `core:model`, `core:vault`, `core:search` and `core:sync` — and
nothing else. Every statement about `app`, `platform:secure`, `data:drive`, `design:tokens`
or `design:components` in this document is a statement about **code that has been read**,
not code that has been observed to work.

The build blockers fixed in the previous commit are the evidence for why that distinction
matters. `material3` was imported in twelve files and declared in none; the app could not
have compiled at all. That defect survived a full implementation phase and a first audit,
because nothing ever tried to build it. Anything in this document marked *reviewed but
unverified* is subject to exactly that failure mode.

### Classification legend

| Label | Meaning |
|---|---|
| **VERIFIED** | Executed by an automated test that runs in CI today, and that test has been shown to fail when the property is broken. |
| **REVIEWED BUT UNVERIFIED** | Read line by line and believed correct. Never compiled, never run. |
| **PARTIALLY IMPLEMENTED** | Some of the subsystem exists and works; a named part of it does not exist. |
| **MISSING** | Specified in the design documents; no implementation exists. |
| **SECURITY RISK** | A defect with security consequence, whether or not it is implemented. |

### Subsystem classification

| Subsystem | Status | Basis |
|---|---|---|
| AEAD envelope, key derivation, HKDF domains | **VERIFIED** | 88 crypto tests; bit-flip, truncation, AAD and commitment coverage |
| PWVAULT v1 container format | **VERIFIED** | `TamperDetectionTest`, `HeaderAadTest` — hostile-input parsing covered |
| Key slots (passphrase / recovery / device) | **VERIFIED** | `KeyCommitmentTest`, `DeviceSlotTest` |
| Recovery key codec | **VERIFIED** | `RecoveryKeyTest`; 500-key round-trip, >97% typo and transposition detection |
| Auth/encryption separation | **VERIFIED** | `NoGoogleKeyPathTest` — structural, over every compiled signature in the module |
| Domain model, codec, migrations | **VERIFIED** | 22 tests; unknown-field preservation covered |
| Password/passphrase generation, strength | **VERIFIED** | 46 tests; entropy never over-counted |
| Search index | **VERIFIED** | 18 tests including a plaintext-leak scan of the serialised index |
| Merge and conflict resolution | **VERIFIED** | 59 tests; commutativity, idempotence and the data-loss invariant are property-tested |
| Rollback / fork detection | **VERIFIED** | `RollbackGuardTest`, `HashChainTest` |
| Android Keystore integration | **REVIEWED BUT UNVERIFIED** | Structurally correct; one API-level crash found and fixed this pass (§B-1) |
| Biometric unlock | **REVIEWED BUT UNVERIFIED** | `CryptoObject`-bound, `BIOMETRIC_STRONG` only. Never run on a device. |
| Encrypted local store | **REVIEWED BUT UNVERIFIED** | Stages and renames; no test |
| Clipboard guard | **REVIEWED BUT UNVERIFIED** | Never executed |
| Screen privacy (`FLAG_SECURE`) | **REVIEWED BUT UNVERIFIED** | Never executed |
| Auto-lock controller | **PARTIALLY IMPLEMENTED** | Policy logic is JVM-tested (`AutoLockTest`); the Android controller that drives it is unverified and unwired |
| Drive transport | **REVIEWED BUT UNVERIFIED** | Staged publish is implemented; see §F for two defects |
| Google account/OAuth | **REVIEWED BUT UNVERIFIED** | Never executed |
| Design system | **PARTIALLY IMPLEMENTED** | Tokens now contrast-checked (56 pairs). No component has ever rendered. |
| **Composition root / DI** | **MISSING** | `PasswirdApp` renders a hard-coded `UnlockScreen` with empty callbacks |
| **`VaultStorage` implementation** | **MISSING** | The interface exists. Nothing implements it. |
| **`VaultRepository` construction** | **MISSING** | The class is never instantiated anywhere |
| **Onboarding / vault creation** | **MISSING** | There is no path by which a vault can come into existence |
| **Recovery flow (UI)** | **MISSING** | The codec exists; nothing calls it |
| **Device enrolment / registry** | **MISSING** | `DeviceRecord` is modelled and merges correctly; nothing ever writes one |
| **Multi-device authorization** | **MISSING** | No design was chosen. §E recommends one. |
| **41 of 47 screens** | **MISSING** | Five screen composables and two sheet components exist |
| Autofill | **MISSING (deliberately deferred)** | Design required before implementation — `15-autofill-design.md` |

---

## A. Architecture findings

### A-1 · The vertical slice does not exist — this is the headline finding

The product is two disconnected halves.

```
        VERIFIED                              UNWIRED
  ┌───────────────────────┐          ┌──────────────────────────┐
  │  core:crypto          │          │  app/ui  (5 screens)     │
  │  core:model           │          │  platform:secure         │
  │  core:vault           │    ??    │  data:drive              │
  │  core:search          │  ◄────►  │  design:components       │
  │  core:sync            │          │                          │
  │  239 tests, 0 failed  │          │  0 tests, never compiled │
  └───────────────────────┘          └──────────────────────────┘
              ▲                                    ▲
              │                                    │
        VaultRepository  ── never constructed ─────┘
              │
        VaultStorage     ── no implementation exists
```

`VaultRepository` is a competent 266-line class holding unlock, mutate, search and sync. It
depends on a `VaultStorage` interface. **Nothing implements that interface, and nothing ever
constructs the repository.** `PasswirdApp` — the file whose own KDoc calls itself "the
composition root" — renders:

```kotlin
UnlockScreen(
    state = UnlockUiState.Ready,
    biometricAvailable = true,
    onBiometricUnlock = {},
    onPassphraseUnlock = {},
    onUseRecoveryKey = {},
)
```

Every callback is empty. There is no state holder, no ViewModel, no dependency graph, and no
code path from a user gesture to `VaultCrypto`. The comment above it says "wired to
`VaultRepository.vault` in the real composition root" — there is no other composition root.

**Consequence.** The correct reading of this repository is: *a verified cryptographic core
and design system, plus an Android shell that has never run.* Not "an app with some gaps".
Everything in §H is ordered around closing this first, because until it closes, no Android
claim in any document can be verified even in principle.

### A-2 · There is no way to create a vault

Every flow assumes a vault exists. `VaultRepository.unlock` reads bytes from storage and
returns `NoVault` when there are none — and nothing handles that case. There is no
onboarding, no passphrase-choosing screen, no recovery-key display, and no first upload.

This is more than a missing screen. Vault creation is where the recovery key is generated and
shown *exactly once*, where the KDF parameters are calibrated to the device, and where the
user is told the one thing they must not forget. It is the highest-stakes flow in the
product and it is entirely absent.

### A-3 · `DeviceRecord` is modelled, merged, and never written

`core:model` defines `DeviceRecord`; `VaultMerge.mergeDevices` correctly unions device lists
across replicas and is covered by tests. But no code constructs a `DeviceRecord`. The device
registry — which `04-key-management.md` §6 relies on for "lost device" and which §7 relies on
for revocation — is an empty list in every vault that could exist.

The merge logic being right in advance is genuinely useful; it is not the same as the feature
existing.

### A-4 · Auto-lock is split across a verified half and an unwired half

The policy (`core:vault/lock/AutoLock.kt`) is pure and tested. The Android half
(`AppLockController`) observes lifecycle and drives it — and nothing constructs it either. The
`onUserInteraction` hook in `MainActivity` is wired to a function that currently does nothing
useful because there is no controller behind it.

This is the shape of the whole codebase: correct logic, no host.

### A-5 · The module boundary is genuinely good, and should not be disturbed

Stated positively, because §H depends on it: the decision to put every security-critical
algorithm in pure-JVM modules is the single best structural decision in the repository. It is
why 239 tests run in 11 seconds with no emulator, why the merge algorithm could be
property-tested at all, and why `NoGoogleKeyPathTest` can make a structural claim rather than
a behavioural one. **The wiring work in §H must not pull logic upward into `app`.** Anything
worth testing belongs below the Android line.

---

## B. Security findings

### B-1 · `setUserAuthenticationParameters` crashes on Android 8–10 — **SECURITY RISK, fixed this pass**

`KeystoreKeyManager.createBiometricKey` called:

```kotlin
builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
```

unguarded. That method arrived in **API 30**. `minSdk` is **26**. On Android 8.0 through 10
this throws `NoSuchMethodError` — at the exact moment the user enables biometric unlock.

Two things make this worth dwelling on:

1. **It is a security defect, not just a crash.** The call is what makes the Keystore key
   per-use authenticated. A future "fix" that simply deleted the line to stop the crash would
   silently produce a key usable without a biometric.
2. **Android lint would have caught it instantly**, and lint has never run. This is the
   clearest available evidence for §C: the unverified Android layer is not merely untested,
   it demonstrably contains defects that the standard toolchain finds for free.

Fixed by branching: `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` on API 30+,
`setUserAuthenticationValidityDurationSeconds(-1)` below it — the pre-30 spelling of "every
use". A sweep of the other API-gated calls in `platform:secure` (`setIsStrongBoxBacked`,
`setUnlockedDeviceRequired`, `setRecentsScreenshotEnabled`, `EXTRA_IS_SENSITIVE`) found them
all correctly guarded.

### B-2 · Five threat-model rows claimed verification that did not exist — **fixed this pass**

`02-threat-model.md` §4 is the document a security reviewer reads first. Five of its
"Verified by" cells named tests that do not exist (clipboard policy, `FLAG_SECURE`,
shoulder-surfing, R8 log stripping, backup rules). An audit of every test name across all
documents found **eleven** names that did not resolve to a class.

Six were real coverage recorded under the wrong name. Two —
`NoGoogleKeyPathTest` and `NoSecretsInLogsTest` — were genuinely missing and have now been
written. Three remain unwritten and are now listed under an explicit *"named but not yet
written"* heading in `12-testing-strategy.md`.

This is filed as a security finding rather than a documentation one on purpose. A threat model
whose verification column is aspirational is worse than one with blank cells: it causes
reviewers to stop looking.

### B-3 · The recovery key specification was arithmetically impossible — **fixed**

`04-key-management.md` specified 128 bits as "24 Crockford Base32 characters plus a checksum
character". Base32 carries 5 bits per character; 24 characters hold 120 bits. An
implementation matching the spec would have discarded 8 bits — a **256-fold** reduction in the
work of guessing a recovery key — and nothing would have looked wrong. Corrected to 26 data
characters plus 2 checksum characters, with the implementation as the normative version.

### B-4 · The accessibility contrast floors were unverified and six pairs failed — **fixed**

`08-design-system.md` claimed its 4.5:1 and 3:1 floors were "verified by test, not by eye",
naming a `ContrastTest` that did not exist. Written now as `scripts/check-contrast.py`. Six
pairs failed, including `textTertiary` at 3.06:1 in light mode — the token that renders field
labels and placeholders — and the border that is the *only* boundary of the transparent-filled
secondary button, at 1.56:1.

Filed under security findings because the pattern is identical to B-2: a commitment asserted
in a document, never checked, and false.

### B-5 · No verified path exists for anything Android-side — **the standing risk**

Every Android-side security control — Keystore binding, biometric `CryptoObject` gating,
`FLAG_SECURE`, clipboard auto-clear, `allowBackup=false`, R8 log stripping — is
**REVIEWED BUT UNVERIFIED**. Reading them, they are structurally correct and avoid the
common mistakes (there is no `if (biometricSucceeded)` boolean gate anywhere; the biometric
path genuinely requires an authenticated `Cipher`).

But B-1 was also structurally correct on the page and would have crashed on a third of
devices. Until §C is executed, the honest summary of Android-side security is: *designed
correctly, never tested, one confirmed defect already found by reading alone.*

### B-6 · The `verifyRoundTrip` comment overstates what the code does

`DriveTransport` documents step 2 of publishing as "**download it back and check it parses and
authenticates**". The implementation is:

```kotlin
private fun verifyRoundTrip(drive: Drive, fileId: String, expected: ByteArray) {
    val readBack = readFile(drive, fileId)
    if (!readBack.contentEquals(expected)) throw TransportError.CorruptUpload()
}
```

A byte comparison against what we just sent. That catches a corrupted transfer, which is the
stated purpose and is worth having — but it does not parse and it does not authenticate, so
it cannot catch a fault in our own serialisation before it becomes the only copy. Either
strengthen it to `VaultContainer.parse` plus an AEAD verification, or correct the comment.
**Recommendation: strengthen it.** The extra cost is a parse of bytes already in memory, and
the failure it would catch is the unrecoverable kind.

### B-7 · Non-findings worth recording

Checked and found correct, listed so a later reviewer does not re-derive them:

- No hard-coded key material anywhere (15 static checks, validated by planting violations).
- No Google or Android type is reachable from `core:crypto`, structurally enforced.
- Biometric authentication is `CryptoObject`-bound; no boolean gate exists.
- `BIOMETRIC_STRONG` only; Class 2 correctly falls back to passphrase rather than weakening.
- No analytics or crash-reporting SDK is present in any module.
- Sensitive types override `toString()`; a full lifecycle including every error path emits no
  sentinel to stdout or stderr.
- Device slots are structurally rejected if found in a synced vault file.

---

## C. Android verification requirements

Nothing below is optional, and nothing in `app`, `platform:secure` or `data:drive` may be
described as working until the relevant item passes.

### C-1 · Gate 1 — it compiles

| # | Requirement | Passes when |
|---|---|---|
| 1 | `./gradlew assembleDebug` with an SDK present | An APK is produced |
| 2 | `./gradlew lint` | Zero errors. **`NewApi` is the specific check that would have caught B-1.** |
| 3 | `./gradlew assembleRelease` with R8 | Minified APK is produced; mapping file retained |

Until item 1 passes once, the correct status for the entire Android layer is "unknown", not
"probably fine".

### C-2 · Gate 2 — it runs

| # | Requirement | Passes when |
|---|---|---|
| 4 | App launches on an API 26 device/emulator | Cold start reaches the first screen without crashing |
| 5 | App launches on API 30 and current | Same |
| 6 | Keystore key creation on API 26–29 | **The B-1 regression test.** Biometric enrolment completes on Android 8. |
| 7 | StrongBox present *and* absent | Falls back to TEE without user-visible failure |

### C-3 · Gate 3 — the security controls actually engage

| # | Requirement | Passes when |
|---|---|---|
| 8 | Biometric key is per-use authenticated | `cipher.doFinal()` before authentication throws; after it succeeds |
| 9 | New fingerprint invalidates the key | `KeyPermanentlyInvalidatedException` is raised and handled as E-07, not as a crash |
| 10 | `FLAG_SECURE` | Screenshot attempt fails; recents thumbnail shows no content |
| 11 | Clipboard | Auto-clear fires at the countdown; `EXTRA_IS_SENSITIVE` suppresses the preview on API 33+ |
| 12 | `allowBackup=false` | `adb backup` produces nothing |
| 13 | R8 log stripping | No `Log.*` or `println` call sites survive in the release DEX |
| 14 | No plaintext at rest | Pull app-private storage after use; scan for sentinels |

### C-4 · Gate 4 — the release build is honest

| # | Requirement | Passes when |
|---|---|---|
| 15 | Release APK contains no key material | Static scan over the built DEX and resources, not just source |
| 16 | Network inventory | Every outbound host in the release build is a Google Drive endpoint |
| 17 | Permission inventory | Manifest permissions match `11-privacy-model.md` exactly |

**Item 15 matters more than it looks.** `scripts/scan-secrets.sh` scans *source*. The claim
made to users is about the APK. Those are different artifacts and only one of them is
currently checked.

---

## D. Recovery — three models evaluated, one recommended

Per the review brief, this section is a **decision record, not an implementation**. Nothing
in the recovery flow should be built until this recommendation is accepted.

### The constraint that eliminates most of the market

There is no server. There is no escrow. Google is assumed hostile (T5). Therefore **no model
that involves anyone but the user holding recoverable key material is admissible**, which
removes: email reset, security questions, vendor-assisted recovery, and any scheme where
signing into Google is sufficient. This is the first of the four attack classes in the Feb
2026 ETH Zürich / USI study, and rejecting it is the product's reason to exist.

### Model 1 — Single user-custodied recovery key *(the current design)*

128 random bits, shown once at vault creation, stored by the user offline. Wraps the VEK in a
`recovery` key slot that travels inside the synced vault.

| | |
|---|---|
| **Security** | Full 128-bit strength; no third party ever holds it. Nothing to compromise but the user's copy. |
| **Recoverability** | Complete — works on a brand-new device with nothing but the account and the key. |
| **Failure mode** | **Total, silent, and permanent.** Lose the key and forget the passphrase and the vault is gone. |
| **UX cost** | One high-friction moment at onboarding, at the worst possible time — before the user has invested anything. |
| **Real-world evidence** | This is the model people write on a sticky note and photograph. The recorded artifact is often less secure than the vault it protects. |

### Model 2 — Threshold social recovery (Shamir k-of-n)

Split the recovery key into *n* shares; any *k* reconstruct it. Shares go to trusted contacts.

| | |
|---|---|
| **Security** | Strong in theory: no single contact can recover alone. |
| **Recoverability** | Survives the user losing everything, which no other model does. |
| **Failure mode** | Distributed and social. Contacts lose shares, change phones, fall out with the user, or die. Recovery requires coordinating *k* people during a crisis. |
| **UX cost** | Very high. The user must choose contacts, explain a cryptographic concept to them, and deliver shares over channels we do not control. |
| **Hidden requirement** | Share distribution and reconstruction want a coordination channel. **We have no server.** Doing this without one means manual transport of *n* secrets, which is where it collapses. |
| **New attack surface** | Each share is a target; a hostile contact plus a compromised second contact reaches the vault. |

Genuinely excellent for high-value, low-frequency secrets (this is roughly what hardware
wallet seed-splitting is for). Wrong for a password manager's first release.

### Model 3 — Device-mediated authorization, recovery key as break-glass

An already-unlocked device is the authority for admitting a new one. The recovery key still
exists and still works, but it stops being the *routine* path onto a second device and becomes
the thing you need only when you have no working device at all.

| | |
|---|---|
| **Security** | Equal to Model 1 at the floor — the recovery key is unchanged. Adds a path whose authority is possession of an unlocked device, which is strictly stronger than knowing the passphrase. |
| **Recoverability** | Better in the common case (new phone, old phone still works). Identical in the disaster case. |
| **Failure mode** | Same as Model 1 when every device is lost — which is the case the recovery key is *for*. |
| **UX cost** | Low, and moves the friction to where it belongs: onboarding gets a *reason* the key matters ("your other device can admit a new one; this key is for when none can"), and adding a device becomes a scan rather than a 28-character transcription. |
| **Cost** | Requires a device-to-device authorization protocol — designed in §E. |

### Recommendation

> **Adopt Model 3: Model 1 as the guaranteed floor, device-mediated authorization as the
> routine path. Defer Model 2 indefinitely and say so.**

Reasoning:

1. **The floor cannot be weakened.** Model 3 does not replace the recovery key; the recovery
   slot stays in the vault, unchanged and independently sufficient. Everything true of Model 1's
   security remains true. This is the property that makes the recommendation safe.
2. **It fixes Model 1's actual failure mode**, which is not cryptographic but behavioural.
   Users lose recovery keys because they are asked to protect something they have not yet
   needed, for a product they have not yet trusted. Making the key the *break-glass* path
   rather than the *new-device* path means the onboarding explanation is finally honest about
   when it is used — and honest explanations are recorded more often than ceremonial ones.
3. **Model 2 is rejected on the server constraint, not on cryptography.** Shamir is sound.
   Distributing and reconstructing shares without a coordination service is where it fails, and
   building that service would mean building the thing this product exists to avoid.

**Explicitly not recommended, and to be stated plainly in the UI:** there is no account
recovery. If the user loses the passphrase, the recovery key, and every enrolled device, the
vault is unrecoverable. That sentence should appear in onboarding in those words.

**Implementation gate:** none of the recovery *flow* is to be built until this section is
accepted. The recovery *codec* (`RecoveryKey.kt`) is already built and tested, which is
deliberate — it is the piece every model above needs identically.

---

## E. Multi-device authorization — recommendation

### The problem a hostile Drive creates

Device slots are local-only and never synced (correctly — a Keystore-wrapped blob is useless
elsewhere and syncing it would leak the device count). So a new device cannot be admitted by
copying a slot. It needs the VEK, delivered from a device that already has it.

The obvious channel is Drive. **Drive is assumed hostile.** If the existing device wraps the
VEK to a public key it received through Drive, a malicious Drive substitutes its own public
key and receives the VEK. Any protocol that trusts the transport for key exchange fails
against the exact adversary this product is designed around.

### Recommended design

**Out-of-band key transfer with in-band ciphertext.** The new device's public key crosses
optically; only the encrypted payload goes through Drive.

```
  NEW DEVICE                        USER                    EXISTING DEVICE
  ──────────                        ────                    ───────────────
  generate ephemeral X25519
  keypair (private key never
  leaves the device)
        │
        ├── render pk as QR ──────► scans ──────────────────►│
        │                                                    │
        │                          (pk arrives optically,    │
        │                           never through Drive)     │
        │                                                    ├─ unlock required
        │                                                    │  (biometric or
        │                                                    │   passphrase)
        │                                                    │
        │                                                    ├─ ECDH → HKDF → K
        │                                                    ├─ seal VEK under K
        │                                                    ├─ write DeviceRecord
        │◄──── short-lived transfer object via Drive ────────┤
        │                                                    │
        ├─ ECDH → HKDF → K, open                             │
        ├─ derive local device key, create local device slot  │
        ├─ zeroise the transferred VEK copy                   │
        │                                                    │
        └──── both screens show a 5-word confirmation ───────►│
                     user confirms they match
```

**Why each piece is there:**

| Element | Reason |
|---|---|
| QR carries the public key | The one channel a hostile Drive cannot touch. This is the whole design. |
| Ephemeral X25519 per enrolment | A transfer object captured later is useless; no long-term device identity to steal. |
| Existing device must be unlocked | Authorization requires *possession of a working vault*, never a Google session. This is the constraint from the brief, enforced structurally. |
| Transfer object is short-lived and single-use | Deleted after pickup; expires regardless. Drive holds it only briefly and only as ciphertext. |
| **Five-word confirmation on both screens** | The residual risk is a substituted QR (someone photographs a screen). A short authentication string derived from the shared secret, compared by the user, closes it. Words, not hex — people compare words correctly and hex incorrectly. |
| `DeviceRecord` written by the *existing* device | The registry is inside the encrypted payload, so it merges and syncs through machinery that already works and is tested. |
| New device creates its own local slot | The transferred VEK is used once and zeroised; steady state matches a device enrolled any other way. |

**Revocation.** Removing a device from the registry is bookkeeping, not security — a removed
device still holds its local slot. Honest revocation requires **VEK rotation**, which
invalidates every device slot and forces re-enrolment everywhere. The UI must say this plainly:
*"Removing a device hides it from this list. To make it lose access, rotate the vault key —
every device will need to be set up again."* Anything softer is a fake security indicator.

**Deferred for a later release, deliberately:** enrolment without co-presence (two devices in
different cities). It needs either a trusted channel we do not have or a weaker
authentication we should not ship. The recovery key already covers this case.

---

## F. Google Drive findings

### F-1 · Staged publish is implemented — and better than the design documents claimed

`DriveTransport.upload` does: create a temp object → read it back and compare → copy the live
vault into `backups/` → re-check the remote generation → delete the live file → rename the
temp over it, with the temp deleted on any failure. An earlier draft of this review recorded
this as missing; that was wrong, and the threat model and testing strategy have been corrected.

### F-2 · There is a window where no live vault exists — **SECURITY RISK (availability)**

```kotlin
existing?.let { drive.files().delete(it.id).execute() }   // ← live vault now gone
val published = drive.files()
    .update(temp.id, DriveFile().apply { name = VAULT_FILE_NAME })  // ← two API calls later
```

Between those calls, `vault.pwv` does not exist. If the process dies, the network drops, or
the token expires in that window, the next `findVaultFile()` returns `null` — and
`VaultRepository.unlock` maps null to **`NoVault`**.

The data is not lost: the bytes are in the `.tmp-*` object and a copy is in `backups/`. But
the *app* cannot tell "no vault has ever existed" from "the vault is mid-publish", and the
first of those leads to onboarding — where a user could create a fresh vault and publish over
the top of their real one.

**Recommendation, in preference order:**

1. **Rename rather than delete.** Rename the live file to a `superseded-*` name, rename the
   temp into place, then delete the superseded one. No window in which the name is unclaimed.
2. **Make `NoVault` a claim the app has to earn.** Before onboarding may offer to create a
   vault, the transport must confirm the folder contains no `.tmp-*` object and no
   `backups/` entry. A vault folder that exists but has no live vault is a *recovery* state,
   not a *first-run* state, and must route to the integrity screen.

Do both. Item 2 is the one that prevents data loss even if item 1 is somehow defeated.

### F-3 · Round-trip verification does not verify what it claims

See §B-6. Strengthen it to parse and authenticate.

### F-4 · Scope and folder decisions are sound

`drive.file` only — not `drive`, not `drive.appdata`. A Passwird compromise cannot reach the
rest of the user's Drive. The visible-folder decision (ADR-0003) is correct and, more
importantly, correctly *argued*: `appDataFolder` would hide the vault from the user and delete
it on uninstall, which converts a routine action into data loss. Keep both.

### F-5 · Optimistic concurrency is honest about its limits

The generation check narrows rather than closes the race, and the code says so. That is the
right call given the merge above it is convergent and property-tested: a lost race costs a
sync cycle, not data. No change recommended — recorded because a reviewer will ask.

---

## G. Critical UX findings

### G-1 · The one flow that must not be missing, is missing

There is no vault creation. The recovery-key moment — generate, display once, verify the user
recorded it — is the highest-stakes screen in the product and does not exist. §D's
recommendation changes what that screen *says* (the key is break-glass, not routine), which is
precisely why the flow should be built after §D is accepted rather than before.

### G-2 · Five of 47 screens exist, and they are the wrong five to stop at

Implemented: Unlock, Home, Item detail, Generator, Integrity, plus a confirm sheet and a toast.
That is a plausible demo and not a usable product: no onboarding, no add/edit, no settings, no
devices, no conflict review.

**Do not build the other 41 next.** The correct next move is to make the existing five
*actually work* against a real repository — that closes A-1, which every other screen depends
on. Screens built against a composition root that does not exist are the same category of
work as tests named in documents that do not exist.

### G-3 · Nine of 32 specified error states are unreachable from code

`10-error-matrix.md` specifies 32 errors; 23 codes appear in the source. Absent: **E-06, E-08,
E-22, E-24, E-26, E-28, E-30, E-31, E-32.** Given §F-2, at least one state — "the vault folder
exists but the live vault does not" — is not merely unhandled but *not specified*, and needs
adding to the matrix.

The error matrix is one of the stronger documents here. Its value collapses if the codes are
not actually reachable.

### G-4 · The critical path is specified well and never measured

`09-ux-flows.md` §2 defines retrieve-a-credential as the path that matters, and the design is
right to organise around it: unlock → find → copy, with copy reachable without opening the
detail screen. Nothing has measured it, because nothing runs. **Instrument it as soon as the
slice closes** — time from cold start to credential in clipboard, on a mid-range device.
That number is the product.

### G-5 · The contrast defects were a real accessibility failure

Six pairs below their floors, including field labels and placeholders at 3.06:1, and the
secondary button's only boundary at 1.56:1. Fixed. Worth noting *how* it happened: the tokens
were chosen to look right in a dark near-monochrome system, and near-monochrome systems are
exactly where tertiary text drifts under the floor without looking wrong to a designer with
good eyesight on a good screen. The check is now in CI because eyes cannot do this job.

### G-6 · The design language is coherent and should be kept

Reviewed against the brief's instruction to maintain Quiet Precision and avoid generic Material
UI: the near-white primary button, the reserved `signal` colour, hairlines over cards, and the
single 420 ms unlock motion are a genuine identity rather than a re-skin. The `borderInteractive`
token added this pass follows the same logic (one token per meaning) rather than compromising
it. No redesign is warranted, and none should be undertaken while A-1 is open.

---

## H. Exact implementation order

Sequenced so that each step is verifiable when it lands, and no step depends on one below it.
Steps 1–5 are the vertical slice; nothing beyond step 5 should start until it is closed.

### Phase 1 — Make the Android layer real

| # | Work | Done when |
|---|---|---|
| **1** | **Build it.** `assembleDebug` + `lint` on a machine with an SDK. Fix whatever falls out. | An APK exists and lint is clean. **This is the single most valuable action available** — it converts the entire Android layer from *unknown* to *known*. |
| **2** | **Implement `VaultStorage`.** File-backed, over `EncryptedLocalStore`, with the Drive transport and sync-state store behind it. | The interface has exactly one implementation and it is exercised by a JVM test using a temp directory and a fake transport. |
| **3** | **Build the composition root.** Construct `KeystoreKeyManager` → `EncryptedLocalStore` → `VaultStorage` → `VaultRepository` once, at the application level. Manual constructor injection — **no DI framework**; the graph is a dozen objects and a framework would add a compile-time dependency for no benefit. | `PasswirdApp` receives a real repository. The empty callbacks are gone. |
| **4** | **State holders for the five existing screens.** Repository state → UI state, one holder per screen, no logic beyond mapping. | Unlock, Home, Item detail, Generator and Integrity work against a real vault. |
| **5** | **Close the loop end-to-end.** Create a vault in a test fixture, unlock it on a device, read a credential, copy it, lock, unlock again. | **The vertical slice exists.** A-1 closes. |

### Phase 2 — The flows that make it a product

| # | Work | Done when |
|---|---|---|
| **6** | **Onboarding and vault creation**, with the recovery-key ceremony written per §D's accepted recommendation. | A user can create a vault from nothing and has verifiably recorded their recovery key. |
| **7** | **Recovery flow.** Unlock via recovery key on a fresh install; checksum feedback before Argon2id runs. | A vault can be opened on a new device with only the account and the key. |
| **8** | **Drive publish hardening** (§F-2): rename-not-delete, and `NoVault` must be earned. Add the missing error state to the matrix. | An interrupted publish cannot present as first-run. |
| **9** | **Add / edit / delete with undo.** The remaining half of the critical path. | The vault can be populated by hand, not just by fixture. |

### Phase 3 — Multi-device

| # | Work | Done when |
|---|---|---|
| **10** | **Device registry.** Write `DeviceRecord` on enrolment; surface the Devices screen. | A-3 closes. |
| **11** | **Device-to-device authorization** per §E: QR, ephemeral X25519, short-lived transfer object, five-word confirmation. Protocol logic in a **pure-JVM module** so it is property-testable; only QR rendering and camera live in `app`. | A second device is admitted without the recovery key, and a substituted QR is caught by the confirmation step. |
| **12** | **VEK rotation and honest revocation UI.** | Removing a device tells the truth about what that does. |

### Phase 4 — Breadth

| # | Work | Done when |
|---|---|---|
| **13** | Remaining screens, in order of the critical path: settings root → auto-lock → sync → change passphrase → security overview → the rest. | |
| **14** | The nine unreachable error states (§G-3). | Every code in the matrix is reachable. |
| **15** | Instrument and tune the retrieval path (§G-4). | A published number for cold-start-to-clipboard. |

### Phase 5 — Autofill (still deferred)

| # | Work | Done when |
|---|---|---|
| **16** | Write `15-autofill-design.md` — security and privacy design first. | Design reviewed and accepted. |
| **17** | Implement only if the design holds up. | |

Autofill is the largest attack surface a password manager can add: it exposes credentials to
other applications' inference, and phishing resistance depends entirely on how the target is
matched. Shipping it because it is expected would be the exact anti-pattern the brief rules
out. **It stays deferred until its design document exists and is accepted.**

---

## I. Tests required before release

Grouped by what a failure would mean. Nothing here is optional for a 1.0 that holds credentials.

### I-1 · Already passing (239 tests) — maintain, do not regress

Crypto envelope, container format, key slots, recovery codec, device slots, domain codec and
migrations, generation and strength, search, merge properties, rollback and fork detection,
auth/encryption separation, log leakage. Plus `scan-secrets.sh` (15 checks),
`check-contrast.py` (56 pairs), `check-android-deps.py` (28 import groups) — each validated by
planting a violation and confirming it fires.

### I-2 · Must exist before any release

| Test | Asserts | Blocking because |
|---|---|---|
| `VaultStorageTest` | Round-trip through the real storage implementation with a fake transport | Step 2 has no meaning otherwise |
| `AtomicPublishTest` | Publish interrupted at **every** step leaves a readable vault, and never presents as first-run | §F-2 is a data-loss path |
| `NoVaultIsEarnedTest` | A folder with a temp object or a backup never routes to onboarding | The specific mechanism by which F-2 destroys a vault |
| `KeystoreApiLevelTest` (instrumented, API 26–29) | Biometric key creation succeeds on Android 8–10 | The B-1 regression |
| `BiometricCryptoObjectTest` (instrumented) | The key is unusable before authentication and usable after | The difference between real biometric gating and theatre |
| `BiometricInvalidationTest` (instrumented) | Enrolling a new fingerprint invalidates the key and surfaces E-07 | An unhandled `KeyPermanentlyInvalidatedException` is a crash at unlock |
| `PreferencesLeakTest` (instrumented) | Nothing vault-derived reaches `SharedPreferences` | Currently only statically checked |
| `ClipboardPolicyTest` (instrumented) | Auto-clear fires; `EXTRA_IS_SENSITIVE` set | Claimed in the threat model, never run |
| `FlagSecureTest` (instrumented) | Screenshots blocked; recents thumbnail empty | Same |
| `ReleaseArtifactScanTest` | The **built APK** contains no key material and no surviving log call sites | `scan-secrets.sh` checks source; the claim is about the artifact |
| `OnboardingRecoveryKeyTest` | The key is displayed once, verification is enforced, and it decrypts the vault afterwards | An unrecorded recovery key is silent, permanent data loss |
| `MigrationFixtureTest` | Every frozen historical fixture still opens | Cross-version data loss is unrecoverable |

### I-3 · Required before multi-device ships

| Test | Asserts |
|---|---|
| `DeviceEnrolmentTest` (JVM) | The §E protocol admits a device and produces a working local slot |
| `SubstitutedKeyTest` (JVM) | A swapped public key produces a **different** confirmation string on each side |
| `TransferObjectExpiryTest` (JVM) | A captured transfer object is single-use and expires |
| `RevocationTest` (JVM) | VEK rotation invalidates every device slot; registry removal alone does not |
| `ThreeDeviceConvergenceTest` (JVM) | Three devices editing concurrently converge with no record lost |

### I-4 · Required before Autofill ships

Deliberately unspecified. They follow from `15-autofill-design.md`, which does not exist yet.
Writing the tests before the design would be assuming the answer.

### I-5 · Accessibility and UX

| Test | Asserts |
|---|---|
| `check-contrast.py` | Already in CI |
| TalkBack traversal (instrumented) | The full critical path is operable; every icon button has a label |
| 200% text scale (instrumented) | No truncation or overlap on any implemented screen |
| Reduced motion (instrumented) | The 420 ms unlock animation is respected as a preference |
| Critical-path timing | Cold start to credential in clipboard, recorded per release |

---

## Summary

**What is genuinely strong:** the cryptographic core, the file format, the merge algorithm and
the module boundary that makes them testable. 239 tests, and the properties that matter are
asserted rather than assumed. The design system is a real identity, and its contrast is now
enforced rather than claimed.

**What is genuinely not ready:** everything above the JVM line. The app has never compiled or
run; the vertical slice does not exist; there is no way to create a vault; five of 47 screens
exist and none of them is connected to anything.

**The single most valuable next action** is to build the Android modules on a machine with an
SDK. Not because the build is interesting, but because B-1 — a crash on a third of supported
devices, in the biometric enrolment path, that standard lint finds for free — is what the
unverified layer looks like when someone finally reads it carefully. There is no reason to
believe it is the only one.

**The pattern worth naming**, because it recurred four times in this review: a document
asserted a property, named a test that would have proved it, and the test did not exist. The
recovery key spec was arithmetically impossible. The contrast floors were false. Five threat
model rows claimed verification of code that had never run. In each case the *documentation*
was the failure surface — plausible, specific, internally consistent, and wrong. The
countermeasure is not better documents. It is that every claim of the form "verified by X"
must be a claim about something that executes in CI, and X must have been shown to fail.
