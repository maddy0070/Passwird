# Passwird — Android Verification Gate

**Date:** 2026-09-08 · **Scope:** the first real Android build, and what it proved.

This records what was **executed**, with the evidence. Where something could not be executed
in this environment it is marked `IMPLEMENTED BUT ENVIRONMENT-UNVERIFIED` or
`REVIEWED BUT UNVERIFIED`, never `VERIFIED`.

---

## 1. Build environment

The environment had **no Android SDK** at the start of this phase. It was installed rather
than worked around:

| Component | Status | Evidence |
|---|---|---|
| Android SDK | **Installed** | `/opt/android-sdk`, via `commandlinetools-linux-13114758` |
| Platform | **Installed** | `platforms/android-35` |
| Build tools | **Installed** | `build-tools/35.0.0` |
| Platform tools (adb) | **Installed** | `platform-tools/adb` runs |
| JDK | **Present** | OpenJDK 21.0.10 |
| Gradle | **Present** | 8.11.1 |
| AGP | **Compatible** | 8.7.3 resolved and executed the full pipeline |
| **Emulator / device** | **UNAVAILABLE** | see below |

### Why nothing can be installed or launched here

Three independent facts, each checked:

1. `adb devices` lists **zero** devices.
2. `/dev/kvm` does **not exist**.
3. `/proc/cpuinfo` reports **zero** `vmx`/`svm` flags; the process is in a Docker container.

The Android emulator on Linux/x86-64 requires KVM. Without hardware virtualisation it cannot
boot a system image at all. **Installation, launch and every on-device flow are therefore
UNVERIFIED, and no amount of care in this environment can change that.**

### What is required to finish the verification

A machine (or CI runner) with:

- an x86-64 Linux host exposing `/dev/kvm`, or a physical Android device over USB/ADB;
- API 26 **and** API 30+ images — API 26–29 specifically, because two of the defects found
  this phase only manifest below API 30;
- a device with Class 3 (`BIOMETRIC_STRONG`) hardware for the biometric gates;
- a Google account plus an OAuth client for the Drive flows.

---

## 2. What the first build actually found

Seven genuine defects. None was visible by reading the code — every one required the
toolchain.

| # | Defect | Severity | How it surfaced |
|---|---|---|---|
| 1 | `FONT-NOTICE.txt` inside `res/font/` | Build-blocking | Resource merger rejects anything but `.xml/.ttf/.ttc/.otf` |
| 2 | `androidx.compose.foundation.clickable` called as a plain function | Build-blocking | It is a `Modifier` extension; cannot be called fully-qualified |
| 3 | `onUserInteraction` **shadowed** `Activity.onUserInteraction` instead of overriding it | **Security** | Kotlin compiler error. The framework never called it, so key events, trackball and switch access all counted as idleness — the auto-lock timer would not have seen them |
| 4 | Google API client jars collide on `META-INF/INDEX.LIST` | Build-blocking | `mergeDebugJavaResource` failure |
| 5 | Manifest named `com.passwird.PasswirdApplication`; the class is `com.passwird.vaultapp.PasswirdApplication` | **Launch-blocking** | Lint `MissingClass`. The app would have died with `ClassNotFoundException` before its first frame |
| 6 | `StrongBoxUnavailableException` named in a `catch` clause | **Security** | Lint `NewApi`. Added in API 28, `minSdk` is 26 — on Android 8.0/8.1 the runtime throws `NoClassDefFoundError` resolving the catch type, turning a graceful StrongBox fallback into a hard crash |
| 7 | `tools:node="remove"` on `androidx.startup.InitializationProvider` | **Security** | Lint `MissingClass`, then dependency analysis. `lifecycle-process` registers `ProcessLifecycleInitializer` through that provider; removing it leaves `AppLockController` observing a lifecycle that never dispatches — **the vault would silently never lock on backgrounding** |

Defects 3, 6 and 7 are the important ones: each disables a security control while leaving an
app that looks like it works.

Two further licence/attribution issues were fixed on the way:

- The packaging block **excluded** `META-INF/LICENSE` and `NOTICE`, silently stripping the
  attribution Apache-2.0 §4(d) requires. Now merged rather than dropped.
- The IBM Plex notice was moved out of `res/font/` rather than deleted.

---

## 3. Build results

| Item | Result |
|---|---|
| `./gradlew assembleDebug` | **SUCCESS** |
| `./gradlew lint` | **SUCCESS** — 0 errors, 45 warnings (36 `GradleDependency`, 6 `AndroidGradlePluginVersion`, 4 `TrustAllX509TrustManager` inside `google-http-client`, 2 `InlinedApi`, 1 `ObsoleteSdkInt`) |
| `./gradlew assembleRelease` | **SUCCESS** (R8 + resource shrinking) |
| `./gradlew test` | **SUCCESS** — 286 tests, 0 failures |

### The artifact

| | |
|---|---|
| **Path** | `app/build/outputs/apk/debug/app-debug.apk` |
| **Variant** | `debug` |
| **Application ID** | `com.passwird.debug` (`.debug` suffix) |
| **Version** | `1.0.0-debug` (versionCode 1) |
| **minSdk / targetSdk / compileSdk** | 26 / 35 / 35 |
| **Size** | 18,975,126 bytes (~19 MB) |
| **Release counterpart** | `app/build/outputs/apk/release/app-release-unsigned.apk`, 5,176,996 bytes — **unsigned**, because no signing config exists yet |

**The debug APK is not verified as installable.** It was produced by the real toolchain and
passes structural analysis, but no device has accepted it.

---

## 4. Security verification of the artifact

`scripts/scan-apk.py` was written this phase and reads the **built APK** — its DEX, resources,
assets and merged manifest. It closes item 15 of the production-readiness review, which noted
that `scan-secrets.sh` scans source while the claim made to users is about the artifact.

Both APKs pass all 10 checks. The scanner was validated in both directions: a planted sentinel
string and a planted 64-hex key literal each made it fail, and removing them made it pass.

| Check | Debug | Release |
|---|---|---|
| No secret-shaped literal in application or resource content | pass | pass |
| No key-length literal in application code (617 / 2 classes disassembled) | pass | pass |
| Every exported component expected or permission-guarded | pass | pass |
| `allowBackup=false` | pass | pass |
| `dataExtractionRules` declared | pass | pass |
| Cleartext traffic not enabled | pass | pass |
| Debuggable flag correct for the variant | pass | pass |
| No permission beyond the documented set (4 declared) | pass | pass |
| No application class calls a TLS-disabling helper | pass | pass |
| No analytics or crash-reporting SDK | pass | pass |

### Findings recorded rather than ignored

**A PEM private key ships in the debug APK.** It belongs to
`com.google.api.client.testing.json.webtoken.TestCertificates` — Google's published test
fixture, reachable by nothing, and **absent from release** (verified by scanning the release
APK, not inferred). It authenticates nothing of ours. It is still recorded: a password manager
should not ship a private key in any build, and the fix is to stop pulling
`google-api-client`'s testing classes.

**`androidx.compose.ui.tooling.PreviewActivity` is exported and unguarded in debug.** It
arrives with `debugImplementation` tooling and is absent from release — again verified against
the release APK.

**The debug APK is debuggable**, so `run-as` and a debugger can read app-private storage. It
must never hold a real vault and must never be distributed.

**`SslUtils.trustAllSSLContext` ships inside `google-http-client`.** No application class
references it; R8 removes it from release. Verified by disassembly, not assumed.

---

## 5. Status after this gate

| Subsystem | Before | After | Basis |
|---|---|---|---|
| Android compilation | REVIEWED BUT UNVERIFIED | **VERIFIED** | `assembleDebug` and `assembleRelease` both succeed |
| Android lint | MISSING | **VERIFIED** | 0 errors |
| Debug APK | MISSING | **VERIFIED (built)** | 19 MB artifact, identified above |
| APK security properties | MISSING | **VERIFIED** | `scan-apk.py`, 10 checks, validated in both directions |
| Composition root / DI | MISSING | **IMPLEMENTED BUT ENVIRONMENT-UNVERIFIED** | `PasswirdContainer` compiles and is wired; never constructed on a device |
| `VaultRepository` construction by the app | MISSING | **IMPLEMENTED BUT ENVIRONMENT-UNVERIFIED** | `MainActivity` builds the graph; never run |
| Unlock flow (real) | MISSING | **IMPLEMENTED BUT ENVIRONMENT-UNVERIFIED** | `UnlockController` drives the real repository; logic covered by JVM tests, the Android path never executed |
| Drive publish ordering (§F-2) | SECURITY RISK | **VERIFIED (logic) / ENVIRONMENT-UNVERIFIED (Drive)** | `VaultPublisher` + 13 crash-injection tests; `DriveTransport` mirrors the ordering but has never run |
| `NoVault` is earned | MISSING | **VERIFIED (logic)** | `NoVaultIsEarnedTest`, 4 tests |
| Round-trip verification parses and authenticates (§B-6) | SECURITY RISK | **IMPLEMENTED BUT ENVIRONMENT-UNVERIFIED** | now calls `VaultContainer.parse`; never run against Drive |
| Android Keystore | REVIEWED BUT UNVERIFIED | **REVIEWED BUT UNVERIFIED** | two API-level crashes fixed; **still never executed** |
| Biometric unlock | REVIEWED BUT UNVERIFIED | **REVIEWED BUT UNVERIFIED** | unchanged; needs a device |
| Google authentication | REVIEWED BUT UNVERIFIED | **IMPLEMENTED BUT ENVIRONMENT-UNVERIFIED** | no OAuth client, no account, no device |
| Google Drive sync | REVIEWED BUT UNVERIFIED | **IMPLEMENTED BUT ENVIRONMENT-UNVERIFIED** | as above |
| Installation / launch | — | **UNVERIFIED** | no device, no KVM |
| Onboarding / vault creation | MISSING | **MISSING** | still no path by which a vault can be created |

### The honest summary

The app **builds, lints, minifies and produces both a debug and a release APK**, and the
artifact passes a security scan that is validated against planted violations. Three latent
security defects that only a real toolchain could find have been fixed.

It has **never been installed, never launched, and no Android security API has ever
executed.** The vertical slice is wired but unproven. `Keystore`, `BiometricPrompt`,
`FLAG_SECURE`, the clipboard guard, Google sign-in and Drive remain untested against a real
platform, and the app still cannot create a vault — so even on a device, the flow in Step 5 of
the brief could not be completed end to end today.

---

## 6. Exact remaining work for the next gate

1. **Onboarding and vault creation.** Without it there is nothing to unlock on a device, and
   the vertical slice cannot be demonstrated. This is now the blocking item.
2. **Run the app on API 26–29 and on API 30+.** Specifically exercise Keystore key creation,
   which is where two of this phase's defects live.
3. **Biometric enrolment and `CryptoObject` unlock** on Class 3 hardware, plus the
   `KeyPermanentlyInvalidatedException` path.
4. **A signing config**, so a release APK can be installed at all.
5. **Google OAuth client and a real account**, then the Drive sequence: upload → download →
   decrypt → modify → sync → restart → sync, with the Drive artifact scanned for plaintext.
6. **`FLAG_SECURE`, clipboard auto-clear and `adb backup`** checked on a device.


---

## 7. Vault state machine (added 2026-09-08, after the app first ran)

Running the APK exposed a defect no test could have caught, because the application had no
concept of the situation: **a fresh installation showed "Your vault is locked"** and asked for
a master passphrase that had never been chosen.

### Root cause

Routing was `if (repository.vault == null) → UnlockScreen`. That expression means *not
unlocked*. It was being read as *locked*. A boolean cannot distinguish the seven situations
this product has to tell apart, and the distinctions are not cosmetic — exactly one of them
permits creating a vault, and creating one in any of the others can overwrite a real vault.

### The fix, at the domain level

`core:store/VaultState.kt` — a sealed hierarchy plus `VaultStateResolver`, pure JVM. States
are resolved **most-evidence-first, with `FirstRun` last**: it is the only state that permits
creating a vault, so it is the hardest to reach.

| State | Reached when |
|---|---|
| `Unlocked` | a session is open — outranks everything, including the remote |
| `Locked` | a local vault file exists and parses |
| `Corrupted` | a local vault file exists and does not parse |
| `RemoteVaultAvailable` | no local vault; the remote holds a live one |
| `VaultRecoveryAvailable` | no local vault; the remote has a staged/superseded/backup copy |
| `RecoveryRequired` | local evidence of a vault, and nothing available to restore |
| `FirstRunRemoteUnchecked` | nothing local; the remote **could not be asked** |
| `FirstRun` | nothing local, and the remote **answered** that it has nothing |

`SyncState` (UNAVAILABLE / SYNCING / SYNCED) is modelled **separately**, on purpose: a vault
is *unlocked and syncing*, or *locked and offline*. Folding them into one enum would require
the product of both sets and would let impossible states be constructed.

`RemoteVaultState.Unavailable` was added alongside `Present` / `Interrupted` / `Empty`. "We
could not ask" is a third answer, and collapsing it into either of the others is how an
offline user gets told they have no vault.

### First-run experience

`WelcomeScreen` — "Your private vault", with **Create new vault** and **Restore existing
vault** as equal paths. When the remote could not be checked, a banner says so and points at
Restore as the safer choice, because offline-first means this cannot block but the ambiguity
must be visible.

Create flow: choose passphrase → confirm → explanation of what it does and that nobody can
reset it → recovery key shown once → acknowledge → **verify a randomly chosen group** →
create → unlocked. The recovery key is generated before the screen that displays it, held only
in memory, and zeroised on completion or cancellation.

### Copy

The unlock screen said "Everything stays on this phone until you unlock it", which is wrong in
both directions — an encrypted copy does go to Drive, and unlocking is not what keeps anything
here. Replaced with "Your vault is encrypted and protected on this device. Unlock it to access
your passwords." Two `scan-secrets.sh` checks now enforce this: one fails the build on
"paraphrase", one on any claim that data never leaves the device. Both validated by planting a
violation.

**On the reported "Master paraphrase":** no occurrence of that spelling exists anywhere in the
source tree, then or now. The field label has always read "Master passphrase". The check was
added regardless, so the term cannot drift.

### Verification status

| Requirement | Status | Evidence |
|---|---|---|
| 1. Fresh installation → FIRST_RUN | **VERIFIED** | `a fresh installation is FIRST_RUN, not LOCKED` |
| 2. Existing local vault → LOCKED | **VERIFIED** | `a readable local vault is LOCKED` |
| 3. Existing unlocked vault → UNLOCKED | **VERIFIED** | `an open session is UNLOCKED and outranks everything the remote says` |
| 4. Drive unreachable + no local vault ≠ FIRST_RUN | **VERIFIED** | `no local vault and an unreachable remote is NOT FIRST_RUN`, `an unreachable Drive with no local vault is never FIRST_RUN` |
| 5. Remote vault exists → RESTORE | **VERIFIED** | `a remote vault with no local one is the RESTORE path` |
| 6. Corrupted vault → CORRUPTED | **VERIFIED** | `a damaged local vault file is CORRUPTED` |
| 7. Recovery available → recovery flow | **VERIFIED** | `an interrupted remote publish routes to recovery, not onboarding` |
| 8. Restart after creation → LOCKED | **VERIFIED** | `restarting after creating a vault is LOCKED, not FIRST_RUN` |
| 9. Successful unlock → UNLOCKED | **VERIFIED** | `a successful unlock moves LOCKED to UNLOCKED` |
| 10. Google sign-out preserves the vault | **VERIFIED** | `losing the Google account does not destroy the local vault` |

Plus: `FIRST_RUN is the only state that fully permits creating a vault`, which enumerates every
state so one added later cannot quietly acquire permission.

**Android-runtime-unverified:** that these states render the right screens on a device. The
routing compiles and lints, and the state machine underneath it is fully tested, but no screen
has been observed. Biometric enrolment, the Drive restore path and device-mediated
authorization (ADR-0010) remain unimplemented — the restore paths are shown and disabled
rather than faked.
