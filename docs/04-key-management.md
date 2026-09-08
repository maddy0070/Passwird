# Passwird — Key Management Architecture

**Status:** v1 · **Last updated:** 2026-09-07

Companion to `03-encryption-architecture.md`, which defines the primitives and the
file format. This document defines the *lifecycle* of keys and the human flows
attached to them.

---

## 1. The separation that defines the product

```
   AUTHENTICATION                    │              VAULT ENCRYPTION
   ───────────────────────────────── │ ─────────────────────────────────────
   Google Sign-In                    │   Master passphrase (user's memory)
   → who you are                     │   Recovery key (user's custody)
   → permission to touch Drive       │   Device biometric slot (Keystore)
                                     │
   Knows: your email, your Drive     │   Knows: how to turn ciphertext into
   Cannot: read your vault           │   credentials
                                     │
              ── NO PATH ACROSS THIS LINE ──
```

There is no code path from a Google credential, ID token, OAuth token or account
identifier to the VEK. Signing out of Google does not lock the vault; locking the
vault does not sign out of Google. They are orthogonal systems that happen to live in
the same app.

**Test that enforces this:** `NoGoogleKeyPathTest`. It does not merely run an unlock with
Google absent — that would prove only that *one* path avoids Google, not that no path
exists. It walks every compiled class in `core:crypto` and inspects the types named in
every field and signature, asserting that no `com.google.*`, `android.*`, `androidx.*` or
platform-layer type is reachable at all, and that no unseal entry point accepts a parameter
identifying a user. `scripts/scan-secrets.sh` asserts the same over source imports; the two
are deliberately redundant, because a type can arrive transitively without ever being
imported by name.

---

## 2. Key inventory

| Key | Size | Lifetime | Storage at rest | Exportable |
|---|---|---|---|---|
| Master passphrase | user-chosen | Until changed | User's memory only | n/a |
| `MUK_p` (from passphrase) | 256 b | Milliseconds | Never stored | No |
| `KEK_p` | 256 b | Milliseconds | Never stored | No |
| **VEK** | 256 b | Vault lifetime | Only ever wrapped | No |
| `contentKey` | 256 b | One write/read | Never stored | No |
| `localDbKey` | 256 b | Session | Derived on unlock | No |
| `indexKey` | 256 b | Session | Derived on unlock | No |
| Recovery key | 128 b | Until rotated | **User's offline custody** | Shown once |
| Device slot key | 256 b | Until revoked/invalidated | Android Keystore, non-exportable | **No — hardware-bound** |
| OAuth refresh token | — | Until revoked | Keystore-wrapped app storage | No |

---

## 3. Key slots

Slots are independent wrappings of the same VEK. Adding, removing or re-wrapping one
slot never touches another and never re-encrypts the payload.

| Slot | Where it lives | Unlock cost | Purpose |
|---|---|---|---|
| `passphrase` | In the synced vault file | Argon2id (~500 ms) | The root of trust. Works on any device, forever. |
| `recovery` | In the synced vault file | Argon2id | New-device access and forgotten-passphrase recovery. |
| `device` | **Local secure storage only — never uploaded** | Hardware, ~0 ms | Fast daily biometric unlock on one specific device. |

### 3.1 Why `device` slots are never synced

A Keystore-wrapped blob is meaningless on any other device (the wrapping key is
hardware-bound and non-exportable), so syncing it would provide zero benefit — while
leaking how many devices the user owns, which is exactly the kind of metadata §3.1 of
the encryption spec works to keep out of the header. Device slots stay local.

---

## 4. Biometrics: gate, not key

> **A fingerprint is not a cryptographic key.** It is a gate that authorises the
> secure hardware to use a key it already holds.

Implementation:

```kotlin
KeyGenParameterSpec.Builder(alias, PURPOSE_ENCRYPT or PURPOSE_DECRYPT)
    .setBlockModes(BLOCK_MODE_GCM)
    .setEncryptionPaddings(ENCRYPTION_PADDING_NONE)
    .setKeySize(256)
    .setUserAuthenticationRequired(true)                       // biometric gate
    .setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG) // 0 ⇒ per-use auth
    .setInvalidatedByBiometricEnrollment(true)                 // see below
    .setIsStrongBoxBacked(strongBoxAvailable)                  // hardware if present
    .setUnlockedDeviceRequired(true)
    .build()
```

The unlock flow binds the authentication to the actual cryptographic operation:

1. Build a `Cipher` initialised with the Keystore key.
2. Wrap it in a `BiometricPrompt.CryptoObject`.
3. `BiometricPrompt.authenticate(cryptoObject)`.
4. Only on success does the OS permit `cipher.doFinal()` to unwrap `KEK_d`.

This matters. The common and *wrong* pattern is `if (biometricSucceeded) { loadKey() }`
— a boolean an attacker can flip with a hooking framework. With `CryptoObject`, the
key is unusable until the secure hardware has itself observed a valid biometric. There
is no boolean to flip.

### 4.1 `setInvalidatedByBiometricEnrollment(true)`

If an attacker with the unlocked device enrols *their own* fingerprint, the key is
irreversibly invalidated rather than becoming usable by the attacker. The user is then
required to re-enrol using the master passphrase.

This creates a real, unavoidable UX event: **enrolling a new fingerprint logs you out
of biometric unlock.** We choose security here and design the recovery to be gentle —
a clear, non-alarming explanation and a one-tap re-enrol behind the passphrase, rather
than a cryptic "key invalidated" error. See `10-error-matrix.md` E-07.

### 4.2 Availability requirements

Biometric enrolment is offered only when `BIOMETRIC_STRONG` (Class 3) is available.
Class 2 and device-credential-only fall back to passphrase unlock. We do not weaken
the gate to widen device support, and we say why in the UI rather than hiding the
option.

---

## 5. Recovery

Recovery is where password managers most often fail their users, so it is designed
first rather than last.

### 5.1 Design

- **128 bits of entropy**, rendered as **26 Crockford Base32 characters plus 2 checksum
  characters**, shown as seven groups of four.

  > **Corrected 2026-09-08.** This section previously specified 24 characters plus one
  > checksum character. That is arithmetically impossible: Base32 carries 5 bits per
  > character, so 24 characters hold 120 bits, not 128. Implementing it as written would
  > have silently discarded 8 bits of recovery-key entropy — a 256-fold reduction in the
  > work of guessing one. 26 data characters (130 bits of capacity, 2 of padding) is the
  > smallest encoding that carries the whole key. The implementation in
  > `core/crypto/.../RecoveryKey.kt` is the normative version and is covered by
  > `RecoveryKeyTest`.
- Generated at vault creation, **shown exactly once**.
- Onboarding requires re-entering a randomly chosen group before continuing. Not a
  checkbox — an actual verification that the user recorded it.
- The 10-bit checksum is validated **before** Argon2id runs, so a mistyped character costs
  the user an instant "there's a typo" rather than a half-second wait followed by an
  ambiguous failure. It is integrity, not security: it protects against fingers, not
  attackers.
- Decoding folds the Crockford confusables (`I`/`l` → `1`, `O` → `0`) and ignores case,
  spacing and separators, so the most common transcription mistakes still decode correctly.
- The recovery slot is inside the synced vault, so recovery works on a brand-new
  device with nothing but the Google account and the key itself.
- **We never see it.** There is no escrow. This is the structural answer to the first
  of the ETH study's four attack classes.

### 5.2 Honest framing

Onboarding says, in these words:

> If you forget your passphrase **and** lose this key, your vault cannot be recovered
> — not by you, not by us, not by Google. That is what makes it private.

No dark patterns, no "remind me later" that quietly means never.

### 5.3 Rotation

Rotating the recovery key re-wraps the VEK into a new recovery slot and invalidates
the old one. The payload is untouched.

---

## 6. Lifecycle flows

| Event | Behaviour |
|---|---|
| **First run, new vault** | Google sign-in (identity + Drive) → choose passphrase → generate + verify recovery key → offer biometrics → create vault → first upload. |
| **First run, existing vault in Drive** | Sign in → discover vault → unlock with passphrase *or* recovery key → offer biometrics → add local device slot. |
| **Daily unlock** | Biometric via `CryptoObject`; passphrase always available as an equal alternative, never buried. |
| **Failed unlock** | Exponential backoff (1 s, 2 s, 4 s … capped at 5 min) after 5 failures. **No wipe-on-failure** — that converts a forgetful user into a data-loss incident and hands an attacker a denial-of-service. Backoff is local-only and cannot be reset by clearing app data, because the counter is inside the encrypted local store. |
| **Change passphrase** | Requires the current passphrase or recovery key. Re-wraps one slot. |
| **New device** | New device slot, created locally after a passphrase/recovery unlock. |
| **Lost device** | From another device: remove that device's entry from the device registry (inside the encrypted payload) and **rotate the VEK** if the user believes the passphrase is compromised — see §7. |
| **Google account change** | Vault is independent of the account. Sign in with the new account, upload the existing local vault. The vault is not "moved"; it was never theirs. |
| **Google access revoked** | Sync stops; the app keeps working offline in full. A single non-modal banner, not an interruption. |
| **Uninstall** | Local vault and all key material destroyed. The Drive copy survives (deliberately — see `06-drive-integration.md` §2 on why we do *not* use `appDataFolder`). |

---

## 7. VEK rotation

Rotation is the heavy operation: generate a new VEK, re-encrypt the payload, re-wrap
every slot, increment `vaultVersion`, upload. Offered when:

- the user believes the passphrase was exposed;
- a device is lost and the user wants certainty rather than just tidiness;
- the recovery key was exposed.

Rotation invalidates every device slot, so all devices must re-enrol. The UI states
this cost up front rather than surprising the user afterwards.

**What rotation cannot do:** an attacker who already copied the *old* ciphertext and
knows the *old* passphrase can still open that old copy. Rotation protects future
writes. The UI says exactly this — see `02-threat-model.md` §6 on non-claims.

---

## 8. OAuth token handling

- Requested scopes: `openid`, `email`, and `drive.file` only. Not `drive`, not
  `drive.appdata` (see `06-drive-integration.md` §2). `drive.file` restricts us to
  files this app created, so a Passwird compromise cannot reach the rest of the user's
  Drive.
- Refresh tokens are wrapped by a Keystore key before being written to app storage —
  never in `SharedPreferences` in the clear.
- Tokens are never logged, never included in error reports, and their holder type
  overrides `toString()`.
- Expiry is handled by refresh with jittered backoff; a hard failure degrades to
  offline mode rather than blocking the vault.
- Sign-out clears tokens and the device registry entry, but **does not** delete the
  local vault — the vault is the user's, not the session's.

---

## 9. Anti-patterns explicitly rejected

| Rejected | Why |
|---|---|
| Google password or ID token as the vault key | Google could then decrypt; account takeover would equal vault takeover. The whole point of §1. |
| Key hard-coded in the APK | Trivially extractable; every install would share one key. CI scans for it. |
| VEK in `SharedPreferences` / plain files | Readable by forensic extraction (T2) and by any backup. |
| Biometric result as a boolean gate | Hookable. `CryptoObject` or nothing. |
| Deriving the VEK directly from the passphrase | Makes passphrase change an O(vault) re-encryption and forecloses multiple unlock paths. |
| Wipe vault after N failed attempts | Turns forgetfulness into data loss and gives attackers a DoS. Backoff instead. |
| Server-assisted recovery / escrow | The first attack class in the ETH study. We have no server; keep it that way. |
