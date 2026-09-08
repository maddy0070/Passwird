# Passwird — Device Verification Pass

**Status:** prepared, **NOT EXECUTED** · **Prepared:** 2026-09-08

A manual verification of the **local vault lifecycle** on a physical Android device.

Every row below is `NOT TESTED`. Nothing in this document has been observed — it was written
in an environment with no device and no emulator (no `/dev/kvm`, no virtualisation support).
**Fill it in as you go, and do not mark a row `PASS` without watching it happen.**

---

## Before you start

### Record these

| Field | Value |
|---|---|
| Device model | |
| Android version | |
| API level | |
| Build fingerprint | |
| Biometric hardware | Class 3 / Class 2 / none |
| APK SHA-256 | |
| Date and tester | |

### Use exactly this test data

The log scan in §9 greps for these literal strings. Substituting your own values makes that
scan prove nothing.

| Field | Value |
|---|---|
| Master passphrase | `Correct-Horse-Device-Test-2026` |
| Title | `Device Test Account` |
| Username | `device-test@example.invalid` |
| Password | `Pw-Device-Test-9f3a2c7e` |
| Website | `https://device-test.example.invalid` |

**Write the recovery key down.** The app shows it once, and §2.7 asks you to type part of it
back. There is no way to see it again afterwards — that is the design, not an oversight.

### Getting a genuinely fresh state

Installing over an existing build is **not** a fresh install. Use one of:

```bash
adb uninstall com.passwird.debug          # cleanest
adb shell pm clear com.passwird.debug     # keeps the install, clears all app data
```

Then verify the app-private directory is gone:

```bash
adb shell run-as com.passwird.debug ls files/vault   # should fail or be empty
```

### Clear the log buffer first

```bash
scripts/device-log-scan.sh --clear
```

---

## 1. Fresh install

| # | Test | Expected | Observed | Status |
|---|---|---|---|---|
| 1.1 | Launch after a clean install | App starts without crashing | | NOT TESTED |
| 1.2 | First screen identity | **"Your private vault"** — *not* "Your vault is locked" | | NOT TESTED |
| 1.3 | No passphrase prompt | No passphrase field anywhere on the first screen | | NOT TESTED |
| 1.4 | Two distinct choices | **Create new vault** and **Restore existing vault**, both visible | | NOT TESTED |
| 1.5 | The difference is legible | Restore explains it needs an existing encrypted copy plus a key | | NOT TESTED |
| 1.6 | No false security claim | Nothing claims data is protected or synced yet — there is no vault | | NOT TESTED |
| 1.7 | Offline first run | With aeroplane mode on, an **amber banner** says Drive could not be checked and points at Restore | | NOT TESTED |

> 1.7 is the one worth being deliberate about. It distinguishes `FIRST_RUN` from
> `FIRST_RUN_REMOTE_UNCHECKED`, and it is the state that stops an existing user reinstalling
> offline from creating an empty vault over a real one.

---

## 2. Create vault

| # | Test | Expected | Observed | Status |
|---|---|---|---|---|
| 2.1 | Tap **Create new vault** | Passphrase screen appears | | NOT TESTED |
| 2.2 | Explanation is present and above the fields | Says the passphrase *is the key*, never leaves the device, and **cannot be reset** | | NOT TESTED |
| 2.3 | Short passphrase rejected | Fewer than 12 characters shows an inline error; Continue stays disabled | | NOT TESTED |
| 2.4 | Mismatched confirmation rejected | "These don't match yet"; Continue stays disabled | | NOT TESTED |
| 2.5 | Recovery key displayed | 28 characters, seven groups of four, monospace | | NOT TESTED |
| 2.6 | Honest framing shown | States plainly that a lost passphrase **and** lost key means the vault cannot be recovered by anyone | | NOT TESTED |
| 2.7 | Acknowledgement required | Continue is disabled until the checkbox is ticked | | NOT TESTED |
| 2.8 | Verification demanded | Asks for a **specific group number**; a wrong entry is rejected with a named error | | NOT TESTED |
| 2.9 | Verification accepts the right group | Correct group proceeds | | NOT TESTED |
| 2.10 | Case and confusables tolerated | Typing the group in lowercase, or `O` for `0`, still passes | | NOT TESTED |
| 2.11 | Creation takes a visible moment | A working screen appears; Argon2id at the floor is deliberately slow | | NOT TESTED |
| 2.12 | Lands unlocked | The vault list appears — no second passphrase prompt | | NOT TESTED |
| 2.13 | Empty state is actionable | Says what belongs here and offers to add something | | NOT TESTED |

**Record the observed creation time for 2.11:** ______ ms. Under ~300 ms on a mid-range device
would suggest the KDF parameters are not what the documentation claims, and is a finding.

---

## 3. Local persistence

| # | Test | Expected | Observed | Status |
|---|---|---|---|---|
| 3.1 | Add the test credential | Editor accepts all five fields | | NOT TESTED |
| 3.2 | Generate a password | **Generate a strong password** fills the field with a 20-character password | | NOT TESTED |
| 3.3 | Save | Returns to the list; the item appears | | NOT TESTED |
| 3.4 | Title required | Save is disabled with an empty title | | NOT TESTED |
| 3.5 | Search finds it | Typing `Device` returns the item | | NOT TESTED |
| 3.6 | Search by username | Typing `device-test` also returns it — the index covers every field | | NOT TESTED |
| 3.7 | Open it | Detail screen shows the title, username and website exactly as entered | | NOT TESTED |
| 3.8 | Password masked by default | Shown as dots until deliberately revealed | | NOT TESTED |
| 3.9 | Reveal works | Revealing shows `Pw-Device-Test-9f3a2c7e` exactly | | NOT TESTED |
| 3.10 | Reveal does not persist | Leaving and returning re-masks it | | NOT TESTED |
| 3.11 | Strength is shown honestly | States an attacker model alongside the figure, not a bare "strong" | | NOT TESTED |
| 3.12 | Edit the title | Change to `Device Test Account (edited)`; saves and displays | | NOT TESTED |
| 3.13 | Edit preserves the password | The password is unchanged after a title-only edit | | NOT TESTED |
| 3.14 | Vault file exists on disk | `adb shell run-as com.passwird.debug ls -la files/vault` lists `vault.pwv` | | NOT TESTED |
| 3.15 | **Vault file is ciphertext** | See the command below — no plaintext field appears | | NOT TESTED |

```bash
# 3.15 — the product's central claim, checked against the real file.
adb shell run-as com.passwird.debug cat files/vault/vault.pwv > /tmp/vault.pwv
strings /tmp/vault.pwv | grep -iE 'Device Test|device-test|Pw-Device|example.invalid' && echo "FAIL" || echo "PASS: no plaintext"
```

---

## 4. Locking

| # | Test | Expected | Observed | Status |
|---|---|---|---|---|
| 4.1 | Lock control is reachable | A lock control is visible on the list screen, not buried in a menu | | NOT TESTED |
| 4.2 | Tap lock | Returns to **"Your vault is locked"** | | NOT TESTED |
| 4.3 | Copy says the right thing | "Your vault is encrypted and protected on this device. Unlock it to access your passwords." | | NOT TESTED |
| 4.4 | Terminology | The field is labelled **Master passphrase** — never "paraphrase" | | NOT TESTED |
| 4.5 | Content is gone | No credential, title or password is visible or reachable | | NOT TESTED |
| 4.6 | Wrong passphrase | Rejected with "that passphrase didn't match" — **not** a corruption error | | NOT TESTED |
| 4.7 | Backoff engages | After 5 failures a wait is imposed and counts down | | NOT TESTED |
| 4.8 | **No wipe** | Repeated failures never destroy the vault (ADR-0008) | | NOT TESTED |
| 4.9 | Correct passphrase unlocks | Vault opens; the credential is still there | | NOT TESTED |
| 4.10 | Recovery key path is separate | **Use recovery key** is present and distinct from the passphrase field | | NOT TESTED |

---

## 5. Process restart

**The most important section.** It validates `FIRST_RUN` / `LOCKED` / `UNLOCKED` against real
Android persistence rather than against a JVM temp directory.

| # | Test | Expected | Observed | Status |
|---|---|---|---|---|
| 5.1 | Force-stop | `adb shell am force-stop com.passwird.debug` | | NOT TESTED |
| 5.2 | Relaunch | Starts without crashing | | NOT TESTED |
| 5.3 | **Not first run** | Does **not** show "Your private vault" or offer to create a vault | | NOT TESTED |
| 5.4 | Locked | Shows "Your vault is locked" | | NOT TESTED |
| 5.5 | Unlock | The passphrase opens it | | NOT TESTED |
| 5.6 | Credential survives | `Device Test Account (edited)` is present with the right password | | NOT TESTED |
| 5.7 | Swipe from recents, relaunch | Same result as 5.3–5.6 | | NOT TESTED |
| 5.8 | Reboot the device, relaunch | Same result as 5.3–5.6 | | NOT TESTED |

> 5.8 is worth the time. A vault that survives a force-stop but not a reboot would point at
> something being held only in memory or in a cache the OS clears — exactly the class of bug
> that a JVM test cannot see.

---

## 6. Backgrounding and auto-lock

Default policy: lock on background is **on**, inactivity timeout **5 minutes**.

| # | Test | Expected | Observed | Status |
|---|---|---|---|---|
| 6.1 | Home button while unlocked | Returning shows the lock screen | | NOT TESTED |
| 6.2 | Quick app switch and back | Returning shows the lock screen (lock-on-background is on by default) | | NOT TESTED |
| 6.3 | **Recents thumbnail** | The app switcher shows no credential content — `FLAG_SECURE` | | NOT TESTED |
| 6.4 | Screenshot attempt while unlocked | Blocked by the OS with a message | | NOT TESTED |
| 6.5 | Screen off, screen on | Locked | | NOT TESTED |
| 6.6 | Idle past the timeout | Locks without any interaction | | NOT TESTED |
| 6.7 | Interaction postpones the timeout | Tapping around keeps it unlocked past the timeout | | NOT TESTED |

> 6.7 is the regression test for a real defect: `onUserInteraction` was shadowing the framework
> callback instead of overriding it, so key events and switch-access input counted as idleness.
> Try it with the keyboard as well as with taps.

---

## 7. Biometrics

Skip and mark `BLOCKED` if the device has no Class 3 sensor.

| # | Test | Expected | Observed | Status |
|---|---|---|---|---|
| 7.1 | Offer appears | **Turn on fingerprint unlock** is visible on the list screen when unlocked and not yet enrolled | | NOT TESTED |
| 7.2 | Offer is absent without hardware | On a device with no Class 3 sensor, the control does not appear at all | | NOT TESTED |
| 7.3 | Enrol | A system biometric prompt appears and enrolment completes | | NOT TESTED |
| 7.4 | Offer disappears after enrolling | The control is gone — already enrolled | | NOT TESTED |
| 7.5 | Lock, then unlock by fingerprint | Prompt appears; a valid fingerprint opens the vault | | NOT TESTED |
| 7.6 | Unlock is fast | Noticeably faster than the passphrase — there is no KDF on this path | | NOT TESTED |
| 7.7 | Wrong finger | Rejected; vault stays locked | | NOT TESTED |
| 7.8 | Repeated failures | Biometric lockout; vault stays locked | | NOT TESTED |
| 7.9 | Fall back to passphrase | **Use passphrase instead** is available and works | | NOT TESTED |
| 7.10 | Cancel the prompt | Vault stays locked; passphrase still available | | NOT TESTED |
| 7.11 | **Enrol a new fingerprint in Android Settings** | Biometric unlock is invalidated; a calm explanation appears, not a crash | | NOT TESTED |
| 7.12 | Vault survives 7.11 | The passphrase still opens it; nothing is lost | | NOT TESTED |

> 7.11 is `setInvalidatedByBiometricEnrollment(true)` doing its job: someone who adds their own
> fingerprint to a stolen unlocked phone gets a dead key, not a vault. It is also the only way
> to observe that the Keystore binding is real.

---

## 8. Clipboard

| # | Test | Expected | Observed | Status |
|---|---|---|---|---|
| 8.1 | Copy the username | Copies; **no** auto-clear countdown (a username is not a secret) | | NOT TESTED |
| 8.2 | Paste the username elsewhere | `device-test@example.invalid` pastes correctly | | NOT TESTED |
| 8.3 | Copy the password | Copies; a countdown appears | | NOT TESTED |
| 8.4 | Paste the password immediately | Pastes correctly | | NOT TESTED |
| 8.5 | **Wait past the countdown, paste again** | The password is **gone** from the clipboard | | NOT TESTED |
| 8.6 | Clipboard preview on Android 13+ | The paste toast/preview does **not** show the password (`EXTRA_IS_SENSITIVE`) | | NOT TESTED |
| 8.7 | Lock while a password is on the clipboard | Clipboard is cleared on lock, not only on the timer | | NOT TESTED |
| 8.8 | Third-party clipboard manager | If one is installed, note whether it captured the password | | NOT TESTED |

> 8.5 is the one to actually watch a clock for. `ClipboardManager` being called correctly proves
> nothing; the only evidence is a paste that produces nothing after the timer.
>
> 8.8 is worth recording even though we cannot control it. On some OEM builds a clipboard
> manager captures content before we clear it, and that is a real limitation to document rather
> than a claim to make.

---

## 9. Log inspection

Run throughout, not only at the end.

```bash
scripts/device-log-scan.sh --clear     # before you start
# ... run sections 1-8 ...
scripts/device-log-scan.sh             # after
scripts/device-log-scan.sh --follow    # or stream while you work
```

| # | Test | Expected | Observed | Status |
|---|---|---|---|---|
| 9.1 | Master passphrase | Never appears | | NOT TESTED |
| 9.2 | Recovery key | Never appears | | NOT TESTED |
| 9.3 | Credential password | Never appears | | NOT TESTED |
| 9.4 | Username | Never appears | | NOT TESTED |
| 9.5 | Website / URL | Never appears | | NOT TESTED |
| 9.6 | Item title | Never appears | | NOT TESTED |
| 9.7 | Key material or OAuth tokens | Never appears | | NOT TESTED |
| 9.8 | Stack traces during errors | Trigger a wrong passphrase and a biometric failure; no secret in the trace | | NOT TESTED |

**Any hit is a security defect.** Record it here, stop the pass, and report it.

---

## 10. Findings

| # | Severity | Description | Reproduction | Section |
|---|---|---|---|---|
| | | | | |

---

## Status summary

Fill in once the pass is complete.

| Section | PASS | FAIL | BLOCKED | NOT TESTED |
|---|---|---|---|---|
| 1. Fresh install | | | | 7 |
| 2. Create vault | | | | 13 |
| 3. Local persistence | | | | 15 |
| 4. Locking | | | | 10 |
| 5. Process restart | | | | 8 |
| 6. Backgrounding | | | | 7 |
| 7. Biometrics | | | | 12 |
| 8. Clipboard | | | | 8 |
| 9. Logs | | | | 8 |
| **Total** | **0** | **0** | **0** | **88** |

---

## Explicitly out of scope

Not tested here, and **not faked** to make the pass look complete:

- **Google sign-in** — not implemented. No OAuth client exists.
- **Drive sync, upload, download, restore** — the transport exists and has never run.
- **Restore existing vault** — both paths are shown and **disabled**. They are visible because
  a user in a recovery state must see the route exists; they do nothing because pretending
  otherwise would be the fake affordance this product refuses to ship.
- **Device-mediated authorization** (ADR-0010) — designed, not built.
- **Multi-device merge and conflict resolution** — property-tested on the JVM, never exercised
  across two real devices.

Per the milestone: once the local lifecycle passes, stop and report before starting Drive
restoration or device-mediated authorization.
