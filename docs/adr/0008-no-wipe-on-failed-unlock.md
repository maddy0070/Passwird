# ADR-0008 — Exponential backoff, never wipe, on failed unlock

**Date:** 2026-09-07 · **Status:** Accepted

## Context

A common pattern — inherited from device-level security and from some competitors — is
to erase the local vault after N consecutive failed unlock attempts, on the theory that
it stops an attacker brute-forcing a stolen device.

## Decision

**Never wipe on failed unlock.** Apply exponential backoff instead: 1s, 2s, 4s, 8s …
capped at 5 minutes, engaging after 5 failures.

## Rationale

**Wipe-on-failure does not protect the vault.** The local file is encrypted under a key
derived through Argon2id at m=64 MiB, t=3, p=4. An attacker with the device can copy the
encrypted file *before* attempting any unlock and grind it offline at their leisure. The
wipe destroys only the copy they were polite enough to leave alone. It is security
theatre against the very threat it names.

**Wipe-on-failure does real harm:**

- It converts a *forgetful user* into a *data-loss incident*. The most likely person to
  fail five unlock attempts is the owner, tired, at the end of a long day.
- It hands an attacker a denial-of-service: anyone with brief physical access to the
  phone can destroy the vault in thirty seconds without knowing anything.
- It punishes exactly the users least able to recover — those who did not store their
  recovery key.

Backoff, by contrast, meaningfully slows on-device guessing, costs a legitimate user
almost nothing (they typically succeed on attempt two), and destroys nothing.

## Implementation notes

- The failure counter lives in the **encrypted local store**, not `SharedPreferences`,
  so clearing app data does not reset the backoff.
- Backoff is per-device and local; it is not a security boundary against an attacker who
  has extracted the file. The real defence there is the Argon2id work factor, and we say
  so rather than implying otherwise.
- The UI states explicitly during backoff that **nothing has been deleted** — see
  `10-error-matrix.md` E-02. In that moment the user's genuine fear is that they have
  destroyed their own vault, and leaving that unanswered would be a design failure.

## Consequences

- **Good:** no path in the product destroys user data as a side effect of a mistake.
- **Good:** no cheap physical-access DoS.
- **Bad:** an attacker with the unlocked-but-locked device can attempt guesses
  indefinitely, slowly. Their expected value is negligible against a strong passphrase,
  and against a weak one the file copy they already made is the faster attack anyway.
- **Bad:** it differs from user expectations set by device-level PIN policies. Addressed
  in the About screen's plain-language security summary.
