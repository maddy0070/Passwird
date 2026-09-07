# ADR-0002 — Random VEK wrapped by independent key slots

**Date:** 2026-09-07 · **Status:** Accepted

## Context

The naive design derives the vault encryption key directly from the master passphrase:
`key = Argon2id(passphrase, salt)`. It is simple and it is what a lot of small projects
do. It has three serious problems:

1. Changing the passphrase requires re-encrypting and re-uploading the **entire vault**.
2. Only one unlock path can ever exist, because every path would have to derive the
   *same* key — which means biometric unlock and recovery keys are impossible without
   storing the passphrase somewhere.
3. Revoking one device is impossible without changing the key for all of them.

## Decision

Generate a **random 256-bit Vault Encryption Key (VEK)** once at vault creation. Never
derive it. Every unlock path *wraps* the same VEK in its own independent **key slot**:

| Slot | Wrapping key derived from | Stored |
|---|---|---|
| `passphrase` | Argon2id(master passphrase) → HKDF | In the synced vault |
| `recovery` | Argon2id(128-bit recovery key) → HKDF | In the synced vault |
| `device` | Android Keystore / StrongBox hardware key | **Local only, never synced** |

This is the LUKS key-slot model.

## Consequences

- **Changing the passphrase re-wraps 32 bytes.** No re-encryption, no re-upload of the
  payload, and it works offline.
- **Multiple unlock paths coexist** without any of them being able to derive another.
  Compromising the biometric slot on one device does not yield the passphrase.
- **Device revocation is slot deletion.** No other slot is affected.
- **Key rotation stays possible** as a distinct, heavier operation when the user
  actually needs it (`04-key-management.md` §7), rather than being forced on every
  passphrase change.
- **Bad:** more moving parts than a derived key — slots, commitments, per-slot AAD
  binding. Mitigated by keeping all of it in one small, heavily tested module.
- **Bad:** the wrapped VEK is visible in the file, so an offline attacker has something
  to grind against. This is inherent to any password-based format; the defence is the
  Argon2id work factor, which is authenticated and floor-enforced.

## Notes

Slot unwrap is bound to `"passwird/v1/slot" ‖ id ‖ type` as AAD, so a slot cannot be
transplanted between files or have its type reinterpreted.

`device` slots are deliberately excluded from the synced artefact: a Keystore-wrapped
blob is useless on any other device, and including it would leak how many devices the
user owns — exactly the metadata the header design works to suppress.
