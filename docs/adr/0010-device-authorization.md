# ADR-0010 — Out-of-band device authorization, never through Drive

**Date:** 2026-09-08 · **Status:** Accepted (design only — implementation gated on this record)

## Context

Device slots are local-only and never synced, correctly: a Keystore-wrapped blob is
meaningless on another device, and syncing one would leak how many devices the user owns. So
a new device cannot be admitted by copying a slot — it needs the VEK, handed over by a device
that already holds it.

The obvious channel is Drive, and Drive is assumed hostile (T5). If the existing device wraps
the VEK to a public key that arrived through Drive, a malicious Drive substitutes its own
public key and receives the VEK. **Any protocol that trusts the transport for key exchange
fails against precisely the adversary this product is built around.**

## Decision

**The new device's public key crosses out of band. Only ciphertext goes through Drive.**

1. The new device generates an ephemeral X25519 keypair; the private key never leaves it.
2. It renders the public key as a QR code.
3. The existing device — **which must be unlocked**, not merely signed in — scans it.
4. ECDH → HKDF → a one-time transfer key; the VEK is sealed under it and written to Drive as
   a short-lived, single-use object.
5. The new device fetches it, unwraps, derives its own local device key, creates its own
   local device slot, and zeroises the transferred copy.
6. **Both screens display a five-word confirmation derived from the shared secret. The user
   compares them.**

Enrolment without co-presence is deferred. The recovery key already covers that case.

## Rationale

**The QR is the whole design.** It is the one channel a hostile Drive cannot touch. Everything
else follows from wanting the key exchange to happen there and the bulk transfer to happen
somewhere convenient.

**The unlock requirement is the constraint from the product brief, enforced structurally.**
Authorization requires possession of a *working vault*, never a Google session. There is no
code path in which signing into Google admits a device.

**The five words close the residual gap.** The remaining attack is a substituted QR — someone
photographs the screen, or relays it. A short authentication string derived from the shared
secret differs on each side if anyone is in the middle, and the user comparing them catches
it. Words rather than hex, because people compare words correctly and hex carelessly.

**Ephemeral keys mean there is no long-term device identity to steal**, and a transfer object
captured after the fact is useless.

## Consequences

- The protocol logic lives in a **pure-JVM module** so it can be property-tested. Only QR
  rendering and the camera live in `app`. This follows the boundary that makes the rest of
  the core testable and must not be compromised for convenience.
- Adding a device requires both devices present and the existing one unlocked. This is a real
  UX cost and it is the correct trade.
- **Revocation remains honest and expensive.** Removing a `DeviceRecord` is bookkeeping; the
  removed device still holds its local slot. Real revocation is VEK rotation, which
  invalidates every device slot and forces re-enrolment everywhere. The UI must say so:
  *"Removing a device hides it from this list. To make it lose access, rotate the vault key —
  every device will need to be set up again."* A softer message would be a fake security
  indicator.
- The transfer object is an availability dependency on Drive at enrolment time. Acceptable:
  the recovery key path needs no second device at all.
