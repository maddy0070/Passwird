# ADR-0001 — AEAD selection: AES-256-GCM with per-write derived message keys

**Date:** 2026-09-07 · **Status:** Accepted

## Context

The vault payload needs authenticated encryption. The obvious modern choice is
XChaCha20-Poly1305: its 192-bit nonce makes randomly-generated nonces safe without
further reasoning, which matters when several devices write independently.

Two constraints collided:

1. BouncyCastle 1.79 does **not** ship XChaCha20-Poly1305 (verified empirically — it
   has RFC 8439 ChaCha20-Poly1305 with a 96-bit nonce only). Synthesising XChaCha would
   mean implementing HChaCha20 ourselves.
2. The brief forbids hand-implementing cryptographic primitives where library
   implementations exist — correctly, since a hand-rolled HChaCha20 is exactly the kind
   of code that looks right and is subtly wrong.

Meanwhile AES-GCM with a random 96-bit nonce has a birthday bound: collision risk
becomes non-negligible around 2³² messages under one key.

## Decision

Use **AES-256-GCM**, and eliminate the nonce concern by deriving a **fresh message key
on every write** from a fresh 256-bit random salt:

```
fileSalt   ← 32 random bytes (new every write)
contentKey ← HKDF-SHA-512(ikm = VEK, salt = fileSalt, info = "passwird/v1/content")
payload    ← AES-256-GCM(contentKey, nonce = 12 random bytes, aad = header, plaintext)
```

Additionally, because AES-GCM is not key-committing, each key slot carries an explicit
commitment `HKDF(KEK, salt = slot.id, info = "passwird/v1/commit")`, verified in
constant time before any unwrap.

## Rationale

- A nonce collision would now additionally require a `fileSalt` collision — a 256-bit
  event. The effective nonce space is 256 bits.
- This is not a novel construction. It is what XChaCha does internally (derive a subkey
  from an extended nonce), and matches the AWS Encryption SDK's derived data keys and
  Tink's `AES-GCM-HKDF` streaming keyset. Every component is a standard library
  primitive.
- AES-GCM is hardware-accelerated on effectively all modern Android devices (ARMv8
  crypto extensions via Conscrypt), so unlock is fast — which matters because unlock is
  on the 4-second critical path.
- It is in the platform JCE, so the identical code path runs on the JVM and on Android
  with **no native dependency** — which is also why the whole crypto core is unit
  testable in CI without an emulator.
- Explicit key commitment closes partitioning-oracle attacks *and* yields a clean
  "wrong passphrase" signal distinguishable from "corrupted data" — a UX win falling out
  of a security requirement.

## Alternatives rejected

| Alternative | Why not |
|---|---|
| Hand-rolled XChaCha20-Poly1305 | Violates "do not implement primitives manually". Highest-risk code in the product would be the least reviewed. |
| ChaCha20-Poly1305 (RFC 8439) as-is | Same 96-bit nonce issue, without AES's hardware acceleration. |
| libsodium via JNI/JNA | Adds a native dependency, complicates the build, and breaks pure-JVM testability of the core. |
| AES-GCM-SIV | Not in BouncyCastle or the platform JCE; would require a third-party implementation. |

## Consequences

- **Good:** no nonce management burden anywhere; fast on-device; testable without a
  device; small dependency surface; key-committing.
- **Bad:** one extra HKDF per read and per write (microseconds — irrelevant).
- **Bad:** a reader must derive `contentKey` before decrypting, so `fileSalt` is
  mandatory in the header and the format cannot be read by a naive AES-GCM tool. This is
  acceptable; the format is ours and is documented.
- **Watch:** if BouncyCastle later ships XChaCha20-Poly1305, revisiting is *not*
  automatic — it would be a format version bump with a migration, and the current
  construction has no known weakness.
