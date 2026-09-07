# Passwird — Encryption Architecture

**Status:** v1 · **Format:** `PWVAULT` v1 · **Last updated:** 2026-09-07

This is the normative specification for the on-disk / in-Drive vault artefact. The
implementation in `core/crypto` must match this document exactly; where they
disagree, the tests decide and one of the two is a bug.

---

## 1. Primitive selection

| Purpose | Choice | Rationale |
|---|---|---|
| Password-based KDF | **Argon2id** | Memory-hard, side-channel resistant, RFC 9106. Floor: m=64 MiB, t=3, p=4. |
| Key derivation (from key material) | **HKDF-SHA-512** | Standard extract-and-expand; domain separation via `info`. |
| Content AEAD | **AES-256-GCM** | Hardware-accelerated on essentially all Android devices via ARMv8 crypto extensions (Conscrypt), and present in the platform JCE — so the same code path runs on the JVM and on Android with no native dependency. |
| Hash | **SHA-256** | Header chain and integrity digests. |
| CSPRNG | `SecureRandom` (platform) | On Android, seeded from the kernel CSPRNG. |

No primitive is implemented by hand. Argon2id and HKDF come from BouncyCastle;
AES-GCM, SHA-256 and `SecureRandom` come from the platform JCE.

### 1.1 Why AES-256-GCM and not XChaCha20-Poly1305

XChaCha20-Poly1305 would be the textbook pick: its 192-bit nonce makes random nonce
generation safe without further thought. But BouncyCastle 1.79 does not ship
XChaCha20-Poly1305 (verified empirically — it has RFC 8439 ChaCha20-Poly1305 only),
and the brief correctly forbids hand-implementing primitives. Implementing HChaCha20
ourselves to synthesise XChaCha would be exactly that.

Rather than accept AES-GCM's 96-bit nonce and the birthday-bound risk that comes with
random nonces, we remove the problem at the source:

> **Every write derives a fresh message key from a fresh 256-bit random salt.**

```
fileSalt   ← 32 random bytes, new on every single write
contentKey ← HKDF-SHA-512(ikm = VEK, salt = fileSalt, info = "passwird/v1/content")
payload    ← AES-256-GCM(key = contentKey, nonce = <12 random bytes>, aad = header)
```

Because `contentKey` is unique per write with overwhelming probability, a nonce
collision would additionally require a `fileSalt` collision — a 256-bit event. The
effective nonce space is 256 bits, not 96.

This is the same construction XChaCha20 uses internally (derive a subkey from part of
an extended nonce), and the same pattern as the AWS Encryption SDK's derived data keys
and Tink's `AES-GCM-HKDF` streaming keyset. It is a composition of standard
primitives, not new cryptography. See `adr/0001-aead-selection.md`.

### 1.2 Key commitment

AES-GCM is **not key-committing**: an attacker can construct a ciphertext that
decrypts successfully under two different keys. For a password-based format this
enables partitioning-oracle attacks that accelerate passphrase search.

Each key slot therefore carries an explicit commitment:

```
commitment = HKDF-SHA-512(ikm = KEK, salt = slot.id, info = "passwird/v1/commit")[0..32]
```

verified with a **constant-time** comparison *before* any unwrap is attempted. This
also yields a clean, unambiguous "wrong passphrase" result instead of an AEAD tag
failure that could equally mean corruption — a real UX benefit falling out of a
security requirement.

Publishing the commitment does not weaken the slot: an attacker who can test the
commitment must still run Argon2id per guess, which is precisely the same work as
testing the unwrap. The work factor, not the absence of a verifier, is the defence.

---

## 2. Key hierarchy

```
    ┌─────────────────────┐        ┌──────────────────────┐
    │  Master passphrase  │        │  Recovery key (128b) │
    │  (user memory)      │        │  (offline custody)   │
    └──────────┬──────────┘        └──────────┬───────────┘
               │ Argon2id(salt_p)             │ Argon2id(salt_r)
               ▼                              ▼
          ┌─────────┐                    ┌─────────┐        ┌────────────────────┐
          │  MUK_p  │                    │  MUK_r  │        │ Android Keystore   │
          └────┬────┘                    └────┬────┘        │ key (StrongBox,    │
               │ HKDF                         │ HKDF        │ biometric-gated,   │
               ▼                              ▼             │ non-exportable)    │
          ┌─────────┐                    ┌─────────┐        └─────────┬──────────┘
          │  KEK_p  │                    │  KEK_r  │                  │ AES-GCM
          └────┬────┘                    └────┬────┘                  ▼
               │ unwraps                      │ unwraps          ┌─────────┐
               │                              │                  │  KEK_d  │
               └──────────────┬───────────────┴──────────────────┘         │
                              ▼                                            │
                     ╔═════════════════╗                                   │
                     ║  VEK (256-bit)  ║ ◄─────────────────────────────────┘
                     ║  random, never  ║
                     ║  derived from   ║
                     ║  any password   ║
                     ╚════════┬════════╝
                              │ HKDF, domain-separated
          ┌───────────────────┼───────────────────┬────────────────────┐
          ▼                   ▼                   ▼                    ▼
    contentKey           localDbKey           indexKey            manifestKey
  (per-write salt)      (local storage)    (search index)    (sync manifest MAC)
```

### 2.1 The VEK is random, not derived

The Vault Encryption Key is 256 random bits generated once at vault creation. Every
unlock path *wraps* the same VEK rather than deriving it. Three consequences, all of
which matter:

1. **Changing the master passphrase re-wraps one 32-byte key** instead of
   re-encrypting and re-uploading the entire vault.
2. **Multiple independent unlock paths** (passphrase, recovery key, per-device
   biometric) coexist without any of them being able to derive another.
3. **Revoking a device** means deleting that device's slot — no other slot is affected.

This is the LUKS key-slot model, and it is the correct shape for this problem.

### 2.2 Domain separation

Every HKDF invocation uses a distinct `info` string under the `passwird/v1/` prefix.
No key is ever used for two purposes. The full registry lives in
`core/crypto/.../KeyDomains.kt` and is asserted unique by `KeyDomainsTest`.

### 2.3 Google is not in this diagram

Deliberately and completely. The Google account provides identity and Drive
authorisation, nothing else. There is no path from a Google credential to the VEK.
An attacker with total control of the Google account (T6) obtains ciphertext.

---

## 3. File format `PWVAULT` v1

All integers big-endian. All lengths validated against remaining bytes **before**
allocation.

```
┌────────────────────────────────────────────────────────────────┐
│ magic          8 B   "PWVAULT\0"  (0x5057 5641 554C 5400)      │
│ formatVersion  2 B   u16 = 1                                   │
│ headerLen      4 B   u32  (≤ 1 MiB, enforced)                  │
│ header         N B   canonical JSON, UTF-8  ── see §3.1        │
├────────────────────────────────────────────────────────────────┤ ◄─ AAD ends here
│ payloadLen     8 B   u64  (≤ 64 MiB, enforced)                 │
│ payload        M B   AES-256-GCM ciphertext ‖ 16 B tag         │
└────────────────────────────────────────────────────────────────┘

AAD = magic ‖ formatVersion ‖ headerLen ‖ header      (the entire prefix)
```

Binding the whole prefix as AAD means **every** header field — KDF cost parameters,
key slots, version counter, hash-chain link — is covered by the authentication tag.
An attacker who lowers Argon2's memory cost, swaps in their own key slot, or forges a
version number produces a file that fails to decrypt. This closes the
"backwards-compatibility" and "vault integrity" attack classes from the ETH study at
the format level rather than with ad-hoc checks.

### 3.1 Header

Canonical JSON: keys sorted lexicographically, no insignificant whitespace, so that
byte-for-byte reconstruction for AAD verification is deterministic.

```jsonc
{
  "chain":   "<base64url 32B>",   // SHA-256 of the previous version's header bytes
  "fileSalt":"<base64url 32B>",   // per-write HKDF salt → contentKey
  "nonce":   "<base64url 12B>",   // per-write GCM nonce
  "slots":   [ /* KeySlot, see §3.2 */ ],
  "v":       1,                   // header schema version
  "vaultId": "<base64url 16B>",   // opaque random identity, not user-derived
  "vaultVersion": 42              // monotonic; rollback detection
}
```

**What is deliberately absent:** item count, titles, URLs, tags, device identifiers,
user identity, timestamps. Everything user-derived is inside the ciphertext.
Writer/device attribution and timestamps live in the *encrypted* payload where they
belong, so an observer with the file learns nothing about how many devices exist or
when they were used beyond what Drive's own `modifiedTime` already reveals.

`vaultId` is random, not derived from the Google account, so possession of two vault
files does not reveal that they belong to the same person.

### 3.2 Key slot

```jsonc
{
  "id":    "<base64url 8B>",
  "type":  "passphrase" | "recovery",
  "label": "Master passphrase",
  "kdf":   { "alg": "argon2id", "m": 65536, "t": 3, "p": 4,
             "salt": "<base64url 16B>", "version": 19 },
  "commitment": "<base64url 32B>",
  "wrapNonce":  "<base64url 12B>",
  "wrapped":    "<base64url 48B>"   // 32 B wrapped VEK ‖ 16 B tag
}
```

Slot unwrap AAD: `"passwird/v1/slot" ‖ id ‖ type`, binding a wrapped key to its slot
so slots cannot be transplanted between files or between types.

> **`type: "device"` slots never appear in this file.** The biometric slot exists only
> in device-local secure storage. Uploading a Keystore-wrapped blob would be useless
> to other devices and would leak the device count. See `04-key-management.md` §4.

### 3.3 Payload

```
plaintext = pad( serialize(VaultDocument) )
payload   = AES-256-GCM(contentKey, nonce, AAD = prefix, plaintext)
```

**Padding** — ISO/IEC 7816-4 (`0x80` then `0x00`s) up to the next size bucket:

| Plaintext size | Bucket granularity |
|---|---|
| ≤ 64 KiB | 4 KiB |
| ≤ 1 MiB | 64 KiB |
| > 1 MiB | 256 KiB |

Padding hides the vault's true size and, more importantly, prevents an observer from
inferring *how much changed* between two uploads. A one-character password edit and
adding forty new records look identical unless they cross a bucket boundary. The
padding is unambiguously removable without a stored length, so no extra metadata is
needed.

---

## 4. Operations

### 4.1 Create

1. `VEK ← 32 random bytes`, `vaultId ← 16 random bytes`.
2. Calibrate Argon2 parameters on-device (target ≈ 500 ms) subject to the floor; store
   the chosen parameters in the passphrase slot.
3. Build the passphrase slot and the recovery slot, each wrapping the same VEK.
4. `vaultVersion = 1`, `chain = SHA-256(0x00 × 32)` (genesis).
5. Serialise, pad, encrypt, write.

### 4.2 Unlock (passphrase)

1. Parse and structurally validate. Reject `formatVersion` outside the supported range.
2. **Enforce the KDF floor.** If the file's parameters are below the floor, refuse to
   use them (downgrade defence) and mark the vault for re-keying.
3. Locate the slot for the supplied secret type.
4. `MUK = Argon2id(secret, slot.kdf)` → `KEK = HKDF(MUK, …)`.
5. **Constant-time commitment check.** Mismatch ⇒ `WrongSecret`, stop. No timing
   difference between a wrong passphrase and a wrong slot.
6. Unwrap the VEK.
7. Derive `contentKey`; decrypt with the full prefix as AAD. Tag failure here (after a
   successful commitment check) means *corruption or tampering*, not a wrong
   passphrase — and is reported as such, which is why the two error states are
   distinguishable in the UI without leaking anything.
8. Verify `vaultVersion ≥ localWatermark` (see `05-sync-architecture.md` §4).
9. Unpad, deserialise, migrate the schema if required.

### 4.3 Save

Every save: new `fileSalt`, new `nonce`, `vaultVersion += 1`,
`chain = SHA-256(previousHeaderBytes)`. Keys are never reused across writes.

### 4.4 Change passphrase

Re-wrap the VEK into a new passphrase slot with a fresh salt and freshly calibrated
parameters. The VEK, the payload and every other slot are untouched. The vault is
*not* re-encrypted, and `vaultVersion` still increments so other devices pick up the
new slot.

### 4.5 Parameter upgrade

If a vault's stored parameters are below the current floor at unlock time, the slot is
transparently re-derived at current parameters after a successful unlock. Legacy weak
KDF settings — the mechanism behind the worst of the LastPass 2022 outcomes — cannot
persist silently.

---

## 5. Memory hygiene

- Key material is held in `ByteArray`/`CharArray`, never `String` (Java strings are
  immutable and interned; they cannot be wiped).
- `SecretBytes` is a closeable wrapper that zeroises on `close()` and is used with
  `use { }` at every call site.
- The VEK is zeroised on lock, on `ON_STOP` where policy dictates, and on process death.
- Sensitive types override `toString()` to return a redacted marker, so an accidental
  interpolation into a log statement cannot leak — enforced by `RedactedToStringTest`.

Caveat, stated honestly: the JVM may copy arrays during GC, so zeroisation is
best-effort and cannot be guaranteed against T4 (root/memory-dump). We do it because
it meaningfully shrinks the window, not because it is airtight.

---

## 6. Version and downgrade policy

| Rule | Enforcement |
|---|---|
| `formatVersion` below `MIN_SUPPORTED` ⇒ refuse | Parser |
| `formatVersion` above `MAX_SUPPORTED` ⇒ refuse with "update the app", never guess | Parser |
| KDF parameters below floor ⇒ refuse to *accept*; upgrade after unlock | `KdfPolicy` |
| Unknown header fields ⇒ preserved verbatim for AAD, ignored semantically | Parser |
| Unknown *payload* fields ⇒ preserved on round-trip so an older client cannot silently strip a newer client's data | Schema layer |

That last rule matters for sync: a v1 client that opens a v2 vault must not write back
a version with the v2 fields deleted. Unknown-field preservation is the difference
between a graceful upgrade and silent data loss across devices.
