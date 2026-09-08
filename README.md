# Passwird

**A private vault that happens to synchronise.**

An offline-first, end-to-end encrypted password manager for Android. The vault lives on the
phone. Google Drive holds a sealed copy and is treated as **hostile by default**.

```
./gradlew test            # 214 tests — crypto, schema, generator, search, sync
./scripts/scan-secrets.sh # 15 static security and architecture checks
```

---

## The idea

> My passwords belong to me. My vault exists on my phone. The cloud only ever holds a
> sealed copy. Only this app, with my secret, can open it.

Every architectural decision in this repository traces back to that sentence. If the user
turns on aeroplane mode, the app must lose **nothing** except the word "Synced" in the
status line.

---

## Five decisions that define it

**Google is not in the key hierarchy.** Signing in with Google establishes identity and
permission to store bytes in Drive. There is no code path from any Google credential to the
vault key. An attacker with total control of the account gets ciphertext.
→ [`docs/04-key-management.md`](docs/04-key-management.md) §1

**The store is assumed hostile.** The February 2026 ETH Zürich / USI paper demonstrated 27
attacks against major password managers under a malicious-server model, exploiting the
routine operations users perform daily. All four of its attack classes are addressed
structurally here: no key escrow, an authenticated header plus a version hash chain, no
sharing, and a hard refusal to downgrade format or KDF parameters.
→ [`docs/02-threat-model.md`](docs/02-threat-model.md)

**Merges never destroy data.** Conflicting edits are kept and adjudicated by the user, not
resolved by picking a winner. Passwords are never auto-resolved. Enforced by a property
test over 400 randomised scenarios, not by care.
→ [`docs/05-sync-architecture.md`](docs/05-sync-architecture.md) §5

**No server, no telemetry, no sharing.** Three entire attack classes removed by
construction rather than mitigated. The complete list of network destinations the app
contacts is two entries long.
→ [`adr/0005`](docs/adr/0005-no-telemetry.md), [`adr/0006`](docs/adr/0006-no-sharing.md)

**Honest, or silent.** Entropy with a stated attacker model instead of a five-bar meter.
Counts instead of a security score. Limits stated in the product rather than buried.
→ [`docs/01-product-spec.md`](docs/01-product-spec.md) §7

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

## Architecture

```
core/crypto     KDF, key hierarchy, key slots, PWVAULT format    pure JVM · 69 tests
core/model      schema, item types, migrations                   pure JVM · 22 tests
core/vault      generator, strength model, auto-lock             pure JVM · 46 tests
core/search     offline index and ranking                        pure JVM · 18 tests
core/sync       state machine, three-way merge, rollback guard   pure JVM · 59 tests
platform/secure Keystore, biometrics, clipboard, FLAG_SECURE     Android
data/drive      OAuth + Drive transport                          Android
design/*        Quiet Precision tokens and components            Android
app             screens and navigation                           Android
```

The `core:*` modules carry no Android and no Google dependency — a boundary the security
scan enforces, since "Google is not in the key hierarchy" is a claim about the module graph
and deserves to be checked by something other than good intentions.

That layering is also why the parts where a bug is most expensive are the parts that are
actually proven: the crypto, the schema, the merge algorithm and the rollback defence all
run their full suites in seconds with no emulator.

**Honest status:** everything under `platform/`, `data/`, `design/` and `app/` is written
but has not been compiled — the development container has a JDK but no Android SDK. See
[`docs/13-roadmap.md`](docs/13-roadmap.md) for the precise per-phase state.

---

## Cryptography, briefly

```
passphrase ──Argon2id──► MUK ──HKDF──► KEK ──unwraps──► ┌─────────────┐
recovery   ──Argon2id──► MUK ──HKDF──► KEK ──unwraps──► │ VEK (random)│
Keystore key (biometric-gated) ────────────────────────► └──────┬──────┘
                                                                │ HKDF
                                            content · localdb · index · manifest
```

- **AES-256-GCM** with a per-write HKDF-derived message key, which removes GCM's 96-bit
  nonce concern without hand-rolling XChaCha ([ADR-0001](docs/adr/0001-aead-selection.md)).
- **Random VEK wrapped by independent key slots**, so changing the passphrase re-wraps 32
  bytes rather than re-encrypting the vault ([ADR-0002](docs/adr/0002-random-vek-key-slots.md)).
- **Explicit key commitment** per slot, checked in constant time before any unwrap.
- **The whole header bound as AEAD AAD**, so lowering the Argon2 cost or transplanting a key
  slot produces a file that simply will not decrypt.
- **Size-bucket padding**, so an observer cannot infer how much changed between uploads.

Full specification: [`docs/03-encryption-architecture.md`](docs/03-encryption-architecture.md)

---

## Documentation

Start with [`docs/00-README.md`](docs/00-README.md) — it has a reading order for the product
side and the security side, plus the eight architecture decision records.

---

## Third-party content

| What | Licence |
|---|---|
| [EFF Long Wordlist](core/vault/src/main/resources/com/passwird/vault/WORDLIST-NOTICE.txt) (7776 words) | CC BY 3.0 US |
| [IBM Plex Sans & Mono](design/tokens/src/main/res/font/FONT-NOTICE.txt) | SIL OFL 1.1 |

Both are bundled rather than fetched at runtime: a webfont or wordlist request would reveal
when the user opens their password manager.
