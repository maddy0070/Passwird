# Passwird — Threat Model

**Status:** v1 · **Method:** asset-driven, with STRIDE applied per trust boundary
**Last updated:** 2026-09-07

This document states what Passwird protects against, **and what it does not**. The
second list is the more important one, and it is deliberately blunt. A security
document that only lists wins is marketing.

---

## 1. Assets

| # | Asset | Sensitivity | Where it lives |
|---|---|---|---|
| A1 | Credential plaintext (passwords, keys, card numbers, notes) | Critical | Vault plaintext — RAM only, while unlocked |
| A2 | Vault Encryption Key (VEK) | Critical | RAM while unlocked; wrapped at rest |
| A3 | Master passphrase | Critical | User's memory; transiently in RAM |
| A4 | Recovery key | Critical | User's physical/offline custody |
| A5 | Vault metadata (titles, URLs, usernames, tags, timestamps) | High | Inside the ciphertext — **not** in the clear |
| A6 | Vault existence, size, modification times | Low–Medium | Visible to Google; partly mitigated by padding |
| A7 | Google OAuth refresh/access tokens | High | Android Keystore-wrapped local storage |
| A8 | Device-local unlock key (biometric slot) | Critical | Android Keystore / StrongBox, non-exportable |
| A9 | Local encrypted vault + search index | Critical (encrypted) | App-private storage |

**A5 deserves emphasis.** In the 2022 LastPass breach the exfiltrated vaults had
*unencrypted URL fields*, which alone revealed every service each victim used. In
Passwird, every field of every record is inside the AEAD ciphertext. There is no
"non-sensitive metadata" tier in the payload. The only cleartext is the structural
header described in `03-encryption-architecture.md` §3, which contains no
user-derived content.

---

## 2. Adversaries

| ID | Adversary | Capability assumed |
|---|---|---|
| **T1** | Opportunistic thief | Physical possession of a locked phone. No lab. |
| **T2** | Forensic attacker | Physical possession + commercial forensic tooling; can attempt chip-off/extraction. |
| **T3** | Malicious app on the device | Unprivileged, sandboxed, can read the clipboard when foregrounded, can attempt overlay/accessibility abuse. |
| **T4** | Device malware with root | Full OS compromise, can read process memory. |
| **T5** | **Malicious or compromised Google Drive** | Can read, withhold, replay, reorder, truncate, corrupt, roll back or replace stored bytes arbitrarily. **This is our baseline assumption, not an edge case.** |
| **T6** | Google account takeover | Full control of the account and hence of Drive contents. Equivalent to T5 plus the ability to sign in as the user. |
| **T7** | Network attacker | Hostile Wi-Fi, TLS interception attempts, replay. |
| **T8** | Shoulder surfer / camera | Observes the screen. |
| **T9** | Curious insider at Google | Read access to stored bytes and account metadata. |

T5 is elevated to baseline because the Feb 2026 ETH Zürich / USI paper showed that
most deployed managers implicitly trust their server, and that this assumption breaks
in exactly the routine operations users perform daily — logging in, opening a vault,
viewing a password, syncing. We assume the store is hostile and design accordingly.

---

## 3. Trust boundaries

```
┌─────────────────────────── UNTRUSTED ───────────────────────────┐
│  Google Drive (bytes)   ·   Network   ·   Other apps on device  │
└─────────────────────────────────────────────────────────────────┘
                    ▲ ciphertext + authenticated header only
                    │
┌─────────────── SEMI-TRUSTED: Android OS & app sandbox ──────────┐
│  App-private storage (encrypted at rest by us, again by OS)     │
│  Android Keystore / StrongBox  ← key material never leaves      │
└─────────────────────────────────────────────────────────────────┘
                    ▲
┌─────────────── TRUSTED: unlocked process memory ────────────────┐
│  VEK, decrypted vault, transient plaintext                      │
└─────────────────────────────────────────────────────────────────┘
                    ▲
              user's memory: passphrase (A3)
              user's custody: recovery key (A4)
```

The critical property: **the boundary between the trusted zone and Google Drive is
crossed only by ciphertext.** This is asserted by an automated test
(`CiphertextOnlyTest`) that serialises a populated vault, scans the outbound byte
stream for every known plaintext value, and fails the build on any hit.

---

## 4. What Passwird protects against

A row's **Verified by** cell names a check that runs today. Where nothing runs yet, the cell
says so in those words — an unverified mitigation is a plan, and recording it as a
verification is how a threat model starts lying to the people relying on it.

| Threat | Mitigation | Verified by |
|---|---|---|
| **T5/T6/T9 — Drive reads the vault** | AES-256-GCM over the entire payload; VEK never leaves the device; Google is never given key material and no escrow exists. | `CiphertextOnlyTest`, `VaultCryptoTest`, `NoGoogleKeyPathTest` |
| **T5 — Drive tampers with the ciphertext** | AEAD authentication tag; any bit flip fails decryption and is surfaced as a *recoverable* error, never as silent partial data. | `TamperDetectionTest` |
| **T5 — Drive tampers with the header** (e.g. lowering Argon2 cost, swapping key slots, forging a version) | The complete header is bound as AEAD **AAD**. Modifying any header byte breaks the tag. | `HeaderAadTest` |
| **T5 — Rollback: Drive serves an older, valid vault** to resurrect a deleted credential or revert a password change | Monotonic `vaultVersion` + **highest-seen-version** watermark held in device secure storage. A remote version below the watermark is refused and surfaced to the user. | `RollbackGuardTest` |
| **T5 — Fork / history rewrite** | Each header commits to `SHA-256(previous header)`, forming a hash chain. A rewritten history fails chain validation. | `HashChainTest` |
| **T5 — Downgrade to a weaker format or KDF** | Client enforces a hard floor on KDF parameters and refuses `formatVersion` below the minimum, regardless of what the file claims. Backwards compatibility is *read-only and floor-checked*, never automatic. | `DowngradeRejectionTest` |
| **T5 — Truncation / partial write** | Length-prefixed framing with declared lengths validated against actual bytes before any allocation. | `TamperDetectionTest` covers the framing. **Atomic publish on Drive is NOT implemented** — the local store stages and renames, the Drive transport does not. |
| **T5 — Key-slot substitution / partitioning oracle** | Explicit **key commitment** per slot, checked in constant time before unwrap. A crafted file cannot decrypt under two different passphrases. | `KeyCommitmentTest` |
| **T7 — Network interception** | TLS to Google; plus the payload is already end-to-end encrypted, so TLS failure alone is not a vault compromise. Certificate handling left to the platform (pinning rejected — see ADR-0007). | — |
| **T1 — Stolen locked phone** | Vault at rest is encrypted under a key that exists only wrapped by Keystore (biometric slot) or derived from the passphrase. Auto-lock zeroises the VEK. | `AutoLockTest` |
| **T2 — Forensic extraction of app storage** | Extracted files are ciphertext. The biometric-slot key is non-exportable and hardware-bound; StrongBox where available. Argon2id (64 MiB, t=3, p=4 floor) makes offline passphrase attack expensive. | `KdfFloorTest` |
| **T3 — Malicious app reads the clipboard** | Clipboard auto-clear with a countdown; `EXTRA_IS_SENSITIVE` set so the OS suppresses clipboard previews; copy is explicit and never automatic. | **Not verified.** Implemented, never executed — no test and no device run. |
| **T3/T8 — Screenshots and the recents thumbnail** | `FLAG_SECURE` on every window; content masked on `ON_STOP` before the OS snapshot is taken. | **Not verified.** Needs an instrumented run that has not happened. |
| **T8 — Shoulder surfing** | Passwords masked by default; reveal is deliberate, momentary and never persisted across navigation. | **Not verified.** No UI test exists yet. |
| **Log / crash / analytics leakage** | No analytics or crash SDK in release. Sensitive types have `toString()` overridden to a redacted form so they cannot be logged accidentally. Release builds strip logging via R8. | `NoSecretsInLogsTest`, `RedactedToStringTest`. The R8 stripping itself is **not verified** — it needs a release build nobody has produced. |
| **Hard-coded secrets** | Static scan over the whole tree in CI; there is no key material in the source or the APK. | `scripts/scan-secrets.sh` in CI |
| **Backup exfiltration via ADB / cloud backup** | `allowBackup=false`, `dataExtractionRules` excludes vault and key material. | **Not verified.** Manifest reviewed by eye; no build has been produced to confirm it. |

---

## 5. What Passwird does **not** protect against

This section is binding. We will not make claims outside it.

| Not protected | Why | What the user can do |
|---|---|---|
| **T4 — Rooted or malware-infected device while unlocked** | If the OS is compromised, the attacker can read our process memory, capture the screen, or hook our code. No userspace application can defend against this. Nothing we could build changes this. | Do not root the device; keep the OS updated. The app performs a *best-effort, non-authoritative* root/integrity check and warns — it is not a security control and is not presented as one. |
| **A weak master passphrase** | Argon2id raises the cost of each guess; it cannot rescue a passphrase from a 10-thousand-word list. This is the single largest residual risk in the design. | Onboarding requires a passphrase measured against a real attacker model and offers a generated 5-word passphrase as the default path. |
| **Loss of both passphrase and recovery key** | The vault is *mathematically* unrecoverable. There is no escrow, no backdoor, no support override. This is the cost of having no server to attack. | Store the recovery key offline. Onboarding forces the user to confirm they have done so. |
| **Keyloggers / hostile IMEs** | The passphrase is typed. A malicious keyboard sees it. | Biometric unlock avoids repeated entry; prefer a trusted system keyboard. |
| **Coercion ("rubber-hose")** | Out of scope. We do not implement duress vaults — a fake vault that is detectably fake is worse than none. | — |
| **Google deleting the account or the file** | We do not control Drive. | Local vault remains fully functional and authoritative; local encrypted backups and manual export exist precisely for this. |
| **Traffic analysis by Google (A6)** | Google necessarily learns that a file exists, roughly how big it is, and when it changes. | Size padding to buckets blunts the size signal; timing is inherent to syncing at all and we say so. |
| **A compromised build/supply chain** | If the artefact the user installs is not the one we built, all guarantees are void. Bitwarden's April 2026 CLI supply-chain compromise is the cautionary case. | Reproducible builds and published artefact hashes (roadmap item). |
| **Screen-reading accessibility-service abuse** | A user-granted accessibility service can read screen content. Android permits this by design. | Warn if a non-allowlisted accessibility service is active during reveal. Advisory only. |
| **Malicious modified builds of Passwird itself** | Obvious, but stated for completeness. | Install from a verified source. |

---

## 6. Explicit non-claims

We will not say, in the product or in marketing:

- "Unhackable", "military-grade", "bank-grade", or "zero-knowledge" without
  qualification. (We *are* zero-knowledge with respect to Google. We are not
  zero-knowledge with respect to a rooted device, and the phrase invites that
  misreading.)
- That biometrics are an encryption key. They are not — see
  `04-key-management.md` §4. A fingerprint gates *access to* a hardware-held key.
- That we can recover a lost vault.
- That the app detects all rooted devices. Root detection is defeatable by design and
  is presented as a hint, never as a guarantee.

---

## 7. Residual risk register

| ID | Risk | Severity | Likelihood | Response |
|---|---|---|---|---|
| R1 | Weak user passphrase | Critical | Medium | Mitigate via onboarding UX + generated passphrase default |
| R2 | User loses recovery key and passphrase | Critical | Low–Medium | Accept; make consequences unmissable during onboarding |
| R3 | Rooted device | Critical | Low | Accept + warn |
| R4 | Supply-chain compromise of a dependency | High | Low | Minimal dependency surface; pinned versions; CI dependency review |
| R5 | Merge bug destroys records | Critical | Low | Mitigate: tombstones, no destructive resolution, pre-merge local snapshot, extensive property tests |
| R6 | Google revokes Drive API access | Medium | Low | Accept; app is fully functional offline; export path always available |
| R7 | Argon2 parameters age out | Medium | Certain over time | Mitigate: parameters versioned in the header and transparently upgraded on unlock |

---

## 8. Review triggers

This model is re-reviewed whenever any of the following changes: the file format,
the key hierarchy, the sync merge algorithm, the set of OAuth scopes, the dependency
set, or the addition of any outbound network call. Additions to §4 require a
corresponding passing test; additions to §5 require a corresponding statement in the
user-facing security copy.
