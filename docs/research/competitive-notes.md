# Competitive & Security Research Notes

**Conducted:** September 2026 · Feeds `01-product-spec.md` §5 and `02-threat-model.md`

Purpose: understand expectations and failure modes in this category. **Not** to copy
patterns. Each finding below is recorded with the design decision it produced; findings
that changed nothing are omitted.

---

## 1. The finding that most shaped this architecture

**ETH Zürich + Università della Svizzera italiana, published 16 Feb 2026** (peer
reviewed; USENIX Security 2026, Baltimore).

Researchers built servers that mimicked compromised password-manager infrastructure — a
**malicious server threat model** — and developed **27 successful attacks** against
Bitwarden (12), LastPass (7), Dashlane (6) and 1Password. Crucially, the attacks
exploited *routine* operations: logging in, opening a vault, viewing a password,
syncing between devices.

The flaws fell into four classes:

| Class | Our structural response |
|---|---|
| **Key escrow** (SSO login, account recovery) | No escrow of any kind exists. Recovery is a user-held 128-bit key wrapping the VEK. There is no server to hold anything. `04-key-management.md` §5. |
| **Vault integrity** | Entire header bound as AEAD AAD; monotonic `vaultVersion` with a device-held watermark; `SHA-256` hash chain across versions. Rollback and fork are detected and refused, never auto-resolved. `03` §3, `05` §4. |
| **Sharing** | Not implemented, at all. A single-user product is structurally immune to this class. Recorded as a security decision, not a missing feature. |
| **Backwards compatibility** | Hard KDF floor and format-version range enforced client-side regardless of file contents; parameters are authenticated so they cannot be lowered; legacy parameters are upgraded on unlock rather than tolerated. `03` §6. |

**This is why Google Drive is treated as hostile by default rather than as a trusted
store.** The paper's central lesson is that clients trust their server implicitly, and
that assumption fails in exactly the everyday paths.

Sources: [ETH Zurich news](https://ethz.ch/en/news-and-events/eth-news/news/2026/02/password-managers-less-secure-than-promised.html) ·
[SecurityWeek](https://www.securityweek.com/password-managers-vulnerable-to-vault-compromise-under-malicious-server/) ·
[iTnews](https://www.itnews.com.au/news/researchers-find-critical-vulnerabilities-in-cloud-based-password-managers-623661) ·
[Infosecurity](https://www.infosecurity-magazine.com/news/vulnerabilities-password-managers/)

---

## 2. Historical incidents

| Incident | Lesson taken |
|---|---|
| **LastPass 2022** — vaults exfiltrated; **URL fields were unencrypted**; older accounts retained weak KDF iteration counts. Settled a $24.5M class action in 2025. | Two hard rules: (a) *everything* user-derived goes inside the ciphertext — there is no "non-sensitive metadata" tier; (b) legacy KDF parameters must never persist silently — floor-enforce and upgrade. |
| **Bitwarden CLI supply-chain compromise, April 2026** (Checkmarx). | Minimal pinned dependency surface; dependency review in CI; reproducible builds on the roadmap; supply chain named explicitly in threat model §5 as something we *cannot* fully mitigate. |
| **1Password macOS vulnerability, 2024** (fixed in 8.10.38) — local malware could bypass protections. | Reinforces that a compromised host defeats userspace defences. Stated as a non-claim rather than hidden. |
| **Third-party audits** (Bitwarden: Fracture Labs, Unit 42, IOActive 2024; Proton Pass: Cure53 2023). | External review is table stakes for credibility; recorded as a roadmap commitment rather than an implied claim. |

Sources: [LastPass 2022 breach](https://en.wikipedia.org/wiki/LastPass_2022_data_breach) ·
[Password-manager breach roundup](https://www.cloaked.com/post/the-top-3-worst-password-manager-breaches-and-security-issues-to-date) ·
[1Password incidents](https://onerep.com/blog/1password-breach-what-happened-and-how-to-stay-safe) ·
[Bitwarden 2025/26 fact-check](https://safepasswordgenerator.net/blog/bitwarden-breach-2025-2026-fact-check/)

---

## 3. User-experience complaints

| Complaint | Consequence for Passwird |
|---|---|
| **Lockout and recovery is the dominant catastrophic story.** Users lose the master password, find recovery does not work or was never set up, and lose everything. 1Password's pre-generated recovery code is the pattern that works. | Recovery key is generated *and verified* during onboarding (`09` §3 step 5). No skip, no "remind me later". The consequence is stated in plain words before the user can continue. |
| **Sync conflicts silently overwriting data** destroys trust permanently. KeePass's merge is admired precisely because it reconciles rather than picks. | Record-level three-way merge with tombstones; conflicting edits preserved as *both*; passwords never auto-resolved. The data-loss invariant is a property test. |
| **KeePass** is trusted but has no official mobile app or built-in sync; users assemble fragile setups. | The gap we aim at: KeePass-grade "the file is yours" ownership with first-class mobile UX and sync that actually works. |
| Anxiety-inducing security dashboards. | Security is a destination with quiet counts, never the greeting. `09` §1. |
| Cloud-dependent apps that stall or degrade offline. | Offline is the primary mode; the app never blocks on sync, ever. |
| Accessibility: unlabelled icon-only reveal/copy controls are endemic in this category. | Every control labelled; 48dp targets on reveal/copy specifically; no colour-only state. `08` §9. |
| Users store 2FA recovery codes in screenshots. | First-class `RecoveryCodes` type with per-code used/unused tracking — solving the whole job, which is what actually changes the behaviour. |

Sources: [Common password manager issues](https://www.makeuseof.com/common-password-manager-issues-how-to-fix-them/) ·
[Reddit-sourced comparisons](https://www.wizcase.com/blog/best-password-managers-by-reddit/)

---

## 4. Technical references

**Argon2id parameters** — OWASP: minimum m=19 MiB, t=2, p=1; recommended m=46 MiB, t=1,
p=1; high-security m=128 MiB, t=3, p=4. We adopt a **floor of m=64 MiB, t=3, p=4** with
on-device calibration targeting ≈500 ms, sitting between OWASP's recommended and
high-security tiers — justified because unlock is infrequent and the vault is a
high-value target.
Source: [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

**Android Keystore / BiometricPrompt** — `setUserAuthenticationRequired(true)` plus
`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` for per-use auth;
`setInvalidatedByBiometricEnrollment(true)` so enrolling a new fingerprint invalidates
the key rather than granting access; `CryptoObject` so the key is unusable until the
secure hardware itself observes a valid biometric — the boolean-gate pattern
(`if (success) loadKey()`) is hookable and is explicitly rejected. StrongBox/TEE keeps
key material outside the OS.
Sources: [Android biometric guide](https://developer.android.com/identity/sign-in/biometric-auth) ·
[BiometricPrompt with CryptoObject](https://medium.com/androiddevelopers/using-biometricprompt-with-cryptoobject-how-and-why-aace500ccdb7) ·
[Keystore pitfalls](https://stytch.com/blog/android-keystore-pitfalls-and-best-practices/)

**Google Drive `appDataFolder`** — hidden per-app folder, `drive.appdata` is a
non-sensitive scope, **but its contents are deleted when the user uninstalls the app**,
and it still consumes the user's quota. That deletion behaviour is disqualifying for a
password vault; see `06-drive-integration.md` §2 and `adr/0003`.
Source: [Google Drive appdata guide](https://developers.google.com/workspace/drive/api/guides/appdata)

---

## 5. Where we intend to be meaningfully better

1. **Hostile-store design as the default**, not an afterthought — rollback, fork and
   downgrade defences that most shipped managers were shown in Feb 2026 to lack.
2. **Merges that cannot lose data**, enforced by a property test rather than by care.
3. **No icon surveillance** — offline generated marks instead of leaking the user's
   account list to an icon CDN.
4. **Honest strength reporting** — entropy with a stated attacker model, not a five-bar
   meter and a vanity score.
5. **Recovery designed first**, verified during onboarding, with the consequences said
   out loud.
6. **A calm interface** that treats retrieval as the job and security review as a place
   you visit.
