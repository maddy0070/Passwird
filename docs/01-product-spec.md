# Passwird — Product Specification

**Status:** v1 baseline · **Owner:** Product + Security · **Last updated:** 2026-09-07

---

## 1. Positioning

> **Passwird is a private vault that happens to synchronise.**

Not a cloud service with a password screen. The vault is a local artefact that the
user owns. Google Drive is a *dumb encrypted blob store* — a courier, not a custodian.

The mental model we are engineering for, in the user's words:

- My passwords belong to me.
- My vault exists on my phone.
- The cloud only ever holds a sealed copy.
- Only this app, with my secret, can open it.

Every architectural decision in this repository is traceable to that sentence.

### 1.1 The one-line product test

If the user turns on aeroplane mode, the app must lose **nothing** except the word
"Synced" in the status line. If that is ever untrue, we have built the wrong product.

---

## 2. Principles (ranked, and they are ranked for a reason)

When two principles conflict, the higher one wins. This ordering is the tie-breaker
we use in every ADR.

| # | Principle | What it overrides |
|---|-----------|-------------------|
| 1 | **Never lose the user's data** | Everything. A vault that is safe but destroyed is a failure. |
| 2 | **Never leak plaintext** | Convenience, features, speed. |
| 3 | **Work fully offline** | Sync elegance, freshness. |
| 4 | **Be honest** | Marketing, perceived security, pretty numbers. |
| 5 | **Feel calm and precise** | Feature count, density, novelty. |
| 6 | **Sync reliably** | Sync immediacy. |

Principle 1 above 2 is deliberate and worth defending: we will accept keeping an
encrypted local backup that an attacker with the device *and* the passphrase could
open, rather than risk a merge bug destroying a decade of credentials. We will not
accept storing that backup in plaintext — principle 2 still binds the *form* of the
backup, principle 1 only forces its *existence*.

Principle 4 is why there is no 5-bar strength meter in this product. See §7.

---

## 3. Scope decisions

The brief was explicit: *do not add features because competitors have them*. Every
candidate below was scored on user value, security cost, UX cost, build cost, offline
behaviour and sync behaviour. Decisions and the reasoning that produced them:

### 3.1 In scope for v1

| Capability | Why it earns its place |
|---|---|
| Login credentials | The core job. Everything else is secondary. |
| Secure notes | Near-zero marginal cost — same encrypted record, different renderer. |
| Payment cards | High user value, high theft value, and no safe alternative storage exists. |
| API keys / tokens | Our likely early adopters are technical; these currently live in plaintext `.env` files. |
| Wi-Fi credentials | Genuinely shared, genuinely forgotten, trivially modelled. |
| Software licences | Same record shape as a note with structured fields. Cheap. |
| Recovery codes | **Strategically important.** Users store 2FA recovery codes in screenshots today — a real, widespread, severe leak we can close. |
| SSH keys (private key as a field) | Technical audience; large but bounded payloads. |
| Database credentials | Modelled as a login variant with host/port/database. No new machinery. |
| Custom item types | Escape hatch that prevents the schema from becoming a prison. |
| Tags + folders + favourites + recents | Organisation without imposing a hierarchy. |
| Offline search | Table stakes, and must never touch the network. |
| Password generator | Table stakes, but see §7 for what we do differently. |
| Auto-lock + biometric unlock | Table stakes for a mobile vault. |
| Encrypted Drive sync + conflict resolution | The differentiator. See `05-sync-architecture.md`. |
| Local encrypted backups + export | Principle 1. Non-negotiable. |

### 3.2 Deliberately deferred

| Capability | Decision | Reasoning |
|---|---|---|
| **Android Autofill Service** | v1.1 | Very high user value; genuinely large surface area with its own leak paths (`AssistStructure` mis-targeting, phishing-domain matching). Deserves its own security review rather than being smuggled into v1. Interface seams are prepared in `core:vault` so it does not require re-architecture. |
| **Passkeys / Credential Manager provider** | v2 | Requires being a system credential provider, plus a considered position on syncing non-extractable private key material. "Technically appropriate" — eventually yes; not while the sync engine is still young. |
| **Breach checking (HIBP k-anonymity)** | v2, opt-in, default **off** | Even k-anonymity transmits a 5-character SHA-1 prefix, which is a real if small signal about your vault, sent to a third party. That collides with principle 2. Shipping it silently on would be dishonest; shipping it opt-in with an accurate description of exactly what leaves the device is defensible. |
| **Vault sharing / organisations** | Out of scope | The ETH Zürich / USI study (Feb 2026) found sharing features to be one of four principal attack classes across every major manager. A single-user product that never implements sharing is *structurally* immune to that class. This is a security feature, not a missing feature. |
| **Browser extension / desktop client** | Out of scope | Different threat model, different product. |
| **Cloud account, server, or telemetry backend** | **Never** | We have no server. There is nothing to breach and no key escrow to attack. |

### 3.3 Explicitly rejected

| Rejected | Why |
|---|---|
| **Remote favicon fetching** | Fetching `https://icons.example/foo.com/icon.png` tells a third party — and every network observer — the exact list of services the user holds accounts with. That is one of the most sensitive things about a vault, and it would leak *without decrypting anything*. Many managers do this. We will not. See §6. |
| **Any analytics or crash SDK in the release build** | See `11-privacy-model.md`. |
| **Server-side key escrow / "account recovery" by us** | Same ETH study: key escrow was the first of the four attack classes. We cannot leak what we never hold. |
| **Password "health score" as a single number** | Compresses unrelated risks into a vanity metric. See §7. |

---

## 4. The three jobs

Ranked by frequency, because frequency should drive the layout of the home screen.

1. **Retrieve** a credential, fast, usually under mild stress, often one-handed.
   *Target: app open → password on clipboard in under 4 seconds including biometric.*
2. **Capture** a new credential without breaking the flow they are already in.
3. **Repair** — find and fix the weak, reused and ancient passwords, occasionally,
   usually prompted rather than spontaneous.

Job 1 outnumbers jobs 2 and 3 by roughly an order of magnitude. Therefore the home
screen is a *search-and-retrieve surface*, not a dashboard. Job 3 is a destination
the user visits, not a wall of anxiety they are greeted by. This is the single most
important information-architecture decision in the product.

---

## 5. What we learned from the competitive research

Sources are listed in `docs/research/competitive-notes.md`. The findings that
actually changed the design:

| Finding | Design consequence |
|---|---|
| The Feb 2026 ETH Zürich / USI paper demonstrated 27 attacks across Bitwarden, LastPass, Dashlane and 1Password under a **malicious-server** model — grouped into key escrow, vault integrity, sharing, and backwards-compatibility exploits. | We adopt the malicious-server model as our *baseline* assumption about Google Drive rather than an edge case. All four classes are addressed structurally: no escrow (§3.3), authenticated headers + hash chain + rollback counters (`03`, `05`), no sharing (§3.2), and a hard refusal to downgrade format or KDF parameters (`03` §6). |
| LastPass 2022: vaults were exfiltrated with **unencrypted URL fields** and weak legacy KDF iteration counts for older accounts. | Encrypt the *entire* payload including URLs and all metadata — no "non-sensitive" fields outside the ciphertext. Never leave legacy KDF parameters in place: parameters are authenticated, floor-enforced, and upgraded on unlock. |
| Recovery is the #1 source of catastrophic user stories ("I lost everything"). | Recovery key generated and *verified* during onboarding, not offered as a skippable afterthought. See `09-ux-flows.md` §3. |
| Sync conflicts silently overwriting data is the #1 source of trust loss. | Record-level three-way merge with tombstones; conflicting edits are preserved as both versions, never resolved by destroying one. `NEVER overwrite blindly` is enforced in code, not in a comment. |
| Users routinely keep 2FA recovery codes in their camera roll. | First-class Recovery Codes item type in v1. |
| Accessibility in this category is generally poor — reveal/copy controls are frequently unlabelled icon buttons. | Every sensitive control carries an explicit content description and a non-colour state cue. `08-design-system.md` §9. |

---

## 6. Icons without surveillance

A credential list is much easier to scan with logos. The industry solves this by
calling a remote icon service, which leaks the user's account list.

Our approach, in priority order:

1. **Bundled offline icon set** for the few hundred most common services, shipped in
   the APK. No network, no leak.
2. **Deterministic generated mark** for everything else: derive a stable hue and a
   1–2 character monogram from the registrable domain. Pure function of the domain,
   computed locally, no I/O.
3. **User-chosen icon** from the bundled set.

The generated marks are a deliberate part of the visual identity rather than a
fallback — see `08-design-system.md` §7. The list looks intentional, not broken,
and nothing about the vault leaves the device to make that happen.

---

## 7. Honest security signals

The brief said: *avoid fake security meters*. Concretely, that means:

- Strength is expressed as **estimated entropy in bits**, plus a plain-language
  consequence: *"about 3 million years of guessing at 100 billion attempts a second"*
  — with the assumed attack rate stated, because a strength claim without a stated
  attacker model is meaningless.
- For generated passwords entropy is *computed exactly* from the generator's own
  configuration, because we know the distribution we sampled from.
- For user-supplied passwords it is *estimated* via pattern-aware analysis and is
  labelled as an estimate. We never show a precise-looking number we cannot justify.
- There is **no single vault health score**. "3 reused, 1 weak, 12 older than two
  years" is actionable; "Security Score: 78" is decorative.
- We never claim a password is "strong" — we say what it would cost to guess and let
  the number carry the argument.

See `06-...` (generator implementation) and `docs/08-design-system.md` §8 for how
this is rendered without resorting to a five-bar meter.

---

## 8. Non-goals

- Multi-user, family or team vaults.
- Being the user's 2FA authenticator app. (We store *recovery codes*; generating TOTP
  in the same app that stores the password collapses two factors into one. Deliberate.)
- Recovering a vault for a user who has lost both their passphrase and their recovery
  key. This is *impossible by construction*, and onboarding says so in plain words
  rather than discovering it during a support incident.

---

## 9. Success criteria

| Dimension | Target |
|---|---|
| Retrieval | Cold start → unlocked → password copied ≤ 4 s |
| Offline | 100% of read/write/generate/search functionality with no network |
| Data loss | Zero credential-losing merge outcomes across the sync test corpus |
| Crypto | Every security claim in `02-threat-model.md` backed by a passing test |
| Cloud content | Byte-for-byte verifiable: nothing but ciphertext + authenticated header leaves the device |
| Accessibility | Every interactive element labelled; no state expressed by colour alone; full function at 200% text scale |
