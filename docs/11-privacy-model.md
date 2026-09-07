# Passwird — Privacy Model

**Status:** v1 · **Last updated:** 2026-09-07

## 1. Position

**Passwird has no backend.** There is no Passwird server, no Passwird account, no
Passwird database. We could not collect your data if we wanted to, because there is
nowhere for it to go.

That is not a policy promise — policies change. It is an architectural fact, and it is
the strongest form of privacy guarantee available: *there is nothing to breach.*

---

## 2. Network calls the app makes

Exhaustively. If a call is not on this list, it is a bug.

| Destination | When | What is sent | What it learns |
|---|---|---|---|
| Google Sign-In | Sign-in, token refresh | Standard OAuth | That you use this app |
| Google Drive API | Sync | **Ciphertext only** | File size (padded), timing |
| — | — | — | — |

That is the complete list. No analytics endpoint, no crash reporter, no feature-flag
service, no icon CDN, no breach-check service, no push service, no ad network, no
attribution SDK, no font CDN.

### 2.1 Calls we deliberately do not make

| Not made | Why it would leak |
|---|---|
| Favicon / icon fetch | Reveals your entire list of accounts to a third party and to every network observer — *without decrypting anything*. Replaced by bundled icons + offline generated marks (`01-product-spec.md` §6). |
| Breach check (HIBP) | Even k-anonymity sends a hash prefix derived from your password. Deferred to v2, opt-in, default off, with the exact leakage stated. |
| Font CDN | A request per launch that reveals app usage. Fonts are bundled. |
| Crash reporting | Stack traces and memory can contain vault data. |
| Analytics | See §3. |
| Push notifications | Requires a device token registered with a server we do not have. |
| Update check | The store handles this. |

---

## 3. Telemetry

**None.** Not "anonymised", not "aggregated", not "privacy-preserving". None.

The bar the brief set was *"prefer no analytics unless genuinely necessary"*. Nothing
in a single-user offline password manager makes analytics necessary. We would be
collecting it because it is habit.

Consequences we accept: we will not know our crash rate, our retention, or which
features are used. We will find bugs the way software found them before telemetry —
by testing well and by users telling us.

There is no opt-out toggle, because there is nothing to opt out of. A "share anonymous
usage data" switch would imply a pipeline exists.

---

## 4. Data classification

| Class | Examples | Rule |
|---|---|---|
| **Secret** | Passwords, keys, card numbers, notes, recovery key, VEK | Encrypted at rest, RAM-only when live, typed `Secret`, never logged, never serialised outside the encrypted payload |
| **Sensitive** | Titles, usernames, URLs, tags, timestamps, item count | Inside the ciphertext. **No "non-sensitive metadata" tier exists** — this is precisely what made the 2022 LastPass breach so damaging |
| **Operational** | Sync watermark, generation token, dirty flag | Encrypted local store (not `SharedPreferences`) |
| **Benign** | Theme, sort order, onboarding-complete flag | `SharedPreferences`. **Nothing vault-derived may ever be written here** — asserted by `PreferencesLeakTest` |

---

## 5. Leak surfaces and controls

| Surface | Control |
|---|---|
| **Logs** | No logging of vault data at any level. `Secret.toString()` returns a redacted marker so accidental interpolation cannot leak. Release builds strip logging via R8. Asserted by `NoSecretsInLogsTest` and `RedactedToStringTest`. |
| **Crash reports** | No crash SDK. Unhandled exceptions are caught at the boundary and re-thrown without vault context attached. |
| **Screenshots / recents** | `FLAG_SECURE` on every window; content masked on `ON_STOP` before the OS snapshot. |
| **Clipboard** | `EXTRA_IS_SENSITIVE` so the OS suppresses the preview; visible auto-clear countdown; cleared on lock and on backgrounding. |
| **Notifications** | The app posts no notifications containing vault content. Sync status is in-app only. |
| **Android backup** | `allowBackup=false`; `dataExtractionRules` excludes vault, index, keys and tokens. |
| **Debug builds** | Debuggable builds refuse to open a production vault path and display a permanent build banner, so a debug build cannot quietly become a leak vector. |
| **Accessibility services** | A non-allowlisted accessibility service active during reveal produces an advisory warning. Advisory only — Android permits this by design and we do not pretend otherwise. |
| **Search index** | Encrypted under `indexKey`, never written in the clear. `SearchIndexLeakTest` scans the serialised index for known plaintext. |
| **IPC / exported components** | No exported activities, services, receivers or providers beyond the launcher. No custom URL scheme that accepts vault data. |
| **WebView** | None in the app. |

---

## 6. Permissions

| Permission | Why |
|---|---|
| `INTERNET` | Drive sync only |
| `ACCESS_NETWORK_STATE` | Detect connectivity to trigger sync |
| `USE_BIOMETRIC` | Biometric unlock |
| `POST_NOTIFICATIONS` | **Not requested** |
| Contacts / storage / location / camera | **Not requested** |

The app functions completely with `INTERNET` revoked.

---

## 7. Third-party code

Minimal by policy, because every dependency is a supply-chain risk — Bitwarden's April
2026 CLI compromise being the recent cautionary case.

| Dependency | Purpose | Why acceptable |
|---|---|---|
| BouncyCastle | Argon2id, HKDF | Mature, audited, widely reviewed. Used for KDF only; AEAD comes from the platform. |
| kotlinx.serialization | Payload codec | Compile-time generated, no reflection |
| AndroidX (Compose, Biometric, Lifecycle, Security) | Platform | First-party |
| Google API client (Drive) | Transport | Confined behind `VaultTransport`; nothing above it depends on it |

No dependency is granted network access to vault data. Versions are pinned; CI runs
dependency review.

---

## 8. User rights

- **Export** the full vault at any time, in an encrypted portable format *and* — behind
  an explicit, clearly-warned confirmation — as plaintext JSON, because a vault you
  cannot leave is a hostage. Lock-in is an anti-feature.
- **Delete** everything: local wipe plus Drive folder removal, with clear confirmation.
- **Inspect**: the About screen shows the plain-language threat model, including what
  we cannot protect against.
- **Take the file**: the Drive vault is in a visible folder precisely so it can be
  copied elsewhere (`06-drive-integration.md` §2). It remains readable by any future
  version of this app given the passphrase.

---

## 9. If this ever changes

Any future addition of a network call, dependency, or stored field requires: an update
to §2 or §4, a threat-model review, and a corresponding test. Adding telemetry would
require changing this document first — deliberately, so that the decision cannot be
made quietly in a pull request.
