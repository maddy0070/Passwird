# Passwird — Autofill Security and Privacy Design

**Status:** Design only · **Implementation: NOT approved** · **Date:** 2026-09-08

This document exists because Autofill must not be built merely because users expect it.
Autofill is the largest attack surface a password manager can add, and the only feature in
which the app deliberately hands a credential to code it does not control.

Nothing here is implemented. This is the design that must be accepted — or rejected — first.

---

## 1. What Autofill actually is, stated honestly

Every other part of Passwird moves a credential from ciphertext to the user's screen.
Autofill moves it **into another application's process**. That is a different security
model, and calling it a convenience feature obscures the change.

Three properties follow, and they are not negotiable:

1. **The target application is untrusted.** We are handing plaintext to T3 — a potentially
   malicious app on the device — every time we fill.
2. **Target matching is the entire security boundary.** If the app fills the right credential
   into the wrong application, it has phished the user on the attacker's behalf, using the
   user's own trust in their password manager. There is no recovery from this: the credential
   is disclosed the instant it is filled.
3. **The Autofill service runs outside the app's own lifecycle.** It is invoked by the system,
   in a process the user did not open, potentially while the vault is locked. Every assumption
   the rest of the product makes about "the user is here, the vault is unlocked, the screen is
   ours" is false inside it.

---

## 2. Threats specific to Autofill

Extends `02-threat-model.md`; T-numbers continue that document's scheme.

| ID | Threat | Why Autofill creates it |
|---|---|---|
| **T10** | **Target impersonation** — a malicious app declares itself as a bank to receive that bank's credential | The framework hands us a package name and, for browsers, a claimed domain. Neither is trustworthy on its own. |
| **T11** | **Domain spoofing in a WebView** | A hostile app hosts a WebView showing an attacker-controlled page and reports whatever domain it likes. |
| **T12** | **Credential enumeration by fingerprinting** | An app can present many login forms in succession and observe which ones we offer to fill, learning which services the user has accounts with — the exact metadata the vault format works to hide. |
| **T13** | **Overlay / tapjacking on the fill prompt** | An overlay covers our authentication prompt so the user authorises a fill they cannot see. |
| **T14** | **Dataset leakage before authentication** | Naively built datasets embed credential values in the response *before* the user authenticates. The framework passes these across process boundaries. |
| **T15** | **Vault unlock outside the app** | Autofill needs vault access while the app is not foregrounded, which stresses the auto-lock model and the "vault is only open when the user is present" invariant. |
| **T16** | **Silent surface expansion** | Compatibility mode, accessibility-based fallbacks, and inline suggestions each widen exposure, and each is easy to enable without noticing. |

---

## 3. Design decisions

### 3.1 Never put a credential in a dataset before authentication — **absolute**

The Android Autofill framework permits building a `Dataset` containing values, returning it,
and letting the system fill on selection. Passwird must never do this. Every dataset is an
**authentication-required** dataset: the response carries a presentation and an
`IntentSender`, and the credential is materialised only inside our own authenticated activity,
after the user has proven presence.

This costs one extra tap. It is not negotiable: it is the difference between a credential
crossing a process boundary under user authorisation and crossing it speculatively.

### 3.2 Matching is verified, never claimed — **the core of the design**

| Target type | What we match on | Why |
|---|---|---|
| **Native app** | The **signing certificate hash**, not the package name | Package names are attacker-choosable on sideloaded builds. The certificate is what actually identifies the publisher. |
| **Browser** | The **verified web domain** from `AssistStructure.getWebDomain()` together with the browser's own certificate hash, checked against a maintained allowlist of real browsers | A domain claimed by an arbitrary app is worthless. It is only meaningful when the app reporting it is a browser we recognise. |
| **WebView inside a non-browser app** | **No fill offered** | This is T11 and it cannot be resolved safely. We decline, and say why. |
| **Unknown / unmatched** | **No fill offered.** Search is available, but the user must choose explicitly | Never guess. |

The association between a stored credential and an app is recorded on **first successful
manual use**, with the certificate hash captured then — and the user is told an association is
being made. A credential is never silently offered to an app it has not been associated with.

### 3.3 No fill without an unlocked vault, and no unlock that outlives the fill

Autofill never unlocks the vault "in the background". When the vault is locked, the dataset
presentation says *"Unlock Passwird to fill"*, and selecting it opens our own authentication
activity. Authentication is biometric via `CryptoObject` — the same path as normal unlock, with
no weaker variant.

An unlock performed for a fill grants access **for that fill only**. It does not open the app's
main session, and it does not reset the auto-lock timer for the main session. A user who fills
a password in another app has not thereby unlocked their vault.

### 3.4 Fingerprinting resistance (T12)

A response that offers datasets only for services the user has an account with is an oracle.
Mitigations, in order of value:

1. **Present the same entry point regardless of matches.** The user always sees a Passwird
   presentation on a recognised login form; whether it leads to a match, a search, or nothing
   is revealed only after authentication — behind a gate the calling app cannot observe.
2. **Never vary the response by vault contents** in any way visible before authentication:
   no count, no title, no icon derived from a stored item.
3. Accept the residual: an app can still learn that Passwird is installed. That is
   unavoidable and not sensitive.

This costs some polish — a "0 matches" state cannot be shown inline — and is worth it. The
alternative leaks the same metadata class the vault format spends its padding budget hiding.

### 3.5 Rejected outright

| Rejected | Why |
|---|---|
| **Compatibility mode** (`android:autofillCompatibilityMode`) | Drives autofill through the accessibility APIs, vastly widening what the service can see and be tricked by. Passwird supports the real Autofill framework or nothing. |
| **Accessibility-service-based filling** | The pattern that made several password managers a liability. An accessibility service can read every screen; we will not hold that permission. |
| **Filling into unrecognised WebViews** | T11, unresolvable. |
| **Saving credentials automatically on form submit** | Save prompts are offered; capture is never silent. A password manager that records what you type without asking is a keylogger with good intentions. |
| **Inline suggestions containing credential values** | Same class as T14; presentations carry labels only. |
| **Filling a TOTP and a password in one action without re-authentication** | Concentrates two factors into one gesture, defeating the point of the second. |

---

## 4. Privacy commitments

Extends `11-privacy-model.md`.

- **The Autofill service transmits nothing.** No network access, no analytics — consistent
  with ADR-0005, which applies to it identically.
- **No log of which apps requested a fill**, beyond the credential-to-app associations the
  user can see and delete in the app. That list is inside the encrypted payload, never in
  `SharedPreferences`.
- **Domain and package data from a request never leaves the process** and is never persisted
  except as a user-visible association.
- **`lastUsed` updates for a filled credential are vault data**, encrypted like everything
  else.

---

## 5. What must be true before implementation starts

Every one of these is blocking.

| # | Precondition |
|---|---|
| 1 | The vertical slice (§H steps 1–5 of the production-readiness review) is closed and the app runs |
| 2 | Biometric unlock is **verified on a device**, not merely reviewed — Autofill depends on it entirely |
| 3 | This document is accepted, or amended and then accepted |
| 4 | The certificate-hash matching logic is implemented in a **pure-JVM module** and property-tested before any Android service class is written |
| 5 | The browser allowlist has a maintenance owner and an update path; a stale allowlist degrades to "no fill", never to "fill anyway" |

---

## 6. Tests required before Autofill ships

| Test | Asserts |
|---|---|
| `TargetMatchingTest` (JVM) | Certificate-hash matching accepts the genuine app and rejects a repackaged one with the same package name |
| `DomainVerificationTest` (JVM) | A web domain is honoured only when the reporting app is an allowlisted browser |
| `NoWebViewFillTest` (JVM) | A WebView in a non-browser app yields no offer |
| `NoValueBeforeAuthTest` (instrumented) | Every returned dataset requires authentication; **no response object ever contains a credential value** |
| `UnlockScopeTest` (instrumented) | An unlock for a fill does not open the main session or reset its auto-lock |
| `FingerprintResistanceTest` (instrumented) | The pre-authentication response is byte-identical whether the vault has 0, 1 or 20 matches |
| `NoAccessibilityServiceTest` (static) | The manifest declares no accessibility service and no compatibility mode |
| `OverlayGuardTest` (instrumented) | The authentication activity sets `FLAG_SECURE` and rejects obscured touches (`filterTouchesWhenObscured`) |
| `AssociationConsentTest` (instrumented) | An app-to-credential association is never created without the user seeing it |

---

## 7. Recommendation

**Defer.** Autofill should be built after the production-readiness review's Phase 3, not
before, and only once every precondition in §5 holds.

The reasoning is not that Autofill is unimportant — for many users it is the difference
between using a password manager and abandoning one. It is that Autofill's security depends
entirely on target matching, and target matching cannot be verified in a product that has
never run. Shipping it earlier would mean shipping the feature with the largest blast radius
on top of the layer with the least verification.

When it is built, §3.2 is the part to get right. Everything else in this document is
hygiene; matching is the security boundary.
