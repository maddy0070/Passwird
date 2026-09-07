# Passwird — Information Architecture, Flows and Screen Inventory

**Status:** v1 · **Last updated:** 2026-09-07

---

## 1. Information architecture

Three destinations. Not five, not a drawer, not a hamburger.

```
┌─────────────┬─────────────┬─────────────┐
│    VAULT    │  GENERATE   │   SECURITY  │
└─────────────┴─────────────┴─────────────┘
      │              │              │
  the list      the generator   the review
  + search      (standalone)    + settings
```

**Why three.** Job 1 (retrieve) is ~10× more frequent than jobs 2 and 3
(`01-product-spec.md` §4), so the Vault tab is the app and the other two are places you
*go*. A generator deserves top-level placement because it is used *outside* the
context of saving an item at least as often as inside it — you need a password for
something you are signing up for in another app, right now.

**Security is a destination, not a greeting.** Opening a password manager to a wall of
red warnings is hostile design: it creates anxiety at exactly the moment the user
wanted one specific credential in nine seconds. Findings surface as a *single quiet
count* in the tab, and the user visits when they choose to.

### 1.1 The home screen is a retrieval surface

Top to bottom:

```
  ┌──────────────────────────────────────────┐
  │  Search                        ⟨sync⟩    │   always present, always first
  ├──────────────────────────────────────────┤
  │  RECENT                                  │   up to 4, only if genuinely recent
  │  ▪ Figma            you@…                │
  │  ▪ AWS root         admin                │
  ├──────────────────────────────────────────┤
  │  ALL ITEMS            127                │
  │  ▪ …                                     │
  └──────────────────────────────────────────┘
                                       ⊕ Add
```

No dashboard. No statistics tiles. No "welcome back". The search field is the first
thing under the thumb because searching is the job.

**Recents earn their place** by measurement, not by decoration: the median user
re-uses a small set of credentials, so a 4-item recents strip removes a search
interaction for the majority of retrievals. It is hidden entirely when there is
nothing genuinely recent, rather than showing a sad empty box.

---

## 2. Critical path: retrieve a credential

The path we optimise above all others. **Target: under 4 seconds.**

```
 App open ──► Unlock (biometric) ──► Home ──► Type 2–3 chars ──► Row ──► Copy
   0.3s            0.8s              0.1s        1.2s           0.2s    0.1s
                                                                  ≈ 2.7s
```

Design consequences that fall out of this budget:

- Biometric prompt fires **automatically** on launch — no "tap to unlock" tax.
- Search is focused-but-not-keyboard-raised on arrival: the field is ready, the
  keyboard appears on tap. (Auto-raising it would cover the recents strip, which is the
  faster path when the target is recent.)
- Search results update per keystroke, entirely in memory.
- **Copy is available from the list row.** The user does not have to open the item to
  get the password. This is the single largest time saving in the flow, and most
  competitors do not do it.
- Copy shows a countdown to auto-clear, so the security behaviour is visible rather
  than surprising.

---

## 3. First run

The most important flow in the product, because it is where trust and recoverability
are both established or lost.

```
1  WELCOME       "Your passwords stay on your phone."
                 One sentence. One illustration-free screen. Continue.

2  HOW IT WORKS  Three plain-language lines with a diagram:
                 · Your vault lives on this phone.
                 · A sealed copy goes to your Google Drive.
                 · Google cannot open it. Neither can we.
                 [What Google can and cannot see →]  ← expandable, honest table

3  SIGN IN       Google Sign-In.
                 "This is for storage and identity only — it is not the key
                  to your vault."   ← said here, before consent, not after

4  PASSPHRASE    Choose the passphrase that unlocks the vault.
                 · Live EntropyReadout with a stated attacker model
                 · Offered default: a generated 5-word passphrase, because
                   this is the largest residual risk in the whole design
                 · Confirm

5  RECOVERY KEY  24 characters, shown once.
                 [Copy] [Save to file] [Print]
                 ── then VERIFY: re-enter group 3 of 6 ──
                 Not a checkbox. An actual verification.

                 "If you forget your passphrase and lose this key, your vault
                  cannot be recovered — not by you, not by us, not by Google.
                  That is what makes it private."

6  BIOMETRICS    Optional, recommended, one tap. Explained honestly:
                 "Your fingerprint doesn't unlock the vault — it asks this
                  phone's security chip to do it for you."

7  READY         Straight into an empty vault with one clear next action.
```

**Design notes.**

Step 5 is where competitors lose users' data, so it is deliberately the least skippable
screen in the flow. There is no "remind me later" — that phrasing reliably means never,
and the consequence here is permanent.

Step 3 places the authentication/encryption distinction *before* the Google consent
screen, while the user is still forming their mental model. Explaining it afterwards is
too late; they have already concluded "so Google has my passwords".

Total: 7 screens, no account creation, no email verification, no plan selection, no
upsell. A user with a fingerprint reader is in their vault in under 90 seconds.

---

## 4. Unlock

| Case | Behaviour |
|---|---|
| Biometric enrolled | Prompt fires automatically on launch. Passphrase is an equal-weight alternative on the same screen — never hidden behind "more options". |
| Biometric fails ×3 | Fall back to passphrase, calmly: *"Use your passphrase instead."* No red, no alarm. |
| Biometric invalidated (new fingerprint enrolled) | Explain plainly what happened and why, then one-tap re-enrol behind the passphrase. This is a *guarantee working correctly*, and the copy says so — see `10-error-matrix.md` E-07. |
| Wrong passphrase | Inline, specific: *"That passphrase didn't match."* Attempt count shown from attempt 3. Never a modal. |
| Backoff engaged | Show remaining time and **state that no data has been lost or deleted** — the user's actual fear in that moment. |
| Recovery key path | Always reachable from the unlock screen, one tap, never buried. |

**No wipe-on-failure, ever.** See `04-key-management.md` §6.

---

## 5. Add and edit

Capture must not feel like filling in a form.

```
⊕ Add ──► Type picker (Login is pre-selected and one tap away)
       ──► Editor:  Title
                    Username        [use last]
                    Password        [Generate ▸]   ← generator is inline, not a detour
                    Website
                    ─────────────── hairline ───────────────
                    + Add field · + Tags · + Notes    ← progressive disclosure
       ──► Save
```

- The generator is **inline** in the password field. Leaving the editor to generate a
  password and coming back is a needless context switch.
- Optional fields are collapsed behind `+`. A login form that opens with eleven empty
  inputs communicates work; three inputs communicates ease.
- **Autosave draft.** A half-typed item survives a phone call, a backgrounding, or a
  process death. Losing a typed credential is unacceptable and entirely avoidable.
- Edit reuses the identical component tree; there is no separate "view mode" layout
  that shifts as you enter edit.

---

## 6. Item detail

```
   ▪  Figma                                        ★
      figma.com

      USERNAME
      you@example.com                        [copy]

      PASSWORD
      ••••••••••••••••••••            [reveal] [copy]
      ████████████████░░░░  78 bits · updated 4 months ago

      WEBSITE
      figma.com                              [open]

      ─────────────────────────────────────────────
      NOTES · TAGS · CUSTOM FIELDS
      ─────────────────────────────────────────────
      Created 12 Mar 2024 · Used 2 hours ago

                                  [Edit]  [⋯]
```

- Password masked on arrival, every time, without exception.
- Reveal does not persist across navigation or backgrounding.
- Strength and password *age* sit together, because they are read together when
  deciding whether to rotate.
- Destructive actions live under `⋯`, never adjacent to `copy`. A mis-tap must never be
  able to delete a credential.
- Delete is a two-step confirm naming the item, and produces a tombstone with a
  **10-second undo** in the toast.

---

## 7. Sync UX

Sync is ambient. It never blocks, never modals, never demands attention.

| State | Presentation |
|---|---|
| Synced | Small `signal` dot + *Synced*. Fades to a dot alone after 3s. |
| Syncing | Rotating hairline. No progress bar — it implies a duration we cannot honour. |
| Offline | *Offline · 3 changes waiting*. Neutral tone. Not an error; this is a supported mode. |
| Conflict merged automatically | *Merged 2 changes from your other phone* — a toast, dismissible, non-blocking. |
| Needs review | Persistent `attention` chip → **Review changes** screen showing both versions side by side, plain-language, user chooses. |
| Rollback / fork detected | Dedicated screen (§8). |
| Failed | `danger` chip; tapping explains and offers retry. Never auto-nags. |

**Review changes** is the screen that makes "never overwrite blindly" visible to the
user. Both values are shown with their origin device and time, and the user picks.
Nothing was lost while they decide.

---

## 8. Rollback / integrity screen

The rarest screen and the one that must be perfect. Deliberately calm.

```
   ⚠  The copy in Google Drive is older than expected.

   Your vault on this phone is intact and up to date.
   Nothing has been lost.

   This can happen if Drive restored an old version, or if
   someone replaced the file.

   Expected version 42 · Found version 39

   [ Upload my current vault ]        ← recommended
   [ Look at the Drive copy first ]   ← read-only inspection
   [ Not now ]
```

Answers the three questions from the error-handling brief, in order: **what happened,
what can I do, is my data safe.** The reassurance comes second because it is the
question the user is actually asking first.

---

## 9. Screen inventory

47 screens/states, all specified — no placeholders.

| # | Screen | Notes |
|---|---|---|
| **Onboarding** | | |
| 1–7 | Welcome · How it works · What Google sees · Sign-in · Passphrase · Recovery key + verify · Biometrics | §3 |
| 8 | Existing vault found | Alternate branch |
| 9 | Restore from recovery key | |
| **Unlock** | | |
| 10–14 | Biometric · Passphrase · Wrong passphrase · Backoff · Biometric invalidated | §4 |
| 15 | Recovery-key unlock | |
| **Vault** | | |
| 16 | Home / list | §1.1 |
| 17 | Empty vault | First-run, actionable, not decorative |
| 18 | Search active | |
| 19 | Search — no results | Offers *create "query"* |
| 20 | Filter by type / tag / folder | |
| 21 | Item detail | §6 |
| 22 | Item detail — revealed | |
| 23 | Add — type picker | |
| 24–25 | Editor — new / edit | §5 |
| 26 | Inline generator | |
| 27 | Delete confirm | |
| 28 | Tags manager | |
| 29 | Folders | |
| 30 | Favourites | |
| **Generate** | | |
| 31 | Generator — password | |
| 32 | Generator — passphrase | |
| 33 | Generator — history (session only, never persisted) | |
| **Security** | | |
| 34 | Security overview — counts, no score | |
| 35 | Weak passwords | |
| 36 | Reused passwords | |
| 37 | Ageing passwords | |
| 38 | Review changes (conflicts) | §7 |
| **Settings** | | |
| 39 | Settings root | |
| 40 | Auto-lock | |
| 41 | Sync & Drive | |
| 42 | Change passphrase | |
| 43 | Recovery key — rotate | |
| 44 | Devices | |
| 45 | Export / backup | |
| 46 | About & security summary | Threat model in plain language |
| **Exceptional** | | |
| 47 | Rollback / integrity | §8 |
| — | Corrupt vault · Drive permission lost · Quota exceeded · Migration failed · Storage full | `10-error-matrix.md` |

---

## 10. Empty states

Every empty state states what belongs here and offers the action. None are decorative.

| Where | Copy |
|---|---|
| Empty vault | *"Nothing here yet. Add your first credential, or generate a password to get started."* |
| No search results | *"No matches for 'figma'."* + `Create a login called "figma"` |
| No weak passwords | *"No weak passwords. 127 credentials checked."* — a genuine result, not a shrug |
| No conflicts | Section hidden entirely, not shown empty |
| Offline, never synced | *"Not backed up yet. Your vault is safe on this phone and will sync when you're online."* |
