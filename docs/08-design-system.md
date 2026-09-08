# Passwird — Design System: “Quiet Precision”

**Status:** v1 · **Last updated:** 2026-09-07

---

## 1. The idea

> **A precision instrument that never raises its voice.**

A vault is not an app you enjoy. It is an app you *trust*, use for nine seconds, and
close. So the interface should behave like a well-made instrument: dense where it
needs to be, silent everywhere else, and absolutely predictable.

Three convictions drive every token below:

**1. Structure, not containers.**
Most password managers are a stack of rounded cards floating on grey. Cards add two
edges, a shadow and a radius to communicate one thing: *these items are separate*. A
hairline does that with one pixel. We build hierarchy from **rules, spacing and
luminance** — never from floating boxes. There is no card component in this system.

**2. Colour is vocabulary, not decoration.**
The interface is monochrome. Colour appears only where it *means* something: sealed,
attention, danger. Because the field is grey, one small mark of colour is unmissable —
which is exactly the property a security interface needs. Consequence: our primary
button is near-white, not brand-coloured. The brand does not need to be on the button.

**3. Numbers are read, not glanced at.**
Passwords, keys, codes and counts get a monospaced face with disambiguated glyphs.
`0` vs `O` and `1` vs `l` vs `I` is a *functional* requirement when someone is reading
a password aloud or typing it into a console — not a stylistic one.

### 1.1 What this rules out

Stated explicitly so the system can be enforced in review:

no Material components in default dress · no elevation shadows in dark · no gradient
fills · no glassmorphism · no rounded-rect-everything · no icon-only controls without
labels · no decorative illustration · no more than one accent hue on screen · no
colour-only state · no animation that does not report a state change.

---

## 2. Colour

Near-monochrome, cool, low-chroma. Dark is the primary theme; light is a first-class
peer, not an afterthought.

### 2.1 Dark (primary)

| Token | Value | Use |
|---|---|---|
| `ground` | `#0A0C0E` | App background. Not pure black — pure black smears on OLED during scroll and crushes the hairlines. |
| `surface` | `#101317` | Sheets, elevated regions |
| `surfaceRaised` | `#161A1F` | Menus, dialogs, pressed rows |
| `surfaceSunken` | `#07090B` | Input wells, code blocks |
| `line` | `#232830` | Default hairline (1dp) |
| `lineStrong` | `#333A44` | Section boundaries. **Decorative only** — below 3:1 by design |
| `borderInteractive` | `#606771` | Control boundaries, focused inputs, selected chips (≥3:1) |
| `textPrimary` | `#E8EBEE` | Body, values |
| `textSecondary` | `#9BA3AD` | Labels, metadata |
| `textTertiary` | `#7A838F` | Placeholders, timestamps, disabled |
| `signal` | `#5FD0BC` | **Sealed / encrypted / synced only** |
| `signalDim` | `#2A5F58` | Signal at rest, borders |
| `attention` | `#E8B166` | Weak, reused, ageing, needs review |
| `danger` | `#E8776B` | Destructive, failed, tampered |
| `focusRing` | `#A8C7FA` | Keyboard/switch-access focus |

### 2.2 Light

| Token | Value |
|---|---|
| `ground` | `#F6F6F4` — warm paper, not clinical white |
| `surface` | `#FFFFFF` |
| `surfaceSunken` | `#EFEFEC` |
| `line` | `#E0E1DD` |
| `lineStrong` | `#C6C8C2` — decorative only |
| `borderInteractive` | `#878983` |
| `textPrimary` | `#14171A` |
| `textSecondary` | `#485059` |
| `textTertiary` | `#646C76` |
| `signal` | `#1B7F6E` (darkened for contrast on light) |
| `attention` | `#9A6414` |
| `danger` | `#B23B2E` |

### 2.3 Rules

- **Never state-by-colour-alone.** Every coloured state carries an icon *and* a word.
  A colour-blind user, a user in bright sunlight, and a screen-reader user all get the
  same information. This is a hard review gate, not a guideline.
- `signal` is reserved. It marks *sealed, synced, verified*. Using it for a generic
  button or a decorative highlight destroys its meaning and is a review failure.
- Contrast floor: **4.5:1** for all text including `textTertiary` at its intended
  sizes; **3:1** for borders and icons carrying meaning. Enforced by
  `scripts/check-contrast.py`, which parses `Color.kt` itself — 56 pairs across both
  palettes, run in CI. Not by eye.
- One accent per screen. If two things are coloured, one of them is wrong.

> **Corrected 2026-09-08.** The floors above were previously attributed to a `ContrastTest`
> that did not exist, so the commitment was never actually checked. When the check was
> written, **six pairs failed**:
>
> | Pair | Was | Floor |
> |---|---|---|
> | `textTertiary` on `ground` (dark) | 4.14:1 | 4.5:1 |
> | `textTertiary` on `surface` (dark) | 3.93:1 | 4.5:1 |
> | `textTertiary` on `ground` (light) | 3.06:1 | 4.5:1 |
> | `textTertiary` on `surface` (light) | 3.31:1 | 4.5:1 |
> | `lineStrong` on `ground` (dark) | 1.71:1 | 3:1 |
> | `lineStrong` on `ground` (light) | 1.56:1 | 3:1 |
>
> These were defects, not stale documentation. `textTertiary` renders field labels and
> placeholders — essential content under WCAG 1.4.3 — and `lineStrong` was the *only*
> boundary of the transparent-filled `SecondaryButton`, which 1.4.11 covers.
>
> The fix: `textTertiary` moved to clear 4.5:1 against all four surfaces (not just the two
> the first draft of the check tested — placeholders sit on `surfaceSunken`, the worst case
> in light mode, which the original pair list missed). Light `textSecondary` moved with it
> to keep three visibly distinct steps. The interactive uses of `lineStrong` were split into
> the new `borderInteractive`; `lineStrong` itself stays quiet and is now documented as
> decorative, which is the exemption WCAG actually grants it.

---

## 3. Typography

**IBM Plex Sans** (UI) + **IBM Plex Mono** (secrets and technical values). Both OFL,
both bundled — no network fetch, no Google Fonts call at runtime.

Chosen over Inter (ubiquitous, characterless here) and Roboto (reads as stock
Android, which the brief forbids). Plex has engineering provenance and genuinely
disambiguated glyphs, which we need functionally.

| Token | Face | Size / line | Tracking | Use |
|---|---|---|---|---|
| `displayL` | Plex Sans Light 300 | 32 / 38 | −0.02em | Unlock screen, empty states |
| `titleL` | Plex Sans Regular | 22 / 28 | −0.01em | Screen titles |
| `titleM` | Plex Sans Medium | 17 / 24 | 0 | Item titles, section heads |
| `body` | Plex Sans Regular | 15 / 22 | 0 | Body |
| `bodyS` | Plex Sans Regular | 13 / 18 | 0 | Metadata |
| `label` | Plex Sans Medium | 11 / 14 | **+0.08em**, uppercase | Field labels |
| `mono` | Plex Mono Regular | 15 / 22 | 0 | **Passwords, keys, codes** |
| `monoS` | Plex Mono Regular | 12 / 16 | +0.02em | Entropy, technical detail |
| `numeric` | Plex Sans Regular, `tnum` | 15 / 22 | 0 | Counts, ages |

Rules:

- Tabular figures (`tnum`) wherever numbers can change in place, so digits do not
  reflow and the eye can stay put.
- Exactly two weights in UI text (Regular 400, Medium 500). Light 300 appears only at
  `displayL`. Bold is not in the system.
- The uppercase `label` with wide tracking is the system's signature texture — it does
  the work a card border would otherwise do.
- **Full support to 200% text scale.** No fixed-height text containers anywhere.

---

## 4. Space and grid

**4dp base.** Scale: `2, 4, 8, 12, 16, 20, 24, 32, 40, 48, 64`. Nothing off-scale.

| Token | dp | Use |
|---|---|---|
| `gutter` | 20 | Screen horizontal margin |
| `rowV` | 14 | List row vertical padding |
| `sectionGap` | 32 | Between sections |
| `fieldGap` | 16 | Between form fields |
| `touchMin` | **48** | Minimum touch target, always |

Rows are optically aligned, not mathematically: icon column 40dp, 12dp gap, content
column flush, trailing affordance 48dp. Every row in the app shares this template so
the eye tracks a single vertical rhythm down the entire product.

---

## 5. Shape and elevation

| Token | Value |
|---|---|
| `radiusNone` | 0 — structural containers, sections, rows |
| `radiusS` | 4 — buttons, inputs, chips, menus |
| `radiusM` | 8 — sheets, dialogs (top corners only for sheets) |
| `radiusFull` | pill — **only** the sync status indicator |
| `hairline` | 1dp `line` |

**Dark theme has no shadows.** Elevation is expressed by surface luminance
(`ground` → `surface` → `surfaceRaised`) plus a hairline. Shadows on near-black are
muddy and fake. Light theme uses one soft shadow for sheets and dialogs only —
`0 8 24 rgba(20,23,26,0.10)`.

The near-square geometry is the most visible break from category convention and it is
deliberate: squared edges read as precise and built; 16dp-rounded everything reads as
soft and generic.

---

## 6. Motion

Motion reports state. Nothing moves for pleasure.

| Token | ms | Easing | Use |
|---|---|---|---|
| `instant` | 0 | — | Reveal/mask toggles — must feel like a switch, not a fade |
| `quick` | 120 | `cubic-bezier(0.2,0,0,1)` | Press, hover, checkbox |
| `base` | 180 | `cubic-bezier(0.2,0,0,1)` | Row expand, chip select |
| `considered` | 260 | `cubic-bezier(0.2,0,0,1)` | Sheets, screen transitions |
| `deliberate` | 420 | `cubic-bezier(0.35,0,0.15,1)` | **Unlock and lock only** |
| `exit` | 140 | `cubic-bezier(0.4,0,1,1)` | Dismissals |

### 6.1 The one signature moment

Unlock gets `deliberate` (420ms) and nothing else does. On success the lock mark
resolves once — a single considered motion, no bounce, no spring, no particles —
and the vault content arrives beneath it with a 60ms stagger across the first six
rows. It should feel like a well-machined mechanism releasing: weighty, brief, final.

That is the entire animation budget for the product's identity. Everything else is
functional feedback measured in 120–180ms.

### 6.2 Reduced motion

`Settings.Global.TRANSITION_ANIMATION_SCALE == 0` or the accessibility preference ⇒
every transition becomes a **100ms opacity crossfade**; no translation, no scale, no
stagger. Unlock still confirms, via an instant state change plus haptic. Reduced
motion never removes *information*, only movement.

### 6.3 Haptics

Sparse and meaningful: unlock success (single confirm), copy-to-clipboard (light tick),
destructive confirm (double), sync failure (single warn). Nothing else vibrates.

---

## 7. Iconography and the generated mark

**Icons:** custom set, 24dp grid, **1.5dp stroke**, square cap, square join, no fills.
The squared terminals match the shape language. No third-party icon pack — a mixed
icon set is the fastest way to look unfinished.

**The generated mark** — our answer to logos-without-surveillance
(`01-product-spec.md` §6). For any domain without a bundled icon we render a
deterministic mark computed **entirely offline**:

- hue = `SHA-256(registrableDomain)` mapped onto a **12-stop curated wheel** (all stops
  pre-checked for contrast against both grounds — never a raw hue, which produces
  muddy or neon results);
- chroma is fixed and low, so marks sit quietly in a list;
- glyph = 1–2 characters from the domain, Plex Sans Medium, optically centred;
- shape = `radiusS` square, matching the system.

Same domain ⇒ same mark on every device, forever, with zero network traffic. The list
looks *composed* rather than broken, and no third party learns which services the user
holds accounts with.

---

## 8. Component inventory

Every component ships with all applicable states:
`default · hover · pressed · focused · selected · disabled · loading · error · empty`.

| Group | Components |
|---|---|
| Actions | `PrimaryButton` (near-white fill), `SecondaryButton` (hairline), `TextButton`, `DestructiveButton`, `IconButton` (always labelled), `RevealToggle`, `CopyButton` |
| Inputs | `TextField`, `SecretField`, `SearchField`, `Stepper`, `Toggle`, `SegmentedControl`, `TagInput`, `PassphraseField` |
| Structure | `Section`, `HairlineDivider`, `ItemRow`, `FieldRow`, `MetaRow`, `Sheet`, `Dialog`, `Menu` |
| Status | `SyncIndicator`, `SecurityBadge`, `EntropyReadout`, `Toast`, `Banner`, `EmptyState`, `ErrorState`, `LockedState` |
| Vault | `GeneratedMark`, `ItemTypeGlyph`, `TagChip`, `StrengthReadout`, `ClipboardCountdown` |

### 8.1 `SecretField` — the most security-critical component

Masked by default, always. Rendered in `mono`. Reveal is press-and-hold *or* toggle,
never automatic. Revealed state is **not** preserved across navigation or
backgrounding. Copy sets `EXTRA_IS_SENSITIVE` so the OS suppresses the clipboard
preview, then starts a visible countdown to auto-clear. When revealed, the character
groups are spaced in fours with digits and symbols tinted at `textSecondary` — reading
a 20-character password aloud is a real task this component is designed for.

### 8.2 `StrengthReadout` — no five-bar meter

```
   ████████████████░░░░   78 bits
   ~2 million years at 100 billion guesses/sec
```

A continuous entropy bar (not five discrete segments), the number in `monoS`, and a
plain-language consequence **with the assumed attack rate stated** — because a strength
claim without an attacker model is meaningless. For generated passwords the figure is
*computed exactly* from the generator's own configuration; for typed passwords it is
labelled *estimated*. We never render a precise-looking number we cannot defend.

### 8.3 `SyncIndicator`

The only `radiusFull` element in the system, and the only persistent status surface.
Six states, each with **glyph + word + colour**, never colour alone:

`Synced` (signal) · `Syncing` (rotating hairline) · `Offline · n waiting` (tertiary) ·
`Merging` (attention) · `Needs review` (attention) · `Failed` (danger).

It never blocks, never modals, never nags.

---

## 9. Accessibility

Not a checklist at the end — several of these decisions already shaped the tokens above.

| Requirement | Implementation |
|---|---|
| Screen readers | Every control has an explicit `contentDescription`. Secret fields announce *"password, hidden"* / *"password, shown"* and **never** read out the value unless explicitly revealed. |
| State without colour | Enforced: every coloured state pairs with a glyph and a word. |
| Text scale | Full function to 200%. No fixed-height text containers. Verified at 100/130/160/200%. |
| Touch targets | 48dp minimum, always, including the reveal and copy controls that are commonly undersized in this category. |
| Focus | Visible 2dp `focusRing` on every focusable element; logical order; full keyboard/switch-access traversal. |
| Reduced motion | §6.2. |
| Contrast | 4.5:1 text, 3:1 meaningful non-text, asserted by test over the token table. |
| Colour vision | The palette is near-monochrome, so the three semantic hues are maximally separable; `signal`/`attention`/`danger` are additionally distinct in luminance, so they differ in greyscale too. |

---

## 10. Enforcement

Tokens are **code**, not a PDF. `design/tokens` exposes them as typed Kotlin; the
Compose layer reads only from the token objects.

CI review gates:

- no raw `Color(0x…)` outside `design/tokens` — grep gate;
- no `dp` literal off the spacing scale in UI code — lint rule;
- no `androidx.compose.material3` component used in default dress — import gate;
- contrast test over the token table;
- every component has a state-coverage preview.

A design system that is not enforced by the build is a suggestion.
