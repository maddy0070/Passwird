# ADR-0009 — Recovery key as the floor, device-mediated authorization as the routine path

**Date:** 2026-09-08 · **Status:** Accepted (design only — implementation gated on this record)

## Context

Recovery is where password managers most often fail their users, in both directions: too
weak and the vendor can read the vault; too strict and a forgetful user loses everything.
With no server and a hostile-by-default storage provider, the admissible design space is
much smaller than the market suggests.

Three models were evaluated in full in `14-production-readiness-review.md` §D:

1. **Single user-custodied recovery key** — 128 bits, shown once, in a synced key slot.
2. **Threshold social recovery** — Shamir *k*-of-*n* shares held by trusted contacts.
3. **Device-mediated authorization** — an unlocked device admits a new one; the recovery
   key becomes the break-glass path rather than the routine one.

Anything involving escrow — email reset, security questions, vendor assistance, or Google
sign-in being sufficient — was excluded before evaluation. It is the first of the four
attack classes in the Feb 2026 ETH Zürich / USI study and rejecting it is the reason this
product exists.

## Decision

**Adopt model 3.** The recovery key remains exactly as designed and remains independently
sufficient; device-mediated authorization is layered on top as the path users actually take
when they get a new phone.

**Reject model 2** — not on cryptographic grounds, which are sound, but because
distributing and reconstructing shares wants a coordination service we deliberately do not
have.

## Rationale

The recovery key's failure mode is behavioural, not cryptographic. Users lose recovery keys
because they are asked to safeguard something for a product they have not yet learned to
trust, at the moment of least investment, for a purpose that sounds hypothetical.

Making the key the *break-glass* path rather than the *new-device* path lets onboarding say
something true and specific — "your other device can admit a new one; this key is for when
none can" — instead of something ceremonial. Honest explanations get acted on; ceremonies
get clicked through.

Critically, this does not weaken the floor. The recovery slot is untouched, still lives in
the synced vault, and still opens it alone. Every security property of model 1 survives.

## Consequences

- A device-to-device authorization protocol is now required. Designed in
  `14-production-readiness-review.md` §E; recorded separately as ADR-0010.
- Onboarding copy changes: the recovery key is framed by *when you will need it*, not as a
  ritual to complete before proceeding.
- **The unrecoverable case still exists and must be stated plainly.** Lose the passphrase,
  the recovery key, and every enrolled device, and the vault is gone. Onboarding says this
  in those words.
- No recovery *flow* may be implemented until this record is accepted. The recovery *codec*
  (`RecoveryKey.kt`) was built ahead of it deliberately — every candidate model needed it
  identically, so it carried no decision risk.
