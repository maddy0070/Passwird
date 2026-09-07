# ADR-0005 — No analytics, no crash reporting, no telemetry

**Date:** 2026-09-07 · **Status:** Accepted

## Context

Standard practice is to ship an analytics SDK and a crash reporter, with the reasoning
that you cannot improve what you cannot measure, and that crash reports are how you find
the bugs users never report.

Both arguments are real. They are also how a password manager leaks.

## Decision

**No telemetry of any kind in any build that reaches a user.** No analytics SDK, no
crash reporting SDK, no feature-flag service, no attribution SDK, no remote logging.

## Rationale

- Crash reports capture stack traces, and sometimes memory and local variables. In this
  app those can contain vault contents, key material, or a passphrase mid-derivation.
  Redaction is a promise; absence is a guarantee.
- "Anonymous" analytics in a single-user app still reveal usage patterns tied to a
  device identifier, and identifiers are more re-identifiable than they look.
- Every SDK is a supply-chain dependency with network access — the exact risk class of
  the April 2026 Bitwarden CLI compromise. An analytics SDK is a third party with a
  network channel inside our process.
- The brief's bar was *"prefer no analytics unless genuinely necessary"*. Nothing about
  a single-user offline vault makes it necessary. We would be adding it out of habit.
- The strongest privacy claim available is architectural: **there is no pipeline.**
  A policy can change silently; a missing dependency cannot.

## Consequences

- **Good:** the privacy claim in `11-privacy-model.md` §3 is verifiable by reading the
  dependency list, not by trusting us.
- **Good:** the complete list of network destinations is two entries long and auditable.
- **Bad:** we will not know our crash rate, retention, or which features are used. We
  accept this and find bugs the way software did before telemetry — thorough automated
  testing, and users reporting problems.
- **Bad:** no remote kill-switch or staged rollout. Mitigated by the store's own staged
  rollout, which requires nothing inside our process.

## Notes

There is deliberately **no** "share anonymous usage data" setting. A toggle would imply
a pipeline exists behind it. Adding one would require editing `11-privacy-model.md`
first — a visible, deliberate act rather than a quiet pull request.
