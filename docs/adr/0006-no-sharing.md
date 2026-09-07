# ADR-0006 — No vault sharing, in any form

**Date:** 2026-09-07 · **Status:** Accepted

## Context

Sharing a credential with a partner, a family member or a colleague is one of the most
requested password-manager features, and every major competitor offers it.

## Decision

**Passwird does not implement sharing.** No shared vaults, no shared items, no
send-a-secret link, no family plan, no organisations.

## Rationale

The Feb 2026 ETH Zürich / USI study identified **sharing features as one of four
principal attack classes** across every major cloud password manager it examined,
alongside key escrow, vault integrity and backwards compatibility. Several of the 27
demonstrated attacks escalated from a single shared item to **compromising every vault
in an organisation.**

Sharing is hard for structural reasons, not because vendors were careless:

- it requires public-key infrastructure and therefore key distribution and verification;
- key distribution needs a trusted directory — which reintroduces the server we
  deliberately do not have;
- revocation is not really possible (the recipient already had the plaintext);
- it creates a second, weaker path to the same secret;
- consent and provenance UI is genuinely difficult to get right.

A single-user product that never implements sharing is **structurally immune** to this
entire class. Not "hardened against" — immune, because the code does not exist.

This is a security decision recorded as such, not a feature we ran out of time for.

## Consequences

- **Good:** one whole attack class is out of scope by construction. No PKI, no key
  directory, no revocation semantics, no cross-user trust model.
- **Good:** the threat model stays small enough to reason about completely.
- **Bad:** users who need to share credentials must use something else for that job.
  Accepted.
- **Bad:** it forecloses a family/team tier and the business model that usually comes
  with it. Accepted — this product is a private vault.

## The escape hatch

Users who need to move a credential to another person can export a single item
(`11-privacy-model.md` §8) and transfer it however they judge appropriate. We do not
pretend this is secure sharing, and we do not dress it up as a feature. It is an
export, and it is labelled as one.
