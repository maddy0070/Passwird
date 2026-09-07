# ADR-0007 — No certificate pinning for Google Drive

**Date:** 2026-09-07 · **Status:** Accepted

## Context

Certificate pinning is a common hardening measure for apps that talk to a known
backend, and it looks like an obvious win for a security-focused product.

## Decision

**No certificate pinning.** Use the platform's trust store and standard TLS validation.

## Rationale

**The payload is already end-to-end encrypted.** An attacker who fully breaks TLS to
Google obtains ciphertext. Pinning would protect a channel whose contents are already
protected by the layer above it. It is defence in depth for a threat that is already
mitigated.

Against that near-zero benefit sit real costs:

- **Pinning breaks apps.** Google rotates certificates and intermediates on their own
  schedule. A pin that goes stale bricks sync for every user until they update — and
  users cannot update if they are offline. For a product whose first principle is *never
  lose the user's data*, an unnecessary self-inflicted outage is a poor trade.
- **It breaks legitimate interception**, including corporate MITM proxies that some
  users are obliged to run. They would simply be unable to sync.
- **It does not stop the attacker we care about.** T5 is a *malicious Drive*, not a
  malicious network. Pinning the certificate of a store we already assume is hostile
  achieves nothing.

Google's own client libraries do not pin, for these reasons.

## Consequences

- **Good:** sync keeps working across certificate rotations without app updates.
- **Good:** one less thing that can break for users in constrained network environments.
- **Bad:** a device with an attacker-installed root CA can observe the TLS channel.
  What they observe is ciphertext plus what Drive already sees — file size and timing —
  so the marginal loss is negligible.
- **Note:** a device on which an attacker can install a root CA is largely a T4
  (compromised device) scenario, which `02-threat-model.md` §5 already states we cannot
  defend against.

## Revisit if

We ever transmit anything that is not already end-to-end encrypted. Today we do not,
and the design intends never to.
