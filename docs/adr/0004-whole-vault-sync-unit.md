# ADR-0004 — Sync the whole vault as one blob; merge after decryption

**Date:** 2026-09-07 · **Status:** Accepted

## Context

Two shapes for a syncing encrypted vault:

**A. Per-record objects** — each credential is its own encrypted object in Drive. Only
changed records upload; conflicts are naturally per-record.

**B. Single artefact** — the whole vault is one encrypted file. Any change re-uploads
everything; any concurrent change is a whole-file conflict.

## Decision

**Option B**, with a record-level three-way merge performed **after decryption**, in
memory, on the device.

## Rationale

Per-record sync leaks a lot to the storage provider, and the leak is *structural* — it
survives any amount of encryption of the record contents:

- the number of records in the vault;
- the size of each record;
- **which** record changed, and when;
- edit frequency per record, from which usage patterns follow.

Under threat model T5 (hostile store), that is a rich side channel. "You edited the
2 KB record you also touched last Tuesday, ten minutes after visiting your bank" is
inferable without decrypting a single byte. It also renders the size-bucket padding in
`03-encryption-architecture.md` §3.3 pointless, since per-record sizes would be exposed
anyway.

A single padded blob reduces what Drive learns to: a file exists, it is roughly this
big, it changed at this time. Nothing about the contents or the shape of the change.

The obvious cost — two devices editing *different* records still conflict at the file
level — is fully recoverable, because we decrypt both sides on-device and merge at the
record level anyway. We get per-record merge semantics *without* per-record metadata
exposure. The cost is bandwidth, not correctness.

## Consequences

- **Good:** minimal metadata leakage; padding actually works; one artefact to reason
  about, verify, back up and export.
- **Good:** the merge runs on plaintext we already hold, so it can be as sophisticated
  as we like (field-level, conflict-preserving) without any server cooperation.
- **Bad:** every change re-uploads the whole vault. At realistic sizes (a 500-item vault
  is well under 1 MB) this is a non-issue; uploads are debounced ~10s to coalesce rapid
  edits.
- **Bad:** a large vault on a metered connection costs more bytes. Accepted; revisit only
  if real vaults exceed a few MB.
- **Bad:** whole-file conflicts are more frequent than per-record ones, so the merge path
  is exercised constantly. Mitigated — and arguably improved — by the merge being
  property-tested for commutativity, idempotence and the data-loss invariant. A rarely
  exercised merge path is more dangerous than a common one.
