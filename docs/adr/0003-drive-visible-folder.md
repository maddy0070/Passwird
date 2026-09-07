# ADR-0003 — Visible `drive.file` folder, not `appDataFolder`

**Date:** 2026-09-07 · **Status:** Accepted

## Context

Google Drive offers `appDataFolder` — a hidden, per-application folder, accessed with
the `drive.appdata` scope. It is invisible to the user and to other apps, and the scope
is classified non-sensitive, which eases OAuth verification. For "app stores its own
config in Drive" it is the intended and obvious answer.

## Decision

**Do not use `appDataFolder`.** Store the vault in a **visible** `Passwird/` folder
using the `drive.file` scope, which limits us to files this app created.

## Rationale

**`appDataFolder` contents are deleted when the user uninstalls the app.**

For a password manager that is a catastrophic failure mode. The user who uninstalls to
free space, factory-resets, or migrates phones in the wrong order would find their
cloud copy silently destroyed at precisely the moment it is the only copy left. That
violates principle 1 — *never lose the user's data* — which outranks every other
principle in this product.

The case *for* `appdata` is concealment. But concealment buys very little here:

- the file is ciphertext, and its confidentiality rests on the encryption architecture,
  not on obscurity;
- Google sees the file's existence, size and modification time either way;
- hiding it from the *user* is not a security property — it is a usability cost.

Trading real durability for cosmetic hiding is a bad trade.

A visible folder is additionally a genuine feature: the user can copy their encrypted
vault to another cloud, an external drive, or an archive. They retain a portable,
self-contained vault that outlives our app, our company and their phone. That is
consistent with §8 of the privacy model — a vault you cannot leave is a hostage.

## Consequences

- **Good:** the vault survives uninstall and reinstall; the user can back it up
  independently; no lock-in; recovery on a new device is straightforward.
- **Good:** `drive.file` is still narrow — we cannot read anything else in the user's
  Drive, enforced by Google rather than by our restraint.
- **Bad:** the user can see, move or delete the file. Mitigated by `README.txt` in the
  folder explaining in plain language what it is, that it is encrypted, and that
  deleting it does not affect the vault on their phone.
- **Bad:** a `Passwird/` folder reveals to anyone browsing the user's Drive that they
  use this app. Accepted, and noted in `06-drive-integration.md` §8 — Google already
  knows this from the OAuth grant.
- **Bad:** slightly heavier OAuth verification than a non-sensitive scope. Acceptable.

## Filename policy

Nothing beyond `vault.pwv` and opaque generation numbers. No email, device name, item
count or date appears in any filename.
