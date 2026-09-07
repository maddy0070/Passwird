# Passwird — Sync Architecture

**Status:** v1 · **Last updated:** 2026-09-07

The sync engine is the part of this product most likely to lose a user's data, so it
is specified before it is written. Its prime directive:

> **Never blindly overwrite. When in doubt, keep both.**

A duplicate credential is an annoyance. A destroyed one is a catastrophe. Every
ambiguous case in this document resolves toward *keep more data*.

---

## 1. Layering

The UI must never touch Drive. The dependency direction is strictly downward:

```
  UI (Compose)
      ↓
  Application / domain use-cases
      ↓
  VaultRepository        ← the only thing the UI knows about
      ↓
  ┌──────────────┬──────────────────┬─────────────────┐
  │ Local store  │ Encryption layer │  Sync engine    │
  │ (encrypted)  │ (core:crypto)    │  (core:sync)    │
  └──────────────┴──────────────────┴────────┬────────┘
                                             ↓
                                    VaultTransport  ← interface
                                             ↓
                              ┌──────────────┴──────────────┐
                              │ DriveTransport  │ FakeTransport │
                              │ (Android)       │ (tests)       │
                              └─────────────────┴───────────────┘
```

`core:sync` is **pure Kotlin/JVM with no Android and no Google dependency**. It is
therefore fully unit-testable in CI without an emulator, which is how the conflict
matrix in §6 gets exhaustively exercised. `VaultTransport` is deliberately tiny:

```kotlin
interface VaultTransport {
    suspend fun stat(): RemoteStat?                              // generation token + size + mtime
    suspend fun download(): RemoteObject                         // bytes + generation
    suspend fun upload(bytes: ByteArray, expectedGeneration: String?): RemoteStat
    suspend fun listBackups(): List<BackupRef>
    suspend fun restoreBackup(ref: BackupRef): RemoteObject
}
```

`expectedGeneration` is the whole concurrency story: an upload that does not match the
generation the client last saw is rejected by the transport rather than clobbering.

---

## 2. The unit of sync

The vault is synced as **one encrypted artefact**, not per-record objects.

Per-record sync would leak the record count, per-record sizes and per-record edit
timing to Drive — significant metadata, and the padding scheme in
`03-encryption-architecture.md` §3.3 exists precisely to suppress that signal. A
single blob keeps Drive maximally ignorant.

The cost is that two devices editing different records still produce a whole-file
conflict. We pay that cost and solve it properly with a record-level three-way merge
*after* decryption (§5), which gives us the same outcome as per-record sync without
the metadata leak.

---

## 3. Sync state machine

```
   IDLE ──(connectivity | local edit | manual | app foreground)──► CHECKING
                                                                      │
                    ┌─────────────────────────────────────────────────┤
                    ▼                    ▼                   ▼        ▼
             REMOTE_NEWER          LOCAL_NEWER          DIVERGED    IN_SYNC
                    │                    │                   │        │
                    ▼                    ▼                   ▼        ▼
              DOWNLOADING            UPLOADING            MERGING    IDLE
                    │                    │                   │
                    └──────────┬─────────┴───────────────────┘
                               ▼
                        VERIFY ──fail──► ERROR (typed, recoverable)
                               │
                               ▼
                             IDLE
```

Classification uses the local watermark, the local dirty flag and the remote
generation token:

| Local dirty | Remote generation vs. last-seen | Classification |
|---|---|---|
| no | same | `IN_SYNC` |
| no | changed | `REMOTE_NEWER` → download, verify, adopt |
| yes | same | `LOCAL_NEWER` → upload with `expectedGeneration` |
| yes | changed | `DIVERGED` → **merge** (§5) |

Note that we never compare wall-clock timestamps to decide *what happened*. Clocks on
mobile devices are unreliable and attacker-influenceable. Timestamps are used only as
a tie-breaker of last resort inside field-level merge (§5.3), never for control flow.

---

## 4. Rollback protection

The defence against a hostile or buggy store serving stale-but-valid data.

- Every write increments `vaultVersion` monotonically.
- Each device persists `highestSeenVersion` in **encrypted local storage** — not in
  `SharedPreferences`, so clearing app cache cannot reset it.
- On every download:

```
if (remote.vaultVersion < highestSeenVersion) → REJECT: SyncError.RollbackDetected
if (remote.vaultVersion == highestSeenVersion && remote.headerHash != lastHeaderHash)
                                               → REJECT: SyncError.ForkDetected
```

- `header.chain` links each version to `SHA-256(previous header)`. A rewritten history
  fails chain validation even if the counters look plausible.

A rollback is **never** auto-resolved. It surfaces as an explicit, calm screen: what
we expected, what we received, that the local vault is intact and authoritative, and
two choices — re-upload the local version, or inspect the remote one read-only. The
local vault is never replaced by a rejected download.

This is the concrete answer to the "vault integrity" class in the Feb 2026 ETH Zürich
/ USI results, where clients accepted whatever the server handed them.

---

## 5. Merge

Runs on **decrypted** documents, in memory, entirely inside `core:sync`.

### 5.1 Inputs

Three-way merge needs a common ancestor. Each device retains the last **common base**
document — the last state it knows both sides agreed on — in encrypted local storage.
Without a base we can only guess; with it we can tell "A changed it" from "B deleted
it".

```
base      = last mutually-known state
local     = current local document
remote    = decrypted downloaded document
```

If the base is missing (fresh install, corruption), we degrade to a **conservative
two-way union**: keep every record from both sides, and where ids collide and content
differs, keep both as a conflict pair. Never silently pick a winner without a base.

### 5.2 Record-level rules

Records are keyed by a stable UUID assigned at creation, never by title or URL.

| base | local | remote | Result |
|---|---|---|---|
| — | new | — | keep local |
| — | — | new | keep remote |
| — | new A | new B (same id) | impossible in practice (random UUIDs); if seen, keep both |
| X | X | X | unchanged |
| X | X′ | X | local edit wins |
| X | X | X′ | remote edit wins |
| X | X′ | X″ | **field-level merge** (§5.3) |
| X | deleted | X | tombstone wins → deleted |
| X | X | deleted | tombstone wins → deleted |
| X | X′ | deleted | **resurrect and flag** — an edit beats a delete |
| X | deleted | X′ | **resurrect and flag** — symmetric |
| X | deleted | deleted | deleted |

The two "resurrect" rows are the heart of the prime directive. Standard
last-writer-wins would delete a record the user was actively editing on another
device. We instead keep it, mark it `needsReview`, and show it in a **Review changes**
surface. The user adjudicates; the algorithm does not.

### 5.3 Field-level merge

When both sides edited the same record:

1. Fields changed on only one side: take that side.
2. Fields changed on both sides to the *same* value: no conflict.
3. Fields changed on both sides to *different* values: keep both. The record retains
   the higher-`revision` value as current and stores the loser in
   `conflicts: List<FieldConflict>`, surfaced in the UI as *"This was also changed on
   your other device — keep this one or that one?"*

**The password field never auto-resolves.** If a password differs on both sides, both
are preserved and the user is asked. Guessing wrong here locks someone out of a real
account.

Each record carries a `revision` counter and an `originDeviceId`; `(revision,
originDeviceId)` gives a deterministic, clock-independent ordering that is identical on
every device — so all devices converge on the same result without needing to agree on
time.

### 5.4 Tombstones

Deletions are tombstones (`id`, `deletedAt`, `revision`), retained **180 days** and
then reaped. Retention must exceed the longest plausible offline period; a device
offline for six months that syncs after reaping would resurrect its deleted records,
which is annoying but not destructive — the correct side of the trade.

---

## 6. Conflict test matrix

`core:sync` tests enumerate the full cross-product:

- {no change, edit, delete, create} × {no change, edit, delete, create}
- with and without a common base
- single-field and multi-field edits
- concurrent edits to the same field
- tombstone vs. edit in both directions
- three-device chains (A→B→C) asserting eventual convergence
- **property test:** merge is commutative — `merge(base, l, r)` ≡ `merge(base, r, l)`
- **property test:** merge is idempotent — merging a merged result changes nothing
- **property test:** no record present in `local` or `remote` is ever absent from the
  result unless a tombstone explicitly covers it *(the data-loss invariant)*

That last property is the single most valuable test in the repository.

---

## 7. Failure handling

| Failure | Behaviour |
|---|---|
| Interrupted upload | Upload to a temporary object; verify; then atomic swap. A partial upload can never become the live vault. |
| Interrupted download | Discard; local vault untouched. Retry with backoff. |
| Corrupted remote (tag failure) | Never adopted. Offer restore from a Drive backup generation (§8). Local vault remains authoritative and fully usable. |
| Generation mismatch on upload | Rejected by transport → re-enter `CHECKING` → merge → retry. Bounded to 5 attempts, then ask the user. |
| Offline | Queue a dirty flag. No spinner, no nag, no modal. The status line reads *Offline · 3 changes waiting*. |
| Auth expired | Refresh; on hard failure, degrade to offline mode with a single quiet banner. |
| Drive quota exhausted | Explicit, actionable error. Local vault unaffected. |
| Clock skew | Irrelevant by construction — see §3. |

### 7.1 Pre-merge safety snapshot

Before *any* merge writes to local storage, the current local vault is snapshotted to
an encrypted local backup. If a merge produces something the user rejects, one tap
restores the pre-merge state. This is principle 1 from the product spec expressed as
code.

---

## 8. Versioning and backups

Drive keeps the live vault plus a rolling set of prior generations written by us:

```
vault.pwv                    live
backups/vault-<n>.pwv        last 10 generations, each a complete encrypted vault
```

Backups are full vaults, not deltas — a delta chain has a single point of failure and
we would rather spend the bytes. All are encrypted identically; a backup is exactly as
opaque to Drive as the live vault.

Restoring is explicit, never automatic, and always previews *what will change* — a
decrypted diff summary (n added, n removed, n modified) shown before the user commits.

---

## 9. Triggers

Sync is attempted on: connectivity regained, app foreground, local edit (debounced
~10 s to coalesce rapid edits), manual pull-to-refresh, and a periodic background
check. All are best-effort. **The app never blocks on sync**, ever, including at
first launch after install — the local vault is always the source of truth for the UI.
