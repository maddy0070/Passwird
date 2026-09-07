# Passwird — Google Drive Integration

**Status:** v1 · **Last updated:** 2026-09-07

Drive's role in this product is narrow and unglamorous: **hold some bytes, tell us
when they changed, and refuse our write if someone else got there first.** It is a
courier. `DriveTransport` implements `VaultTransport` (`05-sync-architecture.md` §1)
and nothing above it knows Google exists.

---

## 1. Scopes

| Scope | Requested | Why |
|---|---|---|
| `openid`, `email` | Yes | Identity, and knowing which account a vault belongs to. |
| `drive.file` | Yes | Per-file access limited to files **this app created**. |
| `drive.appdata` | **No** | See §2. |
| `drive` (full) | **Never** | Wildly excessive. A Passwird compromise must not become a compromise of the user's entire Drive. |

`drive.file` is the narrowest scope that does the job. We cannot read, list or touch
anything else in the user's Drive — not their documents, not other apps' files. This
is enforced by Google, not by our good intentions.

---

## 2. Why not `appDataFolder`

`drive.appdata` looks like the obvious choice: a hidden per-app folder, invisible to
the user and to other apps, and a non-sensitive scope that eases OAuth verification.
We rejected it, and the reasoning is worth recording because the naive answer is wrong.

**Google deletes the `appDataFolder` contents when the user uninstalls the app.**

For a password manager that is a catastrophic failure mode. A user who uninstalls to
free space, or factory-resets, or switches phones the wrong way round, would find
their cloud copy silently destroyed at the exact moment they needed it. That directly
violates principle 1 (*never lose the user's data*), which outranks everything else.

The counter-argument for `appdata` is concealment. But concealment buys us very little
here: the file is **ciphertext**, and Google can see its metadata either way. We are
not relying on obscurity for confidentiality — `03-encryption-architecture.md` does
that work. Trading real durability for cosmetic hiding is a bad trade.

So: a **visible folder** the user can see, back up, copy to another cloud, or archive
to a USB stick. That is a feature. The user retains a portable, self-contained,
encrypted copy of their own vault that outlives our app, our company and their phone.

**Decision recorded in `adr/0003-drive-visible-folder.md`.**

---

## 3. Layout

```
Google Drive/
└── Passwird/
    ├── vault.pwv                 live encrypted vault
    ├── backups/
    │   ├── vault-000041.pwv      rolling generations, newest 10 kept
    │   └── vault-000040.pwv
    └── README.txt                plain text, for a human who finds this folder
```

`README.txt` is deliberate. A user browsing Drive in three years will find an opaque
binary file and wonder whether it is safe to delete. It reads, in plain language:
what this is, that it is encrypted and unreadable without their passphrase, that
deleting it does not delete their phone's vault, and how to restore. It contains no
secrets, no identifiers and no vault metadata.

### 3.1 Filename policy

Filenames leak. `vault.pwv` says only *"a Passwird vault exists"* — which the folder
name already says. Nothing else appears in any name: no email, no device name, no
counts, no dates beyond an opaque generation number.

---

## 4. Concurrency

Drive's `headRevisionId` is our generation token.

```
1. stat()  → headRevisionId = G
2. …decide, merge…
3. upload(bytes, expectedGeneration = G)
   ├─ current revision still G  → commit
   └─ current revision ≠ G      → reject → re-enter CHECKING (never overwrite)
```

Drive has no native compare-and-swap, so `DriveTransport` performs a re-`stat`
immediately before committing and aborts on mismatch. This narrows but does not fully
close the race window. The residual window is handled by the layer above: because
merging is *convergent* (§5 of the sync doc — commutative and idempotent), a lost race
produces a redundant merge on the next cycle, not data loss. We rely on the algebra,
not on the lock.

---

## 5. Upload protocol

Never write in place. In-place writes on a flaky mobile connection are how vaults get
truncated.

```
1. Serialise + encrypt locally.
2. Upload to  Passwird/.tmp-<random>.pwv   (resumable upload for >256 KiB)
3. Download it back and verify: magic, header parse, AEAD tag, vaultVersion.
   ── the round-trip verification is not optional ──
4. Copy the current live vault into backups/vault-<n>.pwv
5. Re-stat; abort if the generation moved.
6. Rename .tmp-<random>.pwv → vault.pwv   (atomic within Drive)
7. Prune backups beyond 10.
8. Update local watermark + last-seen generation.
```

Step 3 catches a class of failure that silent uploads miss entirely: a corrupted
transfer that Drive accepted. We would rather spend one extra round-trip than discover
the corruption on a new device six months later when it is the only copy left.

Failure at any step leaves the previous `vault.pwv` untouched and valid.

---

## 6. Error mapping

`DriveTransport` translates Google's error surface into the small typed vocabulary the
sync engine understands. The engine has no knowledge of HTTP.

| Condition | Typed error | User-facing behaviour |
|---|---|---|
| No connectivity | `Transport.Offline` | Silent. Status line shows *Offline*. |
| 401 / invalid token | `Transport.AuthExpired` | Silent refresh; on failure, quiet banner. |
| 403 `insufficientPermissions` | `Transport.PermissionDenied` | Explain and offer re-consent. |
| 403 `storageQuotaExceeded` | `Transport.QuotaExceeded` | Explicit, actionable. Local unaffected. |
| 403 `rateLimitExceeded` / 429 | `Transport.RateLimited` | Exponential backoff + jitter, invisible. |
| 404 on vault | `Transport.NotFound` | First run, or user deleted it → offer re-upload from local. |
| 5xx | `Transport.ServerError` | Backoff, retry, stay quiet until it persists. |
| Verification failed (step 3) | `Transport.CorruptUpload` | Abort, retain previous vault, retry once, then report. |

Every one of these degrades to *the app keeps working offline*. Not one of them blocks
the vault.

---

## 7. Account handling

- **Multiple accounts:** one active account at a time in v1. The vault is bound to a
  `vaultId`, not to an account, so switching account and re-uploading the same vault is
  a legitimate, supported operation.
- **Switching accounts:** never deletes the local vault. The app asks whether to upload
  the existing vault to the new account or look for a vault already there.
- **Sign-out:** clears tokens only. The local vault stays and remains fully usable
  offline. A sign-out that destroyed the vault would be a data-loss trap.
- **Revoked access:** detected on the next call; degrade to offline, offer re-consent.

---

## 8. What Google can and cannot see

Stated plainly, because onboarding shows the user a version of this table.

| Google can see | Google cannot see |
|---|---|
| That a folder named `Passwird` exists | Any password, username, note, URL or card number |
| The encrypted file's size, rounded up by padding | The number of items in the vault |
| When the file changed | Which items changed |
| That the account uses this app | The master passphrase or the recovery key |
| The `README.txt` (contains nothing sensitive) | Anything inside the ciphertext, ever |

The right-hand column is guaranteed by the encryption architecture, and asserted by
`CiphertextOnlyTest`, which fails the build if any known plaintext value appears
anywhere in the bytes we hand to the transport.
