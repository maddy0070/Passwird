# Passwird — Error State Matrix

**Status:** v1 · **Last updated:** 2026-09-07

Every error answers three questions, in this order:

1. **What happened** — in the user's language, never ours.
2. **What can I do** — at least one concrete action, always.
3. **Is my data safe** — stated explicitly whenever the answer could be in doubt.

Constraints on every string below: no error codes in the primary message, no stack
traces, no cryptographic jargon, no blame, no exclamation marks. Technical detail is
available behind *Details* for a user who wants it, and is scrubbed of secrets.

---

## Matrix

| ID | Condition | Presentation | Message | Actions | Data-safe statement |
|---|---|---|---|---|---|
| **E-01** | Wrong passphrase | Inline, under field | *That passphrase didn't match.* | Retry · Use recovery key | — (nothing at risk) |
| **E-02** | Too many attempts | Inline + timer | *Too many attempts. Try again in 2:00.* | Wait · Use recovery key | **Nothing has been deleted. Your vault is intact.** |
| **E-03** | Biometric hardware unavailable | Inline | *Fingerprint unlock isn't available on this device right now.* | Use passphrase | — |
| **E-04** | Biometric not enrolled | Inline | *No fingerprint is set up on this phone.* | Use passphrase · Open system settings | — |
| **E-05** | Biometric failed ×3 | Inline, neutral | *Use your passphrase instead.* | Passphrase | — |
| **E-06** | Device has no secure lock screen | Screen | *Fingerprint unlock needs a screen lock on this phone.* | Set up screen lock · Continue with passphrase | — |
| **E-07** | Biometric key invalidated (new fingerprint enrolled) | Screen | *Fingerprint unlock was turned off because a new fingerprint was added to this phone. That's a safety feature — it stops someone else's fingerprint from opening your vault.* | Enter passphrase to re-enable | **Your vault is untouched.** |
| **E-08** | Google sign-in cancelled | Inline | *Sign-in wasn't completed.* | Try again · Continue offline | — |
| **E-09** | Google sign-in failed | Inline | *Couldn't sign in to Google. This is usually a temporary network problem.* | Retry · Continue offline | **Your vault works without it.** |
| **E-10** | Drive permission denied / revoked | Banner | *Passwird no longer has permission to use your Google Drive.* | Reconnect · Keep using offline | **Your vault on this phone is unaffected.** |
| **E-11** | No connectivity | Status line only | *Offline · 3 changes waiting* | — (not an error) | — |
| **E-12** | Drive quota exceeded | Banner → screen | *Your Google Drive is full, so the sealed copy couldn't be updated.* | Free up space · Details | **All your changes are saved on this phone.** |
| **E-13** | Drive rate-limited / 5xx | Silent | — (backoff, invisible) | — | — |
| **E-14** | Vault not found in Drive | Screen | *No vault found in your Google Drive.* | Upload this phone's vault · Restore from recovery key | — |
| **E-15** | **Sync conflict — auto-merged** | Toast | *Merged 2 changes from your other phone.* | View changes | — |
| **E-16** | **Sync conflict — needs review** | Persistent chip → screen | *Two devices changed the same credential. Nothing was lost — pick the one you want to keep.* | Review changes | **Both versions are saved.** |
| **E-17** | **Rollback detected** | Dedicated screen | *The copy in Google Drive is older than expected.* (see `09-ux-flows.md` §8) | Upload current vault · Inspect Drive copy · Not now | **Your vault on this phone is intact and up to date.** |
| **E-18** | **Fork detected** (same version, different content) | Dedicated screen | *The copy in Google Drive doesn't match this phone's history.* | Keep mine · Inspect · Restore a backup | **Nothing on this phone has changed.** |
| **E-19** | Corrupt remote vault (tag failure) | Screen | *The sealed copy in Drive is damaged and couldn't be opened.* | Restore an earlier backup · Re-upload from this phone | **Your vault on this phone is fine and still works.** |
| **E-20** | Corrupt **local** vault | Screen, high severity | *The vault on this phone couldn't be opened.* | Restore from Drive · Restore local backup · Use recovery key | Honest: *"Your Drive copy is likely unaffected."* — never claim more than we know |
| **E-21** | Unsupported (newer) vault format | Screen | *This vault was made by a newer version of Passwird.* | Update the app | **Your vault is safe — this version just can't read it yet.** We never guess at a newer format. |
| **E-22** | Vault format too old / below KDF floor | Screen | *This vault uses older protection settings. Passwird will upgrade it after you unlock.* | Unlock to upgrade | **Nothing is lost in the upgrade.** |
| **E-23** | Migration failed | Screen | *Couldn't update the vault to the new format.* | Retry · Restore backup · Export raw file | **Your original vault file has been kept exactly as it was.** |
| **E-24** | Interrupted upload | Silent | — (temp discarded, retried) | — | — |
| **E-25** | Upload verification failed | Banner | *The upload didn't verify, so it wasn't published.* | Retry | **The previous sealed copy is still intact.** |
| **E-26** | Device storage full | Screen | *There isn't enough space on this phone to save your vault.* | Free space · Retry | **Your last saved vault is intact.** — we never partially write |
| **E-27** | Keystore unavailable / key invalidated | Screen | *This phone's security chip couldn't be reached.* | Use passphrase · Retry | **Your vault is unaffected.** |
| **E-28** | Encryption failure (unexpected) | Screen | *Something went wrong while sealing your vault. The change wasn't saved.* | Retry · Export unencrypted-to-nowhere is **not** offered | **Your previous vault is unchanged.** We fail closed. |
| **E-29** | Decryption failure after correct passphrase | Screen | *Your passphrase was right, but the vault data is damaged.* | Restore backup · Restore from Drive | Explains the distinction — this is why key commitment exists (`03` §1.2) |
| **E-30** | Clipboard unavailable | Toast | *Couldn't copy — this phone blocked clipboard access.* | Reveal and type manually | — |
| **E-31** | Root/integrity warning | One-time dialog | *This phone appears to be rooted. Passwird can't protect your vault from software with full access to the device.* | Continue · Learn more | Honest: this is **advisory and defeatable** — never presented as a guarantee |
| **E-32** | Autofill service disabled by OS | Inline | *Autofill is turned off for Passwird.* | Open settings | — |

---

## Notes on specific decisions

**E-02 / E-17 / E-19 / E-20 / E-23 / E-26 / E-28** all lead with a data-safety
statement. In every one of these moments the user's actual first thought is *"have I
lost my passwords?"* Answering an unasked question is bad writing; leaving *this* one
unanswered is bad design.

**E-20** is the only entry where we cannot fully reassure. The copy says what we know
("your Drive copy is likely unaffected") rather than what would comfort. Overclaiming
here would be exactly the kind of dishonesty principle 4 exists to prevent.

**E-28 fails closed.** When encryption fails we abandon the write. There is no path
anywhere in this product that responds to an encryption failure by storing plaintext,
and no fallback that degrades security to preserve a save.

**E-21 refuses to guess.** A client that half-understands a newer format and writes it
back is how vaults get silently truncated across devices. Refusing is the safe move.

**E-15 vs E-16** is the visible expression of *never overwrite blindly*: when the merge
is unambiguous we tell the user quietly; when it is ambiguous we keep both and ask.
There is no third branch where something is discarded.

---

## Copy rules

| Rule | Rationale |
|---|---|
| No error codes in the primary message | `Error 0x8007` communicates nothing and raises anxiety. Available under *Details*. |
| No "Oops" / "Uh oh" / exclamation marks | This product is calm. A vault that sounds panicked is not trustworthy. |
| Never blame the user | *"That passphrase didn't match"*, not *"You entered the wrong passphrase"*. |
| Never expose internals | No stack traces, no class names, no key ids, no file paths, no token fragments. |
| Always ≥1 action | An error with no action is a dead end. Even E-13 has an implicit one (wait). |
| Say "sealed copy", not "ciphertext" | The user's mental model is a sealed envelope, and that model is accurate. |
| Never say "fatal", "critical", "corrupted beyond repair" | Even when true, these produce panic rather than action. |
