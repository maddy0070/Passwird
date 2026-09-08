package com.passwird.sync

/**
 * Publishing a vault to a remote object store, safely.
 *
 * ### The failure this exists to prevent
 *
 * The original Drive publish ended with two calls in this order:
 *
 * ```
 * delete(vault.pwv)          // the live vault is now gone
 * rename(temp -> vault.pwv)  // ...and only now does its replacement appear
 * ```
 *
 * Between them, **no object named `vault.pwv` exists**. A process death, a dropped
 * connection or an expired token in that window leaves the store with no live vault — and
 * `VaultRepository.unlock` maps a missing vault to `NoVault`, which is the signal onboarding
 * uses to offer to create a *new* one. A user could then create a fresh vault over the top
 * of their real one, and the real one would be reachable only by someone who knew to look in
 * `backups/`.
 *
 * That is a data-loss path with no error message, reported as §F-2 of
 * `14-production-readiness-review.md`.
 *
 * ### The fix
 *
 * Two independent defences, because either alone can be defeated:
 *
 * 1. **The live name is never unclaimed.** The existing vault is *renamed aside* rather than
 *    deleted, so at every instant between the first and last operation there is either a
 *    `vault.pwv` or a `superseded-*.pwv` — usually both.
 * 2. **`Empty` has to be earned.** [probe] reports [RemoteVaultState.Interrupted] when the
 *    live object is missing but any evidence of a vault remains, so a caller cannot mistake
 *    a half-finished publish for a new user.
 *
 * This lives in `core:sync` rather than in the Drive transport so the sequence can be tested
 * against a store that fails at each step in turn. The bug it fixes is a bug of *ordering*,
 * and ordering is exactly what an Android-only class cannot demonstrate here.
 */
object VaultPublisher {

    const val LIVE_NAME: String = "vault.pwv"
    const val TEMP_PREFIX: String = ".tmp-"
    const val SUPERSEDED_PREFIX: String = "superseded-"
    const val BACKUP_PREFIX: String = "backup-"

    /**
     * Publishes [bytes] as the live vault.
     *
     * @param verify called with the staged bytes read back from the store. Returning false
     *   aborts the publish with the previous vault untouched.
     */
    suspend fun publish(
        store: ObjectStore,
        bytes: ByteArray,
        uniqueSuffix: String,
        verify: (ByteArray) -> Boolean = { it.contentEquals(bytes) },
    ): PublishResult {
        val tempName = "$TEMP_PREFIX$uniqueSuffix.pwv"
        val supersededName = "$SUPERSEDED_PREFIX$uniqueSuffix.pwv"

        // 1. Stage. Nothing observable has changed yet, so a failure here costs nothing.
        store.put(tempName, bytes)

        try {
            // 2. Read back. Catches a transfer the store accepted but mangled — the failure
            //    that otherwise stays invisible until the vault is the only copy left.
            val readBack = store.read(tempName)
            if (readBack == null || !verify(readBack)) {
                store.delete(tempName)
                return PublishResult.VerificationFailed
            }

            val live = store.read(LIVE_NAME)
            if (live != null) {
                // 3. Archive, so a rollback has somewhere to roll back to.
                store.put("$BACKUP_PREFIX$uniqueSuffix.pwv", live)

                // 4. Move the live vault aside rather than deleting it. This is the whole
                //    fix: the name is handed from one object to another, and at no point is
                //    it unclaimed by anything.
                store.rename(LIVE_NAME, supersededName)
            }

            // 5. Claim the live name.
            store.rename(tempName, LIVE_NAME)

            // 6. Only now, with the new vault live and verified, drop the old one.
            store.delete(supersededName)

            return PublishResult.Published
        } catch (error: Throwable) {
            // Leave every intermediate object in place. They are what [probe] reads to tell
            // "interrupted" from "new user", and deleting them to tidy up would recreate the
            // exact failure this class exists to prevent.
            throw error
        }
    }

    /**
     * What the store actually holds.
     *
     * The distinction between [RemoteVaultState.Empty] and [RemoteVaultState.Interrupted] is
     * the second defence. `Empty` means *no vault has ever existed here*, and it is the only
     * state in which offering to create one is safe.
     */
    suspend fun probe(store: ObjectStore): RemoteVaultState {
        val names = store.list()

        if (LIVE_NAME in names) return RemoteVaultState.Present

        val evidence = names.filter {
            it.startsWith(TEMP_PREFIX) ||
                it.startsWith(SUPERSEDED_PREFIX) ||
                it.startsWith(BACKUP_PREFIX)
        }
        return if (evidence.isEmpty()) {
            RemoteVaultState.Empty
        } else {
            RemoteVaultState.Interrupted(evidence.sorted())
        }
    }

    /**
     * Restores the live vault after an interrupted publish.
     *
     * Prefers the superseded original over the staged replacement. That looks backwards and
     * is deliberate: the superseded object is the vault the user had, already verified and
     * already synced. The staged object may be a write that never completed. Recovering to
     * the known-good state and re-syncing costs one upload; recovering to an unverified one
     * could cost an edit.
     */
    suspend fun recover(store: ObjectStore): RecoveryResult {
        val names = store.list()
        if (LIVE_NAME in names) return RecoveryResult.NothingToDo

        val superseded = names.filter { it.startsWith(SUPERSEDED_PREFIX) }.maxOrNull()
        if (superseded != null) {
            store.rename(superseded, LIVE_NAME)
            return RecoveryResult.RestoredFromSuperseded(superseded)
        }

        val staged = names.filter { it.startsWith(TEMP_PREFIX) }.maxOrNull()
        if (staged != null) {
            store.rename(staged, LIVE_NAME)
            return RecoveryResult.RestoredFromStaged(staged)
        }

        val backup = names.filter { it.startsWith(BACKUP_PREFIX) }.maxOrNull()
        if (backup != null) {
            val bytes = store.read(backup) ?: return RecoveryResult.Unrecoverable
            store.put(LIVE_NAME, bytes)
            return RecoveryResult.RestoredFromBackup(backup)
        }

        return RecoveryResult.Unrecoverable
    }
}

/**
 * The minimum a remote object store must offer.
 *
 * Deliberately tiny, and deliberately free of Google types, so the publish sequence can be
 * exercised against a store that fails on command.
 */
interface ObjectStore {
    suspend fun list(): List<String>
    suspend fun read(name: String): ByteArray?
    suspend fun put(name: String, bytes: ByteArray)
    suspend fun rename(from: String, to: String)
    suspend fun delete(name: String)
}

sealed interface RemoteVaultState {
    /** A live vault is present. */
    data object Present : RemoteVaultState

    /**
     * No live vault, but evidence that one existed.
     *
     * **Never route this to onboarding.** It is a recovery state.
     */
    data class Interrupted(val evidence: List<String>) : RemoteVaultState

    /**
     * The remote could not be reached or read, so **nothing is known**.
     *
     * Deliberately not [Empty] and deliberately not [Interrupted]. "We could not ask" is a
     * third answer, and collapsing it into either of the others is how an offline user gets
     * told they have no vault. It is separate from [Interrupted] because the two need
     * different words on screen: one is "we could not check", the other is "something here
     * needs recovering".
     */
    data class Unavailable(val reason: String) : RemoteVaultState

    /**
     * Nothing here at all — confirmed by a store that answered.
     *
     * The only remote state in which creating a vault is unambiguously safe.
     */
    data object Empty : RemoteVaultState
}

sealed interface PublishResult {
    data object Published : PublishResult

    /** The store accepted bytes that did not read back intact. Previous vault untouched. */
    data object VerificationFailed : PublishResult
}

sealed interface RecoveryResult {
    data object NothingToDo : RecoveryResult
    data class RestoredFromSuperseded(val from: String) : RecoveryResult
    data class RestoredFromStaged(val from: String) : RecoveryResult
    data class RestoredFromBackup(val from: String) : RecoveryResult

    /** No live vault and no evidence. Genuinely nothing to restore. */
    data object Unrecoverable : RecoveryResult
}
