package com.passwird.store

import com.passwird.crypto.CryptoError
import com.passwird.model.VaultDocument
import com.passwird.sync.RemoteVaultState

/**
 * Where the vault is in its lifecycle.
 *
 * ### Why this type exists
 *
 * The app routed its first screen on `repository.vault == null`. That expression means *not
 * unlocked*, and it was being read as *locked* — so a fresh installation, which has no vault
 * at all, was shown "Your vault is locked" and asked for a master passphrase that had never
 * been chosen. There was no passphrase, no vault, and no way to make one.
 *
 * The bug is not that the wrong screen appeared. It is that **the application had no concept
 * of not having a vault yet**. A boolean cannot distinguish seven situations, and this
 * product has seven that must be told apart, because the actions they permit are dangerous
 * in different directions: one of them offers to create a vault, and doing that in the wrong
 * state overwrites a real one.
 *
 * ### The ordering rule
 *
 * States are resolved most-evidence-first, and **[FirstRun] is last**. It is the only state
 * that permits creating a vault, so it must be the hardest to reach: every other explanation
 * for "no readable vault here" is checked and ruled out before the app is willing to believe
 * a user is new.
 */
sealed interface VaultState {

    /**
     * **1 — FIRST_RUN.** No vault locally, and the remote confirmed it has none either.
     *
     * The only state in which offering *Create new vault* is unambiguously safe.
     */
    data object FirstRun : VaultState

    /**
     * **1b — FIRST_RUN, remote unchecked.** No vault locally; the remote could not be asked.
     *
     * Separate from [FirstRun] because the product is offline-first: a genuinely new user with
     * no connectivity must still be able to create a vault, so this cannot simply block. But
     * it also cannot pretend to be [FirstRun], because an existing user reinstalling on a
     * plane would then be one tap from publishing an empty vault over a real one. The screen
     * must say which one it is and offer *Restore* as the safer path.
     */
    data class FirstRunRemoteUnchecked(val reason: String) : VaultState

    /** **2 — VAULT_EXISTS_LOCKED.** A real local vault, readable, waiting for a secret. */
    data object Locked : VaultState

    /** **3 — VAULT_UNLOCKED.** */
    data class Unlocked(val document: VaultDocument) : VaultState

    /**
     * **4 — REMOTE_VAULT_AVAILABLE.** No local vault; the remote has a live one.
     *
     * The restore path. Reaching it requires a secret the user holds — a Google account gets
     * the *bytes*, never the contents.
     */
    data object RemoteVaultAvailable : VaultState

    /**
     * **5 — RECOVERY_REQUIRED.** This device has held a vault, and nothing can restore it
     * automatically.
     *
     * Distinct from [FirstRun] by evidence, and distinct from [VaultRecoveryAvailable] by
     * whether a copy exists to offer. The user needs their recovery key or another device.
     */
    data class RecoveryRequired(val reason: String) : VaultState

    /**
     * **6 — VAULT_CORRUPTED.** A vault file exists and is not readable as a vault.
     *
     * Never silently replaced. `10-error-matrix.md` E-20/E-29.
     */
    data class Corrupted(val detail: String) : VaultState

    /**
     * **7 — VAULT_RECOVERY_AVAILABLE.** No live vault, but a recoverable copy exists.
     *
     * Typically an interrupted publish (§F-2) or a backup. One tap restores it.
     */
    data class VaultRecoveryAvailable(val sources: List<String>) : VaultState

    /** True when the app may offer to create a brand-new vault. Nothing else may. */
    val mayCreateVault: Boolean
        get() = this is FirstRun || this is FirstRunRemoteUnchecked
}

/**
 * Synchronisation status — a **separate** axis, deliberately.
 *
 * The brief listed SYNC_UNAVAILABLE, SYNCING and SYNCED alongside the vault lifecycle states.
 * They are modelled apart because they are genuinely orthogonal: a vault is *unlocked and
 * syncing*, or *locked and offline*, and folding them into one enum would need the product of
 * both sets and would let an impossible state be constructed. Keeping them separate makes
 * "unlocked" and "syncing" independently true, which is what they are.
 */
enum class SyncState {
    /** **8.** No connectivity, no account, or the remote refused. Not an error — E-11. */
    UNAVAILABLE,

    /** **9.** */
    SYNCING,

    /** **10.** Local and remote agree. */
    SYNCED,
}

/**
 * Decides which [VaultState] the application is in.
 *
 * Pure and free of Android and Google types so every branch below can be exercised as a test
 * rather than reasoned about — which is the whole point, given that the defect this replaces
 * was a one-line inference nobody could test.
 */
object VaultStateResolver {

    /**
     * @param unlocked the decrypted document, when a session is already open.
     * @param localVault the stored container, or null.
     * @param localEvidence whether this device holds any trace of a vault having existed.
     * @param remote what the remote store reports.
     * @param parses whether [localVault] is structurally a vault. Injected rather than parsed
     *   here so `core:store` does not have to reach into the container format, and so the
     *   corrupted branch can be tested without crafting a broken file.
     */
    fun resolve(
        unlocked: VaultDocument?,
        localVault: ByteArray?,
        localEvidence: Boolean,
        remote: RemoteVaultState,
        parses: (ByteArray) -> Boolean = { true },
    ): VaultState {
        // 3. An open session outranks everything. Nothing about the remote can lock a vault
        //    the user is currently using.
        if (unlocked != null) return VaultState.Unlocked(unlocked)

        // 2 / 6. A local vault file is the strongest evidence there is.
        if (localVault != null) {
            return if (parses(localVault)) {
                VaultState.Locked
            } else {
                VaultState.Corrupted("the local vault file is not a readable vault")
            }
        }

        // No local vault. Everything from here is about refusing to guess "new user".
        return when (remote) {
            // 4. The remote holds a vault. Restore, whether or not this device has history.
            is RemoteVaultState.Present -> VaultState.RemoteVaultAvailable

            // 7. An interrupted publish, a staged upload, a backup. Recoverable, never new.
            is RemoteVaultState.Interrupted ->
                VaultState.VaultRecoveryAvailable(remote.evidence)

            // The remote could not be asked. Local evidence decides what that means.
            is RemoteVaultState.Unavailable ->
                if (localEvidence) {
                    // 5. This device had a vault and we cannot see the remote. Do not offer
                    //    creation; the user needs recovery or connectivity.
                    VaultState.RecoveryRequired(
                        "this device has held a vault, and the remote could not be reached " +
                            "(${remote.reason})",
                    )
                } else {
                    // 1b. Nothing here, nothing known. Offline-first means this must not be a
                    //     dead end, but it must not claim to be a confirmed first run either.
                    VaultState.FirstRunRemoteUnchecked(remote.reason)
                }

            is RemoteVaultState.Empty ->
                if (localEvidence) {
                    // 5. The device has history the remote does not corroborate. Something was
                    //    lost; creating a vault here would paper over it.
                    VaultState.RecoveryRequired(
                        "this device has held a vault, but no copy remains locally or remotely",
                    )
                } else {
                    // 1. The only path to FirstRun: nothing local, nothing remote, and the
                    //    remote actually answered.
                    VaultState.FirstRun
                }
        }
    }

    /** Maps a transport failure to the state it must produce — never [RemoteVaultState.Empty]. */
    fun remoteFailure(error: Throwable): RemoteVaultState =
        RemoteVaultState.Unavailable(error.message ?: error::class.simpleName ?: "unreachable")

    /** Maps a decryption failure to the vault state it implies. */
    fun fromUnlockFailure(error: CryptoError): VaultState = when (error) {
        // A wrong passphrase says nothing about the vault; it stays locked.
        is CryptoError.WrongSecret -> VaultState.Locked
        else -> VaultState.Corrupted(error.message ?: "the vault could not be opened")
    }
}
