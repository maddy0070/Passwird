package com.passwird.vaultapp

import com.passwird.crypto.SecretBytes
import com.passwird.crypto.SlotType
import com.passwird.store.UnlockResult
import com.passwird.store.VaultRepository
import com.passwird.vaultapp.ui.UnlockUiState
import com.passwird.vault.lock.UnlockBackoff
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Drives the lock screen.
 *
 * Kept deliberately thin. It owns exactly two things the repository cannot: the **attempt
 * counter with its backoff**, and the mapping from a typed [UnlockResult] to the state the
 * screen renders. Everything else is delegated.
 *
 * Not a `ViewModel`: the vault must be dropped when the process is locked, and a
 * `ViewModel`'s whole purpose is to survive configuration changes. Surviving a rotation is
 * the opposite of what an unlock controller should do.
 */
class UnlockController(
    private val repository: VaultRepository,
    private val clock: () -> Long = System::currentTimeMillis,
) {

    private val _state = MutableStateFlow<UnlockUiState>(UnlockUiState.Ready)
    val state: StateFlow<UnlockUiState> = _state.asStateFlow()

    private val backoff = UnlockBackoff()
    private var attempts: Int = 0
    private var lastFailureAt: Long = 0

    /**
     * Attempts an unlock with a typed passphrase.
     *
     * The [CharArray] is wiped by [SecretBytes.fromPassphrase]; the caller's `String` cannot
     * be, which is a known and unavoidable cost of Compose's text field API. It is noted here
     * rather than hidden: the string lives until the next GC, and no amount of care at this
     * layer changes that.
     */
    suspend fun unlockWithPassphrase(passphrase: String): UnlockResult? {
        val waiting = backoff.remainingSeconds(attempts, lastFailureAt, clock())
        if (waiting > 0) {
            _state.value = UnlockUiState.BackedOff(secondsRemaining = waiting)
            return null
        }

        _state.value = UnlockUiState.Authenticating
        val secret = SecretBytes.fromPassphrase(passphrase.toCharArray())
        val result = secret.use { repository.unlock(it, SlotType.PASSPHRASE) }

        applyResult(result)
        return result
    }

    /** Unlock with an already-derived key, from the biometric slot or a parsed recovery key. */
    suspend fun unlockWithSecret(secret: SecretBytes, type: SlotType): UnlockResult {
        _state.value = UnlockUiState.Authenticating
        val result = secret.use { repository.unlock(it, type) }
        applyResult(result)
        return result
    }

    /**
     * Opens the vault with a device key the secure hardware has just released.
     *
     * Separate from [unlockWithSecret] because there is no KDF and no slot type to choose:
     * the biometric path goes straight to the device slot, and that is what makes it instant.
     */
    suspend fun unlockWithSecretKey(
        repository: VaultRepository,
        deviceKey: com.passwird.crypto.SecretBytes,
    ): UnlockResult {
        _state.value = UnlockUiState.Authenticating
        val result = deviceKey.use { repository.unlockWithDeviceKey(it) }
        applyResult(result)
        return result
    }

    fun reportBiometricInvalidated() {
        _state.value = UnlockUiState.BiometricInvalidated
    }

    fun reset() {
        _state.value = UnlockUiState.Ready
    }

    private fun applyResult(result: UnlockResult) {
        when (result) {
            is UnlockResult.Success -> {
                attempts = 0
                lastFailureAt = 0
                _state.value = UnlockUiState.Ready
            }

            is UnlockResult.WrongSecret -> {
                attempts++
                lastFailureAt = clock()
                _state.value = UnlockUiState.WrongPassphrase(attempts)
            }

            // A vault that will not open is not a wrong passphrase, and must not be counted
            // as one — the per-slot key commitment is what lets these be told apart, and
            // conflating them would tell a user with a damaged file to try harder.
            is UnlockResult.Damaged -> _state.value = UnlockUiState.VaultDamaged
            is UnlockResult.NoVault -> _state.value = UnlockUiState.Ready
        }
    }

    /** Seconds the user must still wait, or 0. Backoff, never a wipe — ADR-0008. */
    fun backoffSecondsRemaining(): Long =
        backoff.remainingSeconds(attempts, lastFailureAt, clock())
}
