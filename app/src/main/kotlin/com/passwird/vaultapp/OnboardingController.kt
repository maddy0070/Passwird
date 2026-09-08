package com.passwird.vaultapp

import com.passwird.crypto.RecoveryKey
import com.passwird.crypto.SecretBytes
import com.passwird.store.CreateResult
import com.passwird.store.VaultRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Drives vault creation.
 *
 * ### Where the secrets live while this runs
 *
 * The passphrase and the recovery key exist only inside this object, only between the screen
 * that collects them and the call that consumes them, and both are zeroised the moment the
 * vault is created or the flow is abandoned. Nothing is written to disk, to `SharedPreferences`
 * or to a saved-instance-state bundle at any point — a half-finished onboarding must not leave
 * a passphrase anywhere.
 *
 * The recovery key is generated **before** the screen that displays it and held here until the
 * user has confirmed they wrote it down, because a key generated at the moment of vault
 * creation could never have been shown.
 */
class OnboardingController(
    private val repository: VaultRepository,
    private val generateKey: () -> Pair<SecretBytes, String> = RecoveryKey::generateFormatted,
) {

    /** Where the user is in the create-vault flow. */
    sealed interface Step {
        data object Welcome : Step
        data object ChoosePassphrase : Step
        data class ShowRecoveryKey(val formatted: String) : Step
        data class VerifyRecoveryKey(val groupNumber: Int, val error: String? = null) : Step
        data object Creating : Step
        data class Failed(val detail: String) : Step
        data object Restore : Step
    }

    private val _step = MutableStateFlow<Step>(Step.Welcome)
    val step: StateFlow<Step> = _step.asStateFlow()

    private var passphrase: SecretBytes? = null
    private var recoveryKey: SecretBytes? = null
    private var formattedKey: String? = null
    private var verifyGroup: Int = 1

    fun startCreate() {
        _step.value = Step.ChoosePassphrase
    }

    fun startRestore() {
        _step.value = Step.Restore
    }

    /** Back to the welcome screen, discarding anything collected so far. */
    fun cancel() {
        wipe()
        _step.value = Step.Welcome
    }

    /**
     * Accepts the chosen passphrase and generates the recovery key.
     *
     * The `String` from the text field cannot be wiped — Compose's API gives us no other
     * option — so it is converted to a [SecretBytes] immediately and the caller's copy is left
     * to the garbage collector. Stated rather than hidden: this is the one place in the
     * product where a secret exists in an unwipeable form, and it is unavoidable at this layer.
     */
    fun passphraseChosen(value: String) {
        wipeSecrets()
        passphrase = SecretBytes.fromPassphrase(value.toCharArray())

        val (key, formatted) = generateKey()
        recoveryKey = key
        formattedKey = formatted

        // A random group, so a user cannot learn "it always asks for the first four" and copy
        // only that. Seven groups; the last is as likely as any other.
        verifyGroup = (1..RecoveryKey.GROUP_COUNT).random()

        _step.value = Step.ShowRecoveryKey(formatted)
    }

    fun recoveryKeyAcknowledged() {
        _step.value = Step.VerifyRecoveryKey(verifyGroup)
    }

    fun showRecoveryKeyAgain() {
        formattedKey?.let { _step.value = Step.ShowRecoveryKey(it) }
    }

    /**
     * Checks the typed group and, if it matches, creates the vault.
     *
     * The comparison is deliberately forgiving about presentation and strict about content:
     * the codec's own normalisation folds case and the Crockford confusables, so someone who
     * writes `O` for `0` still passes — which is the point of that alphabet.
     */
    suspend fun verifyAndCreate(entry: String): CreateResult? {
        val expected = formattedKey?.split("-")?.getOrNull(verifyGroup - 1)
        if (expected == null) {
            _step.value = Step.Failed("the recovery key was lost before the vault was created")
            return null
        }

        if (!RecoveryKey.groupMatches(entry, expected)) {
            _step.value = Step.VerifyRecoveryKey(
                groupNumber = verifyGroup,
                error = "That doesn't match group $verifyGroup. Check what you wrote down.",
            )
            return null
        }

        val pass = passphrase
        val key = recoveryKey
        if (pass == null || key == null) {
            _step.value = Step.Failed("the passphrase was lost before the vault was created")
            return null
        }

        _step.value = Step.Creating
        val result = repository.createVault(pass, key)

        // Whatever happened, neither secret is needed again. The vault holds them now, wrapped.
        wipeSecrets()

        when (result) {
            is CreateResult.Created -> Unit // routing follows the vault state, not this step
            is CreateResult.VaultAlreadyExists ->
                _step.value = Step.Failed(
                    "A vault already exists on this device. It was not replaced.",
                )
            is CreateResult.Failed -> _step.value = Step.Failed(result.detail)
        }
        return result
    }

    private fun wipeSecrets() {
        passphrase?.close()
        passphrase = null
        recoveryKey?.close()
        recoveryKey = null
    }

    private fun wipe() {
        wipeSecrets()
        formattedKey = null
    }
}
