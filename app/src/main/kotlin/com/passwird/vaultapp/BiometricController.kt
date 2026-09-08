package com.passwird.vaultapp

import androidx.fragment.app.FragmentActivity
import com.passwird.crypto.SecretBytes
import com.passwird.platform.secure.BiometricAvailability
import com.passwird.platform.secure.BiometricResult
import com.passwird.platform.secure.BiometricUnlock
import com.passwird.platform.secure.WrappedSecret
import com.passwird.store.EnrolResult

/**
 * Biometric enrolment and unlock, joined to the vault.
 *
 * ### The property this exists to preserve
 *
 * A fingerprint is a **gate, not a key**. The device key that opens the vault lives in the
 * Android Keystore behind `setUserAuthenticationRequired(true)`, and the hardware refuses to
 * release it until it has itself observed a valid biometric. There is no boolean here that an
 * attacker with a hooking framework could flip, because the unlock cannot proceed without a
 * `Cipher` the secure hardware has already authorised.
 *
 * That property cannot be proven off-device. `DeviceSlotEnrolmentTest` proves the slot, the
 * wrapping and the unlock path with a fake Keystore; only a real device can prove the gate.
 */
class BiometricController(container: PasswirdContainer) {

    private val repository = container.repository
    private val biometric = BiometricUnlock(container.keyManager)

    /** True when the hardware can do Class 3 biometrics **and** this vault is not yet enrolled. */
    suspend fun canEnrol(activity: FragmentActivity): Boolean =
        repository.isUnlocked &&
            biometric.availability(activity) == BiometricAvailability.Available &&
            !repository.hasDeviceSlot()

    /** True when there is an enrolment to unlock with, and the hardware is ready. */
    suspend fun canUnlock(activity: FragmentActivity): Boolean =
        !repository.isUnlocked &&
            biometric.availability(activity) == BiometricAvailability.Available &&
            repository.hasDeviceSlot()

    /**
     * Enrols this device.
     *
     * Requires an unlocked vault — enforced by the repository, not merely by this call site,
     * because the constraint is a security property rather than a UI nicety: biometrics can
     * only ever be added by someone who has already proven the passphrase.
     */
    suspend fun enrol(activity: FragmentActivity): EnrolResult {
        if (biometric.availability(activity) != BiometricAvailability.Available) {
            return EnrolResult.Failed("this device has no usable Class 3 biometric hardware")
        }
        return repository.enrolDeviceSlot(label = android.os.Build.MODEL ?: "This device") { key ->
            key.withBytes { biometric.enrol(SecretBytes.copyOf(it)).encode() }
        }
    }

    /**
     * Prompts for a biometric and, on success, opens the vault with the released device key.
     *
     * A failure here never falls through to an unlocked vault: every branch that is not
     * [BiometricResult.Success] leaves the vault exactly as locked as it was, and the user
     * still has the passphrase field — which is why the lock screen keeps it one tap away
     * rather than behind the biometric.
     */
    suspend fun unlock(activity: FragmentActivity, unlockController: UnlockController): Outcome {
        val wrapped = repository.wrappedDeviceKey() ?: return Outcome.NotEnrolled

        val result = biometric.unlock(
            activity = activity,
            wrapped = WrappedSecret.decode(wrapped),
            title = "Unlock Passwird",
            subtitle = "Use your fingerprint to open your vault",
            negativeLabel = "Use passphrase",
        )

        return when (result) {
            is BiometricResult.Success -> {
                unlockController.unlockWithSecretKey(repository, result.key)
                Outcome.Unlocked
            }

            // Enrolling a new fingerprint destroys the key by design, and the vault is
            // untouched. The user re-enrols behind the passphrase — E-07.
            is BiometricResult.KeyInvalidated -> {
                repository.clearDeviceSlot()
                unlockController.reportBiometricInvalidated()
                Outcome.Invalidated
            }

            is BiometricResult.Cancelled -> Outcome.Cancelled
            is BiometricResult.Failed -> Outcome.Failed
            is BiometricResult.LockedOut -> Outcome.LockedOut
            is BiometricResult.Error -> Outcome.Failed
        }
    }

    enum class Outcome { Unlocked, Cancelled, Failed, LockedOut, Invalidated, NotEnrolled }
}
