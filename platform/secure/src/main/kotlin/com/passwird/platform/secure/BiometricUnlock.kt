package com.passwird.platform.secure

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.passwird.crypto.SecretBytes
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

/** Whether biometric unlock can be offered, and if not, why — so the UI can say so. */
sealed interface BiometricAvailability {
    data object Available : BiometricAvailability

    /** E-04: hardware exists, nothing enrolled. */
    data object NotEnrolled : BiometricAvailability

    /** E-03. */
    data object NoHardware : BiometricAvailability
    data object TemporarilyUnavailable : BiometricAvailability

    /**
     * Only Class 2 or device-credential authentication is available.
     *
     * We decline rather than weaken the gate: Class 2 sensors cannot back a Keystore
     * `CryptoObject`, so "biometric unlock" would degrade into a boolean check an attacker
     * can bypass. The UI explains this instead of silently offering something weaker.
     */
    data object InsufficientStrength : BiometricAvailability
}

sealed interface BiometricResult {
    data class Success(val key: SecretBytes) : BiometricResult
    data object Cancelled : BiometricResult

    /** E-05: wrong finger, retryable. */
    data class Failed(val attemptsRemaining: Int?) : BiometricResult

    /** Too many failures; the OS has locked the sensor out. */
    data object LockedOut : BiometricResult

    /** E-07: a new biometric was enrolled, so the key was destroyed by design. */
    data object KeyInvalidated : BiometricResult
    data class Error(val message: String) : BiometricResult
}

/**
 * Biometric unlock, bound to a real cryptographic operation.
 *
 * The distinction that matters: a fingerprint is **not a key**. It is a gate that
 * authorises the secure hardware to use a key it already holds. So this class never asks
 * "did authentication succeed?" and then loads a key — it hands the prompt a
 * `CryptoObject` wrapping an initialised `Cipher`, and the hardware refuses to perform the
 * decryption until it has itself observed a valid Class 3 biometric.
 *
 * That is the difference between a check an attacker can hook and one they cannot.
 */
class BiometricUnlock(
    private val keyManager: KeystoreKeyManager,
) {

    fun availability(activity: FragmentActivity): BiometricAvailability {
        val manager = BiometricManager.from(activity)
        return when (manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricAvailability.Available
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricAvailability.NotEnrolled
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricAvailability.NoHardware
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricAvailability.TemporarilyUnavailable
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> BiometricAvailability.InsufficientStrength
            else -> BiometricAvailability.InsufficientStrength
        }
    }

    /**
     * Prompts, and on success unwraps the device slot key.
     *
     * @param wrapped the device slot, previously sealed by [enrol]
     */
    suspend fun unlock(
        activity: FragmentActivity,
        wrapped: WrappedSecret,
        title: String,
        subtitle: String,
        negativeLabel: String,
    ): BiometricResult = suspendCancellableCoroutine { continuation ->
        val cipher = try {
            keyManager.decryptionCipherFor(wrapped)
        } catch (_: KeystoreFailure.KeyInvalidated) {
            continuation.resume(BiometricResult.KeyInvalidated)
            return@suspendCancellableCoroutine
        } catch (e: KeystoreFailure) {
            continuation.resume(BiometricResult.Error(e.message ?: "keystore unavailable"))
            return@suspendCancellableCoroutine
        }

        val prompt = BiometricPrompt(
            activity,
            androidx.core.content.ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authenticated = result.cryptoObject?.cipher
                    if (authenticated == null) {
                        // Without an authenticated cipher there is no cryptographic proof
                        // that the hardware approved anything, so we refuse rather than
                        // fall back to trusting the callback.
                        continuation.resume(BiometricResult.Error("No authenticated cipher was returned"))
                        return
                    }
                    val outcome = runCatching {
                        keyManager.unwrapWithAuthenticatedCipher(authenticated, wrapped)
                    }
                    continuation.resume(
                        outcome.fold(
                            onSuccess = BiometricResult::Success,
                            onFailure = { BiometricResult.KeyInvalidated },
                        ),
                    )
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    continuation.resume(
                        when (code) {
                            BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                            BiometricPrompt.ERROR_USER_CANCELED,
                            BiometricPrompt.ERROR_CANCELED,
                            -> BiometricResult.Cancelled

                            BiometricPrompt.ERROR_LOCKOUT,
                            BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
                            -> BiometricResult.LockedOut

                            else -> BiometricResult.Error(message.toString())
                        },
                    )
                }

                override fun onAuthenticationFailed() {
                    // A non-matching finger. The prompt stays up, so this is informational
                    // only and must not resume the coroutine.
                }
            },
        )

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText(negativeLabel)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setConfirmationRequired(false)
            .build()

        continuation.invokeOnCancellation { prompt.cancelAuthentication() }
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    /**
     * Enrols this device by wrapping [deviceSlotKey] under a fresh biometric-gated key.
     *
     * The result is stored **locally only** and never uploaded: a Keystore-wrapped blob is
     * meaningless on any other device, and syncing it would leak how many devices the user
     * owns.
     */
    fun enrol(deviceSlotKey: SecretBytes): WrappedSecret {
        keyManager.deleteBiometricKey()
        keyManager.createBiometricKey()
        val cipher = keyManager.encryptionCipherForBiometricKey()
        return deviceSlotKey.withBytes { bytes ->
            WrappedSecret(cipher.iv, cipher.doFinal(bytes))
        }
    }

    fun disable() = keyManager.deleteBiometricKey()
}
