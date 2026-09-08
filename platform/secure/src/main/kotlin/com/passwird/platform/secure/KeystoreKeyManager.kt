package com.passwird.platform.secure

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.passwird.crypto.SecretBytes
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Why a Keystore operation could not proceed. Each maps to a row in the error matrix. */
sealed class KeystoreFailure(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /** E-07: a new biometric was enrolled, or the screen lock was removed. */
    class KeyInvalidated(cause: Throwable? = null) :
        KeystoreFailure("The device key was invalidated by a security change", cause)

    /** E-27. */
    class Unavailable(cause: Throwable? = null) :
        KeystoreFailure("The device keystore could not be reached", cause)

    class NoSecureLockScreen : KeystoreFailure("No secure lock screen is configured")
}

/**
 * Hardware-backed key management.
 *
 * Two distinct keys, for two distinct jobs:
 *
 *  - **[BIOMETRIC_KEY_ALIAS]** wraps the vault's device slot and requires a biometric for
 *    every single use. It is what makes fast daily unlock possible without the passphrase.
 *  - **[DEVICE_KEY_ALIAS]** requires only that the device is unlocked, and protects
 *    sync bookkeeping that must be readable *before* the vault is opened — most
 *    importantly the rollback watermark.
 *
 * Neither key's material ever leaves the secure hardware. We hand plaintext in and take
 * ciphertext out; the key itself is not extractable even by us, which is precisely the
 * property that makes a stolen device's storage useless on any other machine.
 */
class KeystoreKeyManager(
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) },
) {

    /**
     * Creates the biometric-gated key.
     *
     * Three settings carry the security of this key, and all three are deliberate:
     *
     * `setUserAuthenticationRequired(true)` with `setUserAuthenticationParameters(0, ...)`
     * means **every use** needs a fresh biometric — not a time window during which the key
     * stays warm.
     *
     * `AUTH_BIOMETRIC_STRONG` restricts this to Class 3 sensors. We do not widen device
     * support by accepting weaker classes; the UI explains why instead.
     *
     * `setInvalidatedByBiometricEnrollment(true)` is the one that matters most. Without
     * it, an attacker holding an unlocked device could enrol *their own* fingerprint and
     * then open the vault. With it, the key is destroyed instead. The cost is a real user
     * event — adding a fingerprint logs you out of biometric unlock — which the product
     * handles with a calm explanation and one-tap re-enrolment rather than a cryptic error.
     */
    fun createBiometricKey(useStrongBox: Boolean = true): SecretKey {
        val builder = KeyGenParameterSpec.Builder(
            BIOMETRIC_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_SIZE_BITS)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(true)
            if (useStrongBox) builder.setIsStrongBoxBacked(true)
        }

        return try {
            generate(builder.build())
        } catch (_: StrongBoxUnavailableException) {
            // Plenty of devices advertise the API without the hardware. Falling back to the
            // TEE is still hardware-backed and far better than refusing to offer biometrics.
            createBiometricKey(useStrongBox = false)
        } catch (e: IllegalStateException) {
            throw KeystoreFailure.NoSecureLockScreen().initCause(e) as KeystoreFailure
        } catch (e: Exception) {
            throw KeystoreFailure.Unavailable(e)
        }
    }

    /**
     * Creates the device-bound key used for pre-unlock storage.
     *
     * No biometric gate — this protects data the app must read before the vault is open —
     * but `setUnlockedDeviceRequired` still ties it to the device being unlocked, so a
     * powered-off stolen phone yields nothing.
     */
    fun createDeviceKey(): SecretKey {
        val builder = KeyGenParameterSpec.Builder(
            DEVICE_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_SIZE_BITS)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(true)
        }
        return try {
            generate(builder.build())
        } catch (e: Exception) {
            throw KeystoreFailure.Unavailable(e)
        }
    }

    fun hasBiometricKey(): Boolean = runCatching { keyStore.containsAlias(BIOMETRIC_KEY_ALIAS) }.getOrDefault(false)

    fun getOrCreateDeviceKey(): SecretKey =
        loadKey(DEVICE_KEY_ALIAS) ?: createDeviceKey()

    fun loadBiometricKey(): SecretKey =
        loadKey(BIOMETRIC_KEY_ALIAS) ?: throw KeystoreFailure.KeyInvalidated()

    /**
     * Prepares a cipher for a biometric-gated decryption.
     *
     * The returned cipher is deliberately **unusable** until [android.hardware.biometrics]
     * has authenticated it via a `CryptoObject`. That is the whole point: the common
     * `if (biometricSucceeded) loadKey()` pattern is a boolean an attacker can flip with a
     * hooking framework, whereas here the secure hardware itself refuses to perform the
     * operation until it has seen a valid biometric. There is no boolean to flip.
     */
    fun decryptionCipherFor(wrapped: WrappedSecret): Cipher = try {
        Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, loadBiometricKey(), GCMParameterSpec(TAG_BITS, wrapped.nonce))
        }
    } catch (e: KeyPermanentlyInvalidatedException) {
        throw KeystoreFailure.KeyInvalidated(e)
    } catch (e: KeystoreFailure) {
        throw e
    } catch (e: Exception) {
        throw KeystoreFailure.Unavailable(e)
    }

    fun encryptionCipherForBiometricKey(): Cipher = try {
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, loadBiometricKey()) }
    } catch (e: KeyPermanentlyInvalidatedException) {
        throw KeystoreFailure.KeyInvalidated(e)
    } catch (e: Exception) {
        throw KeystoreFailure.Unavailable(e)
    }

    /** Encrypts with the device key. Used for pre-unlock storage, no biometric needed. */
    fun sealWithDeviceKey(plaintext: ByteArray): WrappedSecret = try {
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, getOrCreateDeviceKey())
        }
        WrappedSecret(cipher.iv, cipher.doFinal(plaintext))
    } catch (e: Exception) {
        throw KeystoreFailure.Unavailable(e)
    }

    fun openWithDeviceKey(wrapped: WrappedSecret): ByteArray = try {
        Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, getOrCreateDeviceKey(), GCMParameterSpec(TAG_BITS, wrapped.nonce))
        }.doFinal(wrapped.ciphertext)
    } catch (e: KeyPermanentlyInvalidatedException) {
        throw KeystoreFailure.KeyInvalidated(e)
    } catch (e: Exception) {
        throw KeystoreFailure.Unavailable(e)
    }

    /** Completes a biometric-authorised unwrap using the cipher the prompt just approved. */
    fun unwrapWithAuthenticatedCipher(cipher: Cipher, wrapped: WrappedSecret): SecretBytes =
        SecretBytes.adopt(cipher.doFinal(wrapped.ciphertext))

    /** Removes the biometric key. Called on disable, and after invalidation. */
    fun deleteBiometricKey() {
        runCatching { keyStore.deleteEntry(BIOMETRIC_KEY_ALIAS) }
    }

    private fun loadKey(alias: String): SecretKey? = try {
        keyStore.getKey(alias, null) as? SecretKey
    } catch (_: Exception) {
        null
    }

    private fun generate(spec: KeyGenParameterSpec): SecretKey =
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(spec) }
            .generateKey()

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val TAG_BITS = 128
        private const val KEY_SIZE_BITS = 256

        const val BIOMETRIC_KEY_ALIAS = "passwird.vault.biometric.v1"
        const val DEVICE_KEY_ALIAS = "passwird.device.v1"
    }
}

/** Ciphertext plus its nonce. Safe to persist; useless without the hardware key. */
data class WrappedSecret(val nonce: ByteArray, val ciphertext: ByteArray) {
    fun encode(): ByteArray = byteArrayOf(nonce.size.toByte()) + nonce + ciphertext

    override fun equals(other: Any?): Boolean =
        this === other || (
            other is WrappedSecret &&
                nonce.contentEquals(other.nonce) && ciphertext.contentEquals(other.ciphertext)
            )

    override fun hashCode(): Int = 31 * nonce.contentHashCode() + ciphertext.contentHashCode()

    /** Never render wrapped key material, even though it is encrypted. */
    override fun toString(): String = "WrappedSecret(${ciphertext.size} bytes, redacted)"

    companion object {
        fun decode(bytes: ByteArray): WrappedSecret {
            require(bytes.isNotEmpty()) { "empty wrapped secret" }
            val nonceLength = bytes[0].toInt()
            require(nonceLength in 1..16 && bytes.size > nonceLength + 1) { "malformed wrapped secret" }
            return WrappedSecret(
                nonce = bytes.copyOfRange(1, 1 + nonceLength),
                ciphertext = bytes.copyOfRange(1 + nonceLength, bytes.size),
            )
        }
    }
}
