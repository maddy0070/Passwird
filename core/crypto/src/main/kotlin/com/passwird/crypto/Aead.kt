package com.passwird.crypto

import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-256-GCM authenticated encryption.
 *
 * Sourced from the platform JCE rather than BouncyCastle so that on Android it runs
 * through Conscrypt and the ARMv8 crypto extensions — unlock is on a 4-second critical
 * path, and hardware acceleration is the difference between "instant" and "noticeable".
 * The same code runs unmodified on the JVM, which is why the entire security core is
 * testable in CI without an emulator.
 *
 * **Nonce policy.** GCM's 96-bit nonce is too small to generate randomly at scale
 * without worrying about birthday collisions. This module never has to worry, because
 * callers derive a fresh message key per write from a 256-bit random salt — see
 * [VaultCrypto] and ADR-0001. A nonce collision would additionally require a salt
 * collision, which is a 256-bit event.
 */
object Aead {

    const val KEY_BYTES: Int = 32
    const val NONCE_BYTES: Int = 12
    const val TAG_BYTES: Int = 16
    private const val TAG_BITS: Int = TAG_BYTES * 8

    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    private val random = SecureRandom()

    fun randomNonce(): ByteArray = ByteArray(NONCE_BYTES).also(random::nextBytes)

    /**
     * Encrypts [plaintext] under [key], authenticating [aad].
     *
     * @return ciphertext with the 16-byte tag appended
     */
    fun seal(
        key: SecretBytes,
        nonce: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        require(key.size == KEY_BYTES) { "AES-256-GCM requires a $KEY_BYTES-byte key" }
        require(nonce.size == NONCE_BYTES) { "GCM nonce must be $NONCE_BYTES bytes" }
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key.asAesKey(), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(aad)
            cipher.doFinal(plaintext)
        } catch (e: Exception) {
            // Fail closed. There is no path in this product that responds to an
            // encryption failure by storing or transmitting plaintext.
            throw CryptoError.EncryptionFailure("AES-256-GCM seal failed", e)
        }
    }

    /**
     * Decrypts and verifies.
     *
     * @throws CryptoError.IntegrityFailure if the tag does not verify — meaning tampering
     *   or corruption. It never means a wrong passphrase: by the time this is called the
     *   key has already been confirmed by the slot commitment check.
     */
    fun open(
        key: SecretBytes,
        nonce: ByteArray,
        ciphertext: ByteArray,
        aad: ByteArray,
        context: String,
    ): ByteArray {
        require(key.size == KEY_BYTES) { "AES-256-GCM requires a $KEY_BYTES-byte key" }
        if (nonce.size != NONCE_BYTES) {
            throw CryptoError.MalformedVault("Nonce for $context must be $NONCE_BYTES bytes")
        }
        if (ciphertext.size < TAG_BYTES) {
            throw CryptoError.MalformedVault("Ciphertext for $context is shorter than the tag")
        }
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key.asAesKey(), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(aad)
            cipher.doFinal(ciphertext)
        } catch (_: AEADBadTagException) {
            throw CryptoError.IntegrityFailure(context)
        } catch (e: CryptoError) {
            throw e
        } catch (e: Exception) {
            throw CryptoError.IntegrityFailure("$context (${e.javaClass.simpleName})")
        }
    }
}
