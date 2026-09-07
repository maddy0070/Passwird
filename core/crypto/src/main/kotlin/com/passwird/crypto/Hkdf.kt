package com.passwird.crypto

import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters

/**
 * HKDF-SHA-512 (RFC 5869) extract-and-expand.
 *
 * Used for every key derivation in the product except the password-based step, which is
 * [Argon2Kdf]. HKDF is *not* a password KDF — it is fast by design — so it is only ever
 * applied to material that is already high-entropy: the VEK, or a MUK that Argon2id has
 * already produced.
 */
object Hkdf {

    /**
     * Derives [length] bytes from [ikm] under [info], optionally salted.
     *
     * @param ikm  input key material — must already be high-entropy
     * @param info domain-separation label, always a constant from [KeyDomains]
     * @param salt optional; non-secret. Per-write randomness goes here (see ADR-0001)
     */
    fun derive(
        ikm: SecretBytes,
        info: String,
        salt: ByteArray? = null,
        length: Int = 32,
    ): SecretBytes {
        require(length in 1..255 * 64) { "HKDF-SHA-512 output length out of range" }
        require(info.isNotEmpty()) { "refusing to derive a key without domain separation" }

        val out = ByteArray(length)
        ikm.withBytes { keyMaterial ->
            val generator = HKDFBytesGenerator(SHA512Digest())
            generator.init(HKDFParameters(keyMaterial, salt, info.toByteArray(Charsets.UTF_8)))
            generator.generateBytes(out, 0, length)
        }
        return SecretBytes.adopt(out)
    }
}
