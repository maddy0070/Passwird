package com.passwird.crypto

import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec

/**
 * A byte array holding key material or a secret value, with best-effort zeroisation.
 *
 * Why this type exists rather than passing [ByteArray] around:
 *
 *  - **It can be wiped.** [String] is immutable and may be interned, so a secret that
 *    reaches a String cannot be removed from memory. Nothing in this module accepts a
 *    String secret.
 *  - **It cannot be logged by accident.** [toString] is redacted, so an accidental
 *    `"key=$key"` in a log statement leaks nothing. Enforced by `RedactedToStringTest`.
 *  - **It has a lifetime.** [AutoCloseable] means call sites read `use { }`, which makes
 *    a leaked secret visible in review as a missing block rather than invisible as a
 *    missing wipe.
 *
 * Honest limitation: the JVM garbage collector may relocate arrays, leaving copies that
 * [close] cannot reach. Zeroisation meaningfully shrinks the exposure window; it is not a
 * guarantee, and `docs/03-encryption-architecture.md` §5 says so rather than implying
 * otherwise.
 */
class SecretBytes private constructor(
    private val bytes: ByteArray,
) : AutoCloseable {

    @Volatile
    private var closed: Boolean = false

    val size: Int get() = bytes.size

    /**
     * Runs [block] with the raw bytes.
     *
     * The array is the live backing store, not a copy — do not retain it beyond [block],
     * and do not mutate it. Kept deliberately awkward so that reaching for raw bytes is a
     * conscious act.
     */
    fun <T> withBytes(block: (ByteArray) -> T): T {
        check(!closed) { "SecretBytes has been closed" }
        return block(bytes)
    }

    /** Copies the material out. The caller owns — and must wipe — the result. */
    fun copyBytes(): ByteArray {
        check(!closed) { "SecretBytes has been closed" }
        return bytes.copyOf()
    }

    /** Wraps the material as a JCE key. The returned key references live bytes. */
    fun asAesKey(): SecretKeySpec {
        check(!closed) { "SecretBytes has been closed" }
        return SecretKeySpec(bytes, "AES")
    }

    /**
     * Constant-time equality. Runs in time proportional to length only, never returning
     * early on the first differing byte, so it cannot be used as a timing oracle.
     */
    fun constantTimeEquals(other: SecretBytes): Boolean {
        check(!closed && !other.closed) { "SecretBytes has been closed" }
        return ConstantTime.equals(bytes, other.bytes)
    }

    override fun close() {
        if (!closed) {
            bytes.fill(0)
            closed = true
        }
    }

    /** Redacted by design. Never renders the secret, at any log level, ever. */
    override fun toString(): String = "SecretBytes(${bytes.size} bytes, redacted)"

    /** Deliberately unsupported: secrets must not participate in structural equality. */
    override fun equals(other: Any?): Boolean =
        throw UnsupportedOperationException("Use constantTimeEquals; == on secrets leaks timing")

    override fun hashCode(): Int =
        throw UnsupportedOperationException("Hashing a secret risks leaking it into collections/logs")

    companion object {
        private val random = SecureRandom()

        /** Takes ownership of [bytes]; the caller must not retain or reuse the array. */
        fun adopt(bytes: ByteArray): SecretBytes = SecretBytes(bytes)

        /** Copies [bytes]; the caller keeps ownership of the original. */
        fun copyOf(bytes: ByteArray): SecretBytes = SecretBytes(bytes.copyOf())

        /** Cryptographically secure random material of [size] bytes. */
        fun random(size: Int): SecretBytes {
            require(size > 0) { "size must be positive" }
            val b = ByteArray(size)
            random.nextBytes(b)
            return SecretBytes(b)
        }

        /**
         * Encodes a passphrase as UTF-8 and wipes [chars].
         *
         * Takes [CharArray] rather than [String] so the caller's copy is wipeable too.
         * The intermediate encoding buffer is wiped before returning.
         */
        fun fromPassphrase(chars: CharArray): SecretBytes {
            val buffer = java.nio.CharBuffer.wrap(chars)
            val encoded = Charsets.UTF_8.encode(buffer)
            val out = ByteArray(encoded.remaining())
            encoded.get(out)

            // Wipe the intermediate ByteBuffer's backing array if it is accessible.
            if (encoded.hasArray()) encoded.array().fill(0)
            chars.fill('\u0000')

            return SecretBytes(out)
        }
    }
}

/** Constant-time primitives. Separate object so the intent is explicit at call sites. */
object ConstantTime {
    /**
     * Compares [a] and [b] without early exit.
     *
     * Length inequality returns false immediately — lengths are public in every use here
     * (all comparands are fixed-size digests or keys), so this leaks nothing.
     */
    fun equals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }
}
