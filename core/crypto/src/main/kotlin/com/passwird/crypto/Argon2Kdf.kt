package com.passwird.crypto

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

/**
 * Argon2id parameters, as stored in a key slot.
 *
 * These live inside the authenticated header, so an attacker cannot lower them — any
 * change breaks the AEAD tag. They are additionally floor-checked on read, because an
 * authenticated-but-weak parameter set is still weak, and a file could legitimately
 * predate a floor increase.
 *
 * @param memoryKib memory cost in KiB
 * @param iterations time cost
 * @param parallelism lanes
 */
data class KdfParams(
    val memoryKib: Int,
    val iterations: Int,
    val parallelism: Int,
    val salt: ByteArray,
    val version: Int = Argon2Parameters.ARGON2_VERSION_13,
) {
    init {
        require(memoryKib > 0) { "memoryKib must be positive" }
        require(iterations > 0) { "iterations must be positive" }
        require(parallelism > 0) { "parallelism must be positive" }
        require(salt.size >= MIN_SALT_BYTES) { "salt must be at least $MIN_SALT_BYTES bytes" }
    }

    /**
     * True when these parameters meet the current minimum.
     *
     * Deliberately an AND across all three costs: an attacker who could trade memory for
     * iterations would otherwise be able to present a cheap-but-nominally-compliant set.
     */
    fun meetsFloor(): Boolean =
        memoryKib >= FLOOR_MEMORY_KIB &&
            iterations >= FLOOR_ITERATIONS &&
            parallelism >= FLOOR_PARALLELISM &&
            version == Argon2Parameters.ARGON2_VERSION_13

    // Hand-written because the compiler-generated versions compare `salt` by identity.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is KdfParams) return false
        return memoryKib == other.memoryKib &&
            iterations == other.iterations &&
            parallelism == other.parallelism &&
            version == other.version &&
            salt.contentEquals(other.salt)
    }

    override fun hashCode(): Int {
        var result = memoryKib
        result = 31 * result + iterations
        result = 31 * result + parallelism
        result = 31 * result + version
        result = 31 * result + salt.contentHashCode()
        return result
    }

    companion object {
        const val MIN_SALT_BYTES: Int = 16
        const val DEFAULT_SALT_BYTES: Int = 16

        /**
         * Hard floor.
         *
         * OWASP's guidance spans m=19 MiB/t=2/p=1 (minimum) through m=46 MiB/t=1/p=1
         * (recommended) to m=128 MiB/t=3/p=4 (high security). We sit between recommended
         * and high security, which is justified here because unlock is infrequent and a
         * password vault is a maximally valuable offline-attack target.
         */
        const val FLOOR_MEMORY_KIB: Int = 64 * 1024 // 64 MiB
        const val FLOOR_ITERATIONS: Int = 3
        const val FLOOR_PARALLELISM: Int = 4

        /** Ceiling, to stop a hostile file from demanding 8 GiB and killing the process. */
        const val MAX_MEMORY_KIB: Int = 1024 * 1024 // 1 GiB
        const val MAX_ITERATIONS: Int = 64
        const val MAX_PARALLELISM: Int = 64

        /** The parameters used when calibration is unavailable or declines to raise them. */
        fun default(salt: ByteArray): KdfParams = KdfParams(
            memoryKib = FLOOR_MEMORY_KIB,
            iterations = FLOOR_ITERATIONS,
            parallelism = FLOOR_PARALLELISM,
            salt = salt,
        )
    }
}

/**
 * Argon2id key derivation.
 *
 * Argon2id is the RFC 9106 variant that resists both GPU attack and side channels, which
 * is the right trade-off on a mobile device where an attacker may have had physical
 * access.
 */
object Argon2Kdf {

    const val OUTPUT_BYTES: Int = 32

    /**
     * Derives a Master Unlock Key from [secret].
     *
     * [secret] is not consumed — the caller retains ownership and must close it.
     */
    fun deriveMuk(secret: SecretBytes, params: KdfParams): SecretBytes {
        validateBounds(params)

        val builder = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(params.version)
            .withIterations(params.iterations)
            .withMemoryAsKB(params.memoryKib)
            .withParallelism(params.parallelism)
            .withSalt(params.salt)

        val generator = Argon2BytesGenerator().apply { init(builder.build()) }
        val out = ByteArray(OUTPUT_BYTES)
        secret.withBytes { generator.generateBytes(it, out) }
        return SecretBytes.adopt(out)
    }

    /**
     * Rejects parameters outside sane bounds *before* any allocation.
     *
     * A hostile file that declared 8 GiB of memory cost would otherwise crash the app on
     * open — a denial of service that costs an attacker nothing to attempt.
     */
    private fun validateBounds(params: KdfParams) {
        if (params.memoryKib > KdfParams.MAX_MEMORY_KIB) {
            throw CryptoError.MalformedVault("KDF memory cost exceeds the permitted maximum")
        }
        if (params.iterations > KdfParams.MAX_ITERATIONS) {
            throw CryptoError.MalformedVault("KDF iteration count exceeds the permitted maximum")
        }
        if (params.parallelism > KdfParams.MAX_PARALLELISM) {
            throw CryptoError.MalformedVault("KDF parallelism exceeds the permitted maximum")
        }
        if (params.version != Argon2Parameters.ARGON2_VERSION_13) {
            throw CryptoError.MalformedVault("Unsupported Argon2 version")
        }
    }

    /**
     * Picks the strongest parameters this device can run within [targetMillis].
     *
     * Never returns anything below the floor: a slow device gets a slower unlock, not a
     * weaker vault. Raising memory is preferred to raising iterations because memory
     * hardness is what degrades GPU and ASIC attacks.
     */
    fun calibrate(
        salt: ByteArray,
        targetMillis: Long = 500,
        maxMemoryKib: Int = 256 * 1024,
        clock: () -> Long = System::nanoTime,
    ): KdfParams {
        var best = KdfParams.default(salt)
        var memory = KdfParams.FLOOR_MEMORY_KIB

        while (memory <= maxMemoryKib) {
            val candidate = KdfParams(
                memoryKib = memory,
                iterations = KdfParams.FLOOR_ITERATIONS,
                parallelism = KdfParams.FLOOR_PARALLELISM,
                salt = salt,
            )
            val elapsedMillis = timeDerivation(candidate, clock)
            if (elapsedMillis > targetMillis) break
            best = candidate
            memory *= 2
        }
        return best
    }

    private fun timeDerivation(params: KdfParams, clock: () -> Long): Long {
        val probe = SecretBytes.copyOf(ByteArray(16) { 0x61 })
        return probe.use {
            val start = clock()
            deriveMuk(it, params).close()
            (clock() - start) / 1_000_000
        }
    }
}
