package com.passwird.crypto

/**
 * Shared fixtures.
 *
 * Tests deliberately use **fast** Argon2 parameters. The floor (64 MiB, t=3, p=4) costs
 * roughly half a second per derivation by design, which would make a suite that performs
 * hundreds of unlocks unusable. The floor itself is verified directly by [KdfFloorTest];
 * everything else is testing logic above the KDF, where its cost is irrelevant.
 */
object TestVaults {

    /** Fast, deliberately below-floor parameters. Never used outside tests. */
    fun fastKdf(salt: ByteArray = VaultCrypto.randomSalt()): KdfParams = KdfParams(
        memoryKib = 1024,
        iterations = 1,
        parallelism = 1,
        salt = salt,
    )

    fun passphrase(value: String = "correct horse battery staple"): SecretBytes =
        SecretBytes.fromPassphrase(value.toCharArray())

    const val NOW: Long = 1_757_000_000_000L

    /** A vault sealed over [plaintext], with both a passphrase and a recovery slot. */
    fun create(
        plaintext: ByteArray = SAMPLE_PLAINTEXT,
        passphraseValue: String = "correct horse battery staple",
        recovery: SecretBytes = VaultCrypto.generateRecoveryKey(),
    ): Fixture {
        val pass = passphrase(passphraseValue)
        val created = pass.use { p ->
            VaultCrypto.create(
                plaintext = plaintext,
                passphrase = p,
                recoveryKey = recovery,
                nowEpochMillis = NOW,
                passphraseKdf = fastKdf(),
                recoveryKdf = fastKdf(),
            )
        }
        return Fixture(created.bytes, recovery, passphraseValue).also { created.close() }
    }

    class Fixture(
        val bytes: ByteArray,
        val recoveryKey: SecretBytes,
        val passphraseValue: String,
    )

    /**
     * Sentinel values, used by the leak tests.
     *
     * Chosen to be long and unmistakable so a scan over raw bytes cannot produce a false
     * positive, and so a hit is unambiguous evidence of a real leak.
     */
    const val SENTINEL_PASSWORD = "SENTINEL_PW_a7f3c9e12b4d8006_DO_NOT_LEAK"
    const val SENTINEL_USERNAME = "SENTINEL_USER_5c1e77aa93b20411@example.invalid"
    const val SENTINEL_URL = "https://SENTINEL-SITE-8b2f41d9.example.invalid/login"
    const val SENTINEL_NOTE = "SENTINEL_NOTE_ff01aa77cc22e590 recovery words"

    val SENTINELS: List<String> = listOf(
        SENTINEL_PASSWORD, SENTINEL_USERNAME, SENTINEL_URL, SENTINEL_NOTE,
    )

    val SAMPLE_PLAINTEXT: ByteArray = """
        {"items":[{"title":"Example","username":"$SENTINEL_USERNAME",
        "password":"$SENTINEL_PASSWORD","url":"$SENTINEL_URL","notes":"$SENTINEL_NOTE"}]}
    """.trimIndent().toByteArray()

    /** True if [haystack] contains [needle] anywhere, as raw bytes. */
    fun containsBytes(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }
}
