package com.passwird.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * **The test that backs the central product claim.**
 *
 * "Google Drive only ever receives ciphertext." Populates a vault with unmistakable
 * sentinel values, then scans every byte that would leave the device.
 *
 * The 2022 LastPass breach is the reason this is exhaustive rather than spot-checked:
 * those vaults were encrypted, but URL fields were not, and that alone revealed every
 * service each victim used.
 */
class CiphertextOnlyTest {

    @Test
    fun `no sentinel value appears anywhere in the bytes handed to the transport`() {
        val fixture = TestVaults.create()

        for (sentinel in TestVaults.SENTINELS) {
            assertFalse(
                TestVaults.containsBytes(fixture.bytes, sentinel.toByteArray()),
                "Sentinel '$sentinel' leaked into the vault artefact",
            )
        }
    }

    @Test
    fun `the passphrase itself never appears in the artefact`() {
        val fixture = TestVaults.create(passphraseValue = "SENTINEL_PASSPHRASE_9d41f0ba")
        assertFalse(
            TestVaults.containsBytes(fixture.bytes, "SENTINEL_PASSPHRASE_9d41f0ba".toByteArray()),
            "The master passphrase leaked into the vault artefact",
        )
    }

    @Test
    fun `the header carries no user-derived metadata`() {
        val fixture = TestVaults.create()
        val headerJson = VaultContainer.parse(fixture.bytes).headerBytes.toString(Charsets.UTF_8)

        for (sentinel in TestVaults.SENTINELS) {
            assertFalse(headerJson.contains(sentinel), "Header leaked '$sentinel'")
        }
        // The header must also not disclose the shape of the vault.
        for (forbidden in listOf("itemCount", "title", "username", "url", "email", "deviceId")) {
            assertFalse(headerJson.contains(forbidden), "Header exposes metadata field '$forbidden'")
        }
    }

    @Test
    fun `padding hides how much the vault changed between writes`() {
        // Two vaults differing by a single credential must produce identical file sizes,
        // so an observer cannot infer the size of an edit by differencing uploads.
        val small = TestVaults.create(plaintext = ByteArray(1_000) { 0x41 })
        val larger = TestVaults.create(plaintext = ByteArray(1_400) { 0x41 })

        assertEquals(
            VaultContainer.parse(small.bytes).payload.size,
            VaultContainer.parse(larger.bytes).payload.size,
            "payloads within one padding bucket must be indistinguishable in size",
        )
    }
}

/** Rollback and fork detection rest on this chain being verifiable. */
class HashChainTest {

    @Test
    fun `a genesis vault chains from zero`() {
        val fixture = TestVaults.create()
        val header = VaultContainer.peekHeader(fixture.bytes)
        assertTrue(VaultCrypto.verifyChain(header, previousHeaderBytes = null))
        assertContentEquals(ByteArray(VaultHeader.CHAIN_BYTES), header.chain)
    }

    @Test
    fun `a rewritten history fails chain validation`() {
        val fixture = TestVaults.create()
        val forkedHistory = TestVaults.create() // a different lineage entirely

        val v2 = TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            VaultCrypto.unseal(fixture.bytes, pass, SlotType.PASSPHRASE).use {
                VaultCrypto.reseal(it, TestVaults.SAMPLE_PLAINTEXT)
            }
        }

        assertTrue(VaultCrypto.verifyChain(v2.header, VaultContainer.parse(fixture.bytes).headerBytes))
        assertFalse(
            VaultCrypto.verifyChain(v2.header, VaultContainer.parse(forkedHistory.bytes).headerBytes),
            "a header from a different lineage must not validate",
        )
        assertFalse(VaultCrypto.verifyChain(v2.header, previousHeaderBytes = null))
    }
}

/**
 * Backwards compatibility was one of the four attack classes in the Feb 2026 ETH Zürich
 * study. These tests pin our position: never guess at an unknown format, and never let
 * legacy weak parameters persist silently.
 */
class DowngradeRejectionTest {

    @Test
    fun `an unsupported format version is refused rather than guessed at`() {
        val fixture = TestVaults.create()
        val futureFormat = fixture.bytes.copyOf()
        BE.putU16(futureFormat, 8, 99)

        val error = assertFailsWith<CryptoError.UnsupportedVersion> { VaultContainer.parse(futureFormat) }
        assertEquals(99, error.found)
    }

    @Test
    fun `format version zero is refused`() {
        val fixture = TestVaults.create()
        val zeroVersion = fixture.bytes.copyOf()
        BE.putU16(zeroVersion, 8, 0)
        assertFailsWith<CryptoError.UnsupportedVersion> { VaultContainer.parse(zeroVersion) }
    }

    @Test
    fun `strict policy refuses below-floor KDF parameters`() {
        val fixture = TestVaults.create() // built with deliberately fast, below-floor params
        TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            assertFailsWith<CryptoError.WeakKdfParameters> {
                VaultCrypto.unseal(fixture.bytes, pass, SlotType.PASSPHRASE, KdfPolicy.Strict)
            }
        }
    }

    @Test
    fun `legacy vaults open under the default policy but are flagged for re-keying`() {
        // Principle 1 outranks principle 2: refusing to open a genuinely old vault would
        // destroy data to defend against an attack the AAD binding already prevents.
        val fixture = TestVaults.create()
        TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            VaultCrypto.unseal(fixture.bytes, pass, SlotType.PASSPHRASE).use { vault ->
                assertTrue(vault.kdfUpgradeRequired, "below-floor parameters must be flagged")
                assertEquals(
                    setOf(SlotType.PASSPHRASE, SlotType.RECOVERY),
                    vault.weakSlotTypes,
                    "every below-floor slot should be reported",
                )
                assertContentEquals(TestVaults.SAMPLE_PLAINTEXT, vault.plaintext)
            }
        }
    }

    @Test
    fun `upgrading re-keys the slot that was actually used and clears its flag`() {
        val fixture = TestVaults.create()
        val upgraded = TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            VaultCrypto.unseal(fixture.bytes, pass, SlotType.PASSPHRASE).use { vault ->
                TestVaults.passphrase(fixture.passphraseValue).use { same ->
                    VaultCrypto.upgradeKdf(
                        vault, same, TestVaults.NOW,
                        KdfParams.default(VaultCrypto.randomSalt()),
                    )
                }
            }
        }

        TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            VaultCrypto.unseal(upgraded.bytes, pass, SlotType.PASSPHRASE, KdfPolicy.Strict).use { vault ->
                assertFalse(vault.kdfUpgradeRequired, "the upgraded slot must no longer be flagged")
                assertTrue(vault.unlockedWith.kdf!!.meetsFloor())
                assertContentEquals(TestVaults.SAMPLE_PLAINTEXT, vault.plaintext)

                // The recovery slot is deliberately untouched: nobody supplied the recovery
                // key, so it cannot be re-wrapped here. Reported, never silently "fixed".
                assertEquals(setOf(SlotType.RECOVERY), vault.weakSlotTypes)
            }
        }
    }

    @Test
    fun `rotating the recovery key clears the last weak slot`() {
        val fixture = TestVaults.create()
        val strongKdf = { KdfParams.default(VaultCrypto.randomSalt()) }

        val passphraseUpgraded = TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            VaultCrypto.unseal(fixture.bytes, pass, SlotType.PASSPHRASE).use { vault ->
                TestVaults.passphrase(fixture.passphraseValue).use { same ->
                    VaultCrypto.upgradeKdf(vault, same, TestVaults.NOW, strongKdf())
                }
            }
        }

        val newRecovery = VaultCrypto.generateRecoveryKey()
        val fullyUpgraded = TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            VaultCrypto.unseal(passphraseUpgraded.bytes, pass, SlotType.PASSPHRASE).use { vault ->
                VaultCrypto.rotateRecoveryKey(vault, newRecovery, TestVaults.NOW, strongKdf())
            }
        }

        VaultCrypto.unseal(fullyUpgraded.bytes, newRecovery, SlotType.RECOVERY, KdfPolicy.Strict).use { vault ->
            assertFalse(vault.kdfUpgradeRequired)
            assertTrue(vault.weakSlotTypes.isEmpty(), "no slot should remain below the floor")
            assertContentEquals(TestVaults.SAMPLE_PLAINTEXT, vault.plaintext)
        }
    }
}

/** The KDF floor is the last line of defence for a stolen encrypted file (threat T2). */
class KdfFloorTest {

    @Test
    fun `the floor matches the documented parameters`() {
        assertEquals(64 * 1024, KdfParams.FLOOR_MEMORY_KIB, "floor is 64 MiB")
        assertEquals(3, KdfParams.FLOOR_ITERATIONS)
        assertEquals(4, KdfParams.FLOOR_PARALLELISM)
        assertTrue(KdfParams.default(ByteArray(16)).meetsFloor())
    }

    @Test
    fun `weakening any single cost fails the floor`() {
        val salt = ByteArray(16)
        val base = KdfParams.default(salt)
        assertFalse(base.copy(memoryKib = KdfParams.FLOOR_MEMORY_KIB - 1).meetsFloor())
        assertFalse(base.copy(iterations = KdfParams.FLOOR_ITERATIONS - 1).meetsFloor())
        assertFalse(base.copy(parallelism = KdfParams.FLOOR_PARALLELISM - 1).meetsFloor())
    }

    @Test
    fun `absurd cost parameters are rejected instead of exhausting memory`() {
        // A hostile file must cost us an error, not an OOM kill.
        val hostile = KdfParams(
            memoryKib = KdfParams.MAX_MEMORY_KIB + 1,
            iterations = 3,
            parallelism = 4,
            salt = ByteArray(16),
        )
        TestVaults.passphrase().use { pass ->
            assertFailsWith<CryptoError.MalformedVault> { Argon2Kdf.deriveMuk(pass, hostile) }
        }
    }

    @Test
    fun `a short salt is rejected`() {
        assertFailsWith<IllegalArgumentException> {
            KdfParams(memoryKib = 65536, iterations = 3, parallelism = 4, salt = ByteArray(8))
        }
    }

    @Test
    fun `calibration never returns parameters below the floor`() {
        // Even on a device so slow that the very first candidate blows the budget, the
        // user gets a slower unlock — never a weaker vault.
        val instantlySlow = object {
            var calls = 0
            fun clock(): Long = (calls++ * 10_000_000_000L) // 10s per derivation
        }
        val params = Argon2Kdf.calibrate(
            salt = ByteArray(16),
            targetMillis = 1,
            maxMemoryKib = 64 * 1024,
            clock = instantlySlow::clock,
        )
        assertTrue(params.meetsFloor(), "calibration must never go below the floor")
    }

    @Test
    fun `argon2id is deterministic for the same inputs`() {
        val params = TestVaults.fastKdf(ByteArray(16) { 7 })
        val a = TestVaults.passphrase("same").use { Argon2Kdf.deriveMuk(it, params).use { k -> k.copyBytes() } }
        val b = TestVaults.passphrase("same").use { Argon2Kdf.deriveMuk(it, params).use { k -> k.copyBytes() } }
        assertContentEquals(a, b)

        val c = TestVaults.passphrase("different").use {
            Argon2Kdf.deriveMuk(it, params).use { k -> k.copyBytes() }
        }
        assertFalse(a.contentEquals(c))
    }
}
