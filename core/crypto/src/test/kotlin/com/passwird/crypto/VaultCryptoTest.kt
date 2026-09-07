package com.passwird.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Core lifecycle: create, unlock, re-seal, change secrets, rotate. */
class VaultCryptoTest {

    @Test
    fun `round trips a vault through seal and unseal`() {
        val fixture = TestVaults.create()
        TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            VaultCrypto.unseal(fixture.bytes, pass, SlotType.PASSPHRASE).use { vault ->
                assertContentEquals(TestVaults.SAMPLE_PLAINTEXT, vault.plaintext)
                assertEquals(1, vault.header.vaultVersion)
            }
        }
    }

    @Test
    fun `unlocks with the recovery key`() {
        val fixture = TestVaults.create()
        VaultCrypto.unseal(fixture.bytes, fixture.recoveryKey, SlotType.RECOVERY).use { vault ->
            assertContentEquals(TestVaults.SAMPLE_PLAINTEXT, vault.plaintext)
        }
    }

    @Test
    fun `a passphrase cannot open the recovery slot`() {
        val fixture = TestVaults.create()
        TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            // Slot types are bound into the wrap AAD, so a secret is only ever valid for
            // the slot type it was created for.
            assertFailsWith<CryptoError.WrongSecret> {
                VaultCrypto.unseal(fixture.bytes, pass, SlotType.RECOVERY)
            }
        }
    }

    @Test
    fun `handles empty and large payloads`() {
        for (size in listOf(0, 1, 4095, 4096, 65_536, 200_000)) {
            val plaintext = ByteArray(size) { (it % 251).toByte() }
            val fixture = TestVaults.create(plaintext = plaintext)
            TestVaults.passphrase(fixture.passphraseValue).use { pass ->
                VaultCrypto.unseal(fixture.bytes, pass, SlotType.PASSPHRASE).use { vault ->
                    assertContentEquals(plaintext, vault.plaintext, "payload of $size bytes")
                }
            }
        }
    }

    @Test
    fun `preserves adversarial unicode exactly`() {
        val nasty = "\u0000\uFFFD🔐 ünïcødé \u202E\u200B".toByteArray()
        val fixture = TestVaults.create(plaintext = nasty)
        TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            VaultCrypto.unseal(fixture.bytes, pass, SlotType.PASSPHRASE).use {
                assertContentEquals(nasty, it.plaintext)
            }
        }
    }

    @Test
    fun `every write uses a fresh salt nonce and content key`() {
        val fixture = TestVaults.create()
        val salts = mutableSetOf<String>()
        val nonces = mutableSetOf<String>()
        val payloads = mutableSetOf<String>()

        var current = fixture.bytes
        repeat(12) {
            TestVaults.passphrase(fixture.passphraseValue).use { pass ->
                VaultCrypto.unseal(current, pass, SlotType.PASSPHRASE).use { vault ->
                    val sealed = VaultCrypto.reseal(vault, TestVaults.SAMPLE_PLAINTEXT)
                    salts += B64.encode(sealed.header.fileSalt)
                    nonces += B64.encode(sealed.header.nonce)
                    payloads += B64.encode(VaultContainer.parse(sealed.bytes).payload)
                    current = sealed.bytes
                }
            }
        }

        // Identical plaintext must never produce identical ciphertext. This is the
        // property that makes the per-write derived key meaningful (ADR-0001).
        assertEquals(12, salts.size, "fileSalt must be fresh on every write")
        assertEquals(12, nonces.size, "nonce must be fresh on every write")
        assertEquals(12, payloads.size, "identical plaintext must not produce identical ciphertext")
    }

    @Test
    fun `version increments and the hash chain links each write`() {
        val fixture = TestVaults.create()
        var current = fixture.bytes
        var previousHeaderBytes: ByteArray? = null

        for (expectedVersion in 2..5) {
            TestVaults.passphrase(fixture.passphraseValue).use { pass ->
                VaultCrypto.unseal(current, pass, SlotType.PASSPHRASE).use { vault ->
                    previousHeaderBytes = vault.headerBytes
                    val sealed = VaultCrypto.reseal(vault, TestVaults.SAMPLE_PLAINTEXT)
                    assertEquals(expectedVersion.toLong(), sealed.header.vaultVersion)
                    assertTrue(
                        VaultCrypto.verifyChain(sealed.header, previousHeaderBytes),
                        "version $expectedVersion must chain from its predecessor",
                    )
                    current = sealed.bytes
                }
            }
        }
    }

    @Test
    fun `changing the passphrase leaves the payload and other slots intact`() {
        val fixture = TestVaults.create()
        val newPassphrase = "a completely different passphrase"

        val updated = TestVaults.passphrase(fixture.passphraseValue).use { oldPass ->
            VaultCrypto.unseal(fixture.bytes, oldPass, SlotType.PASSPHRASE).use { vault ->
                TestVaults.passphrase(newPassphrase).use { newPass ->
                    VaultCrypto.changePassphrase(
                        vault, newPass, TestVaults.NOW, TestVaults.fastKdf(),
                    )
                }
            }
        }

        TestVaults.passphrase(newPassphrase).use { pass ->
            VaultCrypto.unseal(updated.bytes, pass, SlotType.PASSPHRASE).use {
                assertContentEquals(TestVaults.SAMPLE_PLAINTEXT, it.plaintext)
            }
        }
        // The old passphrase must stop working...
        TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            assertFailsWith<CryptoError.WrongSecret> {
                VaultCrypto.unseal(updated.bytes, pass, SlotType.PASSPHRASE)
            }
        }
        // ...while the recovery key is untouched, because slots are independent.
        VaultCrypto.unseal(updated.bytes, fixture.recoveryKey, SlotType.RECOVERY).use {
            assertContentEquals(TestVaults.SAMPLE_PLAINTEXT, it.plaintext)
        }
    }

    @Test
    fun `rotating the VEK invalidates the old key material but preserves contents`() {
        val fixture = TestVaults.create()
        val newRecovery = VaultCrypto.generateRecoveryKey()

        val rotated = TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            VaultCrypto.unseal(fixture.bytes, pass, SlotType.PASSPHRASE).use { vault ->
                TestVaults.passphrase(fixture.passphraseValue).use { samePass ->
                    VaultCrypto.rotateVek(
                        vault, samePass, newRecovery, TestVaults.NOW,
                        TestVaults.fastKdf(), TestVaults.fastKdf(),
                    )
                }
            }
        }

        TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            VaultCrypto.unseal(rotated.bytes, pass, SlotType.PASSPHRASE).use {
                assertContentEquals(TestVaults.SAMPLE_PLAINTEXT, it.plaintext)
            }
        }
        // The previous recovery key must no longer open the rotated vault.
        assertFailsWith<CryptoError.WrongSecret> {
            VaultCrypto.unseal(rotated.bytes, fixture.recoveryKey, SlotType.RECOVERY)
        }
    }

    @Test
    fun `refuses to seal a vault with no passphrase slot`() {
        // Such a vault could only ever be opened on the device that made it — one lost
        // phone away from being permanently unrecoverable.
        val fixture = TestVaults.create()
        TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            VaultCrypto.unseal(fixture.bytes, pass, SlotType.PASSPHRASE).use { vault ->
                val recoveryOnly = vault.header.slots.filter { it.type == SlotType.RECOVERY }
                assertFailsWith<CryptoError.SlotError> {
                    VaultCrypto.reseal(vault, vault.plaintext, recoveryOnly)
                }
            }
        }
    }

    @Test
    fun `closing an unsealed vault wipes the plaintext and key`() {
        val fixture = TestVaults.create()
        TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            val vault = VaultCrypto.unseal(fixture.bytes, pass, SlotType.PASSPHRASE)
            val plaintextRef = vault.plaintext
            assertTrue(plaintextRef.any { it != 0.toByte() })

            vault.close()

            assertTrue(plaintextRef.all { it == 0.toByte() }, "plaintext must be zeroised on close")
            assertFalse(runCatching { vault.vek.copyBytes() }.isSuccess, "VEK must be closed")
        }
    }
}
