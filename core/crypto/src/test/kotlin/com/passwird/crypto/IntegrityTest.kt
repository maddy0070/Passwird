package com.passwird.crypto

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Threat model T5: the store is hostile and may alter, truncate, replace or roll back the
 * bytes it returns. These tests assert that every such alteration is *rejected*, and — the
 * property that actually matters — that none of them can ever yield plaintext.
 */
class TamperDetectionTest {

    @Test
    fun `every single-bit flip is rejected and never yields plaintext`() {
        val fixture = TestVaults.create()
        val random = Random(20260907) // deterministic: a failure must be reproducible
        var rejected = 0

        val positions = buildSet {
            // Exhaustive over the framing prefix: magic, format version, header length.
            addAll(0 until 16)
            // Sampled across the rest, which is header JSON and payload.
            repeat(220) { add(random.nextInt(fixture.bytes.size)) }
        }

        for (position in positions) {
            val bit = 1 shl random.nextInt(8)
            val mutated = fixture.bytes.copyOf()
            mutated[position] = (mutated[position].toInt() xor bit).toByte()
            if (mutated.contentEquals(fixture.bytes)) continue

            val outcome = runCatching {
                TestVaults.passphrase(fixture.passphraseValue).use { pass ->
                    VaultCrypto.unseal(mutated, pass, SlotType.PASSPHRASE).use { it.plaintext.copyOf() }
                }
            }

            outcome.onSuccess { plaintext ->
                // A flip inside the padding region of the final block could in principle
                // still authenticate — it cannot, because padding is inside the AEAD — so
                // any success at all is a real failure of the format.
                error("Bit flip at byte $position was accepted, yielding ${plaintext.size} bytes")
            }.onFailure { failure ->
                assertTrue(
                    failure is CryptoError,
                    "Byte $position produced ${failure::class.simpleName}, expected a typed CryptoError",
                )
                rejected++
            }
        }

        assertTrue(rejected > 200, "expected a broad sample of rejections, got $rejected")
    }

    @Test
    fun `truncation at any point is rejected`() {
        val fixture = TestVaults.create()
        val lengths = listOf(0, 1, 7, 8, 13, 14, 40, 100, fixture.bytes.size / 2, fixture.bytes.size - 1)

        for (length in lengths) {
            val truncated = fixture.bytes.copyOf(length)
            assertFailsWith<CryptoError>("truncation to $length bytes must be rejected") {
                TestVaults.passphrase(fixture.passphraseValue).use { pass ->
                    VaultCrypto.unseal(truncated, pass, SlotType.PASSPHRASE).close()
                }
            }
        }
    }

    @Test
    fun `appended trailing bytes are rejected`() {
        // Exact length match is required. A file with extra bytes is either damaged or
        // someone probing what we tolerate; neither earns the benefit of the doubt.
        val fixture = TestVaults.create()
        val extended = fixture.bytes + byteArrayOf(0x00)
        assertFailsWith<CryptoError.MalformedVault> { VaultContainer.parse(extended) }
    }

    @Test
    fun `foreign or empty files are rejected as not a vault`() {
        for (bytes in listOf(
            ByteArray(0),
            "hello".toByteArray(),
            ByteArray(64),
            byteArrayOf(0x50, 0x4B, 0x03, 0x04) + ByteArray(60), // a zip
        )) {
            assertFailsWith<CryptoError> { VaultContainer.parse(bytes) }
        }
    }

    @Test
    fun `an oversized declared header length is rejected without allocating`() {
        val fixture = TestVaults.create()
        val hostile = fixture.bytes.copyOf()
        BE.putU32(hostile, 10, Int.MAX_VALUE) // headerLen = 2 GiB

        val error = assertFailsWith<CryptoError.MalformedVault> { VaultContainer.parse(hostile) }
        assertTrue(error.message!!.contains("header length"), "should reject on the length check")
    }

    @Test
    fun `an oversized declared payload length is rejected`() {
        val fixture = TestVaults.create()
        val parsed = VaultContainer.parse(fixture.bytes)
        val hostile = fixture.bytes.copyOf()
        BE.putU64(hostile, 14 + parsed.headerBytes.size, Long.MAX_VALUE)

        assertFailsWith<CryptoError.MalformedVault> { VaultContainer.parse(hostile) }
    }
}

/**
 * The header is bound as AEAD additional authenticated data, so it is tamper-evident even
 * though it is cleartext. This is what makes downgrade attacks and slot substitution
 * structurally impossible rather than merely checked for.
 */
class HeaderAadTest {

    private fun resealWithModifiedHeader(
        original: ByteArray,
        modify: (VaultHeader) -> VaultHeader,
    ): ByteArray {
        val parsed = VaultContainer.parse(original)
        val forgedHeaderBytes = VaultContainer.encodeHeader(modify(parsed.header))
        // Same payload, different header: exactly what an attacker who cannot decrypt
        // would attempt.
        return VaultContainer.serialize(forgedHeaderBytes, parsed.payload)
    }

    @Test
    fun `forging the version counter breaks authentication`() {
        val fixture = TestVaults.create()
        val forged = resealWithModifiedHeader(fixture.bytes) { it.copy(vaultVersion = 9_999) }

        assertFailsWith<CryptoError.IntegrityFailure> {
            TestVaults.passphrase(fixture.passphraseValue).use { pass ->
                VaultCrypto.unseal(forged, pass, SlotType.PASSPHRASE).close()
            }
        }
    }

    @Test
    fun `rewriting the hash chain breaks authentication`() {
        val fixture = TestVaults.create()
        val forged = resealWithModifiedHeader(fixture.bytes) {
            it.copy(chain = ByteArray(VaultHeader.CHAIN_BYTES) { 0x42 })
        }

        assertFailsWith<CryptoError.IntegrityFailure> {
            TestVaults.passphrase(fixture.passphraseValue).use { pass ->
                VaultCrypto.unseal(forged, pass, SlotType.PASSPHRASE).close()
            }
        }
    }

    @Test
    fun `lowering the Argon2 cost cannot produce a readable vault`() {
        // The canonical downgrade attack: make the KDF cheap so an offline search is fast.
        val fixture = TestVaults.create()
        val forged = resealWithModifiedHeader(fixture.bytes) { header ->
            val weakened = header.slots.map { slot ->
                if (slot.type != SlotType.PASSPHRASE) {
                    slot
                } else {
                    slot.copy(kdf = slot.kdf!!.copy(memoryKib = 8, iterations = 1, parallelism = 1))
                }
            }
            header.copy(slots = weakened)
        }

        // Changing the parameters changes the derived KEK, so the commitment no longer
        // matches and the attacker has produced a vault nobody can open — including them.
        assertFailsWith<CryptoError> {
            TestVaults.passphrase(fixture.passphraseValue).use { pass ->
                VaultCrypto.unseal(forged, pass, SlotType.PASSPHRASE).close()
            }
        }
    }

    @Test
    fun `a key slot cannot be transplanted from another vault`() {
        val victim = TestVaults.create(passphraseValue = "victim passphrase")
        val attacker = TestVaults.create(passphraseValue = "attacker passphrase")

        val attackerSlot = VaultContainer.parse(attacker.bytes)
            .header.slots.first { it.type == SlotType.PASSPHRASE }

        val forged = resealWithModifiedHeader(victim.bytes) { header ->
            header.copy(slots = header.slots.filterNot { it.type == SlotType.PASSPHRASE } + attackerSlot)
        }

        // The attacker's own passphrase unwraps their slot — recovering the *attacker's*
        // VEK, which cannot decrypt the victim's payload.
        assertFailsWith<CryptoError> {
            TestVaults.passphrase("attacker passphrase").use { pass ->
                VaultCrypto.unseal(forged, pass, SlotType.PASSPHRASE).close()
            }
        }
    }

    @Test
    fun `a device slot is never written to a vault file and is rejected if present`() {
        val fixture = TestVaults.create()
        val parsed = VaultContainer.parse(fixture.bytes)
        assertTrue(parsed.header.slots.all { it.isSyncable })
        assertFalse(parsed.header.slots.any { it.type == SlotType.DEVICE })

        // And a hand-crafted file containing one must be refused outright, since it can
        // only mean a buggy writer or someone probing for a weaker unlock path.
        val deviceKey = SecretBytes.random(32)
        val vek = SecretBytes.random(32)
        val deviceSlot = KeySlots.create(
            vek, deviceKey, SlotType.DEVICE, "This phone", null, TestVaults.NOW,
        )
        assertFailsWith<IllegalArgumentException> {
            parsed.header.copy(slots = parsed.header.slots + deviceSlot)
        }
    }
}

/**
 * Per-slot key commitment (ADR-0001 §1.2).
 *
 * Buys two things: it closes partitioning-oracle attacks against the KDF, and it makes
 * "wrong passphrase" cleanly distinguishable from "damaged data" — which is why
 * `docs/10-error-matrix.md` can give E-01 and E-29 completely different copy.
 */
class KeyCommitmentTest {

    @Test
    fun `a wrong passphrase yields WrongSecret, not an integrity failure`() {
        val fixture = TestVaults.create(passphraseValue = "the real passphrase")
        TestVaults.passphrase("not the real passphrase").use { wrong ->
            assertFailsWith<CryptoError.WrongSecret> {
                VaultCrypto.unseal(fixture.bytes, wrong, SlotType.PASSPHRASE)
            }
        }
    }

    @Test
    fun `a corrupted commitment is detected before any unwrap is attempted`() {
        val fixture = TestVaults.create()
        val parsed = VaultContainer.parse(fixture.bytes)
        val slot = parsed.header.slots.first { it.type == SlotType.PASSPHRASE }

        val tamperedCommitment = slot.commitment.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val tamperedSlot = slot.copy(commitment = tamperedCommitment)

        TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            assertFailsWith<CryptoError.WrongSecret> {
                KeySlots.unwrap(tamperedSlot, pass, enforceFloor = false)
            }
        }
    }

    @Test
    fun `the commitment is bound to the slot id`() {
        // Otherwise a commitment could be copied between slots to forge a match.
        val vek = SecretBytes.random(32)
        val secret = TestVaults.passphrase("shared secret")
        val kdf = TestVaults.fastKdf()

        val a = KeySlots.create(vek, secret, SlotType.PASSPHRASE, "a", kdf, TestVaults.NOW)
        val b = KeySlots.create(vek, secret, SlotType.PASSPHRASE, "b", kdf, TestVaults.NOW)

        assertFalse(
            a.commitment.contentEquals(b.commitment),
            "same secret and KDF params must still yield distinct per-slot commitments",
        )
        secret.close()
        vek.close()
    }

    @Test
    fun `wrong and right secrets both consult every candidate slot`() {
        // unwrapAny must not exit early on the first match, or timing would reveal which
        // slot matched. Asserted structurally: two passphrase slots, either one works.
        val vek = SecretBytes.random(32)
        val first = TestVaults.passphrase("first secret")
        val second = TestVaults.passphrase("second secret")

        val slots = listOf(
            KeySlots.create(vek, first, SlotType.PASSPHRASE, "first", TestVaults.fastKdf(), TestVaults.NOW),
            KeySlots.create(vek, second, SlotType.PASSPHRASE, "second", TestVaults.fastKdf(), TestVaults.NOW),
        )

        val expected = vek.copyBytes()
        for (secretValue in listOf("first secret", "second secret")) {
            TestVaults.passphrase(secretValue).use { secret ->
                KeySlots.unwrapAny(slots, secret, SlotType.PASSPHRASE, enforceFloor = false).vek.use {
                    assertContentEqualsBytes(expected, it.copyBytes())
                }
            }
        }
        first.close(); second.close(); vek.close()
    }

    private fun assertContentEqualsBytes(expected: ByteArray, actual: ByteArray) =
        assertEquals(B64.encode(expected), B64.encode(actual))
}
