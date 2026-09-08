package com.passwird.crypto

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The recovery key is the only way back into a vault whose passphrase is gone, and it is
 * transcribed by a stressed human onto paper. Every test here is about that transcription
 * surviving contact with reality.
 */
class RecoveryKeyTest {

    @Test
    fun `the format carries the full 128 bits`() {
        // The original specification called for 24 characters, which at 5 bits each holds
        // only 120 bits. Shipping that would have silently thrown away 8 bits of the
        // recovery key — a 256x reduction in guessing work — so the format is 26 data
        // characters plus 2 of checksum.
        assertEquals(26, RecoveryKey.DATA_CHARS)
        assertTrue(
            RecoveryKey.DATA_CHARS * 5 >= RecoveryKey.KEY_BYTES * 8,
            "the encoding must have capacity for every bit of the key",
        )
        assertEquals(28, RecoveryKey.TOTAL_CHARS)
        assertEquals(7, RecoveryKey.GROUP_COUNT)
    }

    @Test
    fun `round trips every generated key exactly`() {
        repeat(500) {
            val (key, rendered) = RecoveryKey.generateFormatted()
            val original = key.copyBytes()

            val parsed = RecoveryKey.parse(rendered)
            assertIs<RecoveryKey.ParseResult.Valid>(parsed, "failed to parse '$rendered'")
            assertContentEquals(original, parsed.key.copyBytes(), "round trip changed the key")

            key.close()
            parsed.key.close()
        }
    }

    @Test
    fun `renders in seven groups of four`() {
        val (key, rendered) = RecoveryKey.generateFormatted()
        val groups = rendered.split("-")

        assertEquals(7, groups.size, "expected seven groups, got '$rendered'")
        assertTrue(groups.all { it.length == 4 })
        assertEquals(28 + 6, rendered.length)
        key.close()
    }

    @Test
    fun `never emits an ambiguous character`() {
        // The whole reason for Crockford: someone reading this aloud or writing it down
        // must not be able to produce a character whose meaning is uncertain.
        repeat(500) {
            val (key, rendered) = RecoveryKey.generateFormatted()
            for (forbidden in listOf('I', 'L', 'O', 'U')) {
                assertFalse(rendered.contains(forbidden), "'$forbidden' appeared in '$rendered'")
            }
            key.close()
        }
    }

    @Test
    fun `accepts the mistakes people actually make`() {
        val (key, rendered) = RecoveryKey.generateFormatted()
        val expected = key.copyBytes()

        val variants = mapOf(
            "lower case" to rendered.lowercase(),
            "spaces instead of hyphens" to rendered.replace("-", " "),
            "no separators at all" to rendered.replace("-", ""),
            "leading and trailing whitespace" to "  $rendered  ",
            "letter O written for zero" to rendered.replace('0', 'O'),
            "letter l written for one" to rendered.replace('1', 'l'),
            "capital I written for one" to rendered.replace('1', 'I'),
        )

        for ((description, variant) in variants) {
            val parsed = RecoveryKey.parse(variant)
            assertIs<RecoveryKey.ParseResult.Valid>(parsed, "rejected $description: '$variant'")
            assertContentEquals(expected, parsed.key.copyBytes(), "$description decoded to the wrong key")
            parsed.key.close()
        }
        key.close()
    }

    @Test
    fun `catches a single mistyped character before the KDF runs`() {
        // Without this the user waits half a second for Argon2 and is then told only that
        // it did not work, with no idea whether they mistyped or have the wrong key.
        val random = Random(20260908)
        var caught = 0
        val attempts = 400

        repeat(attempts) {
            val (key, rendered) = RecoveryKey.generateFormatted()
            val characters = rendered.filter { it != '-' }.toCharArray()

            val position = random.nextInt(characters.size)
            val alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
            var replacement = alphabet[random.nextInt(alphabet.length)]
            while (replacement == characters[position]) {
                replacement = alphabet[random.nextInt(alphabet.length)]
            }
            characters[position] = replacement

            if (RecoveryKey.parse(String(characters)) is RecoveryKey.ParseResult.ChecksumMismatch) {
                caught++
            }
            key.close()
        }

        // Ten bits of checksum: roughly 1 in 1024 typos slips through. Over 400 trials that
        // is ~99.6% expected, so anything below 97% means the checksum is not working.
        val rate = caught.toDouble() / attempts
        assertTrue(rate > 0.97, "only caught ${(rate * 100).toInt()}% of single-character typos")
    }

    @Test
    fun `catches transposed characters`() {
        // A parity checksum would miss these entirely, which is why the checksum is a digest.
        val random = Random(7)
        var caught = 0
        var tried = 0

        repeat(300) {
            val (key, rendered) = RecoveryKey.generateFormatted()
            val characters = rendered.filter { it != '-' }.toCharArray()
            val at = random.nextInt(characters.size - 1)

            if (characters[at] != characters[at + 1]) {
                val swapped = characters.copyOf()
                swapped[at] = characters[at + 1]
                swapped[at + 1] = characters[at]
                tried++
                if (RecoveryKey.parse(String(swapped)) is RecoveryKey.ParseResult.ChecksumMismatch) {
                    caught++
                }
            }
            key.close()
        }

        assertTrue(tried > 200, "test did not exercise enough transpositions")
        assertTrue(caught.toDouble() / tried > 0.97, "transpositions are slipping through")
    }

    @Test
    fun `reports malformed input distinctly from a bad checksum`() {
        // The UI says different things for these: one is "check for a typo", the other is
        // "that doesn't look like a recovery key".
        assertIs<RecoveryKey.ParseResult.Malformed>(RecoveryKey.parse(""))
        assertIs<RecoveryKey.ParseResult.Malformed>(RecoveryKey.parse("TOO-SHORT"))
        assertIs<RecoveryKey.ParseResult.Malformed>(RecoveryKey.parse("A".repeat(40)))
        // U is not in the alphabet and is not folded to anything.
        assertIs<RecoveryKey.ParseResult.Malformed>(RecoveryKey.parse("U".repeat(28)))
    }

    @Test
    fun `a wrong-length key is rejected rather than padded`() {
        assertFailsWith<IllegalArgumentException> { RecoveryKey.encode(ByteArray(15)) }
        assertFailsWith<IllegalArgumentException> { RecoveryKey.encode(ByteArray(17)) }
    }

    @Test
    fun `the encoding is deterministic and injective over sampled keys`() {
        val seen = HashMap<String, String>()
        repeat(2_000) {
            val key = VaultCrypto.generateRecoveryKey()
            val bytes = B64.encode(key.copyBytes())
            val rendered = RecoveryKey.format(key)

            seen[rendered]?.let { previous ->
                assertEquals(previous, bytes, "two different keys rendered identically")
            }
            seen[rendered] = bytes
            assertEquals(rendered, RecoveryKey.format(key), "formatting is not deterministic")
            key.close()
        }
        assertEquals(2_000, seen.size, "the encoding collided")
    }

    @Test
    fun `a parsed key actually opens a vault`() {
        // The property that matters end to end: what the user writes down is what unlocks.
        val recovery = VaultCrypto.generateRecoveryKey()
        val rendered = RecoveryKey.format(recovery)

        val fixture = TestVaults.create(recovery = recovery)

        val parsed = RecoveryKey.parse(rendered)
        assertIs<RecoveryKey.ParseResult.Valid>(parsed)

        VaultCrypto.unseal(fixture.bytes, parsed.key, SlotType.RECOVERY).use { vault ->
            assertContentEquals(TestVaults.SAMPLE_PLAINTEXT, vault.plaintext)
        }
        parsed.key.close()
    }
}

/**
 * The biometric unlock path, end to end at the crypto layer.
 *
 * Before this existed, `SlotType.DEVICE` was defined and tested only in the negative — that
 * a device slot is refused inside a vault file. Nothing created one, so the fast daily
 * unlock the product depends on had no implementation underneath it.
 */
class DeviceSlotTest {

    private fun openVault(): Pair<TestVaults.Fixture, UnsealedVault> {
        val fixture = TestVaults.create()
        val vault = TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            VaultCrypto.unseal(fixture.bytes, pass, SlotType.PASSPHRASE)
        }
        return fixture to vault
    }

    @Test
    fun `a device slot opens the vault without the passphrase`() {
        val (fixture, vault) = openVault()
        val deviceKey = VaultCrypto.generateDeviceKey()

        val slot = vault.use {
            VaultCrypto.createDeviceSlot(it.vek, deviceKey, "Pixel 9", TestVaults.NOW)
        }

        VaultCrypto.unsealWithDeviceSlot(fixture.bytes, slot, deviceKey).use { opened ->
            assertContentEquals(TestVaults.SAMPLE_PLAINTEXT, opened.plaintext)
            assertEquals(SlotType.DEVICE, opened.unlockedWith.type)
            assertFalse(opened.kdfUpgradeRequired, "a device slot has no KDF to upgrade")
        }
        deviceKey.close()
    }

    @Test
    fun `a device slot has no KDF, so unlock is instant`() {
        // The reason biometric unlock is fast: the secret is already full entropy, so
        // stretching it would cost half a second per unlock and add nothing.
        val (_, vault) = openVault()
        val deviceKey = VaultCrypto.generateDeviceKey()

        val slot = vault.use { VaultCrypto.createDeviceSlot(it.vek, deviceKey, "Pixel 9", TestVaults.NOW) }
        assertEquals(null, slot.kdf)
        deviceKey.close()
    }

    @Test
    fun `the wrong device key does not open the slot`() {
        val (fixture, vault) = openVault()
        val deviceKey = VaultCrypto.generateDeviceKey()
        val slot = vault.use { VaultCrypto.createDeviceSlot(it.vek, deviceKey, "Pixel 9", TestVaults.NOW) }

        VaultCrypto.generateDeviceKey().use { impostor ->
            assertFailsWith<CryptoError.WrongSecret> {
                VaultCrypto.unsealWithDeviceSlot(fixture.bytes, slot, impostor)
            }
        }
        deviceKey.close()
    }

    @Test
    fun `a device slot is never accepted inside a vault file`() {
        val (_, vault) = openVault()
        val deviceKey = VaultCrypto.generateDeviceKey()
        val slot = vault.use { vaultOpen ->
            val deviceSlot = VaultCrypto.createDeviceSlot(vaultOpen.vek, deviceKey, "Pixel 9", TestVaults.NOW)
            // Syncing it would leak the device count and be useless on any other phone,
            // so the header refuses it structurally rather than by convention.
            assertFailsWith<IllegalArgumentException> {
                vaultOpen.header.copy(slots = vaultOpen.header.slots + deviceSlot)
            }
            deviceSlot
        }
        assertFalse(slot.isSyncable)
        deviceKey.close()
    }

    @Test
    fun `revoking one device leaves every other unlock path working`() {
        // Device revocation must be a local slot deletion, not something that disturbs the
        // passphrase, the recovery key, or another phone.
        val (fixture, vault) = openVault()
        val phoneA = VaultCrypto.generateDeviceKey()
        val phoneB = VaultCrypto.generateDeviceKey()

        val (slotA, slotB) = vault.use {
            VaultCrypto.createDeviceSlot(it.vek, phoneA, "Phone A", TestVaults.NOW) to
                VaultCrypto.createDeviceSlot(it.vek, phoneB, "Phone B", TestVaults.NOW)
        }

        // Phone A is "revoked" by discarding its slot. Nothing else is touched.
        VaultCrypto.unsealWithDeviceSlot(fixture.bytes, slotB, phoneB).use {
            assertContentEquals(TestVaults.SAMPLE_PLAINTEXT, it.plaintext)
        }
        TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            VaultCrypto.unseal(fixture.bytes, pass, SlotType.PASSPHRASE).use {
                assertContentEquals(TestVaults.SAMPLE_PLAINTEXT, it.plaintext)
            }
        }
        VaultCrypto.unseal(fixture.bytes, fixture.recoveryKey, SlotType.RECOVERY).use {
            assertContentEquals(TestVaults.SAMPLE_PLAINTEXT, it.plaintext)
        }

        // And slot A still works while it is retained, which is what makes revocation an
        // explicit act rather than an accident.
        VaultCrypto.unsealWithDeviceSlot(fixture.bytes, slotA, phoneA).use {
            assertContentEquals(TestVaults.SAMPLE_PLAINTEXT, it.plaintext)
        }

        phoneA.close(); phoneB.close()
    }

    @Test
    fun `rotating the VEK invalidates every device slot`() {
        // The documented cost of rotation: all devices must re-enrol. Asserted so the
        // product cannot quietly stop honouring it.
        val (fixture, vault) = openVault()
        val deviceKey = VaultCrypto.generateDeviceKey()
        val newRecovery = VaultCrypto.generateRecoveryKey()

        val (slot, rotated) = vault.use { open ->
            val deviceSlot = VaultCrypto.createDeviceSlot(open.vek, deviceKey, "Pixel 9", TestVaults.NOW)
            val sealed = TestVaults.passphrase(fixture.passphraseValue).use { pass ->
                VaultCrypto.rotateVek(
                    open, pass, newRecovery, TestVaults.NOW,
                    TestVaults.fastKdf(), TestVaults.fastKdf(),
                )
            }
            deviceSlot to sealed
        }

        assertFailsWith<CryptoError> {
            VaultCrypto.unsealWithDeviceSlot(rotated.bytes, slot, deviceKey)
        }
        deviceKey.close()
    }

    @Test
    fun `a device key must be full-entropy, not a password`() {
        val (_, vault) = openVault()
        vault.use { open ->
            SecretBytes.copyOf("hunter2".toByteArray()).use { weak ->
                // Accepting a short secret here would create an unstretched slot that an
                // attacker with the local file could brute-force instantly.
                assertFailsWith<IllegalArgumentException> {
                    VaultCrypto.createDeviceSlot(open.vek, weak, "Pixel 9", TestVaults.NOW)
                }
            }
        }
    }

    @Test
    fun `each device slot is independently wrapped`() {
        val (_, vault) = openVault()
        val phoneA = VaultCrypto.generateDeviceKey()
        val phoneB = VaultCrypto.generateDeviceKey()

        val (slotA, slotB) = vault.use {
            VaultCrypto.createDeviceSlot(it.vek, phoneA, "Phone A", TestVaults.NOW) to
                VaultCrypto.createDeviceSlot(it.vek, phoneB, "Phone B", TestVaults.NOW)
        }

        assertFalse(slotA.id.contentEquals(slotB.id))
        assertFalse(slotA.wrapped.contentEquals(slotB.wrapped))
        assertFalse(slotA.commitment.contentEquals(slotB.commitment))

        // One device's key must not open another's slot.
        assertFailsWith<CryptoError.WrongSecret> { KeySlots.unwrap(slotA, phoneB, enforceFloor = false) }

        phoneA.close(); phoneB.close()
    }
}
