package com.passwird.crypto

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PaddingTest {

    @Test
    fun `round trips every size across bucket boundaries`() {
        val random = Random(4242)
        val sizes = listOf(0, 1, 2, 4094, 4095, 4096, 4097, 65_535, 65_536, 65_537, 200_000) +
            List(40) { random.nextInt(0, 150_000) }

        for (size in sizes) {
            val original = ByteArray(size) { (it * 31 % 256).toByte() }
            val padded = Padding.pad(original)
            assertTrue(padded.size > size, "padding must always add at least the marker byte")
            assertContentEquals(original, Padding.unpad(padded), "round trip failed at size $size")
        }
    }

    @Test
    fun `pads to coarse buckets so edit size is not observable`() {
        assertEquals(4096, Padding.paddedSize(0))
        assertEquals(4096, Padding.paddedSize(1))
        assertEquals(4096, Padding.paddedSize(4095))
        // 4096 bytes needs a marker, so it spills into the next bucket.
        assertEquals(8192, Padding.paddedSize(4096))
        assertEquals(61_440, Padding.paddedSize(60_000)) // 15 × 4 KiB
        assertEquals(131_072, Padding.paddedSize(65_536))
        assertEquals(1_048_576, Padding.paddedSize(1_000_000))
    }

    @Test
    fun `content that is all zeros still round trips`() {
        // The failure mode this guards: a payload ending in zeros could be mistaken for
        // padding if the marker were not mandatory.
        val zeros = ByteArray(500)
        assertContentEquals(zeros, Padding.unpad(Padding.pad(zeros)))
    }

    @Test
    fun `malformed padding is rejected`() {
        assertFailsWith<CryptoError.MalformedVault> { Padding.unpad(ByteArray(0)) }
        assertFailsWith<CryptoError.MalformedVault> { Padding.unpad(ByteArray(16)) } // no marker
        assertFailsWith<CryptoError.MalformedVault> {
            Padding.unpad(ByteArray(16).also { it[10] = 0x7F }) // wrong marker value
        }
    }
}

class KeyDomainsTest {

    @Test
    fun `every domain label is unique`() {
        // A collision would silently make two logically distinct keys identical.
        assertEquals(KeyDomains.all.size, KeyDomains.all.toSet().size, "duplicate HKDF domain label")
    }

    @Test
    fun `every domain label is versioned`() {
        KeyDomains.all.forEach {
            assertTrue(it.startsWith("passwird/v1/"), "label '$it' is not versioned")
        }
    }

    @Test
    fun `different domains derive different keys from the same input`() {
        SecretBytes.random(32).use { ikm ->
            val derived = KeyDomains.all.map { info ->
                Hkdf.derive(ikm, info).use { B64.encode(it.copyBytes()) }
            }
            assertEquals(derived.size, derived.toSet().size, "domain separation is not effective")
        }
    }

    @Test
    fun `refuses to derive a key without domain separation`() {
        SecretBytes.random(32).use { ikm ->
            assertFailsWith<IllegalArgumentException> { Hkdf.derive(ikm, info = "") }
        }
    }

    @Test
    fun `the salt changes the derived key`() {
        SecretBytes.random(32).use { ikm ->
            val a = Hkdf.derive(ikm, KeyDomains.CONTENT, salt = ByteArray(32) { 1 }).use { it.copyBytes() }
            val b = Hkdf.derive(ikm, KeyDomains.CONTENT, salt = ByteArray(32) { 2 }).use { it.copyBytes() }
            assertFalse(a.contentEquals(b))
        }
    }
}

/**
 * Secrets must be structurally incapable of reaching a log.
 *
 * Redaction in `toString` is what makes an accidental `"key=$key"` harmless. Discipline
 * alone does not survive a codebase; the type system does.
 */
class RedactedToStringTest {

    @Test
    fun `SecretBytes never renders its contents`() {
        SecretBytes.copyOf(TestVaults.SENTINEL_PASSWORD.toByteArray()).use { secret ->
            val rendered = "$secret"
            assertFalse(rendered.contains(TestVaults.SENTINEL_PASSWORD))
            assertTrue(rendered.contains("redacted"))
        }
    }

    @Test
    fun `KeySlot renders no key material`() {
        val fixture = TestVaults.create()
        val slot = VaultContainer.parse(fixture.bytes).header.slots.first()
        val rendered = "$slot"

        assertFalse(rendered.contains(B64.encode(slot.wrapped)))
        assertFalse(rendered.contains(B64.encode(slot.commitment)))
    }

    @Test
    fun `UnsealedVault renders no plaintext`() {
        val fixture = TestVaults.create()
        TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            VaultCrypto.unseal(fixture.bytes, pass, SlotType.PASSPHRASE).use { vault ->
                val rendered = "$vault"
                TestVaults.SENTINELS.forEach { assertFalse(rendered.contains(it)) }
                assertTrue(rendered.contains("redacted"))
            }
        }
    }

    @Test
    fun `VaultHeader renders no key material`() {
        val fixture = TestVaults.create()
        val header = VaultContainer.peekHeader(fixture.bytes)
        val rendered = "$header"
        header.slots.forEach { assertFalse(rendered.contains(B64.encode(it.wrapped))) }
    }

    @Test
    fun `secrets refuse structural equality and hashing`() {
        SecretBytes.random(32).use { a ->
            SecretBytes.random(32).use { b ->
                // == would be a timing oracle; hashCode risks a secret reaching a
                // collection's diagnostics or a log line.
                assertFailsWith<UnsupportedOperationException> { a == b }
                assertFailsWith<UnsupportedOperationException> { a.hashCode() }
            }
        }
    }
}

class SecretBytesTest {

    @Test
    fun `close zeroises the backing array`() {
        val raw = ByteArray(32) { 0x5A }
        val secret = SecretBytes.adopt(raw)
        secret.close()
        assertTrue(raw.all { it == 0.toByte() })
    }

    @Test
    fun `use after close is rejected`() {
        val secret = SecretBytes.random(32)
        secret.close()
        assertFailsWith<IllegalStateException> { secret.copyBytes() }
        assertFailsWith<IllegalStateException> { secret.withBytes { it.size } }
    }

    @Test
    fun `close is idempotent`() {
        val secret = SecretBytes.random(32)
        secret.close()
        secret.close()
    }

    @Test
    fun `fromPassphrase wipes the caller's char array`() {
        val chars = "my secret passphrase".toCharArray()
        SecretBytes.fromPassphrase(chars).use { secret ->
            assertEquals("my secret passphrase".toByteArray().size, secret.size)
        }
        // Wiped to zero, so no residue of the original content remains.
        assertTrue(chars.all { it == '\u0000' }, "the caller's CharArray must be wiped")
    }

    @Test
    fun `fromPassphrase encodes unicode as UTF-8`() {
        val text = "pässwörd–🔐"
        SecretBytes.fromPassphrase(text.toCharArray()).use { secret ->
            assertContentEquals(text.toByteArray(Charsets.UTF_8), secret.copyBytes())
        }
    }

    @Test
    fun `constant time comparison is correct`() {
        val a = SecretBytes.copyOf(ByteArray(32) { 1 })
        val b = SecretBytes.copyOf(ByteArray(32) { 1 })
        val c = SecretBytes.copyOf(ByteArray(32) { 2 })
        val short = SecretBytes.copyOf(ByteArray(16) { 1 })

        assertTrue(a.constantTimeEquals(b))
        assertFalse(a.constantTimeEquals(c))
        assertFalse(a.constantTimeEquals(short))

        listOf(a, b, c, short).forEach(SecretBytes::close)
    }

    @Test
    fun `random material is well distributed and never repeats`() {
        val seen = mutableSetOf<String>()
        repeat(200) {
            SecretBytes.random(32).use { seen += B64.encode(it.copyBytes()) }
        }
        assertEquals(200, seen.size, "SecureRandom produced a repeat in 200 draws")
    }
}

class AeadTest {

    @Test
    fun `round trips with matching aad`() {
        SecretBytes.random(32).use { key ->
            val nonce = Aead.randomNonce()
            val plaintext = "hello".toByteArray()
            val aad = "context".toByteArray()

            val sealed = Aead.seal(key, nonce, plaintext, aad)
            assertContentEquals(plaintext, Aead.open(key, nonce, sealed, aad, "test"))
        }
    }

    @Test
    fun `mismatched aad fails authentication`() {
        SecretBytes.random(32).use { key ->
            val nonce = Aead.randomNonce()
            val sealed = Aead.seal(key, nonce, "hello".toByteArray(), "context-a".toByteArray())
            assertFailsWith<CryptoError.IntegrityFailure> {
                Aead.open(key, nonce, sealed, "context-b".toByteArray(), "test")
            }
        }
    }

    @Test
    fun `a wrong key fails authentication`() {
        val nonce = Aead.randomNonce()
        val sealed = SecretBytes.random(32).use { Aead.seal(it, nonce, "hi".toByteArray(), ByteArray(0)) }
        SecretBytes.random(32).use { other ->
            assertFailsWith<CryptoError.IntegrityFailure> {
                Aead.open(other, nonce, sealed, ByteArray(0), "test")
            }
        }
    }

    @Test
    fun `rejects malformed nonce and short ciphertext`() {
        SecretBytes.random(32).use { key ->
            assertFailsWith<CryptoError.MalformedVault> {
                Aead.open(key, ByteArray(4), ByteArray(32), ByteArray(0), "test")
            }
            assertFailsWith<CryptoError.MalformedVault> {
                Aead.open(key, Aead.randomNonce(), ByteArray(4), ByteArray(0), "test")
            }
        }
    }
}
