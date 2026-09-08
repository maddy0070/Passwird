package com.passwird.store

import com.passwird.crypto.SlotType
import com.passwird.crypto.VaultContainer
import com.passwird.model.codec.VaultDocumentCodec
import com.passwird.sync.LocalSyncState
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/**
 * The storage layer had no implementation at all until now — `VaultStorage` was an interface
 * nothing satisfied — so nothing here is a regression test. It is the first coverage the
 * on-disk format has ever had.
 *
 * The properties worth asserting are not "can it read back what it wrote". They are the ones
 * that destroy vaults: partial writes, decrypted documents reaching disk in the clear, and a
 * missing file being mistaken for a new user.
 */
class FileVaultStorageTest {

    private val root: File = Files.createTempDirectory("passwird-store").toFile()
    private val cipher = FakeDeviceCipher()
    private val transport = FakeTransport()

    private fun storage() = FileVaultStorage(root, cipher, transport)

    @AfterTest
    fun cleanUp() {
        root.deleteRecursively()
    }

    @Test
    fun `a vault round-trips through the filesystem`() = runTest {
        val (bytes, _) = Fixtures.sealedVault()
        val store = storage()

        assertNull(store.readVault(), "a fresh directory must report no vault")

        store.writeVault(bytes)
        assertContentEquals(bytes, store.readVault())
    }

    @Test
    fun `the cached header matches what the container actually contains`() = runTest {
        // The repository feeds this back in as the previous link of the hash chain on every
        // write. A header that drifts from the file would break rollback detection silently,
        // which is the worst way for it to break.
        val (bytes, _) = Fixtures.sealedVault()
        val store = storage()
        store.writeVault(bytes)

        val cached = assertNotNull(store.lastHeaderBytes())
        val parsed = VaultContainer.parse(bytes).headerBytes

        assertContentEquals(parsed, cached, "the cached header is not the container's header")
    }

    @Test
    fun `the vault file is stored as the container, not double-sealed`() = runTest {
        // Deliberate design decision, asserted so it cannot be "tightened" by accident:
        // sealing the container under a device key would mean a lost Keystore entry destroys
        // the local vault. See the class KDoc.
        val (bytes, passphrase) = Fixtures.sealedVault()
        val store = storage()
        store.writeVault(bytes)

        val onDisk = File(root, "vault.pwv").readBytes()
        val opened = Fixtures.passphrase(passphrase).use { pass ->
            com.passwird.crypto.VaultCrypto.unseal(onDisk, pass, SlotType.PASSPHRASE)
        }
        opened.use {
            assertTrue(it.plaintext.isNotEmpty(), "the file on disk is not a usable container")
        }
    }

    @Test
    fun `a decrypted document never reaches disk in the clear`() = runTest {
        // The one bug in this class that would be catastrophic and invisible. `base.bin` and
        // `snapshot.bin` hold fully decrypted VaultDocuments.
        val document = Fixtures.document("Bank", "Email")
        val store = storage()
        val sync = store.syncStateStore()

        sync.saveBase(document)
        sync.snapshot(document)

        val sentinels = listOf("PW-Bank-a7f3c9e1", "PW-Email-a7f3c9e1", "user@Bank.example.invalid")
        for (file in root.listFiles().orEmpty()) {
            val contents = file.readBytes()
            for (sentinel in sentinels) {
                assertFalse(
                    contents.containsBytes(sentinel.toByteArray()),
                    "'$sentinel' is in the clear in ${file.name}",
                )
            }
        }
    }

    @Test
    fun `sealed state round-trips through the cipher`() = runTest {
        val store = storage()
        val sync = store.syncStateStore()
        val state = LocalSyncState(
            highestSeenVersion = 42,
            lastHeaderBytes = byteArrayOf(1, 2, 3, 4),
            lastSeenGeneration = "gen-7",
            dirty = true,
        )

        sync.save(state)
        assertEquals(state, sync.load())

        val document = Fixtures.document("Bank")
        sync.saveBase(document)
        assertEquals(
            VaultDocumentCodec.encodeToBytes(document).decodeToString(),
            VaultDocumentCodec.encodeToBytes(assertNotNull(sync.loadBase())).decodeToString(),
        )
    }

    @Test
    fun `a lost device key degrades to a full resync rather than blocking unlock`() = runTest {
        // Keystore entries are lost on biometric re-enrolment and some OEM update paths. When
        // that happens the bookkeeping is unreadable — and the user must still be able to
        // open their vault. Losing the watermark costs one sync; refusing to unlock costs
        // them their credentials.
        val store = storage()
        val sync = store.syncStateStore()
        sync.save(LocalSyncState(highestSeenVersion = 9, dirty = true))
        sync.saveBase(Fixtures.document("Bank"))

        cipher.broken = true

        assertEquals(LocalSyncState(), sync.load(), "unreadable state must fall back to a zero watermark")
        assertNull(sync.loadBase(), "an unreadable base must be treated as absent, not as garbage")

        // And the vault itself is unaffected, which is the whole point of not double-sealing.
        val (bytes, _) = Fixtures.sealedVault()
        val fresh = storage()
        fresh.writeVault(bytes)
        assertContentEquals(bytes, fresh.readVault())
    }

    @Test
    fun `a tampered state file is rejected rather than decoded`() = runTest {
        val store = storage()
        val sync = store.syncStateStore()
        sync.save(LocalSyncState(highestSeenVersion = 100))

        val stateFile = File(root, "sync-state.bin")
        val bytes = stateFile.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1] + 1).toByte()
        stateFile.writeBytes(bytes)

        // A forged watermark is a rollback attack: an attacker who could lower it would let a
        // stale remote vault be adopted. The AEAD tag is what stops it.
        assertEquals(LocalSyncState(), sync.load())
    }

    @Test
    fun `no temporary file survives a successful write`() = runTest {
        val (bytes, _) = Fixtures.sealedVault()
        val store = storage()
        store.writeVault(bytes)
        store.syncStateStore().save(LocalSyncState(highestSeenVersion = 1))

        val leftovers = root.listFiles { file -> file.name.startsWith(".tmp-") }.orEmpty()
        assertTrue(leftovers.isEmpty(), "temp files left behind: ${leftovers.map { it.name }}")
    }

    @Test
    fun `writing over an existing vault replaces it completely`() = runTest {
        // A rename over a shorter file that left a tail behind would produce a container with
        // trailing bytes, which the format rejects — so the vault would be unopenable.
        val store = storage()
        val (big, _) = Fixtures.sealedVault(Fixtures.document("A", "B", "C", "D", "E", "F"))
        val (small, passphrase) = Fixtures.sealedVault(Fixtures.document("A"))

        store.writeVault(big)
        store.writeVault(small)

        val readBack = assertNotNull(store.readVault())
        assertEquals(small.size, readBack.size, "the old vault's tail survived the overwrite")

        Fixtures.passphrase(passphrase).use { pass ->
            com.passwird.crypto.VaultCrypto.unseal(readBack, pass, SlotType.PASSPHRASE)
        }.close()
    }

    // ------------------------------------------------------------- the F-2 defence

    @Test
    fun `a fresh directory has no evidence of a vault`() = runTest {
        assertFalse(storage().hasEvidenceOfVault(), "an empty directory must read as a new user")
    }

    @Test
    fun `a vault file is evidence`() = runTest {
        val store = storage()
        store.writeVault(Fixtures.sealedVault().first)
        assertTrue(store.hasEvidenceOfVault())
    }

    @Test
    fun `sync bookkeeping alone is evidence, even with no vault file`() = runTest {
        // This is the case that matters. `14-production-readiness-review.md` §F-2 describes a
        // publish interrupted between deleting the live file and renaming its replacement.
        // Locally the equivalent is a vault file that is gone while the bookkeeping remains.
        // If that reads as "new user", onboarding offers to create a fresh vault — over a
        // real one.
        val store = storage()
        store.syncStateStore().save(LocalSyncState(highestSeenVersion = 3))

        assertNull(store.readVault(), "precondition: no vault file")
        assertTrue(
            store.hasEvidenceOfVault(),
            "a device with sync history is not a new user, whatever the vault file says",
        )
    }

    @Test
    fun `an abandoned temp file is evidence`() = runTest {
        val store = storage()
        File(root, ".tmp-vault.pwv.12345").writeBytes(byteArrayOf(1, 2, 3))
        assertTrue(store.hasEvidenceOfVault(), "an interrupted write is not a new user")
    }

    @Test
    fun `destroy removes every trace, including temp files`() = runTest {
        val store = storage()
        store.writeVault(Fixtures.sealedVault().first)
        store.syncStateStore().save(LocalSyncState(highestSeenVersion = 3))
        store.syncStateStore().saveBase(Fixtures.document("Bank"))
        File(root, ".tmp-vault.pwv.999").writeBytes(byteArrayOf(9))

        store.destroy()

        assertFalse(store.hasEvidenceOfVault())
        assertTrue(root.listFiles().orEmpty().isEmpty(), "files survived destroy(): ${root.list()?.toList()}")
    }

    @Test
    fun `a corrupted container is rejected when the header is read back`() = runTest {
        val store = storage()
        val (bytes, _) = Fixtures.sealedVault()

        // A declared header length that overruns the file must not produce a header at all.
        val forged = bytes.copyOf()
        forged[10] = 0x7F
        forged[11] = 0xFF.toByte()

        val failure = runCatching { store.writeVault(forged) }.exceptionOrNull()
        assertNotNull(failure, "an over-long declared header length was accepted")
    }
}

private fun ByteArray.containsBytes(needle: ByteArray): Boolean {
    if (needle.isEmpty() || needle.size > size) return false
    outer@ for (i in 0..size - needle.size) {
        for (j in needle.indices) if (this[i + j] != needle[j]) continue@outer
        return true
    }
    return false
}
