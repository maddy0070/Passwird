package com.passwird.store

import com.passwird.crypto.SlotType
import com.passwird.model.ItemContent
import com.passwird.model.Secret
import com.passwird.model.VaultItem
import java.io.File
import java.nio.file.Files
import java.util.UUID
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/**
 * `VaultRepository` has existed since the first implementation phase and had never been
 * instantiated — not by the app, which never constructs it, and not by a test, because it
 * lived in an Android module that cannot compile here.
 *
 * This is the first time it runs. It is as close to the vertical slice as is reachable
 * without a device: real crypto, real storage on a real filesystem, real sync engine, real
 * search index. The only fakes are the Keystore and Google Drive.
 */
class VaultRepositoryTest {

    private val root: File = Files.createTempDirectory("passwird-repo").toFile()
    private val cipher = FakeDeviceCipher()
    private val transport = FakeTransport()
    private val storage = FileVaultStorage(root, cipher, transport)

    private fun repository() = VaultRepository(
        storage = storage,
        deviceId = Fixtures.DEVICE,
        clock = { Fixtures.NOW },
    )

    @AfterTest
    fun cleanUp() {
        root.deleteRecursively()
    }

    private suspend fun seededRepository(vararg titles: String): VaultRepository {
        val (bytes, passphrase) = Fixtures.sealedVault(Fixtures.document(*titles))
        storage.writeVault(bytes)
        val repo = repository()
        val result = Fixtures.passphrase(passphrase).use { repo.unlock(it, SlotType.PASSPHRASE) }
        assertIs<UnlockResult.Success>(result, "fixture vault failed to unlock")
        return repo
    }

    // -------------------------------------------------------------------- unlock

    @Test
    fun `unlocking an empty device reports NoVault rather than failing`() = runTest {
        val result = Fixtures.passphrase().use { repository().unlock(it, SlotType.PASSPHRASE) }
        assertIs<UnlockResult.NoVault>(result)
    }

    @Test
    fun `a correct passphrase opens the vault and exposes its items`() = runTest {
        val repo = seededRepository("Bank", "Email")

        assertTrue(repo.isUnlocked)
        val document = assertNotNull(repo.vault.value)
        assertEquals(setOf("Bank", "Email"), document.items.map { it.title }.toSet())
    }

    @Test
    fun `a wrong passphrase is distinguishable from damaged data`() = runTest {
        // The distinction the per-slot key commitment buys, asserted at the level the UI
        // consumes it: E-01 "that passphrase didn't match" versus E-29 "this file is damaged".
        // Conflating them is how a user with a typo gets told their vault is corrupt.
        val (bytes, _) = Fixtures.sealedVault()
        storage.writeVault(bytes)

        val wrong = Fixtures.passphrase("not the passphrase at all").use {
            repository().unlock(it, SlotType.PASSPHRASE)
        }
        assertIs<UnlockResult.WrongSecret>(wrong)

        val corrupted = bytes.copyOf()
        corrupted[corrupted.size - 1] = (corrupted[corrupted.size - 1] + 1).toByte()
        storage.writeVault(corrupted)

        val damaged = Fixtures.passphrase().use { repository().unlock(it, SlotType.PASSPHRASE) }
        assertIs<UnlockResult.Damaged>(damaged)
    }

    @Test
    fun `locking clears the decrypted vault`() = runTest {
        val repo = seededRepository("Bank")
        assertNotNull(repo.vault.value)

        repo.lock()

        assertNull(repo.vault.value, "the decrypted document survived lock()")
        assertFalse(repo.isUnlocked)
        assertTrue(repo.search("Bank").isEmpty(), "the search index survived lock()")
    }

    @Test
    fun `locking twice is safe`() = runTest {
        val repo = seededRepository("Bank")
        repo.lock()
        repo.lock()
        assertFalse(repo.isUnlocked)
    }

    // --------------------------------------------------------------------- items

    @Test
    fun `an edit is persisted and survives a lock and unlock cycle`() = runTest {
        // The complete round trip: mutate in memory, seal, write to disk, drop every key,
        // re-derive from the passphrase, and find the edit. If any layer between the
        // repository and the filesystem is wrong, this is where it shows.
        val (bytes, passphrase) = Fixtures.sealedVault(Fixtures.document("Bank"))
        storage.writeVault(bytes)

        val first = repository()
        Fixtures.passphrase(passphrase).use { first.unlock(it, SlotType.PASSPHRASE) }

        val item = assertNotNull(first.vault.value?.items?.first())
        first.upsert(item.copy(title = "Bank of Somewhere"))
        first.lock()

        val second = repository()
        val result = Fixtures.passphrase(passphrase).use { second.unlock(it, SlotType.PASSPHRASE) }
        assertIs<UnlockResult.Success>(result)

        assertEquals("Bank of Somewhere", second.vault.value?.items?.first()?.title)
    }

    @Test
    fun `deleting writes a tombstone rather than removing the record`() = runTest {
        // A plain removal is indistinguishable from "not synced yet", so the next merge
        // resurrects it and the user watches a deleted credential come back.
        val repo = seededRepository("Bank")
        val item = assertNotNull(repo.vault.value?.items?.first())

        repo.delete(item.id)

        val document = assertNotNull(repo.vault.value)
        assertEquals(1, document.tombstones.size, "no tombstone was written")
        assertEquals(item.id, document.tombstones.first().id)
        assertTrue(document.liveItems().isEmpty(), "the item is still live")
    }

    @Test
    fun `restore undoes a delete`() = runTest {
        val repo = seededRepository("Bank")
        val item = assertNotNull(repo.vault.value?.items?.first())

        repo.delete(item.id)
        repo.restore(item)

        val document = assertNotNull(repo.vault.value)
        assertTrue(document.tombstones.isEmpty(), "the tombstone survived the undo")
        assertEquals(listOf("Bank"), document.liveItems().map { it.title })
    }

    @Test
    fun `opening an item does not count as an edit`() = runTest {
        // markUsed must not bump `revision`. If it did, merely viewing a credential on one
        // device could outrank a genuine deletion made on another.
        val repo = seededRepository("Bank")
        val before = assertNotNull(repo.vault.value?.items?.first())

        repo.markUsed(before.id)

        val after = assertNotNull(repo.vault.value?.items?.first())
        assertEquals(before.revision, after.revision, "markUsed bumped the revision")
        assertNotNull(after.lastUsedAt, "markUsed did not record the use")
    }

    @Test
    fun `mutating a locked vault fails loudly rather than silently`() = runTest {
        val repo = repository()
        val failure = runCatching {
            repo.upsert(
                VaultItem(
                    id = UUID.randomUUID(),
                    title = "Nope",
                    content = ItemContent.Login(password = Secret.of("x")),
                    createdAt = Fixtures.NOW,
                    updatedAt = Fixtures.NOW,
                    originDeviceId = Fixtures.DEVICE,
                ),
            )
        }.exceptionOrNull()

        assertNotNull(failure, "writing to a locked vault silently succeeded")
    }

    // -------------------------------------------------------------------- search

    @Test
    fun `search is available immediately after unlock and reflects edits`() = runTest {
        val repo = seededRepository("Bank", "Email")

        assertEquals(listOf("Bank"), repo.titlesMatching("Bank"))
        assertTrue(repo.search("Building").isEmpty(), "precondition: nothing matches yet")

        val item = assertNotNull(repo.vault.value?.items?.first { it.title == "Bank" })
        repo.upsert(item.copy(title = "Building Society"))

        // The new title is findable, which is only possible if the index was rebuilt.
        assertEquals(listOf("Building Society"), repo.titlesMatching("Building"))

        // "Bank" still matches — through the username, which the edit did not touch. That is
        // correct: the index searches every field, not just the title.
        assertEquals(listOf("Building Society"), repo.titlesMatching("Bank"))
    }

    @Test
    fun `recent lists only items that have actually been used`() = runTest {
        val repo = seededRepository("Bank", "Email")
        assertTrue(repo.recent().isEmpty(), "an untouched vault reported recent items")

        val bank = assertNotNull(repo.vault.value?.items?.first { it.title == "Bank" })
        repo.markUsed(bank.id)

        assertEquals(listOf("Bank"), repo.recent().map { it.title })
    }

    // ---------------------------------------------------------------------- sync

    @Test
    fun `sync publishes to the transport and is a no-op when locked`() = runTest {
        val locked = repository()
        assertEquals(0, transport.uploads)
        locked.sync()
        assertEquals(0, transport.uploads, "a locked repository uploaded something")

        val repo = seededRepository("Bank")
        val item = assertNotNull(repo.vault.value?.items?.first())
        repo.upsert(item.copy(title = "Bank plc"))
        repo.sync()

        assertTrue(transport.uploads > 0, "an edited vault was never published")
    }

    @Test
    fun `a transport failure leaves the local vault authoritative and usable`() = runTest {
        // Offline is a supported mode, not an error state. A failed sync must never cost the
        // user access to their own credentials.
        val repo = seededRepository("Bank")
        val item = assertNotNull(repo.vault.value?.items?.first())
        repo.upsert(item.copy(title = "Bank plc"))

        transport.failNextUpload = true
        repo.sync() // must not throw

        assertEquals("Bank plc", repo.vault.value?.items?.first()?.title)
        assertTrue(repo.isUnlocked, "a transport failure locked the vault")
        assertEquals(listOf("Bank plc"), repo.titlesMatching("Bank"))
    }

    @Test
    fun `nothing readable reaches the transport`() = runTest {
        // CiphertextOnlyTest asserts this of the container. This asserts it of the path the
        // application actually takes to get bytes there — repository, storage, sync engine.
        val repo = seededRepository("Bank")
        val item = assertNotNull(repo.vault.value?.items?.first())
        repo.upsert(item.copy(title = "Bank plc"))
        repo.sync()

        val published = transport.download().bytes
        for (sentinel in listOf("Bank plc", "PW-Bank-a7f3c9e1", "user@Bank.example.invalid")) {
            assertFalse(
                published.containsPlaintext(sentinel),
                "'$sentinel' left the device in the clear",
            )
        }
    }
}

/** Search returns ids; the tests read better in titles. */
private fun VaultRepository.titlesMatching(query: String): List<String> {
    val byId = vault.value?.items?.associateBy { it.id }.orEmpty()
    return search(query).mapNotNull { byId[it.itemId]?.title }.distinct()
}

private fun ByteArray.containsPlaintext(value: String): Boolean {
    val needle = value.toByteArray()
    if (needle.size > size) return false
    outer@ for (i in 0..size - needle.size) {
        for (j in needle.indices) if (this[i + j] != needle[j]) continue@outer
        return true
    }
    return false
}
