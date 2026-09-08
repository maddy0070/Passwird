package com.passwird.sync

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/**
 * An in-memory object store that can be made to die mid-sequence.
 *
 * Crash injection rather than mocking: the finding under test is that an *interruption at a
 * particular point* destroys data, so a store that cannot be interrupted cannot test it.
 */
class FakeObjectStore(
    /** Operation index to fail on, counting from 1. Null never fails. */
    private val failAtOperation: Int? = null,
) : ObjectStore {

    private val objects = LinkedHashMap<String, ByteArray>()
    var operations: Int = 0
        private set

    class Interrupted(val operation: Int) : Exception("store died on operation $operation")

    private fun step() {
        operations++
        if (operations == failAtOperation) throw Interrupted(operations)
    }

    override suspend fun list(): List<String> = objects.keys.toList()

    override suspend fun read(name: String): ByteArray? = objects[name]

    override suspend fun put(name: String, bytes: ByteArray) {
        step()
        objects[name] = bytes
    }

    override suspend fun rename(from: String, to: String) {
        step()
        objects.remove(from)?.let { objects[to] = it }
    }

    override suspend fun delete(name: String) {
        step()
        objects.remove(name)
    }

    fun seedLiveVault(bytes: ByteArray) {
        objects[VaultPublisher.LIVE_NAME] = bytes
    }

    fun contents(): Map<String, ByteArray> = objects.toMap()
}

/**
 * The §F-2 data-loss defence.
 *
 * `14-production-readiness-review.md` identified a window in `DriveTransport.upload` between
 * deleting the live vault and renaming its replacement, during which no `vault.pwv` exists.
 * `VaultRepository` maps a missing vault to `NoVault`, and `NoVault` is what onboarding uses
 * to decide it may create a new one — so an interruption in that window could lead a user to
 * publish a fresh empty vault over their real one.
 *
 * These tests interrupt the publish at **every** operation and assert the invariant that
 * makes that impossible.
 */
class VaultPublisherTest {

    private val original = "ORIGINAL-VAULT-BYTES-a7f3c9e1".toByteArray()
    private val replacement = "REPLACEMENT-VAULT-BYTES-5c1e77aa".toByteArray()

    // ------------------------------------------------------- the happy path

    @Test
    fun `publishing to an empty store makes the vault live`() = runTest {
        val store = FakeObjectStore()

        val result = VaultPublisher.publish(store, replacement, uniqueSuffix = "001")

        assertIs<PublishResult.Published>(result)
        assertTrue(replacement.contentEquals(assertNotNull(store.read(VaultPublisher.LIVE_NAME))))
        assertIs<RemoteVaultState.Present>(VaultPublisher.probe(store))
    }

    @Test
    fun `publishing over an existing vault replaces it and archives the old one`() = runTest {
        val store = FakeObjectStore()
        store.seedLiveVault(original)

        VaultPublisher.publish(store, replacement, uniqueSuffix = "001")

        assertTrue(replacement.contentEquals(assertNotNull(store.read(VaultPublisher.LIVE_NAME))))
        val backups = store.list().filter { it.startsWith(VaultPublisher.BACKUP_PREFIX) }
        assertEquals(1, backups.size, "the previous vault was not archived")
        assertTrue(original.contentEquals(assertNotNull(store.read(backups.single()))))
    }

    @Test
    fun `no temporary or superseded object survives a successful publish`() = runTest {
        val store = FakeObjectStore()
        store.seedLiveVault(original)

        VaultPublisher.publish(store, replacement, uniqueSuffix = "001")

        val leftovers = store.list().filter {
            it.startsWith(VaultPublisher.TEMP_PREFIX) || it.startsWith(VaultPublisher.SUPERSEDED_PREFIX)
        }
        assertTrue(leftovers.isEmpty(), "left behind: $leftovers")
    }

    @Test
    fun `bytes that do not read back intact abort the publish and keep the old vault`() = runTest {
        val store = FakeObjectStore()
        store.seedLiveVault(original)

        val result = VaultPublisher.publish(store, replacement, uniqueSuffix = "001") { false }

        assertIs<PublishResult.VerificationFailed>(result)
        assertTrue(
            original.contentEquals(assertNotNull(store.read(VaultPublisher.LIVE_NAME))),
            "a failed verification damaged the live vault",
        )
        assertTrue(store.list().none { it.startsWith(VaultPublisher.TEMP_PREFIX) })
    }

    // ------------------------------------------------- the invariant that matters

    @Test
    fun `an interruption at any operation never reports the store as empty`() = runTest {
        // The core assertion. `Empty` is what onboarding keys off; if an interrupted publish
        // can produce it, a user can be led to create a vault over their real one.
        val total = countOperations()
        assertTrue(total >= 5, "expected a multi-step publish, measured $total operations")

        for (failAt in 1..total) {
            val store = FakeObjectStore(failAtOperation = failAt)
            store.seedLiveVault(original)

            runCatching { VaultPublisher.publish(store, replacement, uniqueSuffix = "001") }

            val state = VaultPublisher.probe(store)
            assertTrue(
                state !is RemoteVaultState.Empty,
                "interrupting at operation $failAt made the store look like a new user's. " +
                    "Contents: ${store.list()}",
            )
        }
    }

    @Test
    fun `an interruption at any operation always leaves a recoverable vault`() = runTest {
        // Stronger than "not empty": after recovery, a readable vault must be live again, and
        // it must be one of the two we know about rather than anything else.
        val total = countOperations()

        for (failAt in 1..total) {
            val store = FakeObjectStore(failAtOperation = failAt)
            store.seedLiveVault(original)

            runCatching { VaultPublisher.publish(store, replacement, uniqueSuffix = "001") }

            if (VaultPublisher.probe(store) is RemoteVaultState.Present) continue

            val recovery = VaultPublisher.recover(store)
            assertTrue(
                recovery !is RecoveryResult.Unrecoverable,
                "interrupting at operation $failAt left nothing to recover: ${store.list()}",
            )

            val live = assertNotNull(
                store.read(VaultPublisher.LIVE_NAME),
                "recovery at operation $failAt did not restore a live vault",
            )
            assertTrue(
                live.contentEquals(original) || live.contentEquals(replacement),
                "recovery at operation $failAt produced unrecognised bytes",
            )
        }
    }

    @Test
    fun `recovery prefers the vault the user already had over an unfinished write`() = runTest {
        // Both candidates present: the superseded original is known-good and known-synced;
        // the staged replacement may be a write that never completed. Re-syncing costs an
        // upload; adopting an unverified write could cost an edit.
        val store = FakeObjectStore()
        store.put(VaultPublisher.SUPERSEDED_PREFIX + "001.pwv", original)
        store.put(VaultPublisher.TEMP_PREFIX + "001.pwv", replacement)

        val recovery = VaultPublisher.recover(store)

        assertIs<RecoveryResult.RestoredFromSuperseded>(recovery)
        assertTrue(original.contentEquals(assertNotNull(store.read(VaultPublisher.LIVE_NAME))))
    }

    @Test
    fun `recovery falls back to a staged object when nothing was superseded`() = runTest {
        // A first-ever publish that died after staging: there is no superseded object because
        // there was no previous vault. The staged bytes are all there is, and they are better
        // than nothing.
        val store = FakeObjectStore()
        store.put(VaultPublisher.TEMP_PREFIX + "001.pwv", replacement)

        assertIs<RecoveryResult.RestoredFromStaged>(VaultPublisher.recover(store))
        assertTrue(replacement.contentEquals(assertNotNull(store.read(VaultPublisher.LIVE_NAME))))
    }

    @Test
    fun `recovery falls back to a backup when both live and superseded are gone`() = runTest {
        val store = FakeObjectStore()
        store.put(VaultPublisher.BACKUP_PREFIX + "001.pwv", original)

        assertIs<RecoveryResult.RestoredFromBackup>(VaultPublisher.recover(store))
        assertTrue(original.contentEquals(assertNotNull(store.read(VaultPublisher.LIVE_NAME))))
    }

    // ------------------------------------------------------------- probe states

    @Test
    fun `a genuinely empty store reports Empty`() = runTest {
        assertIs<RemoteVaultState.Empty>(VaultPublisher.probe(FakeObjectStore()))
    }

    @Test
    fun `a store holding only a temp object reports Interrupted, not Empty`() = runTest {
        val store = FakeObjectStore()
        store.put(VaultPublisher.TEMP_PREFIX + "001.pwv", replacement)

        val state = VaultPublisher.probe(store)
        assertIs<RemoteVaultState.Interrupted>(state)
        assertEquals(1, state.evidence.size)
    }

    @Test
    fun `a store holding only a backup reports Interrupted, not Empty`() = runTest {
        val store = FakeObjectStore()
        store.put(VaultPublisher.BACKUP_PREFIX + "001.pwv", original)

        assertIs<RemoteVaultState.Interrupted>(VaultPublisher.probe(store))
    }

    @Test
    fun `the old delete-then-rename ordering would have failed this suite`() = runTest {
        // Documents the regression rather than only preventing it. This reproduces the
        // original sequence and shows it producing exactly the state that leads onboarding to
        // overwrite a real vault - so the test above is known to be testing something.
        val store = FakeObjectStore()
        store.seedLiveVault(original)
        store.put(VaultPublisher.TEMP_PREFIX + "001.pwv", replacement)

        // The original code: delete the live object, then rename the temp over it.
        store.delete(VaultPublisher.LIVE_NAME)
        // ... interrupted here, before the rename.

        assertIs<RemoteVaultState.Interrupted>(
            VaultPublisher.probe(store),
            "probe must still refuse to call this Empty",
        )

        // And with no temp object either - the case where the old code had already renamed
        // and then failed to clean up - the store is genuinely indistinguishable from new.
        val bare = FakeObjectStore()
        bare.seedLiveVault(original)
        bare.delete(VaultPublisher.LIVE_NAME)
        assertIs<RemoteVaultState.Empty>(
            VaultPublisher.probe(bare),
            "a delete with nothing staged is unrecoverable - which is why the live name is " +
                "now handed over by rename and never released",
        )
    }

    /** How many store operations a full publish performs, measured rather than assumed. */
    private suspend fun countOperations(): Int {
        val store = FakeObjectStore()
        store.seedLiveVault(original)
        VaultPublisher.publish(store, replacement, uniqueSuffix = "001")
        return store.operations
    }
}
