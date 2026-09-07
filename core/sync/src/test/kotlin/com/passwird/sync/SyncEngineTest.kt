package com.passwird.sync

import com.passwird.model.VaultDocument
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/**
 * Rollback and fork detection — the concrete answer to the "vault integrity" attack class
 * in the February 2026 ETH Zürich / USI results.
 */
class RollbackGuardTest {

    private fun info(version: Long, header: ByteArray = ByteArray(8) { version.toByte() }, chain: ByteArray = ByteArray(32)) =
        VaultFileInfo(version, header, chain)

    private fun chainFrom(previousHeader: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(previousHeader)

    @Test
    fun `a correctly chained newer version is accepted`() {
        val previousHeader = ByteArray(8) { 5 }
        val state = LocalSyncState(highestSeenVersion = 5, lastHeaderBytes = previousHeader)

        assertEquals(
            IntegrityVerdict.Ok,
            RollbackGuard.check(state, info(6, chain = chainFrom(previousHeader))),
        )
    }

    @Test
    fun `an older version is refused`() {
        // Google Drive can do this innocently by restoring a previous file version; an
        // attacker with the account can do it deliberately to resurrect a deleted
        // credential or undo a password change made after a breach.
        val state = LocalSyncState(highestSeenVersion = 42)
        val verdict = RollbackGuard.check(state, info(39))

        assertIs<IntegrityVerdict.Rollback>(verdict)
        assertEquals(42, verdict.expectedAtLeast)
        assertEquals(39, verdict.found)
    }

    @Test
    fun `the same version with different bytes is a fork`() {
        val state = LocalSyncState(highestSeenVersion = 7, lastHeaderBytes = ByteArray(8) { 1 })
        val verdict = RollbackGuard.check(state, info(7, header = ByteArray(8) { 2 }))

        assertIs<IntegrityVerdict.Fork>(verdict)
        assertEquals(7, verdict.version)
    }

    @Test
    fun `the same version with identical bytes is fine`() {
        val header = ByteArray(8) { 3 }
        val state = LocalSyncState(highestSeenVersion = 7, lastHeaderBytes = header)
        assertEquals(IntegrityVerdict.Ok, RollbackGuard.check(state, info(7, header = header)))
    }

    @Test
    fun `a broken chain on the immediate successor is caught`() {
        val previous = ByteArray(16) { 9 }
        val state = LocalSyncState(highestSeenVersion = 3, lastHeaderBytes = previous)

        val wrongChain = info(4, chain = ByteArray(32) { 0xEE.toByte() })
        assertIs<IntegrityVerdict.BrokenChain>(RollbackGuard.check(state, wrongChain))

        val rightChain = info(4, chain = java.security.MessageDigest.getInstance("SHA-256").digest(previous))
        assertEquals(IntegrityVerdict.Ok, RollbackGuard.check(state, rightChain))
    }

    @Test
    fun `a gap in versions is allowed`() {
        // Another device may legitimately have written several versions while this one was
        // offline, so only the immediate successor's chain link can be checked.
        val state = LocalSyncState(highestSeenVersion = 3, lastHeaderBytes = ByteArray(16) { 9 })
        assertEquals(IntegrityVerdict.Ok, RollbackGuard.check(state, info(10)))
    }

    @Test
    fun `a first sync with no history is accepted`() {
        assertEquals(IntegrityVerdict.Ok, RollbackGuard.check(LocalSyncState(), info(1)))
    }
}

class SyncEngineTest {

    private val sealer = TestSealerFactory.create()

    private fun engine(transport: FakeTransport, store: InMemorySyncStateStore) =
        SyncEngine(transport, sealer, store, Fx.DEVICE_A, clock = { Fx.NOW })

    private fun localVault(vararg titles: String): VaultDocument =
        Fx.doc(titles.mapIndexed { index, title -> Fx.login(Fx.id(index), title = title) })

    // ------------------------------------------------------------ happy paths

    @Test
    fun `first sync uploads the local vault`() = runTest {
        val transport = FakeTransport()
        val store = InMemorySyncStateStore()

        val outcome = engine(transport, store).synchronise(localVault("Figma"))

        assertIs<SyncOutcome.Uploaded>(outcome)
        assertEquals(1, outcome.vaultVersion)
        assertEquals(1, transport.uploadCount)
        assertEquals(1, store.load().highestSeenVersion)
        assertFalse(store.load().dirty)
    }

    @Test
    fun `an unchanged vault does no work`() = runTest {
        val transport = FakeTransport()
        val store = InMemorySyncStateStore()
        val local = localVault("Figma")

        engine(transport, store).synchronise(local)
        val second = engine(transport, store).synchronise(local)

        assertIs<SyncOutcome.UpToDate>(second)
        assertEquals(1, transport.uploadCount, "an idle sync must not re-upload")
    }

    @Test
    fun `a remote change is downloaded when there are no local edits`() = runTest {
        val transport = FakeTransport()
        val store = InMemorySyncStateStore()
        engine(transport, store).synchronise(localVault("Figma"))

        // Another device publishes.
        val updated = Fx.doc(listOf(Fx.login(Fx.id(0), title = "Figma"), Fx.login(Fx.id(1), title = "GitHub")))
        transport.tamperSetBytes(sealer.seal(updated, previousHeaderBytes = store.load().lastHeaderBytes))

        val outcome = engine(transport, store).synchronise(localVault("Figma"))

        assertIs<SyncOutcome.Downloaded>(outcome)
        assertEquals(2, outcome.document.liveItems().size)
        assertEquals(2, store.load().highestSeenVersion)
    }

    @Test
    fun `local edits are published when the remote has not moved`() = runTest {
        val transport = FakeTransport()
        val store = InMemorySyncStateStore()
        val engine = engine(transport, store)

        engine.synchronise(localVault("Figma"))
        engine.markDirty()
        val outcome = engine.synchronise(localVault("Figma", "GitHub"))

        assertIs<SyncOutcome.Uploaded>(outcome)
        assertEquals(2, outcome.vaultVersion)
        assertEquals(2, transport.uploadCount)
    }

    @Test
    fun `divergent changes are merged and republished`() = runTest {
        val transport = FakeTransport()
        val store = InMemorySyncStateStore()
        val engine = engine(transport, store)

        val original = localVault("Figma")
        engine.synchronise(original)

        // Another device adds an item...
        val remote = Fx.doc(original.items + Fx.login(Fx.id(9), title = "From other device", device = Fx.DEVICE_B))
        transport.tamperSetBytes(sealer.seal(remote, previousHeaderBytes = store.load().lastHeaderBytes))

        // ...while this one adds a different item.
        val local = Fx.doc(original.items + Fx.login(Fx.id(5), title = "From this device"))
        engine.markDirty()

        val outcome = engine.synchronise(local)

        assertIs<SyncOutcome.Merged>(outcome)
        val titles = outcome.document.liveItems().map { it.title }.toSet()
        assertEquals(setOf("Figma", "From other device", "From this device"), titles)
        assertFalse(outcome.summary.needsReview, "additions on both sides are not a conflict")
    }

    @Test
    fun `a snapshot is taken before any merge writes`() = runTest {
        // Principle 1 as code: a merge the user dislikes must be one tap from undone.
        val transport = FakeTransport()
        val store = InMemorySyncStateStore()
        val engine = engine(transport, store)

        val original = localVault("Figma")
        engine.synchronise(original)
        transport.tamperSetBytes(
            sealer.seal(
                Fx.doc(original.items + Fx.login(Fx.id(9), device = Fx.DEVICE_B)),
                previousHeaderBytes = store.load().lastHeaderBytes,
            ),
        )
        engine.markDirty()

        val local = Fx.doc(original.items + Fx.login(Fx.id(5)))
        engine.synchronise(local)

        assertEquals(1, store.snapshots.size, "the pre-merge vault must be snapshotted")
        assertEquals(local.items.map { it.id }, store.snapshots.single().items.map { it.id })
    }

    // --------------------------------------------------------------- integrity

    @Test
    fun `a rolled-back remote is refused and the local vault is untouched`() = runTest {
        val transport = FakeTransport()
        val store = InMemorySyncStateStore()
        val engine = engine(transport, store)

        val local = localVault("Figma")
        engine.synchronise(local)
        engine.synchronise(local.let { engine.markDirty(); it }) // version 2

        val versionTwoState = store.load()
        assertTrue(versionTwoState.highestSeenVersion >= 2)

        // The store serves an older-but-perfectly-valid version.
        transport.tamperSetBytes(sealer.seal(local, previousHeaderBytes = null)) // version 1

        val outcome = engine.synchronise(local)

        assertIs<SyncOutcome.IntegrityProblem>(outcome)
        assertIs<IntegrityVerdict.Rollback>(outcome.verdict)
        assertEquals(
            versionTwoState.highestSeenVersion,
            store.load().highestSeenVersion,
            "the watermark must never be lowered by a rejected download",
        )
    }

    @Test
    fun `corrupt remote bytes are reported without touching the local vault`() = runTest {
        val transport = FakeTransport()
        val store = InMemorySyncStateStore()
        val engine = engine(transport, store)

        engine.synchronise(localVault("Figma"))
        val good = transport.currentBytes()!!

        // Flip a bit deep inside the ciphertext.
        val corrupt = good.copyOf().also { it[it.size - 5] = (it[it.size - 5].toInt() xor 0xFF).toByte() }
        transport.tamperSetBytes(corrupt)

        val outcome = engine.synchronise(localVault("Figma"))
        assertIs<SyncOutcome.RemoteCorrupt>(outcome)
    }

    // ---------------------------------------------------------------- failures

    @Test
    fun `offline is reported as a state, not an error`() = runTest {
        val transport = FakeTransport().apply { offline = true }
        val outcome = engine(transport, InMemorySyncStateStore()).synchronise(localVault("Figma"))
        assertIs<SyncOutcome.Offline>(outcome)
    }

    @Test
    fun `a lost race is re-planned rather than forced`() = runTest {
        val transport = FakeTransport()
        val store = InMemorySyncStateStore()
        val engine = engine(transport, store)

        val local = localVault("Figma")
        engine.synchronise(local)
        engine.markDirty()

        // A competing device publishes in the window between our plan and our write —
        // exactly once, so the retry can succeed.
        var interfered = false
        transport.onBeforeUpload = {
            if (!interfered) {
                interfered = true
                transport.tamperSetBytes(ByteArray(0).let { transport.currentBytes()!! })
            }
        }

        val outcome = engine.synchronise(local)
        assertTrue(
            outcome is SyncOutcome.Uploaded || outcome is SyncOutcome.Merged,
            "the engine should re-plan and succeed, got $outcome",
        )
    }

    @Test
    fun `a persistent race gives up instead of looping forever`() = runTest {
        val transport = FakeTransport()
        val store = InMemorySyncStateStore()
        val engine = SyncEngine(transport, sealer, store, Fx.DEVICE_A, clock = { Fx.NOW }, maxAttempts = 3)

        engine.synchronise(localVault("Figma"))
        engine.markDirty()
        // Someone rewrites the remote before every single attempt.
        transport.onBeforeUpload = { transport.tamperSetBytes(transport.currentBytes()!!) }

        val outcome = engine.synchronise(localVault("Figma"))
        assertIs<SyncOutcome.Failed>(outcome)
        assertIs<TransportError.GenerationMismatch>(outcome.error)
    }

    @Test
    fun `transport failures are surfaced without disturbing local state`() = runTest {
        val transport = FakeTransport()
        val store = InMemorySyncStateStore()
        val engine = engine(transport, store)

        transport.failNextUploadWith = TransportError.QuotaExceeded()
        val outcome = engine.synchronise(localVault("Figma"))

        assertIs<SyncOutcome.Failed>(outcome)
        assertIs<TransportError.QuotaExceeded>(outcome.error)
        assertEquals(0, store.load().highestSeenVersion, "a failed upload must not advance the watermark")
    }

    @Test
    fun `every upload states the generation it expects`() = runTest {
        // Blind writes are how one device silently overwrites another.
        val transport = object : FakeTransport() {
            val expectations = mutableListOf<String?>()
            override suspend fun upload(bytes: ByteArray, expectedGeneration: String?): RemoteStat {
                expectations += expectedGeneration
                return super.upload(bytes, expectedGeneration)
            }
        }
        val store = InMemorySyncStateStore()
        val engine = engine(transport, store)

        engine.synchronise(localVault("Figma"))
        engine.markDirty()
        engine.synchronise(localVault("Figma", "GitHub"))

        assertEquals(listOf(null, "1"), transport.expectations)
    }

    @Test
    fun `force publish is available after an integrity problem`() = runTest {
        val transport = FakeTransport()
        val store = InMemorySyncStateStore()
        val engine = engine(transport, store)

        val local = localVault("Figma")
        engine.synchronise(local)
        engine.markDirty()
        engine.synchronise(local)

        transport.tamperSetBytes(sealer.seal(local, previousHeaderBytes = null))
        assertIs<SyncOutcome.IntegrityProblem>(engine.synchronise(local))

        // The user chooses, on the E-17 screen, to publish their copy.
        val outcome = engine.forcePublishLocal(local)
        assertIs<SyncOutcome.Uploaded>(outcome)
        assertNotNull(transport.currentBytes())
    }

    @Test
    fun `the round trip through real encryption preserves the vault`() = runTest {
        val transport = FakeTransport()
        val store = InMemorySyncStateStore()
        val engine = engine(transport, store)

        val local = Fx.doc(listOf(Fx.login(Fx.id(1), title = "Bank", password = "s3cr3t-value")))
        engine.synchronise(local)

        val restored = sealer.open(transport.currentBytes()!!)
        val password = (restored.items.single().content as com.passwird.model.ItemContent.Login).password.reveal()
        assertEquals("s3cr3t-value", password)
    }

    @Test
    fun `the uploaded bytes contain no plaintext`() = runTest {
        // The product's central claim, asserted on the exact bytes handed to the transport.
        val transport = FakeTransport()
        val engine = engine(transport, InMemorySyncStateStore())

        engine.synchronise(
            Fx.doc(listOf(Fx.login(Fx.id(1), title = "SENTINEL_TITLE_a1", password = "SENTINEL_PW_b2"))),
        )

        val uploaded = transport.currentBytes()!!.toString(Charsets.ISO_8859_1)
        assertFalse(uploaded.contains("SENTINEL_TITLE_a1"), "a title reached Drive in the clear")
        assertFalse(uploaded.contains("SENTINEL_PW_b2"), "a password reached Drive in the clear")
    }
}
