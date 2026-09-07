package com.passwird.sync

import com.passwird.model.ItemContent
import com.passwird.model.VaultDocument
import com.passwird.model.VaultItem
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The full `{none, edit, delete, create}²` matrix from `docs/05-sync-architecture.md` §5.2.
 *
 * Every row here is a case where a careless implementation destroys a credential.
 */
class VaultMergeTest {

    private val itemId = Fx.id(1)

    private fun password(document: VaultDocument, id: java.util.UUID = itemId): String? =
        (document.itemById(id)?.content as? ItemContent.Login)?.password?.reveal()

    // ---------------------------------------------------------------- creation

    @Test
    fun `an item created only locally is kept`() {
        val local = Fx.doc(listOf(Fx.login(itemId)))
        val result = Fx.merge(base = Fx.doc(), local = local, remote = Fx.doc())
        assertEquals(1, result.document.liveItems().size)
        assertEquals(1, result.summary.keptFromLocal)
    }

    @Test
    fun `an item created only remotely is adopted`() {
        val remote = Fx.doc(listOf(Fx.login(itemId)))
        val result = Fx.merge(base = Fx.doc(), local = Fx.doc(), remote = remote)
        assertEquals(1, result.document.liveItems().size)
        assertEquals(1, result.summary.addedFromRemote)
    }

    @Test
    fun `items created on both devices all survive`() {
        val local = Fx.doc(listOf(Fx.login(Fx.id(1), title = "Local")))
        val remote = Fx.doc(listOf(Fx.login(Fx.id(2), title = "Remote")))
        val result = Fx.merge(Fx.doc(), local, remote)

        assertEquals(
            setOf(Fx.id(1), Fx.id(2)),
            result.document.liveItems().map { it.id }.toSet(),
        )
    }

    // ------------------------------------------------------------------ edits

    @Test
    fun `an unchanged item stays unchanged`() {
        val item = Fx.login(itemId)
        val result = Fx.merge(Fx.doc(listOf(item)), Fx.doc(listOf(item)), Fx.doc(listOf(item)))
        assertEquals(1, result.summary.unchanged)
        assertEquals(0, result.summary.conflictedFields)
    }

    @Test
    fun `a local-only edit wins`() {
        val base = Fx.login(itemId, title = "Original")
        val local = base.copy(title = "Edited locally", revision = 2)
        val result = Fx.merge(Fx.doc(listOf(base)), Fx.doc(listOf(local)), Fx.doc(listOf(base)))

        assertEquals("Edited locally", result.document.itemById(itemId)!!.title)
        assertEquals(1, result.summary.localEditWon)
    }

    @Test
    fun `a remote-only edit wins`() {
        val base = Fx.login(itemId, title = "Original")
        val remote = base.copy(title = "Edited remotely", revision = 2)
        val result = Fx.merge(Fx.doc(listOf(base)), Fx.doc(listOf(base)), Fx.doc(listOf(remote)))

        assertEquals("Edited remotely", result.document.itemById(itemId)!!.title)
        assertEquals(1, result.summary.remoteEditWon)
    }

    @Test
    fun `edits to different fields both survive`() {
        // The case that makes field-level merge worth the complexity: neither device loses
        // its change, and the user is not asked about anything.
        val base = Fx.login(itemId, title = "Original", notes = "")
        val local = base.copy(title = "New title", revision = 2, originDeviceId = Fx.DEVICE_A)
        val remote = base.copy(notes = "New notes", revision = 2, originDeviceId = Fx.DEVICE_B)

        val result = Fx.merge(Fx.doc(listOf(base)), Fx.doc(listOf(local)), Fx.doc(listOf(remote)))
        val merged = result.document.itemById(itemId)!!

        assertEquals("New title", merged.title)
        assertEquals("New notes", merged.notes)
        assertEquals(0, result.summary.conflictedFields, "different fields must not conflict")
        assertFalse(merged.needsReview)
    }

    @Test
    fun `the same edit on both devices is not a conflict`() {
        val base = Fx.login(itemId, title = "Original")
        val local = base.copy(title = "Same new title", revision = 2, originDeviceId = Fx.DEVICE_A)
        val remote = base.copy(title = "Same new title", revision = 2, originDeviceId = Fx.DEVICE_B)

        val result = Fx.merge(Fx.doc(listOf(base)), Fx.doc(listOf(local)), Fx.doc(listOf(remote)))
        assertEquals(0, result.summary.conflictedFields)
        assertEquals("Same new title", result.document.itemById(itemId)!!.title)
    }

    @Test
    fun `conflicting edits to the same field keep both values`() {
        val base = Fx.login(itemId, title = "Original")
        val local = base.copy(title = "Local title", revision = 3, originDeviceId = Fx.DEVICE_A)
        val remote = base.copy(title = "Remote title", revision = 2, originDeviceId = Fx.DEVICE_B)

        val result = Fx.merge(Fx.doc(listOf(base)), Fx.doc(listOf(local)), Fx.doc(listOf(remote)))
        val merged = result.document.itemById(itemId)!!

        assertEquals("Local title", merged.title, "higher revision becomes current")
        assertEquals(1, merged.conflicts.size, "the losing value must be preserved, not discarded")
        assertTrue(merged.needsReview)
        assertEquals("title", merged.conflicts.single().field)
    }

    @Test
    fun `a password conflict is never auto-resolved`() {
        // Guessing wrong here locks somebody out of a real account.
        val base = Fx.login(itemId, password = "original")
        val local = base.copy(
            content = ItemContent.Login(username = "user", password = com.passwird.model.Secret.of("local-new")),
            revision = 2, originDeviceId = Fx.DEVICE_A,
        )
        val remote = base.copy(
            content = ItemContent.Login(username = "user", password = com.passwird.model.Secret.of("remote-new")),
            revision = 2, originDeviceId = Fx.DEVICE_B,
        )

        val result = Fx.merge(Fx.doc(listOf(base)), Fx.doc(listOf(local)), Fx.doc(listOf(remote)))
        val merged = result.document.itemById(itemId)!!

        assertTrue(merged.needsReview, "a password conflict must be surfaced to the user")
        assertEquals(1, merged.conflicts.size)
        assertEquals("content.password", merged.conflicts.single().field)

        // Whichever value became current, the other is retained and readable.
        val current = password(result.document)
        val kept = (merged.conflicts.single().losingValue as com.passwird.model.FieldValue.Hidden).value.reveal()
        assertEquals(setOf("local-new", "remote-new"), setOf(current, kept))
    }

    @Test
    fun `a losing secret is preserved as a hidden value, not plain text`() {
        val base = Fx.login(itemId, password = "original")
        val local = base.copy(
            content = ItemContent.Login(password = com.passwird.model.Secret.of("local-secret")),
            revision = 5, originDeviceId = Fx.DEVICE_A,
        )
        val remote = base.copy(
            content = ItemContent.Login(password = com.passwird.model.Secret.of("remote-secret")),
            revision = 2, originDeviceId = Fx.DEVICE_B,
        )

        val merged = Fx.merge(Fx.doc(listOf(base)), Fx.doc(listOf(local)), Fx.doc(listOf(remote)))
            .document.itemById(itemId)!!

        val conflict = merged.conflicts.single { it.field == "content.password" }
        assertTrue(
            conflict.losingValue is com.passwird.model.FieldValue.Hidden,
            "a preserved secret must stay a Secret so it cannot be logged",
        )
        assertFalse("$conflict".contains("remote-secret"), "the conflict must not render the value")
    }

    // --------------------------------------------------------------- deletions

    @Test
    fun `a deletion propagates when the other side did not change the item`() {
        val item = Fx.login(itemId)
        val local = Fx.doc(tombstones = listOf(Fx.tombstone(itemId)))
        val remote = Fx.doc(listOf(item))

        val result = Fx.merge(Fx.doc(listOf(item)), local, remote)
        assertTrue(result.document.liveItems().isEmpty())
        assertEquals(1, result.document.tombstones.size, "the tombstone must be retained")
    }

    @Test
    fun `a deletion propagates in the other direction too`() {
        val item = Fx.login(itemId)
        val local = Fx.doc(listOf(item))
        val remote = Fx.doc(tombstones = listOf(Fx.tombstone(itemId)))

        assertTrue(Fx.merge(Fx.doc(listOf(item)), local, remote).document.liveItems().isEmpty())
    }

    @Test
    fun `an edit beats a delete and the item comes back flagged`() {
        // Last-writer-wins would silently destroy a credential the user was actively
        // editing on another device. Instead it survives and a person decides.
        val base = Fx.login(itemId, title = "Original")
        val edited = base.copy(title = "Still wanted", revision = 4, originDeviceId = Fx.DEVICE_B)

        val local = Fx.doc(tombstones = listOf(Fx.tombstone(itemId)))
        val remote = Fx.doc(listOf(edited))

        val result = Fx.merge(Fx.doc(listOf(base)), local, remote)
        val survivor = result.document.liveItems().single()

        assertEquals("Still wanted", survivor.title)
        assertTrue(survivor.needsReview, "a resurrected item must be flagged for review")
        assertEquals(1, result.summary.resurrected)
        assertTrue(result.summary.needsReview)
    }

    @Test
    fun `an edit beats a delete symmetrically`() {
        val base = Fx.login(itemId, title = "Original")
        val edited = base.copy(title = "Still wanted", revision = 4, originDeviceId = Fx.DEVICE_A)

        val result = Fx.merge(
            base = Fx.doc(listOf(base)),
            local = Fx.doc(listOf(edited)),
            remote = Fx.doc(tombstones = listOf(Fx.tombstone(itemId, device = Fx.DEVICE_B))),
        )
        assertEquals(1, result.document.liveItems().size)
        assertEquals(1, result.summary.resurrected)
    }

    @Test
    fun `deleting on both sides simply deletes`() {
        val item = Fx.login(itemId)
        val result = Fx.merge(
            base = Fx.doc(listOf(item)),
            local = Fx.doc(tombstones = listOf(Fx.tombstone(itemId, device = Fx.DEVICE_A))),
            remote = Fx.doc(tombstones = listOf(Fx.tombstone(itemId, device = Fx.DEVICE_B))),
        )
        assertTrue(result.document.liveItems().isEmpty())
        assertEquals(1, result.document.tombstones.size)
    }

    @Test
    fun `an unchanged item alongside a delete does not resurrect`() {
        // The item is byte-identical to base on the surviving side, so the delete stands.
        val item = Fx.login(itemId)
        val result = Fx.merge(
            base = Fx.doc(listOf(item)),
            local = Fx.doc(listOf(item), tombstones = listOf(Fx.tombstone(itemId))),
            remote = Fx.doc(listOf(item)),
        )
        assertTrue(result.document.liveItems().isEmpty())
    }

    @Test
    fun `merely opening an item does not resurrect a deletion`() {
        // lastUsedAt changes when a credential is viewed. Treating that as an edit would
        // undo deletions just because the user glanced at the item on another device.
        val item = Fx.login(itemId)
        val viewed = item.copy(lastUsedAt = Fx.NOW.plusSeconds(60))

        val result = Fx.merge(
            base = Fx.doc(listOf(item)),
            local = Fx.doc(tombstones = listOf(Fx.tombstone(itemId))),
            remote = Fx.doc(listOf(viewed)),
        )
        assertTrue(result.document.liveItems().isEmpty(), "a view is not an edit")
    }

    // --------------------------------------------------------------- no base

    @Test
    fun `without a base nothing is discarded`() {
        // A fresh install or a lost base means we cannot tell who changed what. The
        // conservative answer is to keep everything and ask.
        val local = Fx.login(itemId, title = "Local version", revision = 2, device = Fx.DEVICE_A)
        val remote = Fx.login(itemId, title = "Remote version", revision = 2, device = Fx.DEVICE_B)

        val result = Fx.merge(base = null, local = Fx.doc(listOf(local)), remote = Fx.doc(listOf(remote)))
        val merged = result.document.itemById(itemId)!!

        assertEquals(1, merged.conflicts.size)
        assertTrue(merged.needsReview)
        assertEquals(
            setOf("Local version", "Remote version"),
            setOf(merged.title, (merged.conflicts.single().losingValue as com.passwird.model.FieldValue.Text).value),
        )
    }

    // ------------------------------------------------------- ordering and misc

    @Test
    fun `the winner is chosen by revision then device id, never by argument order`() {
        val base = Fx.login(itemId, title = "Original")
        val lower = base.copy(title = "Lower", revision = 2, originDeviceId = Fx.DEVICE_A)
        val higher = base.copy(title = "Higher", revision = 7, originDeviceId = Fx.DEVICE_B)

        val forward = Fx.merge(Fx.doc(listOf(base)), Fx.doc(listOf(lower)), Fx.doc(listOf(higher)))
        val reverse = Fx.merge(Fx.doc(listOf(base)), Fx.doc(listOf(higher)), Fx.doc(listOf(lower)))

        assertEquals("Higher", forward.document.itemById(itemId)!!.title)
        assertEquals("Higher", reverse.document.itemById(itemId)!!.title)
    }

    @Test
    fun `equal revisions are broken deterministically by device id`() {
        val base = Fx.login(itemId, title = "Original")
        val a = base.copy(title = "From A", revision = 2, originDeviceId = Fx.DEVICE_A)
        val b = base.copy(title = "From B", revision = 2, originDeviceId = Fx.DEVICE_B)

        // device-b sorts after device-a, so it wins on every device, in either order.
        assertEquals("From B", Fx.merge(Fx.doc(listOf(base)), Fx.doc(listOf(a)), Fx.doc(listOf(b))).document.itemById(itemId)!!.title)
        assertEquals("From B", Fx.merge(Fx.doc(listOf(base)), Fx.doc(listOf(b)), Fx.doc(listOf(a))).document.itemById(itemId)!!.title)
    }

    @Test
    fun `a merged item outranks both of its inputs`() {
        // Otherwise the next sync would treat the merge result as stale and redo it.
        val base = Fx.login(itemId, title = "Original")
        val local = base.copy(title = "A", revision = 4, originDeviceId = Fx.DEVICE_A)
        val remote = base.copy(notes = "B", revision = 9, originDeviceId = Fx.DEVICE_B)

        val merged = Fx.merge(Fx.doc(listOf(base)), Fx.doc(listOf(local)), Fx.doc(listOf(remote)))
            .document.itemById(itemId)!!

        assertEquals(10, merged.revision)
        assertEquals(Fx.MERGER, merged.originDeviceId)
    }

    @Test
    fun `the most recent use is retained from either side`() {
        val item = Fx.login(itemId)
        val localUse = Fx.NOW.plusSeconds(10)
        val remoteUse = Fx.NOW.plusSeconds(99)

        val result = Fx.merge(
            Fx.doc(listOf(item)),
            Fx.doc(listOf(item.copy(lastUsedAt = localUse))),
            Fx.doc(listOf(item.copy(lastUsedAt = remoteUse))),
        )
        assertEquals(remoteUse, result.document.itemById(itemId)!!.lastUsedAt)
    }

    @Test
    fun `settings merge to the stricter option on every axis`() {
        // Two devices disagreeing about a security setting is not a coin toss.
        val local = Fx.doc().copy(
            settings = com.passwird.model.VaultSettings(
                autoLockSeconds = 900, lockOnBackground = false,
                clipboardClearSeconds = 90, requireBiometricForReveal = false,
            ),
        )
        val remote = Fx.doc().copy(
            settings = com.passwird.model.VaultSettings(
                autoLockSeconds = 60, lockOnBackground = true,
                clipboardClearSeconds = 30, requireBiometricForReveal = true,
            ),
        )

        val settings = Fx.merge(null, local, remote).document.settings
        assertEquals(60, settings.autoLockSeconds)
        assertTrue(settings.lockOnBackground)
        assertEquals(30, settings.clipboardClearSeconds)
        assertTrue(settings.requireBiometricForReveal)
    }

    @Test
    fun `merging two different vaults is refused rather than attempted`() {
        val other = VaultDocument(vaultId = java.util.UUID.randomUUID())
        assertFailsWith<IllegalArgumentException> { Fx.merge(null, Fx.doc(), other) }
    }

    @Test
    fun `unknown fields from both sides survive the merge`() {
        val local = Fx.doc().copy(unknown = mapOf("futureA" to kotlinx.serialization.json.JsonPrimitive(1)))
        val remote = Fx.doc().copy(unknown = mapOf("futureB" to kotlinx.serialization.json.JsonPrimitive(2)))

        val merged = Fx.merge(null, local, remote).document
        assertEquals(setOf("futureA", "futureB"), merged.unknown.keys)
    }

    @Test
    fun `an expired tombstone is only reaped once nothing references it`() {
        val old = Fx.tombstone(itemId).copy(deletedAt = Fx.NOW.minusSeconds(400L * 86_400))
        val result = Fx.merge(Fx.doc(), Fx.doc(tombstones = listOf(old)), Fx.doc(tombstones = listOf(old)))
        assertTrue(result.document.tombstones.isEmpty(), "an old tombstone with no item should be reaped")
    }

    @Test
    fun `a recent tombstone is retained through the offline window`() {
        val recent = Fx.tombstone(itemId).copy(deletedAt = Fx.NOW.minusSeconds(30L * 86_400))
        val result = Fx.merge(Fx.doc(), Fx.doc(tombstones = listOf(recent)), Fx.doc())
        assertEquals(1, result.document.tombstones.size)
    }

    @Test
    fun `item ordering in the result is deterministic`() {
        val items = (1..5).map { Fx.login(Fx.id(it), title = "Item $it") }
        val a = Fx.merge(null, Fx.doc(items), Fx.doc(items.reversed())).document
        val b = Fx.merge(null, Fx.doc(items.reversed()), Fx.doc(items)).document
        assertContentEquals(a.items.map(VaultItem::id), b.items.map(VaultItem::id))
    }
}
