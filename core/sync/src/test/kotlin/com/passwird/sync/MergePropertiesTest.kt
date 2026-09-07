package com.passwird.sync

import com.passwird.model.ItemContent
import com.passwird.model.Secret
import com.passwird.model.Tombstone
import com.passwird.model.VaultDocument
import com.passwird.model.VaultItem
import java.util.UUID
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Randomised invariants over the merge.
 *
 * The matrix in [VaultMergeTest] covers the cases we thought of. These cover the ones we
 * did not: 400 pseudo-random three-way scenarios per property, with a fixed seed so any
 * failure is reproducible from the output alone.
 */
class MergePropertiesTest {

    private val scenarios = 400

    private class Scenario(
        val base: VaultDocument?,
        val local: VaultDocument,
        val remote: VaultDocument,
        val seed: Int,
    ) {
        override fun toString() = "scenario(seed=$seed)"
    }

    /** Builds a base and then applies random divergent edits to each side. */
    private fun scenario(seed: Int): Scenario {
        val random = Random(seed)
        val itemCount = random.nextInt(0, 7)
        val baseItems = (0 until itemCount).map { index ->
            Fx.login(
                id = Fx.id(index),
                title = "Item $index",
                password = "pw-$index",
                revision = 1,
                device = Fx.DEVICE_A,
            )
        }
        val hasBase = random.nextBoolean()
        val base = if (hasBase) Fx.doc(baseItems) else null

        fun diverge(device: com.passwird.model.DeviceId, startFrom: List<VaultItem>): VaultDocument {
            val items = startFrom.toMutableList()
            val tombstones = mutableListOf<Tombstone>()

            for (index in items.indices.reversed()) {
                when (random.nextInt(5)) {
                    0 -> Unit // untouched
                    1 -> items[index] = items[index].copy(
                        title = "Edited by $device",
                        revision = items[index].revision + 1,
                        originDeviceId = device,
                    )
                    2 -> items[index] = items[index].copy(
                        content = ItemContent.Login(password = Secret.of("pw-from-$device")),
                        revision = items[index].revision + 1,
                        originDeviceId = device,
                    )
                    3 -> {
                        tombstones += Tombstone(items[index].id, Fx.NOW, items[index].revision + 1, device)
                        items.removeAt(index)
                    }
                    else -> items[index] = items[index].copy(
                        notes = "Note from $device",
                        revision = items[index].revision + 1,
                        originDeviceId = device,
                    )
                }
            }
            // Newly created items, which must always survive.
            repeat(random.nextInt(0, 3)) { n ->
                items += Fx.login(
                    id = UUID(device.value.hashCode().toLong(), (100 + n).toLong()),
                    title = "New on $device",
                    device = device,
                )
            }
            return Fx.doc(items, tombstones)
        }

        return Scenario(
            base = base,
            local = diverge(Fx.DEVICE_A, baseItems),
            remote = diverge(Fx.DEVICE_B, baseItems),
            seed = seed,
        )
    }

    /**
     * **The single most valuable test in the repository.**
     *
     * No item present on either side may be absent from the result unless a tombstone
     * explicitly covers it. This is the property that stops a merge bug from quietly
     * destroying someone's credentials, and it is the reason the merge is written to keep
     * more data whenever a case is ambiguous.
     */
    @Test
    fun `no item is ever lost without an explicit tombstone`() {
        repeat(scenarios) { seed ->
            val s = scenario(seed)
            val result = Fx.merge(s.base, s.local, s.remote)

            val survivingIds = result.document.items.mapTo(HashSet()) { it.id }
            val tombstonedIds = result.document.tombstones.mapTo(HashSet()) { it.id }
            val presentBefore = (s.local.items + s.remote.items).mapTo(HashSet()) { it.id }

            for (id in presentBefore) {
                assertTrue(
                    id in survivingIds || id in tombstonedIds,
                    "$s: item $id vanished with no tombstone to account for it",
                )
            }
        }
    }

    @Test
    fun `a contested password never loses a value`() {
        // Scoped to genuine contests: when *both* devices changed the password away from
        // the base, neither value may be discarded. If only one side edited it, superseding
        // the old value is the correct outcome, not a loss — the user replaced it on purpose.
        repeat(scenarios) { seed ->
            val s = scenario(seed)
            val result = Fx.merge(s.base, s.local, s.remote)

            for (id in (s.local.items + s.remote.items).map { it.id }.distinct()) {
                val localPassword = passwordOf(s.local, id)
                val remotePassword = passwordOf(s.remote, id)
                if (localPassword == null || remotePassword == null || localPassword == remotePassword) continue

                // A base value that only one side moved away from is superseded, not lost.
                val basePassword = s.base?.let { passwordOf(it, id) }
                if (basePassword != null && (localPassword == basePassword || remotePassword == basePassword)) continue

                val merged = result.document.itemById(id) ?: continue
                val reachable = buildSet {
                    passwordOf(result.document, id)?.let(::add)
                    merged.conflicts.forEach { conflict ->
                        when (val value = conflict.losingValue) {
                            is com.passwird.model.FieldValue.Hidden -> add(value.value.reveal())
                            is com.passwird.model.FieldValue.Text -> add(value.value)
                            else -> Unit
                        }
                    }
                }
                assertTrue(
                    localPassword in reachable && remotePassword in reachable,
                    "$s: item $id lost a password ($localPassword / $remotePassword kept=$reachable)",
                )
            }
        }
    }

    /**
     * Commutativity is what lets every device reach the same vault without coordination.
     *
     * If `merge(base, l, r)` differed from `merge(base, r, l)`, two phones syncing the same
     * pair of changes would produce two different vaults and then fight over them forever.
     */
    @Test
    fun `merge is commutative`() {
        repeat(scenarios) { seed ->
            val s = scenario(seed)
            val forward = Fx.merge(s.base, s.local, s.remote).document
            val reverse = Fx.merge(s.base, s.remote, s.local).document

            assertEquals(normalise(forward), normalise(reverse), "$s: merge is not commutative")
        }
    }

    @Test
    fun `merge is idempotent`() {
        repeat(scenarios) { seed ->
            val s = scenario(seed)
            val once = Fx.merge(s.base, s.local, s.remote).document
            val twice = Fx.merge(once, once, once).document

            assertEquals(normalise(once), normalise(twice), "$s: merging a merged result changed it")
        }
    }

    @Test
    fun `three devices converge regardless of sync order`() {
        // A syncs with B, then C; versus C syncs with B, then A. Both orders must land on
        // the same vault, or the fleet never settles.
        repeat(200) { seed ->
            val s = scenario(seed)
            val third = Fx.doc(
                listOf(Fx.login(Fx.id(99), title = "From C", device = Fx.DEVICE_C)),
            )

            val orderOne = Fx.merge(s.base, Fx.merge(s.base, s.local, s.remote).document, third).document
            val orderTwo = Fx.merge(s.base, Fx.merge(s.base, third, s.remote).document, s.local).document

            val idsOne = orderOne.liveItems().map { it.id }.toSet()
            val idsTwo = orderTwo.liveItems().map { it.id }.toSet()
            assertEquals(idsOne, idsTwo, "$s: devices did not converge on the same item set")
        }
    }

    @Test
    fun `an item is never duplicated`() {
        repeat(scenarios) { seed ->
            val s = scenario(seed)
            val items = Fx.merge(s.base, s.local, s.remote).document.items
            assertEquals(items.size, items.map { it.id }.toSet().size, "$s: duplicate item id")
        }
    }

    @Test
    fun `merging with an empty remote preserves everything local`() {
        repeat(scenarios) { seed ->
            val s = scenario(seed)
            val result = Fx.merge(base = null, local = s.local, remote = Fx.doc()).document
            assertEquals(
                s.local.items.map { it.id }.toSet(),
                result.items.map { it.id }.toSet(),
                "$s: merging against an empty remote dropped a local item",
            )
        }
    }

    private fun passwordOf(document: VaultDocument, id: UUID): String? =
        (document.itemById(id)?.content as? ItemContent.Login)?.password?.reveal()

    /**
     * Compares documents by content, ignoring list ordering.
     *
     * `at` timestamps on conflicts are all `Fx.NOW`, so they do not perturb the comparison.
     */
    private fun normalise(document: VaultDocument): String {
        val items = document.items.sortedBy { it.id }.joinToString("\n") { item ->
            buildString {
                append(item.id).append('|').append(item.title).append('|')
                append((item.content as? ItemContent.Login)?.password?.reveal()).append('|')
                append(item.notes).append('|').append(item.revision).append('|')
                append(item.needsReview).append('|')
                append(item.conflicts.sortedBy { it.field }.joinToString(",") { "${it.field}=${it.losingValue}" })
            }
        }
        val tombstones = document.tombstones.sortedBy { it.id }.joinToString(",") { "${it.id}@${it.revision}" }
        return "$items\n--\n$tombstones\n--\n${document.settings}\n--\n${document.unknown.toSortedMap()}"
    }
}
