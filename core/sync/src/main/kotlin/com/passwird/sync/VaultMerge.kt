package com.passwird.sync

import com.passwird.model.DeviceId
import com.passwird.model.DeviceRecord
import com.passwird.model.FieldConflict
import com.passwird.model.FieldValue
import com.passwird.model.Folder
import com.passwird.model.Secret
import com.passwird.model.Tombstone
import com.passwird.model.TombstoneRetention
import com.passwird.model.VaultDocument
import com.passwird.model.VaultItem
import com.passwird.model.VaultSettings
import com.passwird.model.codec.VaultDocumentCodec
import java.time.Instant
import java.util.UUID
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

data class MergeSummary(
    val unchanged: Int = 0,
    val addedFromRemote: Int = 0,
    val keptFromLocal: Int = 0,
    val localEditWon: Int = 0,
    val remoteEditWon: Int = 0,
    val fieldMerged: Int = 0,
    val conflictedFields: Int = 0,
    val resurrected: Int = 0,
    val deleted: Int = 0,
) {
    /** True when the user must adjudicate — drives the E-16 "Review changes" surface. */
    val needsReview: Boolean get() = conflictedFields > 0 || resurrected > 0

    val changed: Int
        get() = addedFromRemote + remoteEditWon + fieldMerged + resurrected + deleted
}

data class MergeResult(val document: VaultDocument, val summary: MergeSummary)

/**
 * Three-way record merge.
 *
 * **The prime directive: never blindly overwrite. When in doubt, keep both.** A duplicate
 * credential is an annoyance; a destroyed one can lock somebody out of their bank. Every
 * ambiguous case here resolves toward keeping more data, and the invariant is enforced by
 * a property test (`no item present on either side is ever absent unless a tombstone
 * explicitly covers it`) rather than by care.
 *
 * Field-level merging works on the **JSON projection** of an item rather than the typed
 * union. One implementation therefore covers all eleven item types — and any type added
 * later — instead of eleven separate chances to get a data-losing case wrong.
 *
 * Two properties make the algorithm safe to run on several devices at once, and both are
 * property-tested:
 *
 *  - **Commutative:** `merge(base, l, r) == merge(base, r, l)`. Winners are chosen by
 *    content (`revision`, then `originDeviceId`), never by argument order.
 *  - **Idempotent:** merging a merged result changes nothing.
 *
 * Note what is *not* used anywhere: wall-clock time. Mobile clocks are unreliable, and
 * under threat model T5 an attacker can influence them. Timestamps are data we merge, not
 * a basis for deciding who wins.
 */
object VaultMerge {

    /**
     * Fields excluded when asking "did this side change the item?".
     *
     * `lastUsedAt` matters: merely *opening* a credential on one device is not an edit, and
     * counting it as one could resurrect an item the user deliberately deleted elsewhere.
     */
    private val VOLATILE_KEYS = setOf(
        "revision", "originDeviceId", "conflicts", "needsReview", "lastUsedAt",
    )

    /**
     * Fields that must never be auto-resolved.
     *
     * Guessing wrong on a password locks someone out of a real account, so when two
     * devices disagree about one, both values are kept and the user decides.
     */
    private val PROTECTED_FIELDS = setOf(
        "password", "secret", "privateKey", "keyPassphrase", "number", "cvv", "pin",
        "licenseKey", "connectionString", "nationalId", "passportNumber",
    )

    fun merge(
        base: VaultDocument?,
        local: VaultDocument,
        remote: VaultDocument,
        mergingDevice: DeviceId,
        now: Instant,
    ): MergeResult {
        require(local.vaultId == remote.vaultId) {
            "refusing to merge two different vaults (${local.vaultId} vs ${remote.vaultId})"
        }

        val tombstones = mergeTombstones(local.tombstones, remote.tombstones)
        val localItems = local.items.associateBy { it.id }
        val remoteItems = remote.items.associateBy { it.id }
        val baseItems = base?.items?.associateBy { it.id } ?: emptyMap()

        var summary = MergeSummary()
        val merged = mutableListOf<VaultItem>()
        val resurrectedIds = mutableSetOf<UUID>()

        for (id in (localItems.keys + remoteItems.keys).sorted()) {
            val localItem = localItems[id]
            val remoteItem = remoteItems[id]
            val baseItem = baseItems[id]
            val tombstoned = tombstones.containsKey(id)

            val outcome = resolve(baseItem, localItem, remoteItem, tombstoned, mergingDevice, now)

            outcome.item?.let(merged::add)
            if (outcome.resurrect) resurrectedIds += id
            summary = outcome.applyTo(summary)
        }

        // A resurrection must also retract the tombstone, or the item would be added and
        // then immediately filtered back out by `liveItems()`.
        val effectiveTombstones = tombstones.filterKeys { it !in resurrectedIds }

        val liveIds = merged.mapTo(HashSet()) { it.id }
        val retained = effectiveTombstones.values.filterNot { tombstone ->
            // Reap only once nothing references the id: dropping a tombstone while a copy
            // of the item still exists elsewhere would resurrect a deletion.
            TombstoneRetention.isExpired(tombstone, now) && tombstone.id !in liveIds
        }

        return MergeResult(
            document = VaultDocument(
                schemaVersion = VaultDocument.CURRENT_SCHEMA_VERSION,
                vaultId = local.vaultId,
                items = merged.sortedBy { it.id },
                tombstones = retained.sortedBy { it.id },
                folders = mergeFolders(local.folders, remote.folders),
                devices = mergeDevices(local.devices, remote.devices),
                settings = mergeSettings(local.settings, remote.settings),
                unknown = symmetricUnion(local.unknown, remote.unknown),
            ),
            summary = summary.copy(deleted = retained.count { it.id !in liveIds }),
        )
    }

    // ------------------------------------------------------------- item resolution

    private class Outcome(
        val item: VaultItem?,
        val resurrect: Boolean = false,
        val applyTo: (MergeSummary) -> MergeSummary,
    )

    private fun resolve(
        baseItem: VaultItem?,
        localItem: VaultItem?,
        remoteItem: VaultItem?,
        tombstoned: Boolean,
        mergingDevice: DeviceId,
        now: Instant,
    ): Outcome {
        // --- deletion cases ---
        if (tombstoned) {
            val edited = listOfNotNull(localItem, remoteItem).filter { editedSince(baseItem, it) }

            return when (edited.size) {
                // Nobody touched it since the base: the delete stands.
                0 -> Outcome(item = null, applyTo = { it })

                // An edit beats a delete. Last-writer-wins would silently destroy a
                // credential the user was actively editing on their other device; instead
                // the record comes back flagged, and a person decides.
                1 -> Outcome(
                    item = edited.single().copy(needsReview = true),
                    resurrect = true,
                    applyTo = { it.copy(resurrected = it.resurrected + 1) },
                )

                // Deleted on one device, edited on *both*. Keeping either edit alone would
                // discard the other, so the two are field-merged before being resurrected.
                else -> {
                    val outcome = fieldMerge(baseItem, localItem!!, remoteItem!!, mergingDevice, now)
                    Outcome(
                        item = outcome.item.copy(needsReview = true),
                        resurrect = true,
                        applyTo = {
                            it.copy(
                                resurrected = it.resurrected + 1,
                                conflictedFields = it.conflictedFields + outcome.conflicts,
                            )
                        },
                    )
                }
            }
        }

        // --- present on one side only ---
        if (localItem == null) {
            return Outcome(remoteItem, applyTo = { it.copy(addedFromRemote = it.addedFromRemote + 1) })
        }
        if (remoteItem == null) {
            return Outcome(localItem, applyTo = { it.copy(keptFromLocal = it.keptFromLocal + 1) })
        }

        // --- present on both sides ---
        val localJson = VaultDocumentCodec.encodeItem(localItem)
        val remoteJson = VaultDocumentCodec.encodeItem(remoteItem)
        val baseJson = baseItem?.let(VaultDocumentCodec::encodeItem)

        if (signature(localJson) == signature(remoteJson)) {
            return Outcome(
                mergeVolatileOnly(localItem, remoteItem),
                applyTo = { it.copy(unchanged = it.unchanged + 1) },
            )
        }

        if (baseJson != null) {
            if (signature(localJson) == signature(baseJson)) {
                return Outcome(remoteItem, applyTo = { it.copy(remoteEditWon = it.remoteEditWon + 1) })
            }
            if (signature(remoteJson) == signature(baseJson)) {
                return Outcome(localItem, applyTo = { it.copy(localEditWon = it.localEditWon + 1) })
            }
        }

        // Both sides changed, or there is no base to tell us who did.
        val outcome = fieldMerge(baseItem, localItem, remoteItem, mergingDevice, now)
        return Outcome(
            outcome.item,
            applyTo = {
                it.copy(
                    fieldMerged = it.fieldMerged + 1,
                    conflictedFields = it.conflictedFields + outcome.conflicts,
                )
            },
        )
    }

    private class FieldMergeOutcome(val item: VaultItem, val conflicts: Int)

    /**
     * Merges two edited versions of one item, field by field.
     *
     * Every choice inside is symmetric in its arguments, which is what makes the whole
     * merge commutative: the winner comes from `(revision, originDeviceId)`, the resulting
     * revision from `max`, and the conflict list is sorted.
     */
    private fun fieldMerge(
        baseItem: VaultItem?,
        localItem: VaultItem,
        remoteItem: VaultItem,
        mergingDevice: DeviceId,
        now: Instant,
    ): FieldMergeOutcome {
        val context = MergeContext(
            localWins = outranksOrEquals(ordering(localItem), ordering(remoteItem)),
            localDevice = localItem.originDeviceId,
            remoteDevice = remoteItem.originDeviceId,
            now = now,
        )
        val mergedJson = mergeObject(
            base = baseItem?.let(VaultDocumentCodec::encodeItem),
            local = VaultDocumentCodec.encodeItem(localItem),
            remote = VaultDocumentCodec.encodeItem(remoteItem),
            path = "",
            context = context,
        )

        val item = VaultDocumentCodec.decodeItem(mergedJson).copy(
            // A merge is itself an edit, so the result must outrank both inputs or the next
            // sync would see it as stale. max() keeps this symmetric in the arguments.
            revision = maxOf(localItem.revision, remoteItem.revision) + 1,
            originDeviceId = mergingDevice,
            lastUsedAt = latest(localItem.lastUsedAt, remoteItem.lastUsedAt),
            conflicts = mergeConflicts(localItem, remoteItem, context.conflicts),
            needsReview = localItem.needsReview || remoteItem.needsReview || context.conflicts.isNotEmpty(),
        )
        return FieldMergeOutcome(item, context.conflicts.size)
    }

    private fun mergeConflicts(
        local: VaultItem,
        remote: VaultItem,
        fresh: List<FieldConflict>,
    ): List<FieldConflict> =
        (local.conflicts + remote.conflicts + fresh)
            .distinctBy { Triple(it.field, it.losingValue, it.fromDeviceId) }
            .sortedWith(compareBy({ it.field }, { it.fromDeviceId.value }, { it.at }))

    /**
     * Identical content, but `lastUsedAt` may differ purely from opening the item.
     *
     * The surviving record is chosen by `(revision, originDeviceId)` rather than by being
     * the "local" argument. Taking local unconditionally would make the merge
     * non-commutative whenever two devices held the same content under different revision
     * bookkeeping, and every device would then converge on a different answer.
     */
    private fun mergeVolatileOnly(local: VaultItem, remote: VaultItem): VaultItem {
        val winner = if (outranksOrEquals(ordering(local), ordering(remote))) local else remote
        return winner.copy(
            lastUsedAt = latest(local.lastUsedAt, remote.lastUsedAt),
            revision = maxOf(local.revision, remote.revision),
            conflicts = mergeConflicts(local, remote, emptyList()),
            needsReview = local.needsReview || remote.needsReview,
        )
    }

    private fun latest(a: Instant?, b: Instant?): Instant? = when {
        a == null -> b
        b == null -> a
        else -> if (a.isAfter(b)) a else b
    }

    private fun editedSince(base: VaultItem?, candidate: VaultItem): Boolean {
        val baseJson = base?.let(VaultDocumentCodec::encodeItem) ?: return true
        return signature(VaultDocumentCodec.encodeItem(candidate)) != signature(baseJson)
    }

    /**
     * `(revision, originDeviceId)` — a total order every device computes identically.
     *
     * Kotlin's Pair is not Comparable, and relying on an implicit ordering here would be a
     * poor idea anyway: the tie-break rule is load-bearing for convergence, so it is
     * spelled out.
     */
    private fun ordering(item: VaultItem): Pair<Long, String> = item.revision to item.originDeviceId.value

    private fun outranks(a: Pair<Long, String>, b: Pair<Long, String>): Boolean =
        compareValuesBy(a, b, { it.first }, { it.second }) > 0

    private fun outranksOrEquals(a: Pair<Long, String>, b: Pair<Long, String>): Boolean =
        compareValuesBy(a, b, { it.first }, { it.second }) >= 0

    private fun signature(json: JsonObject): JsonObject =
        JsonObject(json.filterKeys { it !in VOLATILE_KEYS })

    // ------------------------------------------------------------- field merging

    private class MergeContext(
        val localWins: Boolean,
        val localDevice: DeviceId,
        val remoteDevice: DeviceId,
        val now: Instant,
    ) {
        val conflicts = mutableListOf<FieldConflict>()
    }

    private fun mergeObject(
        base: JsonObject?,
        local: JsonObject,
        remote: JsonObject,
        path: String,
        context: MergeContext,
    ): JsonObject {
        val keys = (local.keys + remote.keys + (base?.keys ?: emptySet())).sorted()
        val merged = sortedMapOf<String, JsonElement>()

        for (key in keys) {
            // Merge metadata is recomputed by the caller, so carrying it through here would
            // only create spurious conflicts on bookkeeping fields.
            if (path.isEmpty() && key in VOLATILE_KEYS) {
                local[key]?.let { merged[key] = it }
                continue
            }
            val childPath = if (path.isEmpty()) key else "$path.$key"
            mergeValue(base?.get(key), local[key], remote[key], childPath, context)
                ?.let { merged[key] = it }
        }
        return JsonObject(merged)
    }

    private fun mergeValue(
        base: JsonElement?,
        local: JsonElement?,
        remote: JsonElement?,
        path: String,
        context: MergeContext,
    ): JsonElement? {
        if (local == remote) return local
        if (base != null && local == base) return remote // only remote changed
        if (base != null && remote == base) return local // only local changed

        if (local is JsonObject && remote is JsonObject) {
            return mergeObject(base as? JsonObject, local, remote, path, context)
        }

        // A genuine both-sides conflict. Keep the loser rather than discarding it.
        val leaf = path.substringAfterLast('.')
        val winner = if (context.localWins) local else remote
        val loser = if (context.localWins) remote else local
        val loserDevice = if (context.localWins) context.remoteDevice else context.localDevice

        if (loser != null) {
            context.conflicts += FieldConflict(
                field = path,
                losingValue = describeLosingValue(leaf, loser),
                fromDeviceId = loserDevice,
                at = context.now,
            )
        }
        return winner ?: loser
    }

    /** Protected fields keep their losing value as a [Secret] so it stays unloggable. */
    private fun describeLosingValue(leaf: String, value: JsonElement): FieldValue {
        val text = (value as? JsonPrimitive)?.content ?: value.toString()
        return if (leaf in PROTECTED_FIELDS) {
            FieldValue.Hidden(Secret.of(text))
        } else {
            FieldValue.Text(text)
        }
    }

    // ------------------------------------------------------------- other sections

    private fun mergeTombstones(local: List<Tombstone>, remote: List<Tombstone>): Map<UUID, Tombstone> {
        val merged = LinkedHashMap<UUID, Tombstone>()
        for (tombstone in local + remote) {
            val existing = merged[tombstone.id]
            if (existing == null || outranks(tombstoneOrder(tombstone), tombstoneOrder(existing))) {
                merged[tombstone.id] = tombstone
            }
        }
        return merged
    }

    private fun tombstoneOrder(tombstone: Tombstone): Pair<Long, String> =
        tombstone.revision to tombstone.originDeviceId.value

    /**
     * Union that does not depend on argument order.
     *
     * Colliding keys with differing values are vanishingly unlikely for fields written by
     * a future version, but "unlikely" is not "convergent": every device must reach the
     * same answer, so the tie is broken deterministically on the encoded value.
     */
    private fun symmetricUnion(
        a: Map<String, JsonElement>,
        b: Map<String, JsonElement>,
    ): Map<String, JsonElement> =
        (a.keys + b.keys).sorted().associateWith { key ->
            val left = a[key]
            val right = b[key]
            when {
                left == null -> right!!
                right == null -> left
                left == right -> left
                else -> if (left.toString() >= right.toString()) left else right
            }
        }

    private fun mergeFolders(local: List<Folder>, remote: List<Folder>): List<Folder> {
        val merged = LinkedHashMap<UUID, Folder>()
        for (folder in local + remote) {
            val existing = merged[folder.id]
            val order = folder.revision to folder.originDeviceId.value
            val existingOrder = existing?.let { it.revision to it.originDeviceId.value }
            val wins = existingOrder == null || outranks(order, existingOrder) ||
                (order == existingOrder && folder.name > existing.name)
            if (wins) merged[folder.id] = folder
        }
        return merged.values.sortedBy { it.id }
    }

    private fun mergeDevices(local: List<DeviceRecord>, remote: List<DeviceRecord>): List<DeviceRecord> {
        val merged = LinkedHashMap<DeviceId, DeviceRecord>()
        for (device in local + remote) {
            val existing = merged[device.id]
            val seen = device.lastSyncAt ?: device.addedAt
            val existingSeen = existing?.let { it.lastSyncAt ?: it.addedAt }
            val wins = existingSeen == null || seen > existingSeen ||
                (seen == existingSeen && device.label > existing.label)
            if (wins) merged[device.id] = device
        }
        return merged.values.sortedBy { it.id.value }
    }

    /**
     * Settings merge takes the **stricter** option on every axis.
     *
     * Two devices disagreeing about a security setting is not a coin toss: shorter
     * timeouts and more locking are the safe direction, and the choice is symmetric, so
     * every device converges on the same answer without needing a revision counter.
     */
    private fun mergeSettings(local: VaultSettings, remote: VaultSettings): VaultSettings =
        VaultSettings(
            autoLockSeconds = minOf(local.autoLockSeconds, remote.autoLockSeconds),
            lockOnBackground = local.lockOnBackground || remote.lockOnBackground,
            clipboardClearSeconds = minOf(local.clipboardClearSeconds, remote.clipboardClearSeconds),
            requireBiometricForReveal = local.requireBiometricForReveal || remote.requireBiometricForReveal,
            unknown = symmetricUnion(local.unknown, remote.unknown),
        )
}
