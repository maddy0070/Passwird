package com.passwird.model

import java.time.Instant
import java.util.UUID
import kotlinx.serialization.json.JsonElement

/**
 * The envelope every item shares, regardless of type.
 *
 * The merge metadata ([revision], [originDeviceId], [fieldRevisions], [conflicts]) is on
 * the base record from day one rather than bolted on later. Retro-fitting merge metadata
 * into a shipped schema is close to impossible, because existing records have no history
 * to reconstruct it from.
 */
data class VaultItem(
    val id: UUID,
    val title: String,
    val content: ItemContent,
    val tags: Set<String> = emptySet(),
    val folderId: UUID? = null,
    val favorite: Boolean = false,
    val customFields: List<CustomField> = emptyList(),
    val notes: String = "",
    val createdAt: Instant,
    val updatedAt: Instant,
    val lastUsedAt: Instant? = null,
    /** Increments on every local edit. With [originDeviceId], gives a total order. */
    val revision: Long = 1,
    val originDeviceId: DeviceId,
    /** Per-field revisions, enabling field-level rather than whole-record merge. */
    val fieldRevisions: Map<String, Long> = emptyMap(),
    /**
     * Values that lost a merge, retained rather than discarded.
     *
     * This is *never overwrite blindly* expressed in the schema: a losing value moves
     * here, it does not evaporate.
     */
    val conflicts: List<FieldConflict> = emptyList(),
    /** Set when a merge resurrected this item or could not resolve it automatically. */
    val needsReview: Boolean = false,
    /** Fields written by a newer client. Preserved verbatim on round-trip. */
    val unknown: Map<String, JsonElement> = emptyMap(),
) {
    val type: ItemType get() = content.type

    /**
     * Deterministic ordering key, independent of any clock.
     *
     * Mobile clocks are unreliable and, under threat model T5, influenceable — so merge
     * outcomes must never depend on them. Every device computes the same order from this.
     */
    fun orderingKey(): Pair<Long, String> = revision to originDeviceId.value

    /** Redacted: an item's own fields may hold secrets. */
    override fun toString(): String = "VaultItem(id=$id, type=${type.wire}, rev=$revision)"
}

/** A value that lost a field-level merge, kept so the user can adjudicate. */
data class FieldConflict(
    val field: String,
    val losingValue: FieldValue,
    val fromDeviceId: DeviceId,
    val at: Instant,
)

/**
 * A deletion.
 *
 * Deletions are recorded, never merely absent, because absence is indistinguishable from
 * "not synced yet" — and treating one as the other is how records get resurrected or
 * silently destroyed.
 */
data class Tombstone(
    val id: UUID,
    val deletedAt: Instant,
    val revision: Long,
    val originDeviceId: DeviceId,
)

/**
 * A single optional level of grouping.
 *
 * Deliberately not a tree. Deep hierarchies make moves ambiguous during merge, admit
 * cycles, and users mostly do not build them. Tags, search, favourites and recents cover
 * the real organising behaviour without the liability.
 */
data class Folder(
    val id: UUID,
    val name: String,
    val revision: Long = 1,
    val originDeviceId: DeviceId,
)

/** A device known to this vault. Lives inside the ciphertext so Drive cannot count them. */
data class DeviceRecord(
    val id: DeviceId,
    val label: String,
    val addedAt: Instant,
    val lastSyncAt: Instant? = null,
    val platform: String = "android",
)

data class VaultSettings(
    val autoLockSeconds: Int = 300,
    val lockOnBackground: Boolean = true,
    val clipboardClearSeconds: Int = 45,
    val requireBiometricForReveal: Boolean = false,
    val unknown: Map<String, JsonElement> = emptyMap(),
)

/**
 * The decrypted vault payload.
 *
 * Everything here lives inside the AEAD ciphertext. There is no "non-sensitive" tier —
 * the 2022 LastPass breach is what that costs.
 */
data class VaultDocument(
    val schemaVersion: Int = CURRENT_SCHEMA_VERSION,
    val vaultId: UUID,
    val items: List<VaultItem> = emptyList(),
    val tombstones: List<Tombstone> = emptyList(),
    val folders: List<Folder> = emptyList(),
    val devices: List<DeviceRecord> = emptyList(),
    val settings: VaultSettings = VaultSettings(),
    val unknown: Map<String, JsonElement> = emptyMap(),
) {
    /** Live items, i.e. excluding anything a tombstone covers. */
    fun liveItems(): List<VaultItem> {
        if (tombstones.isEmpty()) return items
        val deleted = tombstones.mapTo(HashSet(tombstones.size)) { it.id }
        return items.filterNot { it.id in deleted }
    }

    fun itemById(id: UUID): VaultItem? = items.firstOrNull { it.id == id }

    override fun toString(): String =
        "VaultDocument(schema=$schemaVersion, items=${items.size}, tombstones=${tombstones.size})"

    companion object {
        const val CURRENT_SCHEMA_VERSION: Int = 1

        fun empty(vaultId: UUID): VaultDocument = VaultDocument(vaultId = vaultId)
    }
}

/** Tombstones older than this are reaped. */
object TombstoneRetention {
    /**
     * 180 days.
     *
     * Must comfortably exceed the longest plausible offline period. A device offline for
     * longer than the window will resurrect its deleted items on the next sync — annoying,
     * but recoverable, and the right side of the trade against reaping too eagerly and
     * losing a deletion.
     */
    const val DAYS: Long = 180

    fun isExpired(tombstone: Tombstone, now: Instant): Boolean =
        tombstone.deletedAt.plusSeconds(DAYS * 86_400).isBefore(now)
}
