package com.passwird.store

import com.passwird.crypto.CryptoError
import com.passwird.crypto.KdfPolicy
import com.passwird.crypto.SecretBytes
import com.passwird.crypto.SlotType
import com.passwird.crypto.VaultCrypto
import com.passwird.model.DeviceId
import com.passwird.model.Tombstone
import com.passwird.model.VaultDocument
import com.passwird.model.VaultItem
import com.passwird.model.codec.VaultDocumentCodec
import com.passwird.search.SearchIndex
import com.passwird.search.SearchResult
import com.passwird.sync.CryptoVaultSealer
import com.passwird.sync.SyncEngine
import com.passwird.sync.SyncOutcome
import com.passwird.sync.SyncStateStore
import com.passwird.sync.VaultTransport
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The only vault surface the UI knows about.
 *
 * The layering rule from `docs/05-sync-architecture.md` §1 is enforced here: screens call
 * this, and this calls encryption, storage and sync. **No screen ever touches Google Drive,
 * a cipher, or a key.** That is what keeps the security-critical code in a handful of
 * reviewable files instead of smeared across a UI.
 *
 * The vault is held decrypted in memory only while unlocked, and [lock] zeroises it.
 */
class VaultRepository(
    private val storage: VaultStorage,
    private val deviceId: DeviceId,
    private val clock: () -> Instant = Instant::now,
) {

    private val mutex = Mutex()

    private var vek: SecretBytes? = null
    private var sealer: CryptoVaultSealer? = null
    private var syncEngine: SyncEngine? = null
    private var searchIndex: SearchIndex? = null

    private val _vault = MutableStateFlow<VaultDocument?>(null)

    /** Null while locked. Emitting null is what causes the UI to fall back to the lock screen. */
    val vault: StateFlow<VaultDocument?> = _vault.asStateFlow()

    private val _syncStatus = MutableStateFlow<SyncOutcome?>(null)
    val syncStatus: StateFlow<SyncOutcome?> = _syncStatus.asStateFlow()

    val isUnlocked: Boolean get() = _vault.value != null

    // ---------------------------------------------------------------- lifecycle

    /**
     * Opens the vault with a passphrase or recovery key.
     *
     * The typed failure matters to the UI: [CryptoError.WrongSecret] is "that passphrase
     * didn't match" (E-01), while [CryptoError.IntegrityFailure] means the data is damaged
     * (E-29). Being able to tell them apart is what the per-slot key commitment buys.
     */
    suspend fun unlock(secret: SecretBytes, type: SlotType): UnlockResult = mutex.withLock {
        val bytes = storage.readVault() ?: return UnlockResult.NoVault

        return try {
            VaultCrypto.unseal(bytes, secret, type, KdfPolicy.UpgradeAfterUnlock).use { opened ->
                val document = VaultDocumentCodec.decodeFromBytes(opened.plaintext)

                // Keep a copy of the VEK that outlives the `use` block, so sync can decrypt
                // downloads without re-prompting for the passphrase.
                val sessionKey = SecretBytes.copyOf(opened.vek.copyBytes())

                install(sessionKey, opened.header.vaultId, opened.header.slots, document)

                UnlockResult.Success(
                    kdfUpgradeRequired = opened.kdfUpgradeRequired,
                    weakSlots = opened.weakSlotTypes,
                )
            }
        } catch (error: CryptoError.WrongSecret) {
            UnlockResult.WrongSecret
        } catch (error: CryptoError) {
            UnlockResult.Damaged(error)
        }
    }

    /**
     * Seals the vault and wipes everything derived from it.
     *
     * Called on auto-lock, on manual lock, and on backgrounding. Must be safe to call at
     * any time, including when already locked.
     */
    suspend fun lock() = mutex.withLock {
        vek?.close()
        vek = null
        sealer = null
        syncEngine = null
        searchIndex = null
        _vault.value = null
    }

    private fun install(
        sessionKey: SecretBytes,
        vaultId: ByteArray,
        slots: List<com.passwird.crypto.KeySlot>,
        document: VaultDocument,
    ) {
        vek = sessionKey
        sealer = CryptoVaultSealer(sessionKey, vaultId, slots)
        syncEngine = SyncEngine(
            transport = storage.transport(),
            sealer = sealer!!,
            store = storage.syncStateStore(),
            deviceId = deviceId,
            clock = clock,
        )
        searchIndex = SearchIndex.build(document)
        _vault.value = document
    }

    // ------------------------------------------------------------------- items

    suspend fun upsert(item: VaultItem) = mutate { document ->
        val existing = document.itemById(item.id)
        val next = item.copy(
            revision = (existing?.revision ?: 0) + 1,
            originDeviceId = deviceId,
            updatedAt = clock(),
            createdAt = existing?.createdAt ?: clock(),
        )
        document.copy(items = document.items.filterNot { it.id == item.id } + next)
    }

    /**
     * Deletes by writing a tombstone, never by removing the record.
     *
     * An absent item is indistinguishable from one that has not synced yet, so a plain
     * removal would be resurrected by the next merge — and the user would watch a deleted
     * credential come back.
     */
    suspend fun delete(itemId: UUID) = mutate { document ->
        val existing = document.itemById(itemId)
        document.copy(
            items = document.items.filterNot { it.id == itemId },
            tombstones = document.tombstones.filterNot { it.id == itemId } + Tombstone(
                id = itemId,
                deletedAt = clock(),
                revision = (existing?.revision ?: 0) + 1,
                originDeviceId = deviceId,
            ),
        )
    }

    /** Undo for the 10-second window after a delete. */
    suspend fun restore(item: VaultItem) = mutate { document ->
        document.copy(
            items = document.items + item.copy(revision = item.revision + 1, originDeviceId = deviceId),
            tombstones = document.tombstones.filterNot { it.id == item.id },
        )
    }

    suspend fun markUsed(itemId: UUID) = mutate { document ->
        val item = document.itemById(itemId) ?: return@mutate document
        // Deliberately does not bump `revision`: opening an item is not an edit, and
        // treating it as one could resurrect a deletion made on another device.
        document.copy(
            items = document.items.map { if (it.id == itemId) it.copy(lastUsedAt = clock()) else it },
        )
    }

    private suspend fun mutate(transform: (VaultDocument) -> VaultDocument) = mutex.withLock {
        val current = _vault.value ?: error("The vault is locked")
        val next = transform(current)

        val bytes = requireNotNull(sealer).seal(next, previousHeaderBytes = storage.lastHeaderBytes())
        storage.writeVault(bytes)

        _vault.value = next
        searchIndex = SearchIndex.build(next)
        syncEngine?.markDirty()
    }

    // ------------------------------------------------------------------ search

    fun search(query: String, limit: Int = 50): List<SearchResult> =
        searchIndex?.search(query, limit).orEmpty()

    fun recent(limit: Int = 4): List<VaultItem> =
        _vault.value?.liveItems()
            ?.filter { it.lastUsedAt != null }
            ?.sortedByDescending { it.lastUsedAt }
            ?.take(limit)
            .orEmpty()

    fun favourites(): List<VaultItem> =
        _vault.value?.liveItems()?.filter { it.favorite }.orEmpty()

    // -------------------------------------------------------------------- sync

    /**
     * Attempts a sync.
     *
     * Never throws and never blocks the UI: every failure is a value, and every one of them
     * leaves the local vault authoritative and fully usable.
     */
    suspend fun sync(): SyncOutcome {
        val engine = syncEngine ?: return SyncOutcome.UpToDate
        val document = _vault.value ?: return SyncOutcome.UpToDate

        val outcome = engine.synchronise(document)
        _syncStatus.value = outcome

        // Adopt whatever the engine settled on, so the UI reflects the merged truth.
        when (outcome) {
            is SyncOutcome.Downloaded -> adopt(outcome.document)
            is SyncOutcome.Merged -> adopt(outcome.document)
            else -> Unit
        }
        return outcome
    }

    private suspend fun adopt(document: VaultDocument) = mutex.withLock {
        val bytes = requireNotNull(sealer).seal(document, previousHeaderBytes = storage.lastHeaderBytes())
        storage.writeVault(bytes)
        _vault.value = document
        searchIndex = SearchIndex.build(document)
    }

    /** Only reachable from the E-17 / E-18 screen, after the user has explicitly chosen it. */
    suspend fun forcePublishLocal(): SyncOutcome {
        val engine = syncEngine ?: return SyncOutcome.UpToDate
        val document = _vault.value ?: return SyncOutcome.UpToDate
        return engine.forcePublishLocal(document).also { _syncStatus.value = it }
    }
}

sealed interface UnlockResult {
    data class Success(
        val kdfUpgradeRequired: Boolean,
        val weakSlots: Set<SlotType>,
    ) : UnlockResult

    /** E-01. */
    data object WrongSecret : UnlockResult

    /** E-14: nothing on this device yet. */
    data object NoVault : UnlockResult

    /** E-20 / E-29: the passphrase was right but the data is damaged. */
    data class Damaged(val error: CryptoError) : UnlockResult
}

/**
 * Storage and transport, injected so the repository stays testable without Android.
 *
 * That sentence used to be aspirational: this interface and [VaultRepository] both lived in
 * the `app` module, so neither could be built — let alone tested — without an Android SDK.
 * They now live in a pure-JVM module, which is what makes the comment true.
 */
interface VaultStorage {
    /** The sealed vault container, or null when this device holds no vault yet. */
    suspend fun readVault(): ByteArray?

    /** Replaces the stored vault. Must be atomic: a partial write is a destroyed vault. */
    suspend fun writeVault(bytes: ByteArray)

    /** Header of the last stored version, for the hash chain. */
    suspend fun lastHeaderBytes(): ByteArray?

    fun transport(): VaultTransport
    fun syncStateStore(): SyncStateStore
}
