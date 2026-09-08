package com.passwird.store

import com.passwird.crypto.CryptoError
import com.passwird.crypto.KdfParams
import com.passwird.crypto.KdfPolicy
import com.passwird.crypto.SecretBytes
import com.passwird.crypto.SlotType
import com.passwird.crypto.VaultContainer
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
import com.passwird.sync.RemoteVaultState
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

    /**
     * What the remote store holds, for callers deciding whether a user is genuinely new.
     *
     * Separated from [unlock] deliberately: unlocking must work offline, so it can never
     * depend on a network round trip. This is the question onboarding has to ask *before*
     * offering to create a vault, and it is allowed to be slow and allowed to fail.
     *
     * A failure is reported as [RemoteVaultState.Interrupted], not [RemoteVaultState.Empty].
     * "We could not reach Drive" and "Drive has nothing" must never collapse into the same
     * answer when the action that follows is *create a new vault*.
     */
    suspend fun remoteVaultState(): RemoteVaultState =
        runCatching { storage.transport().probe() }
            .getOrElse { VaultStateResolver.remoteFailure(it) }

    /**
     * Which [VaultState] the application is in.
     *
     * The single question the first screen must ask. It replaces `vault == null`, which meant
     * *not unlocked* and was being read as *locked* — so a fresh install was shown a lock
     * screen and asked for a passphrase that had never been chosen.
     *
     * Consults the remote only when there is no local vault, so an ordinary unlock stays
     * offline and instant. A locked vault is a locked vault whatever Drive says.
     */
    suspend fun currentState(): VaultState {
        val open = _vault.value
        if (open != null) return VaultState.Unlocked(open)

        val bytes = storage.readVault()
        if (bytes != null) {
            return VaultStateResolver.resolve(
                unlocked = null,
                localVault = bytes,
                localEvidence = true,
                remote = RemoteVaultState.Empty, // unreachable here: a local vault decides it
                parses = { runCatching { VaultContainer.parse(it) }.isSuccess },
            )
        }

        return VaultStateResolver.resolve(
            unlocked = null,
            localVault = null,
            localEvidence = storage.hasEvidenceOfVault(),
            remote = remoteVaultState(),
        )
    }

    /**
     * Creates a brand-new vault on this device.
     *
     * **The caller must have established [VaultState.mayCreateVault] first.** This method
     * cannot check for itself without racing the state it was given, so it enforces the one
     * thing it can see: it refuses to overwrite a vault that already exists locally. That is
     * a backstop, not the safety argument — the safety argument is the state machine.
     *
     * The vault is left **unlocked**, because the user has just proven the passphrase by
     * typing it twice and immediately needs to be inside. It is written to disk before this
     * returns, so a crash on the next frame cannot lose it.
     *
     * @param recoveryKey the caller generates, displays and verifies this before calling.
     *   Passed in rather than generated here so it cannot be created without a screen having
     *   shown it — a recovery key the user never saw is worse than none, because it makes the
     *   vault look recoverable when it is not.
     */
    suspend fun createVault(
        passphrase: SecretBytes,
        recoveryKey: SecretBytes,
        kdf: KdfParams = KdfParams.default(VaultCrypto.randomSalt()),
    ): CreateResult = mutex.withLock {
        if (storage.readVault() != null) return CreateResult.VaultAlreadyExists

        val document = VaultDocument(vaultId = UUID.randomUUID())

        return try {
            VaultCrypto.create(
                plaintext = VaultDocumentCodec.encodeToBytes(document),
                passphrase = passphrase,
                recoveryKey = recoveryKey,
                nowEpochMillis = clock().toEpochMilli(),
                passphraseKdf = kdf,
                recoveryKdf = KdfParams.default(VaultCrypto.randomSalt()),
            ).use { created ->
                storage.writeVault(created.bytes)

                val sessionKey = SecretBytes.copyOf(created.vek.copyBytes())
                install(sessionKey, created.header.vaultId, created.header.slots, document)

                CreateResult.Created
            }
        } catch (error: Throwable) {
            CreateResult.Failed(error.message ?: "the vault could not be created")
        }
    }

    /** Only reachable from the E-17 / E-18 screen, after the user has explicitly chosen it. */
    suspend fun forcePublishLocal(): SyncOutcome {
        val engine = syncEngine ?: return SyncOutcome.UpToDate
        val document = _vault.value ?: return SyncOutcome.UpToDate
        return engine.forcePublishLocal(document).also { _syncStatus.value = it }
    }
}

/** The outcome of creating a vault. */
sealed interface CreateResult {
    data object Created : CreateResult

    /** A vault already exists here. The backstop against a state-machine mistake. */
    data object VaultAlreadyExists : CreateResult

    data class Failed(val detail: String) : CreateResult
}

sealed interface UnlockResult {
    data class Success(
        val kdfUpgradeRequired: Boolean,
        val weakSlots: Set<SlotType>,
    ) : UnlockResult

    /** E-01. */
    data object WrongSecret : UnlockResult

    /**
     * E-14: nothing on this device yet.
     *
     * **Not a licence to offer onboarding.** This says only that this device holds no vault
     * file — which is also true immediately after an interrupted publish, after a partial
     * restore, and after a Keystore loss. Creating a vault on that basis can overwrite a real
     * one. Callers must consult [VaultRepository.remoteVaultState] and the local
     * `hasEvidenceOfVault` before treating a user as new; see §F-2 of
     * `docs/14-production-readiness-review.md`.
     */
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

    /**
     * Whether this device holds any trace of a vault, even when [readVault] returns null.
     *
     * Part of the storage contract rather than an implementation detail, because the vault
     * state machine cannot decide [VaultState.FirstRun] without it. A device with sync
     * bookkeeping, a cached header or an abandoned staged write has held a vault, and must
     * never be offered vault creation.
     */
    suspend fun hasEvidenceOfVault(): Boolean

    fun transport(): VaultTransport
    fun syncStateStore(): SyncStateStore
}
