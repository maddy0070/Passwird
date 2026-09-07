package com.passwird.sync

import com.passwird.crypto.KdfParams
import com.passwird.crypto.KeySlot
import com.passwird.crypto.KeySlots
import com.passwird.crypto.SecretBytes
import com.passwird.crypto.SlotType
import com.passwird.model.DeviceId
import com.passwird.model.ItemContent
import com.passwird.model.Secret
import com.passwird.model.Tombstone
import com.passwird.model.VaultDocument
import com.passwird.model.VaultItem
import java.time.Instant
import java.util.UUID

object Fx {
    val NOW: Instant = Instant.parse("2026-09-07T12:00:00Z")
    val VAULT_ID: UUID = UUID.fromString("11111111-2222-3333-4444-555555555555")

    val DEVICE_A = DeviceId("device-a")
    val DEVICE_B = DeviceId("device-b")
    val DEVICE_C = DeviceId("device-c")
    val MERGER = DeviceId("merger")

    fun id(seed: Int): UUID = UUID(seed.toLong(), seed.toLong())

    fun login(
        id: UUID,
        title: String = "Item $id",
        username: String = "user",
        password: String = "pw",
        revision: Long = 1,
        device: DeviceId = DEVICE_A,
        notes: String = "",
        favorite: Boolean = false,
        lastUsed: Instant? = null,
    ) = VaultItem(
        id = id,
        title = title,
        content = ItemContent.Login(username = username, password = Secret.of(password)),
        notes = notes,
        favorite = favorite,
        lastUsedAt = lastUsed,
        createdAt = NOW,
        updatedAt = NOW,
        revision = revision,
        originDeviceId = device,
    )

    fun doc(
        items: List<VaultItem> = emptyList(),
        tombstones: List<Tombstone> = emptyList(),
    ) = VaultDocument(vaultId = VAULT_ID, items = items, tombstones = tombstones)

    fun tombstone(id: UUID, revision: Long = 2, device: DeviceId = DEVICE_A) =
        Tombstone(id, NOW, revision, device)

    fun merge(base: VaultDocument?, local: VaultDocument, remote: VaultDocument) =
        VaultMerge.merge(base, local, remote, MERGER, NOW)
}

/**
 * An in-memory [VaultTransport] with a real generation token.
 *
 * Models the properties that actually matter for correctness: a generation that changes on
 * every write, and rejection of any upload whose expectation no longer holds. Fault
 * injection covers the failure paths the engine must survive.
 */
open class FakeTransport(
    private var bytes: ByteArray? = null,
) : VaultTransport {

    private var generation: Long = 0
    private val backups = mutableListOf<Pair<BackupRef, ByteArray>>()

    var offline: Boolean = false
    var failNextUploadWith: TransportError? = null
    var uploadCount: Int = 0
        private set
    var downloadCount: Int = 0
        private set

    /** Simulates another device publishing between our plan and our write. */
    var onBeforeUpload: (() -> Unit)? = null

    override suspend fun stat(): RemoteStat? {
        if (offline) throw TransportError.Offline()
        return bytes?.let { RemoteStat(generation.toString(), it.size.toLong(), Fx.NOW.toEpochMilli()) }
    }

    override suspend fun download(): RemoteObject {
        if (offline) throw TransportError.Offline()
        downloadCount++
        val current = bytes ?: throw TransportError.NotFound()
        return RemoteObject(current.copyOf(), RemoteStat(generation.toString(), current.size.toLong(), Fx.NOW.toEpochMilli()))
    }

    override suspend fun upload(bytes: ByteArray, expectedGeneration: String?): RemoteStat {
        if (offline) throw TransportError.Offline()
        onBeforeUpload?.invoke()
        failNextUploadWith?.let {
            failNextUploadWith = null
            throw it
        }

        val actual = if (this.bytes == null) null else generation.toString()
        if (expectedGeneration != actual) {
            throw TransportError.GenerationMismatch(expectedGeneration, actual)
        }

        this.bytes?.let { previous ->
            backups += BackupRef("b${backups.size}", "backup", 0, Fx.NOW.toEpochMilli()) to previous
        }
        uploadCount++
        this.bytes = bytes.copyOf()
        generation++
        return RemoteStat(generation.toString(), bytes.size.toLong(), Fx.NOW.toEpochMilli())
    }

    override suspend fun listBackups(): List<BackupRef> = backups.map { it.first }

    override suspend fun restoreBackup(ref: BackupRef): RemoteObject {
        val found = backups.first { it.first.id == ref.id }
        return RemoteObject(found.second, RemoteStat("restored", found.second.size.toLong(), Fx.NOW.toEpochMilli()))
    }

    /** Directly replaces the stored bytes, as a hostile or buggy store would. */
    fun tamperSetBytes(newBytes: ByteArray, bumpGeneration: Boolean = true) {
        bytes = newBytes.copyOf()
        if (bumpGeneration) generation++
    }

    fun currentBytes(): ByteArray? = bytes?.copyOf()
}

class InMemorySyncStateStore(
    private var state: LocalSyncState = LocalSyncState(),
) : SyncStateStore {
    private var base: VaultDocument? = null
    val snapshots = mutableListOf<VaultDocument>()

    override suspend fun load(): LocalSyncState = state
    override suspend fun save(state: LocalSyncState) { this.state = state }
    override suspend fun loadBase(): VaultDocument? = base
    override suspend fun saveBase(document: VaultDocument) { base = document }
    override suspend fun snapshot(document: VaultDocument) { snapshots += document }
}

/** Builds a real [CryptoVaultSealer] so sync tests exercise genuine encryption. */
object TestSealerFactory {

    fun create(): CryptoVaultSealer {
        val vek = SecretBytes.random(32)
        val vaultId = ByteArray(16) { it.toByte() }
        val passphrase = SecretBytes.fromPassphrase("test passphrase".toCharArray())

        val slots: List<KeySlot> = passphrase.use { secret ->
            listOf(
                KeySlots.create(
                    vek = vek,
                    secret = secret,
                    type = SlotType.PASSPHRASE,
                    label = "Master passphrase",
                    // Fast parameters: these tests exercise sync logic, not the KDF, which
                    // has its own coverage in core:crypto.
                    kdf = KdfParams(memoryKib = 1024, iterations = 1, parallelism = 1, salt = ByteArray(16)),
                    nowEpochMillis = Fx.NOW.toEpochMilli(),
                ),
            )
        }
        return CryptoVaultSealer(vek, vaultId, slots)
    }
}
