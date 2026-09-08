package com.passwird.platform.secure

import android.content.Context
import com.passwird.model.VaultDocument
import com.passwird.model.codec.VaultDocumentCodec
import com.passwird.sync.LocalSyncState
import com.passwird.sync.SyncStateStore
import java.io.File
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

/**
 * Sync bookkeeping, encrypted under the hardware device key.
 *
 * **Deliberately not `SharedPreferences`.** The rollback watermark is a security control:
 * if clearing app data reset it, an attacker who could clear our data could then replay an
 * old vault — defeating the exact defence in `RollbackGuard`. Preferences are also
 * world-readable to anyone with a backup or root, and Android's automatic backup would
 * happily ship them off-device.
 *
 * Encrypted under the *device* key rather than a vault-derived one, because the watermark
 * has to be readable **before** the vault is unlocked: we must be able to detect a rolled
 * back file without first asking the user for their passphrase.
 */
class EncryptedLocalStore(
    context: Context,
    private val keyManager: KeystoreKeyManager,
) : SyncStateStore {

    private val root = File(context.filesDir, "vault").apply { mkdirs() }
    private val stateFile = File(root, "sync-state.bin")
    private val baseFile = File(root, "sync-base.bin")
    private val snapshotDir = File(root, "snapshots").apply { mkdirs() }

    private val mutex = Mutex()
    private val json = Json { isLenient = false }

    override suspend fun load(): LocalSyncState = withContext(Dispatchers.IO) {
        mutex.withLock {
            if (!stateFile.exists()) return@withLock LocalSyncState()
            runCatching {
                val plaintext = keyManager.openWithDeviceKey(WrappedSecret.decode(stateFile.readBytes()))
                decodeState(json.parseToJsonElement(plaintext.decodeToString()).jsonObject)
            }.getOrElse {
                // A state file we cannot read must never silently become a fresh, zeroed
                // state — that would clear the watermark and reopen the rollback window.
                // Treating it as a hard read failure keeps the vault usable while the app
                // refuses to sync until the user is told.
                throw KeystoreFailure.Unavailable(it)
            }
        }
    }

    override suspend fun save(state: LocalSyncState) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val encoded = json.encodeToString(JsonObject.serializer(), encodeState(state))
            writeAtomically(stateFile, keyManager.sealWithDeviceKey(encoded.toByteArray()).encode())
        }
    }

    override suspend fun loadBase(): VaultDocument? = withContext(Dispatchers.IO) {
        mutex.withLock {
            if (!baseFile.exists()) return@withLock null
            runCatching {
                val plaintext = keyManager.openWithDeviceKey(WrappedSecret.decode(baseFile.readBytes()))
                try {
                    VaultDocumentCodec.decodeFromBytes(plaintext)
                } finally {
                    plaintext.fill(0)
                }
            }.getOrNull() // A lost base degrades merge to a conservative union, never a loss.
        }
    }

    override suspend fun saveBase(document: VaultDocument) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val plaintext = VaultDocumentCodec.encodeToBytes(document)
            try {
                writeAtomically(baseFile, keyManager.sealWithDeviceKey(plaintext).encode())
            } finally {
                plaintext.fill(0)
            }
        }
    }

    /**
     * Keeps the last few pre-merge states.
     *
     * Principle 1 as code: a merge the user dislikes is one tap from being undone. Kept
     * small — this is an undo buffer, not an archive.
     */
    override suspend fun snapshot(document: VaultDocument) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val plaintext = VaultDocumentCodec.encodeToBytes(document)
            try {
                val file = File(snapshotDir, "pre-merge-${System.currentTimeMillis()}.bin")
                writeAtomically(file, keyManager.sealWithDeviceKey(plaintext).encode())
                pruneSnapshots()
            } finally {
                plaintext.fill(0)
            }
        }
    }

    suspend fun listSnapshots(): List<File> = withContext(Dispatchers.IO) {
        snapshotDir.listFiles()?.sortedByDescending(File::lastModified) ?: emptyList()
    }

    suspend fun readSnapshot(file: File): VaultDocument = withContext(Dispatchers.IO) {
        val plaintext = keyManager.openWithDeviceKey(WrappedSecret.decode(file.readBytes()))
        try {
            VaultDocumentCodec.decodeFromBytes(plaintext)
        } finally {
            plaintext.fill(0)
        }
    }

    private fun pruneSnapshots() {
        snapshotDir.listFiles()
            ?.sortedByDescending(File::lastModified)
            ?.drop(MAX_SNAPSHOTS)
            ?.forEach { it.delete() }
    }

    /**
     * Write to a temporary file, then rename.
     *
     * A process death or a full disk halfway through a direct write would leave a
     * truncated file, and a truncated *state* file is a lost watermark. Rename is atomic
     * on the filesystems Android uses.
     */
    private fun writeAtomically(target: File, bytes: ByteArray) {
        val temp = File(target.parentFile, "${target.name}.tmp")
        temp.writeBytes(bytes)
        if (!temp.renameTo(target)) {
            target.writeBytes(bytes)
            temp.delete()
        }
    }

    private fun encodeState(state: LocalSyncState): JsonObject = JsonObject(
        sortedMapOf(
            "highestSeenVersion" to JsonPrimitive(state.highestSeenVersion),
            "lastHeaderBytes" to JsonPrimitive(state.lastHeaderBytes?.let(base64::encodeToString) ?: ""),
            "lastSeenGeneration" to JsonPrimitive(state.lastSeenGeneration ?: ""),
            "dirty" to JsonPrimitive(state.dirty),
        ),
    )

    private fun decodeState(obj: JsonObject): LocalSyncState = LocalSyncState(
        highestSeenVersion = obj["highestSeenVersion"]?.jsonPrimitive?.longOrNull ?: 0,
        lastHeaderBytes = obj["lastHeaderBytes"]?.jsonPrimitive?.content
            ?.takeIf(String::isNotEmpty)?.let(Base64.getDecoder()::decode),
        lastSeenGeneration = obj["lastSeenGeneration"]?.jsonPrimitive?.content?.takeIf(String::isNotEmpty),
        dirty = obj["dirty"]?.jsonPrimitive?.booleanOrNull ?: false,
    )

    private companion object {
        const val MAX_SNAPSHOTS = 5
        val base64: Base64.Encoder = Base64.getEncoder()
    }
}
