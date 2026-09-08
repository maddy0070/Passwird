package com.passwird.store

import com.passwird.model.VaultDocument
import com.passwird.model.codec.VaultDocumentCodec
import com.passwird.sync.LocalSyncState
import com.passwird.sync.SyncStateStore
import com.passwird.sync.VaultTransport
import java.io.File
import java.io.IOException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

/**
 * The one Android-shaped hole in this module.
 *
 * On a device this is backed by a hardware key in the Android Keystore. In tests it is
 * backed by an in-memory AEAD. Keeping it an interface is what lets the storage layer —
 * where atomicity and file-format bugs actually live — be tested without an emulator.
 *
 * Implementations must be authenticated encryption. A tampered blob has to fail, not decrypt
 * to garbage, because [FileVaultStorage] treats a decryption failure as "start again" and
 * garbage as truth.
 */
interface DeviceCipher {
    fun seal(plaintext: ByteArray): ByteArray

    /** @throws IOException if the blob is not authentic — never returns garbage. */
    fun open(ciphertext: ByteArray): ByteArray
}

/**
 * On-disk vault storage.
 *
 * ### What is sealed with the device key, and what is not
 *
 * | File | Contents | Device-key sealed |
 * |---|---|---|
 * | `vault.pwv` | The PWVAULT container | **No** |
 * | `sync-state.bin` | Watermark, generation, last header | Yes |
 * | `base.bin` | The last agreed **decrypted** document | Yes |
 * | `snapshot.bin` | Pre-merge **decrypted** document | Yes |
 *
 * The asymmetry is deliberate and worth stating, because "encrypt everything" sounds
 * stricter and is wrong here.
 *
 * `base.bin` and `snapshot.bin` hold decrypted `VaultDocument`s — every password in the
 * clear. Writing those without sealing them would be the single worst bug this class could
 * contain, and it is exactly the bug an "it's already in app-private storage" argument
 * produces. They are sealed.
 *
 * `vault.pwv` is *already* a container encrypted under the VEK, designed to be safe in a
 * store we assume is hostile. Sealing it again with a device key would add a layer whose
 * only real effect is that **losing the Keystore key destroys the local vault** — Keystore
 * entries are lost on biometric re-enrolment, factory-reset-protection events and some OEM
 * update paths. That converts a routine hardware event into data loss, which is the same
 * anti-pattern as wipe-on-failed-unlock (ADR-0008). The local copy stays as the container,
 * whose security is Argon2id and the VEK, exactly as `02-threat-model.md` T2 describes.
 *
 * ### Atomicity
 *
 * Every write is staged to a temp file in the same directory and renamed over the target.
 * A rename within a directory is atomic on every filesystem Android uses, so a process
 * death mid-write leaves either the old file or the new one — never half of either. A
 * truncated `vault.pwv` is an unrecoverable vault, so this is not a nicety.
 */
class FileVaultStorage(
    private val root: File,
    private val cipher: DeviceCipher,
    private val transport: VaultTransport,
    private val io: CoroutineDispatcher = Dispatchers.IO,
) : VaultStorage {

    private val vaultFile = File(root, VAULT_FILE)
    private val headerFile = File(root, HEADER_FILE)
    private val stateFile = File(root, STATE_FILE)
    private val baseFile = File(root, BASE_FILE)
    private val snapshotFile = File(root, SNAPSHOT_FILE)

    init {
        if (!root.exists() && !root.mkdirs()) {
            throw IOException("cannot create vault directory ${root.path}")
        }
    }

    override suspend fun readVault(): ByteArray? = withContext(io) {
        vaultFile.takeIf { it.isFile }?.readBytes()
    }

    override suspend fun writeVault(bytes: ByteArray) = withContext(io) {
        writeAtomically(vaultFile, bytes)
        // Cached rather than re-parsed on every mutation: the repository asks for the
        // previous header on every single write, and parsing the container to answer would
        // make each save cost a full structural parse of the whole vault.
        writeAtomically(headerFile, headerBytesOf(bytes))
    }

    override suspend fun lastHeaderBytes(): ByteArray? = withContext(io) {
        headerFile.takeIf { it.isFile }?.readBytes()
    }

    override fun transport(): VaultTransport = transport

    override fun syncStateStore(): SyncStateStore = FileSyncStateStore()

    /**
     * True when this directory holds evidence of a vault, even if [readVault] returns null.
     *
     * This exists because of a specific failure identified in
     * `14-production-readiness-review.md` §F-2: a publish interrupted between deleting the
     * live file and renaming its replacement leaves no vault under the expected name. If
     * "no vault file" is allowed to mean "new user", onboarding will offer to create a fresh
     * vault over the top of a real one.
     *
     * **A `NoVault` verdict has to be earned.** Any of these means the opposite: this device
     * has had a vault, and the right destination is recovery, not onboarding.
     */
    suspend fun hasEvidenceOfVault(): Boolean = withContext(io) {
        vaultFile.isFile || headerFile.isFile || stateFile.isFile || baseFile.isFile ||
            snapshotFile.isFile ||
            root.listFiles { file -> file.name.startsWith(TEMP_PREFIX) }?.isNotEmpty() == true
    }

    /**
     * Erases every local trace of the vault.
     *
     * Used on sign-out-and-forget and on uninstall paths. Deliberately not offered as a
     * recovery action anywhere in the UI: "delete everything" is never the fix for a state
     * the user does not understand.
     */
    suspend fun destroy() = withContext(io) {
        listOf(vaultFile, headerFile, stateFile, baseFile, snapshotFile).forEach { it.delete() }
        root.listFiles { file -> file.name.startsWith(TEMP_PREFIX) }?.forEach { it.delete() }
        Unit
    }

    // ------------------------------------------------------------------ internals

    /**
     * The authenticated prefix of a container: magic, version, header length and header.
     *
     * Recomputed from the framing rather than trusting a cached copy, so a corrupted file
     * cannot silently poison the hash chain.
     */
    private fun headerBytesOf(container: ByteArray): ByteArray {
        require(container.size >= PREFIX_MIN) { "container too short to contain a header" }
        val headerLength = ((container[10].toInt() and 0xFF) shl 24) or
            ((container[11].toInt() and 0xFF) shl 16) or
            ((container[12].toInt() and 0xFF) shl 8) or
            (container[13].toInt() and 0xFF)
        require(headerLength in 1..(container.size - PREFIX_MIN)) {
            "declared header length $headerLength is not consistent with a ${container.size}-byte file"
        }
        return container.copyOfRange(PREFIX_MIN, PREFIX_MIN + headerLength)
    }

    private fun writeAtomically(target: File, bytes: ByteArray) {
        val temp = File(root, "$TEMP_PREFIX${target.name}.${System.nanoTime()}")
        try {
            temp.writeBytes(bytes)
            if (!temp.renameTo(target)) {
                // Some filesystems refuse a rename onto an existing file. Deleting first
                // opens a window where neither exists, so it is the fallback rather than
                // the default, and the temp file survives to make the loss recoverable.
                if (!target.delete() || !temp.renameTo(target)) {
                    throw IOException("could not replace ${target.name}")
                }
            }
        } finally {
            if (temp.exists()) temp.delete()
        }
    }

    private inner class FileSyncStateStore : SyncStateStore {

        override suspend fun load(): LocalSyncState = withContext(io) {
            val bytes = readSealed(stateFile) ?: return@withContext LocalSyncState()
            runCatching { decodeState(bytes) }.getOrElse {
                // Unreadable bookkeeping must never block access to the vault. Starting from
                // a zero watermark costs one full sync; refusing to unlock costs the user
                // their credentials.
                LocalSyncState()
            }
        }

        override suspend fun save(state: LocalSyncState) = withContext(io) {
            writeSealed(stateFile, encodeState(state))
        }

        override suspend fun loadBase(): VaultDocument? = withContext(io) {
            val bytes = readSealed(baseFile) ?: return@withContext null
            runCatching { VaultDocumentCodec.decodeFromBytes(bytes) }.getOrNull()
        }

        override suspend fun saveBase(document: VaultDocument) = withContext(io) {
            writeSealed(baseFile, VaultDocumentCodec.encodeToBytes(document))
        }

        override suspend fun snapshot(document: VaultDocument) = withContext(io) {
            writeSealed(snapshotFile, VaultDocumentCodec.encodeToBytes(document))
        }

        private fun readSealed(file: File): ByteArray? {
            if (!file.isFile) return null
            return runCatching { cipher.open(file.readBytes()) }.getOrNull()
        }

        private fun writeSealed(file: File, plaintext: ByteArray) {
            writeAtomically(file, cipher.seal(plaintext))
        }

        private fun encodeState(state: LocalSyncState): ByteArray = buildString {
            append(
                JsonObject(
                    buildMap {
                        put("highestSeenVersion", JsonPrimitive(state.highestSeenVersion))
                        put("dirty", JsonPrimitive(state.dirty))
                        state.lastSeenGeneration?.let { put("lastSeenGeneration", JsonPrimitive(it)) }
                        state.lastHeaderBytes?.let {
                            put("lastHeaderBytes", JsonPrimitive(it.toBase64()))
                        }
                    },
                ),
            )
        }.toByteArray()

        private fun decodeState(bytes: ByteArray): LocalSyncState {
            val json = Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
            return LocalSyncState(
                highestSeenVersion = json["highestSeenVersion"]?.jsonPrimitive?.longOrNull ?: 0,
                lastHeaderBytes = json["lastHeaderBytes"]?.jsonPrimitive?.contentOrNull?.fromBase64(),
                lastSeenGeneration = json["lastSeenGeneration"]?.jsonPrimitive?.contentOrNull,
                dirty = json["dirty"]?.jsonPrimitive?.contentOrNull?.toBoolean() ?: false,
            )
        }
    }

    private companion object {
        const val VAULT_FILE = "vault.pwv"
        const val HEADER_FILE = "last-header.bin"
        const val STATE_FILE = "sync-state.bin"
        const val BASE_FILE = "base.bin"
        const val SNAPSHOT_FILE = "snapshot.bin"
        const val TEMP_PREFIX = ".tmp-"

        /** magic(8) + formatVersion(2) + headerLen(4) — see `03-encryption-architecture.md` §3. */
        const val PREFIX_MIN = 14
    }
}

private fun ByteArray.toBase64(): String = java.util.Base64.getEncoder().encodeToString(this)

private fun String.fromBase64(): ByteArray? =
    runCatching { java.util.Base64.getDecoder().decode(this) }.getOrNull()
