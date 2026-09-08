package com.passwird.sync

/**
 * The complete surface the sync engine needs from a cloud store.
 *
 * Deliberately tiny. Everything above this line is pure logic that runs in unit tests;
 * everything below it is one adapter per backend. Google Drive is *an implementation of
 * this interface*, not a dependency of the engine — which is what makes the whole conflict
 * matrix testable without a network, and what would let a WebDAV or local-network backend
 * drop in without touching a line of merge code.
 *
 * Note what is absent: no notion of accounts, folders, revisions-as-Drive-understands-them,
 * or HTTP. The engine never learns that Google exists.
 */
interface VaultTransport {

    /** Metadata for the stored vault, or null if none exists yet. */
    suspend fun stat(): RemoteStat?

    /**
     * Distinguishes *no vault has ever existed* from *the vault is missing right now*.
     *
     * [stat] returning null cannot tell those apart, and the difference decides whether the
     * app offers to create a vault. An interrupted publish, a partially restored folder or a
     * half-deleted one all present as "no vault" to `stat`, and treating any of them as a new
     * user invites publishing an empty vault over a real one — see
     * `docs/14-production-readiness-review.md` §F-2 and [VaultPublisher].
     *
     * The default is the conservative reading for a transport that cannot enumerate: a vault
     * is [RemoteVaultState.Present] or the state is unknown, never provably [RemoteVaultState.Empty].
     * A transport that *can* list its objects must override this.
     */
    suspend fun probe(): RemoteVaultState =
        if (stat() != null) RemoteVaultState.Present else RemoteVaultState.Interrupted(emptyList())

    /** Fetches the current bytes together with the generation they were read at. */
    suspend fun download(): RemoteObject

    /**
     * Publishes [bytes], but only if the remote is still at [expectedGeneration].
     *
     * The whole concurrency story lives in this parameter. An upload whose expectation no
     * longer holds must be **rejected**, never applied — that is the difference between
     * "two devices converge" and "one device silently overwrote the other".
     *
     * @param expectedGeneration the generation the caller last saw; null means "only if
     *   nothing exists yet".
     * @throws TransportError.GenerationMismatch if the remote moved on.
     */
    suspend fun upload(bytes: ByteArray, expectedGeneration: String?): RemoteStat

    suspend fun listBackups(): List<BackupRef>

    suspend fun restoreBackup(ref: BackupRef): RemoteObject
}

/**
 * @param generation an opaque token that changes whenever the stored bytes change. It is
 *   never parsed or ordered by the engine — only compared for equality.
 */
data class RemoteStat(
    val generation: String,
    val sizeBytes: Long,
    val modifiedAtEpochMillis: Long,
)

data class RemoteObject(val bytes: ByteArray, val stat: RemoteStat) {
    override fun equals(other: Any?): Boolean =
        this === other || (other is RemoteObject && bytes.contentEquals(other.bytes) && stat == other.stat)

    override fun hashCode(): Int = 31 * bytes.contentHashCode() + stat.hashCode()

    /** Never render vault bytes, even ciphertext, into a log line. */
    override fun toString(): String = "RemoteObject(${bytes.size} bytes, generation=${stat.generation})"
}

data class BackupRef(
    val id: String,
    val label: String,
    val vaultVersion: Long,
    val createdAtEpochMillis: Long,
)

/**
 * The small typed vocabulary the engine understands.
 *
 * Adapters translate their backend's error surface into exactly these; the engine has no
 * knowledge of HTTP status codes, and each of these maps to a specific row in
 * `docs/10-error-matrix.md`.
 */
sealed class TransportError(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /** E-11. Not an error state — offline is a supported mode. */
    class Offline : TransportError("No network connectivity")

    /** E-09 / E-10. */
    class AuthExpired : TransportError("Authentication has expired")
    class PermissionDenied : TransportError("Access to the remote store was denied")

    /** E-12. */
    class QuotaExceeded : TransportError("Remote storage quota exceeded")

    /** E-13. Handled invisibly with backoff. */
    class RateLimited(val retryAfterSeconds: Long?) : TransportError("Rate limited by the remote store")
    class ServerError(detail: String) : TransportError("Remote store error: $detail")

    /** E-14. Usually first run, or the user deleted the file. */
    class NotFound : TransportError("No vault found in the remote store")

    /** Someone else wrote first. The engine re-plans rather than overwriting. */
    class GenerationMismatch(val expected: String?, val actual: String?) :
        TransportError("Remote generation changed (expected $expected, found $actual)")

    /** E-25. The round-trip verification after upload failed. */
    class CorruptUpload : TransportError("Uploaded bytes did not verify")
}
