package com.passwird.data.drive

import com.google.api.client.googleapis.json.GoogleJsonResponseException
import com.google.api.client.http.ByteArrayContent
import com.google.api.services.drive.Drive
import com.google.api.services.drive.model.File as DriveFile
import com.passwird.crypto.VaultContainer
import com.passwird.sync.BackupRef
import com.passwird.sync.RemoteObject
import com.passwird.sync.RemoteStat
import com.passwird.sync.RemoteVaultState
import com.passwird.sync.TransportError
import com.passwird.sync.VaultTransport
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.UnknownHostException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Google Drive as a [VaultTransport].
 *
 * This class is the *only* place in the product that knows Google exists. Everything above
 * it — the sync engine, the merge, the repository, the UI — sees the small interface in
 * `core:sync`, which is what lets all of that be tested without a network and would let a
 * different backend drop in unchanged.
 *
 * Drive's role here is narrow and unglamorous: hold some bytes, say when they changed, and
 * refuse our write if someone got there first. It is a courier, not a custodian, and the
 * bytes it carries are opaque to it.
 */
class DriveTransport(
    private val driveProvider: suspend () -> Drive,
    private val io: CoroutineDispatcher = Dispatchers.IO,
) : VaultTransport {

    private var cachedFolderId: String? = null

    override suspend fun stat(): RemoteStat? = call {
        val drive = driveProvider()
        val file = findVaultFile(drive) ?: return@call null
        RemoteStat(
            generation = file.headRevisionId ?: file.version?.toString() ?: file.modifiedTime.toString(),
            sizeBytes = file.getSize() ?: 0L,
            modifiedAtEpochMillis = file.modifiedTime?.value ?: 0L,
        )
    }

    override suspend fun download(): RemoteObject = call {
        val drive = driveProvider()
        val file = findVaultFile(drive) ?: throw TransportError.NotFound()
        RemoteObject(bytes = readFile(drive, file.id), stat = statOf(file))
    }

    /**
     * Publishes via **temp, verify, swap** — never an in-place write.
     *
     * Step order matters and every step earns its place:
     *
     *  1. Upload to a temporary name. A connection dropped mid-transfer can then only
     *     damage a file nothing points at.
     *  2. **Download it back, and check it parses and authenticates.** This catches a
     *     corrupted transfer that Drive nonetheless accepted — the failure mode that
     *     otherwise stays invisible until a new device finds the only copy unreadable.
     *  3. Copy the current live vault into `backups/`.
     *  4. Re-check the generation, and abort if the remote moved while we worked.
     *  5. **Rename** the live vault aside, then rename the temp into its place, then delete
     *     the superseded one.
     *
     * Step 5 is the shape it is because of a data-loss finding: it previously deleted the
     * live vault before renaming the replacement, leaving a window with no `vault.pwv` at
     * all. See the comment at that step, and [com.passwird.sync.VaultPublisher] for the same
     * sequence under test.
     *
     * A failure at any point leaves a readable vault reachable, and never leaves the folder
     * looking like a new user's.
     */
    override suspend fun upload(bytes: ByteArray, expectedGeneration: String?): RemoteStat = call {
        val drive = driveProvider()
        val folderId = ensureFolder(drive)
        val existing = findVaultFile(drive)

        // Optimistic concurrency. Drive has no compare-and-swap, so this narrows the window
        // rather than closing it; the residual race is safe because the merge above us is
        // convergent, so a lost race costs a cycle rather than data.
        val actualGeneration = existing?.let { statOf(it).generation }
        if (expectedGeneration != actualGeneration) {
            throw TransportError.GenerationMismatch(expectedGeneration, actualGeneration)
        }

        val stamp = "${System.nanoTime()}-${(0..0xFFFF).random().toString(16)}"
        val tempName = "$TEMP_PREFIX$stamp.pwv"
        val temp = drive.files().create(
            DriveFile().apply {
                name = tempName
                parents = listOf(folderId)
            },
            ByteArrayContent(MIME_BINARY, bytes),
        ).setFields(FILE_FIELDS).execute()

        try {
            verifyRoundTrip(drive, temp.id, bytes)

            existing?.let { current -> archive(drive, folderId, current) }

            // One last look before committing.
            val stillExpected = findVaultFile(drive)?.let { statOf(it).generation }
            if (stillExpected != actualGeneration) {
                throw TransportError.GenerationMismatch(expectedGeneration, stillExpected)
            }

            // The live name is handed over by rename, never released.
            //
            // This used to delete the live vault and only then rename the replacement into
            // place. Between those two calls no object named vault.pwv existed, and
            // VaultRepository maps a missing vault to NoVault - the signal onboarding uses to
            // offer to create a new one. A process death or dropped connection in that window
            // could therefore lead a user to publish a fresh empty vault over their real one.
            // Reported as section F-2 of docs/14-production-readiness-review.md; the ordering
            // below is the same one VaultPublisher implements and VaultPublisherTest proves
            // correct by interrupting it at every step.
            val supersededName = "$SUPERSEDED_PREFIX$stamp.pwv"
            existing?.let { current ->
                drive.files()
                    .update(current.id, DriveFile().apply { name = supersededName })
                    .execute()
            }

            val published = drive.files()
                .update(temp.id, DriveFile().apply { name = VAULT_FILE_NAME })
                .setFields(FILE_FIELDS)
                .execute()

            // Only now that the replacement is live and verified. A failure here leaves a
            // superseded object behind, which `probe` reads as "interrupted" rather than
            // "new user" - the second, independent defence.
            existing?.let { current -> runCatching { drive.files().delete(current.id).execute() } }

            pruneBackups(drive, folderId)
            statOf(published)
        } catch (error: Throwable) {
            runCatching { drive.files().delete(temp.id).execute() }
            throw error
        }
    }

    /**
     * Whether this Drive folder holds a vault, has held one, or has never held one.
     *
     * The second, independent defence against the §F-2 data-loss path. Even if the ordering
     * in [upload] were somehow defeated and the live object went missing, a folder containing
     * a staged upload, a superseded vault or a backup is **not** a new user's folder, and the
     * app must route it to recovery rather than to onboarding.
     *
     * A folder that does not exist at all is the one honest [RemoteVaultState.Empty]: nothing
     * has ever been written here.
     */
    override suspend fun probe(): RemoteVaultState = call {
        val drive = driveProvider()
        val folderId = findFolder(drive) ?: return@call RemoteVaultState.Empty

        val names = drive.files().list()
            .setQ("'$folderId' in parents and trashed = false")
            .setFields("files(name)")
            .setSpaces("drive")
            .execute()
            .files
            ?.map { it.name }
            .orEmpty()

        if (VAULT_FILE_NAME in names) return@call RemoteVaultState.Present

        // `backups` is a folder, and its presence is itself evidence: it is only ever created
        // when a vault is first replaced.
        val evidence = names.filter {
            it.startsWith(TEMP_PREFIX) || it.startsWith(SUPERSEDED_PREFIX) || it == BACKUPS_FOLDER
        }
        if (evidence.isEmpty()) RemoteVaultState.Empty else RemoteVaultState.Interrupted(evidence.sorted())
    }

    override suspend fun listBackups(): List<BackupRef> = call {
        val drive = driveProvider()
        val folderId = ensureFolder(drive)
        backupFiles(drive, folderId).map { file ->
            BackupRef(
                id = file.id,
                label = file.name,
                vaultVersion = file.name.removePrefix(BACKUP_PREFIX).removeSuffix(".pwv").toLongOrNull() ?: 0,
                createdAtEpochMillis = file.createdTime?.value ?: 0L,
            )
        }
    }

    override suspend fun restoreBackup(ref: BackupRef): RemoteObject = call {
        val drive = driveProvider()
        val bytes = readFile(drive, ref.id)
        RemoteObject(bytes, RemoteStat(ref.id, bytes.size.toLong(), ref.createdAtEpochMillis))
    }

    // ------------------------------------------------------------------ internals

    /**
     * Round-trip verification.
     *
     * Deliberately an extra fetch. Discovering a corrupted upload six months later, on a
     * new device, when it is the only copy left, is not a trade worth making to save one
     * request.
     *
     * Checks two different things, because they fail differently. Byte equality catches a
     * transfer Drive mangled. **Parsing the container catches a fault in our own
     * serialisation** — bytes that survived the network perfectly and are still not a vault.
     * The doc comment above claimed both from the beginning; only the first was implemented,
     * which was recorded as §B-6 of the production-readiness review.
     */
    private fun verifyRoundTrip(drive: Drive, fileId: String, expected: ByteArray) {
        val readBack = readFile(drive, fileId)
        if (!readBack.contentEquals(expected)) throw TransportError.CorruptUpload()

        // Structural parse with every declared length bounds-checked. Cheap - the bytes are
        // already in memory - and it is the difference between "Drive stored what we sent"
        // and "what we sent is openable".
        runCatching { VaultContainer.parse(readBack) }
            .onFailure { throw TransportError.CorruptUpload() }
    }

    private fun readFile(drive: Drive, fileId: String): ByteArray {
        val out = ByteArrayOutputStream()
        drive.files().get(fileId).executeMediaAndDownloadTo(out)
        return out.toByteArray()
    }

    private fun archive(drive: Drive, folderId: String, current: DriveFile) {
        val backupsId = ensureSubfolder(drive, folderId, BACKUPS_FOLDER)
        drive.files().copy(
            current.id,
            DriveFile().apply {
                name = "$BACKUP_PREFIX${System.currentTimeMillis()}.pwv"
                parents = listOf(backupsId)
            },
        ).execute()
    }

    private fun pruneBackups(drive: Drive, folderId: String) {
        val backups = backupFiles(drive, folderId)
        backups.drop(MAX_BACKUPS).forEach { stale ->
            runCatching { drive.files().delete(stale.id).execute() }
        }
    }

    private fun backupFiles(drive: Drive, folderId: String): List<DriveFile> {
        val backupsId = findSubfolder(drive, folderId, BACKUPS_FOLDER) ?: return emptyList()
        return drive.files().list()
            .setQ("'$backupsId' in parents and trashed = false")
            .setOrderBy("createdTime desc")
            .setFields("files($FILE_FIELDS)")
            .setSpaces("drive")
            .execute()
            .files
            .orEmpty()
    }

    private fun findVaultFile(drive: Drive): DriveFile? {
        val folderId = cachedFolderId ?: findFolder(drive) ?: return null
        return drive.files().list()
            .setQ("name = '$VAULT_FILE_NAME' and '$folderId' in parents and trashed = false")
            .setFields("files($FILE_FIELDS)")
            .setSpaces("drive")
            .execute()
            .files
            ?.firstOrNull()
    }

    private fun statOf(file: DriveFile) = RemoteStat(
        generation = file.headRevisionId ?: file.version?.toString() ?: "0",
        sizeBytes = file.getSize() ?: 0L,
        modifiedAtEpochMillis = file.modifiedTime?.value ?: 0L,
    )

    private fun ensureFolder(drive: Drive): String =
        cachedFolderId ?: findFolder(drive) ?: createFolder(drive).also { cachedFolderId = it }

    private fun findFolder(drive: Drive): String? =
        drive.files().list()
            .setQ("name = '$FOLDER_NAME' and mimeType = '$MIME_FOLDER' and trashed = false")
            .setFields("files(id)")
            .setSpaces("drive")
            .execute()
            .files
            ?.firstOrNull()
            ?.id
            ?.also { cachedFolderId = it }

    private fun createFolder(drive: Drive): String {
        val folder = drive.files().create(
            DriveFile().apply {
                name = FOLDER_NAME
                mimeType = MIME_FOLDER
            },
        ).setFields("id").execute()

        writeReadme(drive, folder.id)
        return folder.id
    }

    /**
     * A note for a human who finds this folder in three years.
     *
     * They will see an opaque binary file and wonder whether it is safe to delete. Contains
     * no secrets, no identifiers and nothing about the vault's contents.
     */
    private fun writeReadme(drive: Drive, folderId: String) {
        val text = """
            Passwird vault
            ==============

            vault.pwv is an encrypted copy of your password vault.

            It is encrypted on your phone before it is uploaded. Google cannot read it, and
            neither can we. Opening it in a text editor will show only random-looking bytes.

            Deleting this folder does NOT delete the vault on your phone. Your phone keeps
            the original and will simply upload a fresh copy the next time it syncs.

            You are welcome to copy this folder somewhere else as an extra backup. The file
            can be restored by any version of Passwird, given your passphrase or your
            recovery key.

            Without one of those two, nobody can open it. That is the point.
        """.trimIndent()

        runCatching {
            drive.files().create(
                DriveFile().apply {
                    name = README_NAME
                    parents = listOf(folderId)
                },
                ByteArrayContent("text/plain", text.toByteArray()),
            ).execute()
        }
    }

    private fun findSubfolder(drive: Drive, parentId: String, name: String): String? =
        drive.files().list()
            .setQ("name = '$name' and mimeType = '$MIME_FOLDER' and '$parentId' in parents and trashed = false")
            .setFields("files(id)")
            .setSpaces("drive")
            .execute()
            .files
            ?.firstOrNull()
            ?.id

    private fun ensureSubfolder(drive: Drive, parentId: String, name: String): String =
        findSubfolder(drive, parentId, name) ?: drive.files().create(
            DriveFile().apply {
                this.name = name
                mimeType = MIME_FOLDER
                parents = listOf(parentId)
            },
        ).setFields("id").execute().id

    /**
     * Runs a Drive call, translating its error surface into the engine's small vocabulary.
     *
     * The engine has no knowledge of HTTP status codes, and every case here degrades to
     * "the app keeps working offline" rather than blocking the vault.
     */
    private suspend fun <T> call(block: suspend () -> T): T = withContext(io) {
        try {
            block()
        } catch (error: TransportError) {
            throw error
        } catch (error: GoogleJsonResponseException) {
            throw when (error.statusCode) {
                401 -> TransportError.AuthExpired()
                403 -> when (error.details?.errors?.firstOrNull()?.reason) {
                    "storageQuotaExceeded" -> TransportError.QuotaExceeded()
                    "rateLimitExceeded", "userRateLimitExceeded" -> TransportError.RateLimited(null)
                    else -> TransportError.PermissionDenied()
                }
                404 -> TransportError.NotFound()
                429 -> TransportError.RateLimited(null)
                in 500..599 -> TransportError.ServerError("HTTP ${error.statusCode}")
                else -> TransportError.ServerError("HTTP ${error.statusCode}")
            }
        } catch (error: UnknownHostException) {
            throw TransportError.Offline()
        } catch (error: IOException) {
            // A dropped connection is indistinguishable from being offline, and treating it
            // as such is the behaviour the user wants: retry quietly, never interrupt.
            throw TransportError.Offline()
        }
    }

    private companion object {
        const val FOLDER_NAME = "Passwird"
        const val BACKUPS_FOLDER = "backups"
        const val VAULT_FILE_NAME = "vault.pwv"
        const val TEMP_PREFIX = ".tmp-"
        const val SUPERSEDED_PREFIX = "superseded-"
        const val README_NAME = "README.txt"
        const val BACKUP_PREFIX = "vault-"
        const val MIME_FOLDER = "application/vnd.google-apps.folder"
        const val MIME_BINARY = "application/octet-stream"
        const val MAX_BACKUPS = 10
        const val FILE_FIELDS = "id,name,size,modifiedTime,createdTime,headRevisionId,version"
    }
}

/**
 * Builds a transport for the currently signed-in account.
 *
 * [DriveTransport]'s own KDoc says this class is "the only place in the product that knows
 * Google exists" — and its constructor contradicted that, because `driveProvider` names
 * `Drive` in its type, forcing every caller onto Google's classpath. The composition root
 * could not compile without it.
 *
 * This factory is what makes the claim true: the app module names neither `Drive` nor any
 * other Google type, and `data:drive` keeps its dependency `implementation`-scoped rather
 * than leaking it upward as `api`.
 */
fun driveTransportFor(accountManager: GoogleAccountManager): DriveTransport =
    DriveTransport(driveProvider = { accountManager.drive() })
