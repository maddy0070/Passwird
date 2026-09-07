package com.passwird.sync

import com.passwird.crypto.CryptoError
import com.passwird.model.DeviceId
import com.passwird.model.VaultDocument
import java.time.Instant

/** What a sync attempt did. Every case maps to a row in `docs/10-error-matrix.md`. */
sealed interface SyncOutcome {
    /** Nothing to do. */
    data object UpToDate : SyncOutcome

    /** No connectivity. Not an error — offline is a supported mode (E-11). */
    data object Offline : SyncOutcome

    data class Uploaded(val vaultVersion: Long) : SyncOutcome

    data class Downloaded(val document: VaultDocument, val vaultVersion: Long) : SyncOutcome

    /** E-15 when `summary.needsReview` is false, E-16 when it is true. */
    data class Merged(
        val document: VaultDocument,
        val summary: MergeSummary,
        val vaultVersion: Long,
    ) : SyncOutcome

    /**
     * The remote failed an integrity check (E-17 / E-18 / E-19).
     *
     * The local vault is untouched and remains authoritative. This is surfaced to the user
     * as a decision, never resolved automatically.
     */
    data class IntegrityProblem(val verdict: IntegrityVerdict) : SyncOutcome

    /** The remote bytes did not decrypt or parse (E-19). Local vault unaffected. */
    data class RemoteCorrupt(val detail: String) : SyncOutcome

    data class Failed(val error: TransportError) : SyncOutcome
}

/**
 * Orchestrates synchronisation.
 *
 * Pure Kotlin: no Android, no Google, no HTTP. Drive arrives as a [VaultTransport], keys
 * as a [VaultSealer]. That is what lets the entire conflict matrix and every failure path
 * run as fast unit tests instead of needing an emulator and a network.
 *
 * Two rules hold everywhere in this class:
 *
 *  - **The local vault is authoritative.** No failure path replaces it, and none blocks
 *    the UI. A sync that cannot complete leaves the user with a working vault.
 *  - **Never publish over an unexpected generation.** Every upload states the generation
 *    it expects; if the remote moved, the write is rejected and we re-plan rather than
 *    overwrite.
 */
class SyncEngine(
    private val transport: VaultTransport,
    private val sealer: VaultSealer,
    private val store: SyncStateStore,
    private val deviceId: DeviceId,
    private val clock: () -> Instant = Instant::now,
    private val maxAttempts: Int = 5,
) {

    suspend fun synchronise(local: VaultDocument): SyncOutcome {
        var attempt = 0
        while (true) {
            attempt++
            val outcome = runCatching { attemptSync(local) }.getOrElse { error ->
                when (error) {
                    is TransportError.Offline -> return SyncOutcome.Offline
                    is TransportError.GenerationMismatch -> {
                        // Someone published between our plan and our write. Re-plan rather
                        // than force: the merge is convergent, so a lost race costs one
                        // extra cycle, never data.
                        if (attempt >= maxAttempts) return SyncOutcome.Failed(error)
                        null
                    }
                    is TransportError -> return SyncOutcome.Failed(error)
                    is CryptoError -> return SyncOutcome.RemoteCorrupt(error.message ?: "unreadable vault")
                    else -> throw error
                }
            }
            if (outcome != null) return outcome
        }
    }

    private suspend fun attemptSync(local: VaultDocument): SyncOutcome {
        val state = store.load()
        val remoteStat = transport.stat()
            ?: return publishFirstVersion(local, state)

        val remoteMoved = remoteStat.generation != state.lastSeenGeneration

        return when {
            !state.dirty && !remoteMoved -> SyncOutcome.UpToDate
            !state.dirty && remoteMoved -> adoptRemote(state)
            state.dirty && !remoteMoved -> publishLocal(local, state, remoteStat.generation)
            else -> mergeAndPublish(local, state)
        }
    }

    /** First run, or the user deleted the remote file (E-14). */
    private suspend fun publishFirstVersion(local: VaultDocument, state: LocalSyncState): SyncOutcome {
        val bytes = sealer.seal(local, previousHeaderBytes = state.lastHeaderBytes)
        val info = VaultFileInspector.inspect(bytes)
        val stat = transport.upload(bytes, expectedGeneration = null)

        commit(state, info, stat.generation, local)
        return SyncOutcome.Uploaded(info.vaultVersion)
    }

    /** Remote moved while we had no local changes: take it, after checking integrity. */
    private suspend fun adoptRemote(state: LocalSyncState): SyncOutcome {
        val remote = transport.download()
        val info = VaultFileInspector.inspect(remote.bytes)

        RollbackGuard.check(state, info).let { verdict ->
            if (verdict != IntegrityVerdict.Ok) return SyncOutcome.IntegrityProblem(verdict)
        }

        val document = sealer.open(remote.bytes)
        commit(state, info, remote.stat.generation, document)
        return SyncOutcome.Downloaded(document, info.vaultVersion)
    }

    /** Local changes, remote unchanged: publish, but still state our expectation. */
    private suspend fun publishLocal(
        local: VaultDocument,
        state: LocalSyncState,
        expectedGeneration: String,
    ): SyncOutcome {
        val bytes = sealer.seal(local, previousHeaderBytes = state.lastHeaderBytes)
        val info = VaultFileInspector.inspect(bytes)
        val stat = transport.upload(bytes, expectedGeneration)

        commit(state, info, stat.generation, local)
        return SyncOutcome.Uploaded(info.vaultVersion)
    }

    /** Both sides changed. The interesting path. */
    private suspend fun mergeAndPublish(local: VaultDocument, state: LocalSyncState): SyncOutcome {
        val remote = transport.download()
        val info = VaultFileInspector.inspect(remote.bytes)

        RollbackGuard.check(state, info).let { verdict ->
            if (verdict != IntegrityVerdict.Ok) return SyncOutcome.IntegrityProblem(verdict)
        }

        val remoteDocument = sealer.open(remote.bytes)

        // Snapshot before anything is written, so a merge the user dislikes is one tap
        // from being undone.
        store.snapshot(local)

        val result = VaultMerge.merge(
            base = store.loadBase(),
            local = local,
            remote = remoteDocument,
            mergingDevice = deviceId,
            now = clock(),
        )

        val bytes = sealer.seal(result.document, previousHeaderBytes = info.headerBytes)
        val mergedInfo = VaultFileInspector.inspect(bytes)
        val stat = transport.upload(bytes, expectedGeneration = remote.stat.generation)

        commit(state, mergedInfo, stat.generation, result.document)
        return SyncOutcome.Merged(result.document, result.summary, mergedInfo.vaultVersion)
    }

    /**
     * Records what we accepted.
     *
     * The watermark only ever rises — `maxOf` is what makes the rollback defence
     * monotonic, and it must survive even an out-of-order or replayed response.
     */
    private suspend fun commit(
        state: LocalSyncState,
        info: VaultFileInfo,
        generation: String,
        document: VaultDocument,
    ) {
        store.save(
            state.copy(
                highestSeenVersion = maxOf(state.highestSeenVersion, info.vaultVersion),
                lastHeaderBytes = info.headerBytes,
                lastSeenGeneration = generation,
                dirty = false,
            ),
        )
        store.saveBase(document)
    }

    /** Marks that the vault has local changes awaiting upload. */
    suspend fun markDirty() {
        val state = store.load()
        if (!state.dirty) store.save(state.copy(dirty = true))
    }

    /**
     * Replaces the remote with the local vault after an integrity problem.
     *
     * Only reachable from the E-17 / E-18 screen, where the user has been told what was
     * found and has explicitly chosen to publish their copy. Deliberately not something
     * the engine can decide on its own.
     */
    suspend fun forcePublishLocal(local: VaultDocument): SyncOutcome {
        val state = store.load()
        val remoteStat = runCatching { transport.stat() }.getOrNull()
        val bytes = sealer.seal(local, previousHeaderBytes = state.lastHeaderBytes)
        val info = VaultFileInspector.inspect(bytes)

        return try {
            val stat = transport.upload(bytes, expectedGeneration = remoteStat?.generation)
            commit(state, info, stat.generation, local)
            SyncOutcome.Uploaded(info.vaultVersion)
        } catch (error: TransportError) {
            if (error is TransportError.Offline) SyncOutcome.Offline else SyncOutcome.Failed(error)
        }
    }
}
