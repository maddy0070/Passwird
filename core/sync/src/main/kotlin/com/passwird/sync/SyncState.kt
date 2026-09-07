package com.passwird.sync

import com.passwird.crypto.VaultContainer
import com.passwird.model.VaultDocument
import java.security.MessageDigest
import java.util.Base64

/**
 * What this device remembers about the remote vault.
 *
 * **Must be persisted in encrypted local storage, not `SharedPreferences`.** The rollback
 * watermark is a security control: an attacker who could reset it by clearing app data
 * would be able to replay an old vault, which is exactly the attack [RollbackGuard]
 * exists to prevent.
 */
data class LocalSyncState(
    /** The highest `vaultVersion` this device has ever accepted. Monotonic, never lowered. */
    val highestSeenVersion: Long = 0,
    /** Header bytes of the last accepted version, for the hash chain. */
    val lastHeaderBytes: ByteArray? = null,
    /** The remote generation token last observed. */
    val lastSeenGeneration: String? = null,
    /** Local changes are waiting to be uploaded. */
    val dirty: Boolean = false,
) {
    val lastHeaderHash: String? get() = lastHeaderBytes?.let(::sha256B64)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is LocalSyncState) return false
        return highestSeenVersion == other.highestSeenVersion &&
            lastSeenGeneration == other.lastSeenGeneration &&
            dirty == other.dirty &&
            (lastHeaderBytes?.contentEquals(other.lastHeaderBytes) ?: (other.lastHeaderBytes == null))
    }

    override fun hashCode(): Int {
        var result = highestSeenVersion.hashCode()
        result = 31 * result + (lastHeaderBytes?.contentHashCode() ?: 0)
        result = 31 * result + (lastSeenGeneration?.hashCode() ?: 0)
        result = 31 * result + dirty.hashCode()
        return result
    }

    companion object {
        fun sha256B64(bytes: ByteArray): String =
            Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(bytes))
    }
}

/** Version and chain metadata, readable **without** unlocking the vault. */
data class VaultFileInfo(
    val vaultVersion: Long,
    val headerBytes: ByteArray,
    val chain: ByteArray,
) {
    val headerHash: String get() = LocalSyncState.sha256B64(headerBytes)

    override fun equals(other: Any?): Boolean =
        this === other || (
            other is VaultFileInfo &&
                vaultVersion == other.vaultVersion &&
                headerBytes.contentEquals(other.headerBytes) &&
                chain.contentEquals(other.chain)
            )

    override fun hashCode(): Int =
        31 * (31 * vaultVersion.hashCode() + headerBytes.contentHashCode()) + chain.contentHashCode()
}

/**
 * Reads a vault's version metadata without any key material.
 *
 * Rollback detection has to work **before** the user is asked for their passphrase —
 * making someone type a secret in order to be told the file was tampered with would be
 * both bad UX and an unnecessary exposure of the passphrase to a hostile situation.
 */
object VaultFileInspector {
    fun inspect(bytes: ByteArray): VaultFileInfo {
        val parsed = VaultContainer.parse(bytes)
        return VaultFileInfo(
            vaultVersion = parsed.header.vaultVersion,
            headerBytes = parsed.headerBytes,
            chain = parsed.header.chain,
        )
    }
}

/** The outcome of an integrity check on a downloaded vault. */
sealed interface IntegrityVerdict {
    data object Ok : IntegrityVerdict

    /** E-17: the remote is older than a version we already accepted. */
    data class Rollback(val expectedAtLeast: Long, val found: Long) : IntegrityVerdict

    /** E-18: same version, different content — the history was rewritten. */
    data class Fork(val version: Long) : IntegrityVerdict

    /** The chain does not link to what we last saw. */
    data class BrokenChain(val version: Long) : IntegrityVerdict
}

/**
 * Defends against a store that serves stale-but-valid data.
 *
 * This is the concrete answer to the "vault integrity" attack class in the February 2026
 * ETH Zürich / USI results, where clients accepted whatever the server handed them. Google
 * Drive can legitimately do this by restoring an old file version; an attacker with the
 * account can do it deliberately, to resurrect a deleted credential or revert a password
 * change the user made after a breach.
 *
 * **No verdict here is ever auto-resolved.** A rejected download never replaces the local
 * vault; it raises a screen that explains what happened and lets the user decide.
 */
object RollbackGuard {

    fun check(state: LocalSyncState, remote: VaultFileInfo): IntegrityVerdict {
        if (remote.vaultVersion < state.highestSeenVersion) {
            return IntegrityVerdict.Rollback(state.highestSeenVersion, remote.vaultVersion)
        }

        if (remote.vaultVersion == state.highestSeenVersion && state.lastHeaderBytes != null) {
            // Same version number, different bytes: someone rewrote this version in place.
            if (!remote.headerBytes.contentEquals(state.lastHeaderBytes)) {
                return IntegrityVerdict.Fork(remote.vaultVersion)
            }
        }

        // The immediate successor must chain to the header we last accepted. Gaps are
        // legitimate (another device may have written several versions while we were
        // offline), so the link is only checked where it can be.
        if (state.lastHeaderBytes != null && remote.vaultVersion == state.highestSeenVersion + 1) {
            val expected = MessageDigest.getInstance("SHA-256").digest(state.lastHeaderBytes)
            if (!remote.chain.contentEquals(expected)) {
                return IntegrityVerdict.BrokenChain(remote.vaultVersion)
            }
        }

        return IntegrityVerdict.Ok
    }
}

/**
 * Encryption, from the sync engine's point of view.
 *
 * Keeps key management out of `core:sync` entirely: the engine can merge and publish
 * without ever holding, or knowing the shape of, key material.
 */
interface VaultSealer {
    /** Decrypts and decodes. */
    fun open(bytes: ByteArray): VaultDocument

    /** Encodes and encrypts, advancing the version counter and chaining from [previousHeaderBytes]. */
    fun seal(document: VaultDocument, previousHeaderBytes: ByteArray?): ByteArray
}

/** Persistence for sync bookkeeping. Backed by encrypted storage on device. */
interface SyncStateStore {
    suspend fun load(): LocalSyncState
    suspend fun save(state: LocalSyncState)

    /** The last state both sides are known to have agreed on, for three-way merge. */
    suspend fun loadBase(): VaultDocument?
    suspend fun saveBase(document: VaultDocument)

    /**
     * Captures the local vault before a merge writes anything.
     *
     * Principle 1 as code: if a merge produces something the user rejects, one tap
     * restores the pre-merge state.
     */
    suspend fun snapshot(document: VaultDocument)
}
