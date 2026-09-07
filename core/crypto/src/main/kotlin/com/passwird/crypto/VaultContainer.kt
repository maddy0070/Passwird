package com.passwird.crypto

import java.security.MessageDigest

/**
 * Binary framing for the PWVAULT container.
 *
 * ```
 *  magic          8 B   "PWVAULT\0"
 *  formatVersion  2 B   u16
 *  headerLen      4 B   u32
 *  header         N B   canonical JSON
 *  ── AAD covers everything above ──
 *  payloadLen     8 B   u64
 *  payload        M B   AES-256-GCM ciphertext ‖ 16 B tag
 * ```
 *
 * Binding the whole prefix as AAD is what makes the header tamper-evident: an attacker
 * who lowers the Argon2 cost, swaps a key slot or forges the version counter produces a
 * file that simply fails to decrypt.
 *
 * This parser runs on bytes fetched from a store we assume is hostile (threat model T5),
 * so every declared length is validated against the bytes actually present *before* any
 * allocation. A header claiming 4 GiB must cost us an error, not an OOM.
 */
object VaultContainer {

    /** ASCII "PWVAULT" followed by a NUL byte. */
    val MAGIC: ByteArray = byteArrayOf(0x50, 0x57, 0x56, 0x41, 0x55, 0x4C, 0x54, 0x00)

    const val FORMAT_VERSION: Int = 1
    const val MIN_SUPPORTED_VERSION: Int = 1
    const val MAX_SUPPORTED_VERSION: Int = 1

    const val MAX_HEADER_BYTES: Int = 1 shl 20 // 1 MiB
    const val MAX_PAYLOAD_BYTES: Long = 64L shl 20 // 64 MiB

    private const val OFF_FORMAT_VERSION = 8
    private const val OFF_HEADER_LEN = 10
    private const val OFF_HEADER = 14

    /** A parsed container. [aad] and [headerBytes] are the exact bytes from the file. */
    class Parsed(
        val formatVersion: Int,
        val header: VaultHeader,
        val headerBytes: ByteArray,
        val aad: ByteArray,
        val payload: ByteArray,
    )

    fun serialize(headerBytes: ByteArray, payload: ByteArray): ByteArray {
        require(headerBytes.size <= MAX_HEADER_BYTES) { "header too large" }
        val total = OFF_HEADER + headerBytes.size + 8 + payload.size
        val out = ByteArray(total)

        MAGIC.copyInto(out, 0)
        BE.putU16(out, OFF_FORMAT_VERSION, FORMAT_VERSION)
        BE.putU32(out, OFF_HEADER_LEN, headerBytes.size)
        headerBytes.copyInto(out, OFF_HEADER)

        val payloadLenOffset = OFF_HEADER + headerBytes.size
        BE.putU64(out, payloadLenOffset, payload.size.toLong())
        payload.copyInto(out, payloadLenOffset + 8)

        return out
    }

    fun parse(bytes: ByteArray): Parsed {
        if (bytes.size < OFF_HEADER) {
            throw CryptoError.MalformedVault("File is too short to be a vault")
        }
        for (i in MAGIC.indices) {
            if (bytes[i] != MAGIC[i]) {
                throw CryptoError.MalformedVault("Not a Passwird vault file")
            }
        }

        val formatVersion = BE.getU16(bytes, OFF_FORMAT_VERSION)
        if (formatVersion !in MIN_SUPPORTED_VERSION..MAX_SUPPORTED_VERSION) {
            // Never guess at an unknown format. A client that half-understands a newer
            // file and writes it back is how vaults get silently truncated across
            // devices — see docs/10-error-matrix.md E-21.
            throw CryptoError.UnsupportedVersion(
                formatVersion, MIN_SUPPORTED_VERSION, MAX_SUPPORTED_VERSION,
            )
        }

        val headerLen = BE.getU32(bytes, OFF_HEADER_LEN)
        if (headerLen <= 0 || headerLen > MAX_HEADER_BYTES) {
            throw CryptoError.MalformedVault("Declared header length is out of range")
        }
        val headerEnd = OFF_HEADER.toLong() + headerLen
        if (headerEnd + 8 > bytes.size) {
            throw CryptoError.MalformedVault("File is truncated inside the header")
        }

        val headerBytes = bytes.copyOfRange(OFF_HEADER, headerEnd.toInt())
        val payloadLen = BE.getU64(bytes, headerEnd.toInt())
        if (payloadLen < Aead.TAG_BYTES || payloadLen > MAX_PAYLOAD_BYTES) {
            throw CryptoError.MalformedVault("Declared payload length is out of range")
        }
        val payloadStart = headerEnd + 8
        if (payloadStart + payloadLen != bytes.size.toLong()) {
            // Exact match required. A file with trailing bytes is either corrupt or
            // someone is probing what we tolerate; neither deserves the benefit of doubt.
            throw CryptoError.MalformedVault("File length does not match declared payload length")
        }

        val aad = bytes.copyOfRange(0, headerEnd.toInt())
        val payload = bytes.copyOfRange(payloadStart.toInt(), bytes.size)

        return Parsed(
            formatVersion = formatVersion,
            header = VaultHeaderCodec.decode(headerBytes),
            headerBytes = headerBytes,
            aad = aad,
            payload = payload,
        )
    }

    /**
     * Reads only the header.
     *
     * Lets the sync engine check the version counter and hash chain of a downloaded file
     * before the vault is unlocked — rollback detection must not require the user to
     * enter their passphrase first.
     */
    fun peekHeader(bytes: ByteArray): VaultHeader = parse(bytes).header

    /**
     * Decodes a bare header, without the surrounding container.
     *
     * The sync layer retains the last accepted header bytes to chain the next version onto
     * and to detect a fork, so it needs to read one back without holding the whole file.
     */
    fun decodeHeaderBytes(headerBytes: ByteArray): VaultHeader = VaultHeaderCodec.decode(headerBytes)

    /** Convenience for the common case of only wanting the version counter. */
    fun peekHeaderVersion(headerBytes: ByteArray): Long = decodeHeaderBytes(headerBytes).vaultVersion

    internal fun encodeHeader(header: VaultHeader): ByteArray = VaultHeaderCodec.encode(header)

    /**
     * Builds the AAD for a set of header bytes.
     *
     * Lives here, next to [parse], so the sealing and parsing sides cannot drift apart.
     * A mismatch between them would surface as an integrity failure on every read — the
     * kind of bug that is obvious in testing and catastrophic if it ever shipped.
     */
    internal fun aadFor(headerBytes: ByteArray): ByteArray {
        val aad = ByteArray(OFF_HEADER + headerBytes.size)
        MAGIC.copyInto(aad, 0)
        BE.putU16(aad, OFF_FORMAT_VERSION, FORMAT_VERSION)
        BE.putU32(aad, OFF_HEADER_LEN, headerBytes.size)
        headerBytes.copyInto(aad, OFF_HEADER)
        return aad
    }
}

/** SHA-256, used for the header hash chain. */
object Digest {
    fun sha256(vararg parts: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        parts.forEach(digest::update)
        return digest.digest()
    }
}
