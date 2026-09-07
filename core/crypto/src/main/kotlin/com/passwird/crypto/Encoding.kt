package com.passwird.crypto

import java.util.Base64

/** Base64url without padding, used for every binary field in the vault header. */
internal object B64 {
    private val encoder: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder: Base64.Decoder = Base64.getUrlDecoder()

    fun encode(bytes: ByteArray): String = encoder.encodeToString(bytes)

    /**
     * Decodes, expecting exactly [expectedLength] bytes when given.
     *
     * Length is checked here rather than at the use site so that a hostile header cannot
     * smuggle a 4 MB "nonce" into a downstream buffer.
     */
    fun decode(value: String, field: String, expectedLength: Int? = null): ByteArray {
        val bytes = try {
            decoder.decode(value)
        } catch (_: IllegalArgumentException) {
            throw CryptoError.MalformedVault("Field '$field' is not valid base64url")
        }
        if (expectedLength != null && bytes.size != expectedLength) {
            throw CryptoError.MalformedVault(
                "Field '$field' must be $expectedLength bytes, found ${bytes.size}",
            )
        }
        return bytes
    }
}

/** Big-endian integer framing helpers for the container. */
internal object BE {
    fun putU16(out: ByteArray, offset: Int, value: Int) {
        out[offset] = (value ushr 8 and 0xFF).toByte()
        out[offset + 1] = (value and 0xFF).toByte()
    }

    fun getU16(src: ByteArray, offset: Int): Int =
        (src[offset].toInt() and 0xFF shl 8) or (src[offset + 1].toInt() and 0xFF)

    fun putU32(out: ByteArray, offset: Int, value: Int) {
        out[offset] = (value ushr 24 and 0xFF).toByte()
        out[offset + 1] = (value ushr 16 and 0xFF).toByte()
        out[offset + 2] = (value ushr 8 and 0xFF).toByte()
        out[offset + 3] = (value and 0xFF).toByte()
    }

    fun getU32(src: ByteArray, offset: Int): Long {
        var result = 0L
        for (i in 0 until 4) result = (result shl 8) or (src[offset + i].toLong() and 0xFF)
        return result
    }

    fun putU64(out: ByteArray, offset: Int, value: Long) {
        for (i in 0 until 8) out[offset + i] = (value ushr (56 - 8 * i) and 0xFF).toByte()
    }

    fun getU64(src: ByteArray, offset: Int): Long {
        var result = 0L
        for (i in 0 until 8) result = (result shl 8) or (src[offset + i].toLong() and 0xFF)
        return result
    }
}
