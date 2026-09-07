package com.passwird.crypto

/**
 * Size-bucket padding (ISO/IEC 7816-4) applied to the payload before encryption.
 *
 * Google can see the size of the file we upload. Without padding, that size tracks the
 * vault's real content closely enough to leak: roughly how many credentials exist, and —
 * by differencing successive uploads — roughly how much changed each time. "You added
 * something substantial on Tuesday" is inferable without decrypting a byte.
 *
 * Rounding to coarse buckets collapses that signal. A one-character password edit and
 * adding forty records produce byte-identical file sizes unless they cross a boundary.
 *
 * The 7816-4 scheme (a `0x80` marker followed by zeros) is self-describing, so no length
 * field is needed — which matters, because a stored plaintext length would put the very
 * number we are hiding back into the header.
 */
object Padding {

    private const val KIB = 1024
    private const val SMALL_LIMIT = 64 * KIB
    private const val SMALL_BUCKET = 4 * KIB
    private const val MEDIUM_LIMIT = 1024 * KIB
    private const val MEDIUM_BUCKET = 64 * KIB
    private const val LARGE_BUCKET = 256 * KIB

    /** Padded size for a plaintext of [length] bytes, always strictly greater. */
    fun paddedSize(length: Int): Int {
        require(length >= 0) { "length must not be negative" }
        val required = length + 1 // the 0x80 marker is mandatory
        return when {
            required <= SMALL_LIMIT -> roundUp(required, SMALL_BUCKET)
            required <= MEDIUM_LIMIT -> roundUp(required, MEDIUM_BUCKET)
            else -> roundUp(required, LARGE_BUCKET)
        }
    }

    fun pad(plaintext: ByteArray): ByteArray {
        val out = ByteArray(paddedSize(plaintext.size))
        plaintext.copyInto(out)
        out[plaintext.size] = MARKER
        return out
    }

    /**
     * Removes padding.
     *
     * Hostile input is expected here: this runs on bytes that authenticated correctly but
     * whose *contents* are still only as trustworthy as whoever held the key. Every
     * malformed shape is rejected explicitly rather than producing a wrong-length array.
     */
    fun unpad(padded: ByteArray): ByteArray {
        if (padded.isEmpty()) throw CryptoError.MalformedVault("Padded payload is empty")

        var i = padded.size - 1
        while (i >= 0 && padded[i] == ZERO) i--

        if (i < 0) throw CryptoError.MalformedVault("Padding contains no marker byte")
        if (padded[i] != MARKER) throw CryptoError.MalformedVault("Padding marker byte is invalid")

        return padded.copyOfRange(0, i)
    }

    private fun roundUp(value: Int, multiple: Int): Int = ((value + multiple - 1) / multiple) * multiple

    private const val MARKER: Byte = 0x80.toByte()
    private const val ZERO: Byte = 0x00
}
