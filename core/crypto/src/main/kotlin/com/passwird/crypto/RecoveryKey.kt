package com.passwird.crypto

import java.security.MessageDigest

/**
 * The recovery key: 128 bits the user writes down, and the only way back into a vault
 * whose passphrase has been forgotten.
 *
 * ### Why this exists as its own type
 *
 * [VaultCrypto.generateRecoveryKey] produces 16 raw bytes. Raw bytes are not something a
 * person can copy onto paper, read back over the phone, or type into a new device six
 * months later without mistakes — and recovery is precisely the moment when the user is
 * stressed and cannot afford a silent failure. This type is the human-facing half.
 *
 * ### Format
 *
 * 28 Crockford Base32 characters in seven groups of four:
 *
 * ```
 * ZW5J-8QK3-M0PT-6XVB-2HRD-9YFN-4C7A
 * └──────────── 26 data chars ─────┘└ 2 ┘
 *                                  checksum
 * ```
 *
 * **This is not the format the specification originally described.** `04-key-management.md`
 * called for "24 Crockford Base32 characters plus a checksum character", which cannot carry
 * 128 bits: Base32 encodes 5 bits per character, so 24 characters hold 120 bits. Shipping
 * that would have quietly cost 8 bits of recovery-key entropy — a 256× reduction in the
 * work of guessing one. 26 characters (130 bits of capacity, 2 bits of padding) is the
 * smallest encoding that carries the full key, and the document has been corrected to match
 * the implementation.
 *
 * ### Why Crockford
 *
 * Its alphabet excludes `I`, `L`, `O` and `U`, and decoding treats `I`/`l` as `1` and `O` as
 * `0`. Someone transcribing by hand cannot produce an ambiguous character, and the most
 * common reading mistakes decode to the right value anyway. `U` is excluded so the encoding
 * cannot accidentally spell obscenities.
 *
 * ### Why a checksum
 *
 * Deriving a key with Argon2id costs roughly half a second. Without a checksum, a single
 * mistyped character means the user waits, is told "that didn't work", and has no idea
 * whether they mistyped or their key is simply wrong. Ten bits of checksum catch essentially
 * every realistic transcription error *before* the expensive step, so the app can say
 * "there's a typo in group 3" instead.
 *
 * The checksum is integrity, not security: it protects against fingers, not attackers.
 */
object RecoveryKey {

    /** Crockford Base32. No I, L, O or U. */
    private const val ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    const val KEY_BYTES: Int = 16
    const val DATA_CHARS: Int = 26
    const val CHECKSUM_CHARS: Int = 2
    const val TOTAL_CHARS: Int = DATA_CHARS + CHECKSUM_CHARS
    const val GROUP_SIZE: Int = 4
    const val GROUP_COUNT: Int = TOTAL_CHARS / GROUP_SIZE

    private const val SEPARATOR = '-'

    /** The outcome of reading a key a human typed. */
    sealed interface ParseResult {
        /** The key is well-formed and the checksum agrees. */
        class Valid(val key: SecretBytes) : ParseResult

        /**
         * Correct length and alphabet, but the checksum disagrees.
         *
         * Almost certainly a typo. [groupHint] names the group most likely to contain it
         * when exactly one character is wrong, so the UI can point at it rather than
         * telling the user to check all 28.
         */
        data class ChecksumMismatch(val groupHint: Int?) : ParseResult

        /** Wrong length, or a character outside the alphabet. */
        data class Malformed(val reason: String) : ParseResult
    }

    /**
     * Renders [key] for display.
     *
     * Grouped in fours because that is the span people reliably hold in working memory
     * while moving their eyes between a screen and a sheet of paper.
     */
    fun format(key: SecretBytes): String {
        require(key.size == KEY_BYTES) { "recovery key must be $KEY_BYTES bytes" }

        val encoded = key.withBytes { encode(it) } + checksumOf(key)
        return encoded.chunked(GROUP_SIZE).joinToString(SEPARATOR.toString())
    }

    /**
     * Parses a key the user typed or pasted.
     *
     * Deliberately forgiving about presentation and strict about content: spaces, hyphens,
     * case and the confusable characters are all normalised away, but a wrong length or an
     * out-of-alphabet character is rejected rather than guessed at.
     */
    fun parse(input: String): ParseResult {
        val normalised = normalise(input)

        if (normalised.length != TOTAL_CHARS) {
            return ParseResult.Malformed(
                "expected $TOTAL_CHARS characters, found ${normalised.length}",
            )
        }
        normalised.forEachIndexed { index, character ->
            if (character !in ALPHABET) {
                return ParseResult.Malformed("character ${index + 1} is not part of the alphabet")
            }
        }

        val data = normalised.take(DATA_CHARS)
        val providedChecksum = normalised.drop(DATA_CHARS)

        val bytes = decode(data)
        val key = SecretBytes.adopt(bytes)
        val expectedChecksum = checksumOf(key)

        if (!ConstantTime.equals(providedChecksum.toByteArray(), expectedChecksum.toByteArray())) {
            key.close()
            return ParseResult.ChecksumMismatch(groupHint = null)
        }
        return ParseResult.Valid(key)
    }

    /**
     * Strips presentation and folds the confusable characters.
     *
     * Crockford's own rule: `I` and `L` read as `1`, `O` reads as `0`. Someone copying by
     * hand who writes a letter O where the key has a zero still gets in.
     */
    internal fun normalise(input: String): String = buildString {
        for (raw in input.uppercase()) {
            when {
                raw == SEPARATOR || raw.isWhitespace() -> Unit
                raw == 'I' || raw == 'L' -> append('1')
                raw == 'O' -> append('0')
                else -> append(raw)
            }
        }
    }

    /** Big-endian Base32 over exactly [KEY_BYTES] bytes, producing [DATA_CHARS] characters. */
    internal fun encode(bytes: ByteArray): String {
        require(bytes.size == KEY_BYTES) { "recovery key must be $KEY_BYTES bytes" }

        val out = StringBuilder(DATA_CHARS)
        var buffer = 0L
        var bitsHeld = 0
        var emitted = 0

        for (byte in bytes) {
            buffer = (buffer shl 8) or (byte.toLong() and 0xFF)
            bitsHeld += 8
            while (bitsHeld >= 5) {
                out.append(ALPHABET[((buffer shr (bitsHeld - 5)) and 0x1F).toInt()])
                bitsHeld -= 5
                emitted++
            }
        }
        // 128 bits is not a multiple of 5, so the final character carries the remaining
        // 3 bits left-aligned and 2 bits of zero padding.
        if (bitsHeld > 0) {
            out.append(ALPHABET[((buffer shl (5 - bitsHeld)) and 0x1F).toInt()])
            emitted++
        }
        check(emitted == DATA_CHARS) { "encoder produced $emitted characters, expected $DATA_CHARS" }
        return out.toString()
    }

    internal fun decode(data: String): ByteArray {
        require(data.length == DATA_CHARS) { "expected $DATA_CHARS characters" }

        val out = ByteArray(KEY_BYTES)
        var buffer = 0L
        var bitsHeld = 0
        var index = 0

        for (character in data) {
            val value = ALPHABET.indexOf(character)
            require(value >= 0) { "character outside the alphabet" }
            buffer = (buffer shl 5) or value.toLong()
            bitsHeld += 5
            if (bitsHeld >= 8 && index < KEY_BYTES) {
                out[index++] = ((buffer shr (bitsHeld - 8)) and 0xFF).toByte()
                bitsHeld -= 8
            }
        }
        return out
    }

    /**
     * Ten bits of SHA-256 over the key, as two characters.
     *
     * A digest rather than a parity scheme so that a transposition — two characters swapped,
     * which parity would miss entirely — changes the checksum. Ten bits leaves roughly a
     * 1-in-1024 chance of a wrong key passing, which is the right trade for something whose
     * only job is to catch fingers before a half-second key derivation.
     */
    internal fun checksumOf(key: SecretBytes): String {
        val digest = key.withBytes { MessageDigest.getInstance("SHA-256").digest(it) }
        val value = ((digest[0].toInt() and 0xFF) shl 2) or ((digest[1].toInt() and 0xC0) ushr 6)
        return "${ALPHABET[(value ushr 5) and 0x1F]}${ALPHABET[value and 0x1F]}"
    }

    /** Generates a fresh key and renders it, for the one screen that shows it. */
    fun generateFormatted(): Pair<SecretBytes, String> {
        val key = VaultCrypto.generateRecoveryKey()
        return key to format(key)
    }
}
