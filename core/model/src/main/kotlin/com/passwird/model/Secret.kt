package com.passwird.model

/**
 * A sensitive field value — a password, card number, private key, CVV.
 *
 * The point of the type is that it is *structurally* hard to leak:
 *
 *  - [toString] is redacted, so `"pw=$secret"` in a log statement is harmless;
 *  - [equals] and [hashCode] compare in constant time and never expose content;
 *  - the value is held as a [CharArray] so long-lived storage can be wiped.
 *
 * **Honest limitation.** The vault payload is JSON, and decoding it necessarily
 * materialises a `String` for each value before it reaches this wrapper. That
 * intermediate `String` is immutable and cannot be wiped, so it lives until the
 * collector reclaims it. Holding the durable copy in a wipeable array is a genuine
 * improvement over keeping `String` fields, but it is not a guarantee, and
 * `docs/02-threat-model.md` §5 says so rather than implying otherwise.
 */
class Secret private constructor(private val chars: CharArray) {

    val length: Int get() = chars.size

    val isEmpty: Boolean get() = chars.isEmpty()

    /**
     * Exposes the value.
     *
     * Named to be conspicuous in review: a call to `reveal()` should always be
     * justifiable by the line it appears on.
     */
    fun reveal(): String = String(chars)

    /** Runs [block] with the characters, avoiding an intermediate `String` entirely. */
    fun <T> withChars(block: (CharArray) -> T): T = block(chars)

    /** Best-effort wipe of the durable copy. */
    fun wipe() = chars.fill('\u0000')

    /** Constant-time, so equality checks cannot be turned into a character oracle. */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Secret) return false
        if (chars.size != other.chars.size) return false
        var diff = 0
        for (i in chars.indices) diff = diff or (chars[i].code xor other.chars[i].code)
        return diff == 0
    }

    /**
     * Length only.
     *
     * Enough to keep hash-based collections usable, while never mixing content into a
     * value that could surface in a diagnostic. Equal secrets still hash equally.
     */
    override fun hashCode(): Int = chars.size

    override fun toString(): String = REDACTED

    companion object {
        const val REDACTED: String = "Secret(redacted)"

        val EMPTY: Secret = Secret(CharArray(0))

        fun of(value: String): Secret = Secret(value.toCharArray())

        /** Takes ownership of [chars]; the caller must not retain the array. */
        fun adopt(chars: CharArray): Secret = Secret(chars)
    }
}
