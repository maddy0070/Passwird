package com.passwird.vault.generator

import com.passwird.model.Secret
import java.security.SecureRandom

/** Character classes a generated password may draw from. */
enum class CharClass(val label: String) {
    LOWERCASE("abc"),
    UPPERCASE("ABC"),
    DIGITS("123"),
    SYMBOLS("#$&"),
}

data class PasswordPolicy(
    val length: Int = 20,
    val classes: Set<CharClass> = setOf(CharClass.LOWERCASE, CharClass.UPPERCASE, CharClass.DIGITS, CharClass.SYMBOLS),
    /** Drop glyphs that are hard to tell apart when read aloud or transcribed. */
    val excludeAmbiguous: Boolean = false,
    /** Require at least one character from every selected class. */
    val requireEachClass: Boolean = true,
) {
    init {
        require(length in MIN_LENGTH..MAX_LENGTH) { "length must be between $MIN_LENGTH and $MAX_LENGTH" }
        require(classes.isNotEmpty()) { "at least one character class must be selected" }
        require(!requireEachClass || length >= classes.size) {
            "length $length cannot contain one character from each of ${classes.size} classes"
        }
    }

    companion object {
        const val MIN_LENGTH = 4
        const val MAX_LENGTH = 256
    }
}

data class GeneratedPassword(
    val value: Secret,
    /**
     * **Exact**, not estimated.
     *
     * We know the distribution because we sampled from it, so this is the true entropy of
     * the generation procedure rather than a guess about a string's structure.
     */
    val entropyBits: Double,
)

/**
 * Cryptographically secure password generation.
 *
 * Two things here are commonly got wrong, and both matter:
 *
 * **1. Unbiased selection.** `random.nextInt() % alphabet.size` is biased toward the
 * first `2^31 % size` characters. The bias is small but it is real, it is systematic, and
 * it silently invalidates the entropy figure we print next to the password. [uniformInt]
 * uses rejection sampling instead.
 *
 * **2. Honest entropy under constraints.** The usual way to satisfy "at least one digit"
 * is to generate freely and then overwrite a position with a digit. That distorts the
 * distribution — the last position is no longer uniform — so `length * log2(alphabet)`
 * becomes an overstatement. We use rejection sampling: generate uniformly, discard
 * anything that misses a class, which leaves the result uniform over exactly the set of
 * valid strings, and compute the size of that set by inclusion–exclusion (§[entropyBits]).
 * The number we print is then true by construction.
 */
object PasswordGenerator {

    private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val DIGIT = "0123456789"
    private const val SYMBOL = "!#$%&()*+,-./:;<=>?@[]^_{|}~"

    /** Glyphs that are routinely confused when read aloud or copied by hand. */
    private const val AMBIGUOUS = "0O1lI|5S2Z8B"

    /**
     * Sizes of each class, shared with the strength estimator.
     *
     * The estimator must assume the *same* alphabet we generate from, or it would report a
     * different figure for a password than the generator did when it produced it.
     */
    val classSizes: Map<CharClass, Int> = mapOf(
        CharClass.LOWERCASE to LOWER.length,
        CharClass.UPPERCASE to UPPER.length,
        CharClass.DIGITS to DIGIT.length,
        CharClass.SYMBOLS to SYMBOL.length,
    )

    private val defaultRandom = SecureRandom()

    fun alphabetFor(policy: PasswordPolicy): Map<CharClass, String> =
        policy.classes.associateWith { charClass ->
            val base = when (charClass) {
                CharClass.LOWERCASE -> LOWER
                CharClass.UPPERCASE -> UPPER
                CharClass.DIGITS -> DIGIT
                CharClass.SYMBOLS -> SYMBOL
            }
            if (policy.excludeAmbiguous) base.filterNot { it in AMBIGUOUS } else base
        }.filterValues { it.isNotEmpty() }

    fun generate(policy: PasswordPolicy, random: SecureRandom = defaultRandom): GeneratedPassword {
        val classAlphabets = alphabetFor(policy)
        require(classAlphabets.isNotEmpty()) { "excluding ambiguous characters emptied every class" }
        val alphabet = classAlphabets.values.joinToString("").toCharArray()

        val chars = CharArray(policy.length)
        var attempts = 0

        while (true) {
            for (i in chars.indices) chars[i] = alphabet[uniformInt(alphabet.size, random)]

            if (!policy.requireEachClass || satisfiesEveryClass(chars, classAlphabets)) break

            // Rejection sampling keeps the result uniform over valid strings, which is
            // what makes the printed entropy exact rather than optimistic.
            if (++attempts > MAX_ATTEMPTS) {
                error("Could not satisfy the class constraints for this policy")
            }
        }

        return GeneratedPassword(Secret.adopt(chars), entropyBits(policy))
    }

    private fun satisfiesEveryClass(chars: CharArray, classAlphabets: Map<CharClass, String>): Boolean =
        classAlphabets.values.all { classChars -> chars.any { it in classChars } }

    /**
     * Draws uniformly from `[0, bound)` by rejection sampling.
     *
     * Values in the final, incomplete block of the 32-bit range are discarded rather than
     * folded back with a modulo, which is what removes the bias.
     */
    internal fun uniformInt(bound: Int, random: SecureRandom): Int {
        require(bound > 0) { "bound must be positive" }
        val limit = Int.MAX_VALUE - (Int.MAX_VALUE % bound) - 1
        while (true) {
            val candidate = random.nextInt() and Int.MAX_VALUE
            if (candidate <= limit) return candidate % bound
        }
    }

    /**
     * The exact entropy of [policy]'s output distribution.
     *
     * Unconstrained, that is `length * log2(alphabet)`. With `requireEachClass`, the valid
     * set is smaller, and its size follows from inclusion–exclusion over which classes are
     * absent:
     *
     * ```
     * valid = Σ over subsets S of classes  (-1)^|S| · (N − Σ_{i∈S} nᵢ)^length
     * ```
     *
     * Entropy is `log2(valid)`. This is always slightly *below* the naive figure, which is
     * the correct direction for a number a user relies on.
     */
    fun entropyBits(policy: PasswordPolicy): Double {
        val classAlphabets = alphabetFor(policy)
        val sizes = classAlphabets.values.map { it.length }
        val total = sizes.sum()

        if (!policy.requireEachClass) return policy.length * log2(total.toDouble())
        return EntropyMath.bitsUsingEveryClass(sizes, policy.length)
    }

    private const val MAX_ATTEMPTS = 10_000

    private fun log2(value: Double): Double = EntropyMath.log2(value)
}
