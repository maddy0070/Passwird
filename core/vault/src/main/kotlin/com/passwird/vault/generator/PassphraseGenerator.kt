package com.passwird.vault.generator

import com.passwird.model.Secret
import java.security.SecureRandom
import kotlin.math.ln

/**
 * The bundled EFF Long Wordlist.
 *
 * Loaded once from resources — never fetched, so generating a passphrase involves no
 * network traffic and reveals nothing.
 */
object WordList {

    private const val RESOURCE = "/com/passwird/vault/wordlist-eff-large.txt"

    val words: List<String> by lazy {
        val stream = WordList::class.java.getResourceAsStream(RESOURCE)
            ?: error("Bundled wordlist is missing from the build")
        stream.bufferedReader(Charsets.UTF_8).useLines { lines ->
            lines.map(String::trim).filter(String::isNotEmpty).toList()
        }
    }

    val size: Int get() = words.size

    /** log2(7776) = 12.9248 bits per word. */
    val bitsPerWord: Double by lazy { ln(size.toDouble()) / ln(2.0) }
}

enum class WordSeparator(val value: String) {
    HYPHEN("-"), DOT("."), SPACE(" "), UNDERSCORE("_"), NONE("")
}

data class PassphrasePolicy(
    val wordCount: Int = 5,
    val separator: WordSeparator = WordSeparator.HYPHEN,
    val capitalise: Boolean = false,
    /** Appends one digit to one randomly chosen word. Adds a measured, honest 3.32 bits. */
    val includeNumber: Boolean = false,
) {
    init {
        require(wordCount in MIN_WORDS..MAX_WORDS) { "wordCount must be between $MIN_WORDS and $MAX_WORDS" }
    }

    companion object {
        const val MIN_WORDS = 3
        const val MAX_WORDS = 12

        /**
         * The onboarding default.
         *
         * Five EFF words is ~64.6 bits — comfortably beyond offline attack at any
         * plausible rate, while remaining something a person can actually memorise. A weak
         * master passphrase is the largest residual risk in the entire design
         * (`docs/02-threat-model.md` §7 R1), so the default has to be strong *and*
         * memorable, not merely strong.
         */
        val RECOMMENDED = PassphrasePolicy(wordCount = 5)
    }
}

data class GeneratedPassphrase(
    val value: Secret,
    val words: List<String>,
    val entropyBits: Double,
)

/**
 * Diceware-style passphrase generation.
 *
 * Entropy is exact: each word is drawn independently and uniformly from 7776 options, so
 * the passphrase carries `wordCount * log2(7776)` bits — with anything cosmetic
 * contributing exactly zero, and it is important to say so.
 *
 * **Capitalisation adds no entropy** when it is applied deterministically to every word:
 * an attacker knows the rule. We surface the option because people like it, and we
 * decline to credit it in the number. Adding a digit *is* credited, but only the 3.32
 * bits it actually contributes.
 */
object PassphraseGenerator {

    private val defaultRandom = SecureRandom()

    fun generate(
        policy: PassphrasePolicy = PassphrasePolicy.RECOMMENDED,
        random: SecureRandom = defaultRandom,
    ): GeneratedPassphrase {
        val chosen = List(policy.wordCount) {
            WordList.words[PasswordGenerator.uniformInt(WordList.size, random)]
        }

        var rendered = chosen.map { if (policy.capitalise) it.replaceFirstChar(Char::uppercase) else it }

        if (policy.includeNumber) {
            val position = PasswordGenerator.uniformInt(rendered.size, random)
            val digit = PasswordGenerator.uniformInt(10, random)
            rendered = rendered.toMutableList().also { it[position] = it[position] + digit }
        }

        return GeneratedPassphrase(
            value = Secret.of(rendered.joinToString(policy.separator.value)),
            words = chosen,
            entropyBits = entropyBits(policy),
        )
    }

    /**
     * Exact entropy for [policy].
     *
     * A digit contributes `log2(10 * wordCount)` — the value *and* which word carries it
     * are both random. Capitalisation and the separator contribute nothing, deliberately.
     */
    fun entropyBits(policy: PassphrasePolicy): Double {
        val base = policy.wordCount * WordList.bitsPerWord
        val numberBits = if (policy.includeNumber) {
            ln(10.0 * policy.wordCount) / ln(2.0)
        } else {
            0.0
        }
        return base + numberBits
    }
}
