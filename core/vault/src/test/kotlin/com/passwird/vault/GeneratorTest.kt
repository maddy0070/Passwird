package com.passwird.vault

import com.passwird.vault.generator.CharClass
import com.passwird.vault.generator.PassphraseGenerator
import com.passwird.vault.generator.PassphrasePolicy
import com.passwird.vault.generator.PasswordGenerator
import com.passwird.vault.generator.PasswordPolicy
import com.passwird.vault.generator.WordList
import com.passwird.vault.generator.WordSeparator
import java.security.SecureRandom
import kotlin.math.abs
import kotlin.math.ln
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PasswordGeneratorTest {

    private val random = SecureRandom()

    @Test
    fun `produces the requested length and only permitted characters`() {
        val policy = PasswordPolicy(length = 32, classes = setOf(CharClass.LOWERCASE, CharClass.DIGITS))
        val permitted = PasswordGenerator.alphabetFor(policy).values.joinToString("").toSet()

        repeat(200) {
            val generated = PasswordGenerator.generate(policy, random)
            val value = generated.value.reveal()
            assertEquals(32, value.length)
            assertTrue(value.all { it in permitted }, "generated a character outside the alphabet")
        }
    }

    @Test
    fun `every selected class appears when required`() {
        val policy = PasswordPolicy(
            length = 8,
            classes = setOf(CharClass.LOWERCASE, CharClass.UPPERCASE, CharClass.DIGITS, CharClass.SYMBOLS),
            requireEachClass = true,
        )
        repeat(300) {
            val value = PasswordGenerator.generate(policy, random).value.reveal()
            assertTrue(value.any(Char::isLowerCase), "missing lowercase in '$value'")
            assertTrue(value.any(Char::isUpperCase), "missing uppercase in '$value'")
            assertTrue(value.any(Char::isDigit), "missing digit in '$value'")
            assertTrue(value.any { !it.isLetterOrDigit() }, "missing symbol in '$value'")
        }
    }

    @Test
    fun `excluding ambiguous characters removes the confusable glyphs`() {
        val policy = PasswordPolicy(length = 40, excludeAmbiguous = true)
        repeat(100) {
            val value = PasswordGenerator.generate(policy, random).value.reveal()
            for (glyph in "0O1lI|5S2Z8B") {
                assertFalse(value.contains(glyph), "ambiguous '$glyph' survived exclusion")
            }
        }
    }

    @Test
    fun `an impossible policy is rejected at construction`() {
        assertFailsWith<IllegalArgumentException> {
            PasswordPolicy(
                length = 4,
                classes = setOf(CharClass.LOWERCASE, CharClass.UPPERCASE, CharClass.DIGITS, CharClass.SYMBOLS),
                requireEachClass = true,
            ).let { PasswordPolicy(length = 3, classes = it.classes, requireEachClass = true) }
        }
        assertFailsWith<IllegalArgumentException> { PasswordPolicy(classes = emptySet()) }
    }

    @Test
    fun `selection is unbiased`() {
        // A modulo-reduced RNG over a bound that does not divide 2^31 skews toward the low
        // end. The bias is small, systematic, and would silently invalidate every entropy
        // figure the app prints, so it gets a real statistical check.
        val bound = 37 // deliberately coprime with powers of two
        val draws = 370_000
        val counts = IntArray(bound)
        repeat(draws) { counts[PasswordGenerator.uniformInt(bound, random)]++ }

        val expected = draws.toDouble() / bound
        val chiSquare = counts.sumOf { count ->
            val delta = count - expected
            delta * delta / expected
        }
        // 36 degrees of freedom: the 99.9th percentile is ~67.9. Comfortably loose, so the
        // test is not itself flaky, but tight enough to catch real modulo bias.
        assertTrue(chiSquare < 67.9, "distribution looks biased (chi-square = $chiSquare)")
        assertTrue(counts.all { it > 0 }, "some value was never drawn")
    }

    @Test
    fun `entropy under class constraints matches an exhaustive count`() {
        // Cross-checks the inclusion-exclusion formula against brute force. With lowercase
        // + digits at length 4 there are 36^4 candidates, few enough to simply count.
        val policy = PasswordPolicy(
            length = 4,
            classes = setOf(CharClass.LOWERCASE, CharClass.DIGITS),
            requireEachClass = true,
        )

        val alphabet = ("abcdefghijklmnopqrstuvwxyz" + "0123456789").toCharArray()
        var valid = 0L
        for (a in alphabet) for (b in alphabet) for (c in alphabet) for (d in alphabet) {
            val s = charArrayOf(a, b, c, d)
            if (s.any(Char::isLetter) && s.any(Char::isDigit)) valid++
        }

        val expectedBits = ln(valid.toDouble()) / ln(2.0)
        assertEquals(expectedBits, PasswordGenerator.entropyBits(policy), 1e-9)
        assertEquals(1_212_640L, valid, "sanity: 36^4 - 26^4 - 10^4")
    }

    @Test
    fun `requiring every class never overstates entropy`() {
        // Generators that force a class by overwriting a position quietly break this.
        val classes = setOf(CharClass.LOWERCASE, CharClass.UPPERCASE, CharClass.DIGITS, CharClass.SYMBOLS)
        for (length in listOf(8, 12, 16, 20, 32)) {
            val constrained = PasswordGenerator.entropyBits(
                PasswordPolicy(length = length, classes = classes, requireEachClass = true),
            )
            val unconstrained = PasswordGenerator.entropyBits(
                PasswordPolicy(length = length, classes = classes, requireEachClass = false),
            )
            assertTrue(
                constrained < unconstrained,
                "constrained entropy must be lower at length $length ($constrained vs $unconstrained)",
            )
            assertTrue(unconstrained - constrained < 2.0, "the correction should be small, not dramatic")
        }
    }

    @Test
    fun `a 20 character full alphabet password clears 120 bits`() {
        val bits = PasswordGenerator.entropyBits(PasswordPolicy(length = 20))
        assertTrue(bits > 120, "expected > 120 bits, got $bits")
    }

    @Test
    fun `generated passwords do not repeat`() {
        val seen = HashSet<String>()
        repeat(500) { seen += PasswordGenerator.generate(PasswordPolicy(length = 16), random).value.reveal() }
        assertEquals(500, seen.size, "the generator produced a duplicate")
    }
}

class PassphraseGeneratorTest {

    private val random = SecureRandom()

    @Test
    fun `the bundled wordlist is intact`() {
        assertEquals(7776, WordList.size, "EFF long wordlist must have exactly 7776 entries")
        assertEquals(WordList.size, WordList.words.toSet().size, "wordlist contains duplicates")
        assertEquals(12.9248, WordList.bitsPerWord, 1e-4)
        assertTrue(WordList.words.all { it.isNotBlank() && it.length in 3..9 })
    }

    @Test
    fun `produces the requested number of words`() {
        repeat(100) {
            val result = PassphraseGenerator.generate(PassphrasePolicy(wordCount = 6), random)
            assertEquals(6, result.words.size)
            assertEquals(6, result.value.reveal().split("-").size)
            assertTrue(result.words.all { it in WordList.words })
        }
    }

    @Test
    fun `entropy is exactly word count times bits per word`() {
        for (count in 3..12) {
            val expected = count * WordList.bitsPerWord
            assertEquals(expected, PassphraseGenerator.entropyBits(PassphrasePolicy(wordCount = count)), 1e-9)
        }
    }

    @Test
    fun `capitalisation is offered but credited with zero entropy`() {
        // The rule is deterministic and therefore known to an attacker. Crediting it would
        // be exactly the kind of flattering-but-false number this product refuses to print.
        val plain = PassphrasePolicy(wordCount = 5, capitalise = false)
        val capitalised = PassphrasePolicy(wordCount = 5, capitalise = true)
        assertEquals(
            PassphraseGenerator.entropyBits(plain),
            PassphraseGenerator.entropyBits(capitalised),
            1e-9,
        )
    }

    @Test
    fun `adding a digit is credited only with what it actually contributes`() {
        val without = PassphraseGenerator.entropyBits(PassphrasePolicy(wordCount = 5))
        val with = PassphraseGenerator.entropyBits(PassphrasePolicy(wordCount = 5, includeNumber = true))
        val added = with - without
        // log2(10 values * 5 possible positions) = 5.64 bits.
        assertEquals(ln(50.0) / ln(2.0), added, 1e-9)
        assertTrue(added < 6.0, "a single digit must not be credited like a whole word")
    }

    @Test
    fun `the recommended default is strong enough to matter`() {
        val bits = PassphraseGenerator.entropyBits(PassphrasePolicy.RECOMMENDED)
        assertTrue(bits > 64, "the onboarding default must exceed 64 bits, got $bits")
    }

    @Test
    fun `word selection is uniform across the list`() {
        val counts = HashMap<String, Int>()
        val draws = 60_000
        repeat(draws / 6) {
            PassphraseGenerator.generate(PassphrasePolicy(wordCount = 6), random)
                .words.forEach { counts.merge(it, 1, Int::plus) }
        }
        val expected = draws.toDouble() / WordList.size
        val mean = counts.values.average()
        assertTrue(abs(mean - expected) < expected * 0.5, "word distribution looks skewed")
        assertTrue(counts.size > WordList.size * 0.9, "large parts of the wordlist were never drawn")
    }

    @Test
    fun `separators are applied without affecting the words chosen`() {
        val result = PassphraseGenerator.generate(
            PassphrasePolicy(wordCount = 4, separator = WordSeparator.DOT),
            random,
        )
        assertEquals(result.words.joinToString("."), result.value.reveal())
    }
}
