package com.passwird.vault.strength

import com.passwird.vault.generator.CharClass
import com.passwird.vault.generator.EntropyMath
import com.passwird.vault.generator.PasswordGenerator
import com.passwird.vault.generator.WordList
import kotlin.math.ln
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.roundToLong

/** Something that makes a password cheaper to guess than its length suggests. */
data class Weakness(val kind: Kind, val detail: String, val at: IntRange) {
    enum class Kind { DICTIONARY_WORD, COMMON_PASSWORD, DIGIT_RUN, SEQUENCE, REPEAT, KEYBOARD_PATTERN, YEAR }
}

/**
 * A strength result.
 *
 * [isExact] is the load-bearing field. When we generated the password we *know* its
 * entropy; when the user typed one we can only estimate structure, and the UI must say
 * which it is showing rather than presenting a guess with the authority of a measurement.
 */
data class StrengthEstimate(
    val entropyBits: Double,
    val isExact: Boolean,
    val weaknesses: List<Weakness>,
) {
    /**
     * Seconds to exhaust the space at [guessesPerSecond], assuming the attacker holds the
     * encrypted vault and attacks it offline.
     *
     * The rate is a required parameter, never a hidden constant: a strength claim without
     * a stated attacker model is meaningless, and the whole point of this type is to stop
     * making meaningless claims.
     */
    fun secondsToCrack(guessesPerSecond: Double): Double {
        val guesses = 2.0.pow(min(entropyBits, MAX_EXPONENT)) / 2.0 // expected, not worst case
        return guesses / guessesPerSecond
    }

    fun band(): Band = when {
        entropyBits < 28 -> Band.VERY_WEAK
        entropyBits < 40 -> Band.WEAK
        entropyBits < 60 -> Band.FAIR
        entropyBits < 80 -> Band.STRONG
        else -> Band.VERY_STRONG
    }

    /**
     * A coarse band, for ordering and for the non-colour state cue the design system
     * requires — never rendered as a score out of 100.
     */
    enum class Band { VERY_WEAK, WEAK, FAIR, STRONG, VERY_STRONG }

    private companion object {
        /** Keeps `2^bits` finite for absurdly long inputs. */
        const val MAX_EXPONENT = 1023.0
    }
}

/** Reference attack rates, so the UI states an assumption instead of implying one. */
object AttackRates {
    /** A well-funded offline attacker against a fast hash. The figure we quote by default. */
    const val OFFLINE_FAST: Double = 1e11

    /** Offline attack against this vault's Argon2id parameters — far slower in practice. */
    const val OFFLINE_ARGON2ID: Double = 1e4

    /** Rate-limited online guessing. */
    const val ONLINE_THROTTLED: Double = 10.0
}

/**
 * Structure-aware entropy estimation for passwords the user typed.
 *
 * Method: find every cheap-to-guess segment (dictionary word, digit run, repeat,
 * sequence, keyboard run), then take the **minimum-cost segmentation** by dynamic
 * programming — because an attacker will use the cheapest decomposition available, not
 * the one that flatters the password.
 *
 * Two deliberate choices about honesty:
 *
 * **We lean low, never high.** Three things push the figure down. No structural bonus is
 * added for the attacker having to discover the segmentation, even though a real attacker
 * does pay something for it. The assumed alphabet is the same one [PasswordGenerator]
 * draws from rather than the full printable set, so an unusual symbol is never credited
 * with more than we can justify. And the result is capped at the entropy of *"a random
 * string of this length using exactly these character classes"* — a search space a real
 * attacker can and does target once they know the format.
 *
 * The asymmetry is the point: overstating strength leaves someone keeping a password they
 * should have replaced, while understating it costs them one unnecessary rotation.
 *
 * **We report what we found.** [Weakness] entries let the UI say *"'dragon' is a common
 * word and '2019' looks like a year"* rather than showing three amber bars. That is the
 * difference between a judgement a user can act on and a verdict they can only resent.
 */
object StrengthEstimator {

    private val wordSet: Set<String> by lazy { WordList.words.toHashSet() }

    /** Small, high-value list: these dominate real-world credential stuffing. */
    private val commonPasswords: Set<String> = setOf(
        "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
        "1234567", "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein",
        "shadow", "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890",
        "michael", "654321", "superman", "1qaz2wsx", "7777777", "121212", "000000", "qazwsx",
        "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter",
        "buster", "soccer", "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou",
        "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars", "klaster",
        "112233", "george", "computer", "michelle", "jessica", "pepper", "1111", "zxcvbn",
        "555555", "11111111", "131313", "freedom", "777777", "pass", "maggie", "159753",
        "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda", "summer", "love",
        "ashley", "nicole", "chelsea", "biteme", "matthew", "access", "yankees", "987654321",
        "dallas", "austin", "thunder", "taylor", "matrix", "william", "corvette", "hello",
        "martin", "heather", "secret", "merlin", "diamond", "1234qwer", "gfhjkm", "hammer",
        "silver", "222222", "88888888", "anthony", "justin", "test", "bailey", "q1w2e3r4t5",
        "patrick", "internet", "scooter", "orange", "11111", "golfer", "cookie", "richard",
        "samantha", "bigdog", "guitar", "jackson", "whatever", "mickey", "chicken", "sparky",
        "snoopy", "maverick", "phoenix", "camaro", "sexy", "peanut", "morgan", "welcome",
        "falcon", "cowboy", "ferrari", "samsung", "andrea", "smokey", "steelers", "joseph",
        "mercedes", "dakota", "arsenal", "eagles", "melissa", "boomer", "booboo", "spider",
        "nascar", "monster", "tigers", "yellow", "xxxxxx", "123123123", "gateway", "marina",
        "diablo", "bulldog", "qwer1234", "compaq", "purple", "hardcore", "banana", "junior",
        "hannah", "123654", "porsche", "lakers", "iceman", "money", "cowboys", "987654",
        "london", "tennis", "999999", "ncc1701", "coffee", "scooby", "0000", "miller",
        "boston", "q1w2e3r4", "fuckoff", "brandon", "yamaha", "chester", "mother", "forever",
        "johnny", "edward", "333333", "oliver", "redsox", "player", "nikita", "knight",
        "letmein1", "p@ssw0rd", "passw0rd", "admin", "administrator", "root", "toor",
        "changeme", "default", "guest", "temp", "welcome1", "password1", "password123",
        "qwerty123", "iloveyou1", "trustno1!", "sunshine1",
    )

    private val keyboardRows = listOf(
        "`1234567890-=", "qwertyuiop[]\\", "asdfghjkl;'", "zxcvbnm,./",
        "~!@#\$%^&*()_+", "QWERTYUIOP{}|", "ASDFGHJKL:\"", "ZXCVBNM<>?",
    )

    private val leetMap = mapOf(
        '4' to 'a', '@' to 'a', '8' to 'b', '(' to 'c', '3' to 'e', '6' to 'g',
        '1' to 'l', '!' to 'i', '0' to 'o', '5' to 's', '$' to 's', '7' to 't', '2' to 'z',
    )

    private val LN2 = ln(2.0)
    private fun log2(value: Double): Double = ln(value) / LN2

    fun estimate(password: String): StrengthEstimate {
        if (password.isEmpty()) return StrengthEstimate(0.0, isExact = false, weaknesses = emptyList())

        val n = password.length
        val perCharBits = log2(observedAlphabetSize(password).toDouble())

        // best[i] = minimum bits to explain password[0, i)
        val best = DoubleArray(n + 1) { Double.MAX_VALUE }
        val chosen = arrayOfNulls<Segment>(n + 1)
        best[0] = 0.0

        for (end in 1..n) {
            for (start in 0 until end) {
                if (best[start] == Double.MAX_VALUE) continue
                for (segment in segmentsFor(password, start, end, perCharBits)) {
                    val total = best[start] + segment.bits
                    if (total < best[end]) {
                        best[end] = total
                        chosen[end] = segment
                    }
                }
            }
        }

        val weaknesses = mutableListOf<Weakness>()
        var cursor = n
        while (cursor > 0) {
            val segment = chosen[cursor] ?: break
            segment.weakness?.let(weaknesses::add)
            cursor = segment.start
        }

        val segmented = best[n].takeIf { it != Double.MAX_VALUE } ?: (n * perCharBits)

        // Cap at "a random string of this length using exactly these classes". An attacker
        // who observes the format searches that space, so crediting more than it contains
        // would overstate the password — and it keeps this estimate consistent with the
        // exact figure the generator reported when it produced the password.
        val formatCap = EntropyMath.bitsUsingEveryClass(observedClassSizes(password), n)

        return StrengthEstimate(
            entropyBits = min(segmented, formatCap),
            isExact = false,
            weaknesses = weaknesses.reversed(),
        )
    }

    /** For a password we generated, entropy is known exactly rather than inferred. */
    fun exact(entropyBits: Double): StrengthEstimate =
        StrengthEstimate(entropyBits, isExact = true, weaknesses = emptyList())

    private class Segment(val start: Int, val bits: Double, val weakness: Weakness?)

    private fun segmentsFor(password: String, start: Int, end: Int, perCharBits: Double): List<Segment> {
        val piece = password.substring(start, end)
        val lower = piece.lowercase()
        val range = start until end
        val out = mutableListOf<Segment>()

        // Single character, the always-available fallback.
        if (piece.length == 1) out += Segment(start, perCharBits, null)

        if (piece.length >= 3) {
            if (lower in commonPasswords) {
                out += Segment(
                    start,
                    log2(commonPasswords.size.toDouble()) + capitalisationBits(piece),
                    Weakness(Weakness.Kind.COMMON_PASSWORD, piece, range),
                )
            }

            val deLeeted = lower.map { leetMap[it] ?: it }.joinToString("")
            if (lower in wordSet || deLeeted in wordSet || lower.reversed() in wordSet) {
                // A word drawn from a 7776-entry list costs log2(7776) whichever word it is.
                // Character substitutions add a little, but far less than users assume.
                val leetBits = if (lower !in wordSet && deLeeted in wordSet) 1.0 else 0.0
                out += Segment(
                    start,
                    WordList.bitsPerWord + capitalisationBits(piece) + leetBits,
                    Weakness(Weakness.Kind.DICTIONARY_WORD, piece, range),
                )
            }
        }

        if (piece.length >= 2 && piece.all(Char::isDigit)) {
            val isYear = piece.length == 4 && piece.toIntOrNull()?.let { it in 1900..2099 } == true
            out += Segment(
                start,
                if (isYear) log2(200.0) else piece.length * log2(10.0),
                Weakness(
                    if (isYear) Weakness.Kind.YEAR else Weakness.Kind.DIGIT_RUN,
                    piece,
                    range,
                ),
            )
        }

        if (piece.length >= 3 && isRepeat(piece)) {
            out += Segment(
                start,
                perCharBits + log2(piece.length.toDouble()),
                Weakness(Weakness.Kind.REPEAT, piece, range),
            )
        }

        if (piece.length >= 3 && isSequence(piece)) {
            // Choose a start character, a direction and a length: cheap, and users
            // consistently overrate it.
            out += Segment(
                start,
                log2(96.0) + 1 + log2(piece.length.toDouble()),
                Weakness(Weakness.Kind.SEQUENCE, piece, range),
            )
        }

        if (piece.length >= 3 && isKeyboardRun(lower)) {
            out += Segment(
                start,
                log2(96.0) + 1 + log2(piece.length.toDouble()),
                Weakness(Weakness.Kind.KEYBOARD_PATTERN, piece, range),
            )
        }

        // Always allow a plain multi-character run so a segmentation always exists.
        if (piece.length > 1) out += Segment(start, piece.length * perCharBits, null)

        return out
    }

    private fun capitalisationBits(piece: String): Double {
        val letters = piece.count(Char::isLetter)
        if (letters == 0) return 0.0
        val upper = piece.count(Char::isUpperCase)
        return when {
            upper == 0 || upper == letters -> 0.0 // all one case: the attacker tries both
            upper == 1 && piece.firstOrNull()?.isUpperCase() == true -> 1.0 // capitalised: 1 bit
            else -> min(letters.toDouble(), log2(2.0.pow(letters)))
        }
    }

    /**
     * Sizes of the character classes the password actually uses.
     *
     * Taken from [PasswordGenerator.classSizes] rather than the full printable ASCII set,
     * so the estimator and the generator agree on the alphabet — and so an exotic symbol
     * is never credited with entropy we cannot defend.
     */
    private fun observedClassSizes(password: String): List<Int> = buildList {
        val sizes = PasswordGenerator.classSizes
        if (password.any { it in 'a'..'z' }) add(sizes.getValue(CharClass.LOWERCASE))
        if (password.any { it in 'A'..'Z' }) add(sizes.getValue(CharClass.UPPERCASE))
        if (password.any(Char::isDigit)) add(sizes.getValue(CharClass.DIGITS))
        if (password.any { !it.isLetterOrDigit() }) add(sizes.getValue(CharClass.SYMBOLS))
    }

    private fun observedAlphabetSize(password: String): Int =
        max(observedClassSizes(password).sum(), 2)

    private fun isRepeat(piece: String): Boolean {
        for (unit in 1..piece.length / 2) {
            if (piece.length % unit != 0) continue
            val base = piece.substring(0, unit)
            if ((0 until piece.length / unit).all { piece.startsWith(base, it * unit) }) return true
        }
        return false
    }

    private fun isSequence(piece: String): Boolean {
        val delta = piece[1] - piece[0]
        if (delta != 1 && delta != -1) return false
        return piece.zipWithNext().all { (a, b) -> b - a == delta }
    }

    private fun isKeyboardRun(piece: String): Boolean = keyboardRows.any { row ->
        val forward = row.lowercase()
        forward.contains(piece) || forward.reversed().contains(piece)
    }
}

/** Renders a duration as something a person can reason about. */
object CrackTimeFormatter {

    fun describe(seconds: Double): String = when {
        seconds < 1 -> "instantly"
        seconds < 60 -> "${seconds.roundToLong()} seconds"
        seconds < 3_600 -> "${(seconds / 60).roundToLong()} minutes"
        seconds < 86_400 -> "${(seconds / 3_600).roundToLong()} hours"
        seconds < 2_592_000 -> "${(seconds / 86_400).roundToLong()} days"
        seconds < 31_557_600 -> "${(seconds / 2_592_000).roundToLong()} months"
        seconds < 31_557_600e3 -> "${(seconds / 31_557_600).roundToLong()} years"
        seconds < 31_557_600e6 -> "${round((seconds / 31_557_600e3))} thousand years"
        seconds < 31_557_600e9 -> "${round((seconds / 31_557_600e6))} million years"
        seconds < 31_557_600e12 -> "${round((seconds / 31_557_600e9))} billion years"
        else -> "longer than the age of the universe"
    }

    private fun round(value: Double): Long = value.roundToLong()
}
