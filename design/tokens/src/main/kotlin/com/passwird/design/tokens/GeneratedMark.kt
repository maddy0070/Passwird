package com.passwird.design.tokens

import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.Color
import java.security.MessageDigest
import java.util.Locale

/**
 * A deterministic identifying mark, computed entirely offline.
 *
 * **This is a privacy decision wearing a visual-design costume.**
 *
 * A credential list is much easier to scan with logos, and the industry solves that by
 * calling a remote icon service. Doing so hands a third party — and every network observer
 * on the path — the complete list of services the user holds accounts with. That leak
 * happens without decrypting anything, and it is one of the most sensitive facts about a
 * vault.
 *
 * So we never fetch. For anything without a bundled icon we derive a stable mark from the
 * domain: a hue from a curated twelve-stop wheel, and a one- or two-character monogram.
 * Same domain, same mark, on every device, forever, with zero network traffic.
 *
 * The marks are treated as part of the visual identity rather than as a fallback, which is
 * why the wheel is hand-picked for contrast rather than being a raw hue sweep — the list
 * should look composed, not broken.
 */
@Immutable
data class GeneratedMark(
    val monogram: String,
    val hue: Color,
    val onHue: Color,
)

object MarkGenerator {

    /**
     * Builds the mark for [source], which may be a URL, a bare domain or an item title.
     *
     * Pure: no I/O, no clock, no randomness.
     */
    fun forSource(source: String, isDark: Boolean): GeneratedMark {
        val key = registrableName(source)
        val digest = MessageDigest.getInstance("SHA-256").digest(key.toByteArray(Charsets.UTF_8))

        // Unsigned, so the index is stable across platforms with different byte signedness.
        val hueIndex = (digest[0].toInt() and 0xFF) % MarkHues.size

        return GeneratedMark(
            monogram = monogramOf(key),
            hue = MarkHues[hueIndex],
            // The wheel is chosen so a single dark ink reads on every stop; picking per-hue
            // would be more "correct" and would make the list less coherent.
            onHue = if (isDark) Color(0xFF0A0C0E) else Color(0xFF14171A),
        )
    }

    /**
     * Reduces a URL or title to the part a person would recognise.
     *
     * `https://www.figma.com/files` and `figma.com` must produce the *same* mark, or one
     * credential would visibly change identity when the user edited its URL.
     */
    internal fun registrableName(source: String): String {
        val trimmed = source.trim().lowercase(Locale.ROOT)
        if (trimmed.isEmpty()) return "?"

        val withoutScheme = trimmed.substringAfter("://", trimmed)
        val host = withoutScheme.substringBefore('/').substringBefore(':').removePrefix("www.")
        if (host.isBlank()) return trimmed

        // Keep the registrable label: "mail.google.com" and "google.com" should agree.
        val labels = host.split('.').filter(String::isNotBlank)
        return when {
            labels.size >= 2 -> labels[labels.size - 2]
            labels.isNotEmpty() -> labels[0]
            else -> host
        }
    }

    /**
     * One or two characters.
     *
     * Two initials for a multi-word name ("First National" reads better as FN), otherwise
     * the first two letters of a single word. Digits and symbols are skipped so a title
     * like "1Password" still produces a letter.
     */
    internal fun monogramOf(key: String): String {
        val words = key.split(' ', '-', '_', '.').filter { it.any(Char::isLetterOrDigit) }

        return when {
            words.size >= 2 -> (words[0].firstLetterOrDigit() + words[1].firstLetterOrDigit()).uppercase(Locale.ROOT)
            words.size == 1 -> words[0].take(2).uppercase(Locale.ROOT)
            else -> "?"
        }.ifBlank { "?" }
    }

    private fun String.firstLetterOrDigit(): String =
        firstOrNull(Char::isLetterOrDigit)?.toString() ?: ""
}
