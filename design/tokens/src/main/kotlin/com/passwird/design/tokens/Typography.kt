package com.passwird.design.tokens

import androidx.compose.runtime.Immutable
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp

/**
 * IBM Plex Sans and IBM Plex Mono, bundled in the APK.
 *
 * Bundled rather than fetched: a font request on every launch would tell a CDN when the
 * user opens their password manager, which is exactly the kind of quiet leak this product
 * exists to avoid.
 *
 * Chosen over Inter (ubiquitous and characterless here) and Roboto (reads as stock
 * Android, which the brief rules out). Plex has engineering provenance, and — the part
 * that is functional rather than aesthetic — genuinely disambiguated glyphs. Telling `0`
 * from `O` and `1` from `l` from `I` matters when someone is reading a generated password
 * aloud or typing it into a console.
 */
object PasswirdFonts {
    val Sans: FontFamily = FontFamily(
        Font(R.font.plex_sans_light, FontWeight.Light),
        Font(R.font.plex_sans_regular, FontWeight.Normal),
        Font(R.font.plex_sans_medium, FontWeight.Medium),
    )

    val Mono: FontFamily = FontFamily(
        Font(R.font.plex_mono_regular, FontWeight.Normal),
        Font(R.font.plex_mono_medium, FontWeight.Medium),
    )
}

/**
 * The type scale.
 *
 * Exactly two weights in UI text (Regular and Medium). Light appears only at [displayL];
 * Bold is not in the system at all. Restraint in weight is what keeps a dense interface
 * calm — the hierarchy comes from size, colour and space instead.
 *
 * Every style must survive 200% text scale, so no container in this product may have a
 * fixed height.
 */
@Immutable
data class PasswirdTypography(
    val displayL: TextStyle,
    val titleL: TextStyle,
    val titleM: TextStyle,
    val body: TextStyle,
    val bodyS: TextStyle,
    /** Uppercase, widely tracked. The system's signature texture — it does the work a card border would. */
    val label: TextStyle,
    /** **Passwords, keys, codes.** Monospaced for disambiguation, not for style. */
    val mono: TextStyle,
    val monoS: TextStyle,
    /** Tabular figures, so numbers that change in place do not make the layout jump. */
    val numeric: TextStyle,
)

val DefaultTypography = PasswirdTypography(
    displayL = TextStyle(
        fontFamily = PasswirdFonts.Sans,
        fontWeight = FontWeight.Light,
        fontSize = 32.sp,
        lineHeight = 38.sp,
        letterSpacing = (-0.02).em,
    ),
    titleL = TextStyle(
        fontFamily = PasswirdFonts.Sans,
        fontWeight = FontWeight.Normal,
        fontSize = 22.sp,
        lineHeight = 28.sp,
        letterSpacing = (-0.01).em,
    ),
    titleM = TextStyle(
        fontFamily = PasswirdFonts.Sans,
        fontWeight = FontWeight.Medium,
        fontSize = 17.sp,
        lineHeight = 24.sp,
    ),
    body = TextStyle(
        fontFamily = PasswirdFonts.Sans,
        fontWeight = FontWeight.Normal,
        fontSize = 15.sp,
        lineHeight = 22.sp,
    ),
    bodyS = TextStyle(
        fontFamily = PasswirdFonts.Sans,
        fontWeight = FontWeight.Normal,
        fontSize = 13.sp,
        lineHeight = 18.sp,
    ),
    label = TextStyle(
        fontFamily = PasswirdFonts.Sans,
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        lineHeight = 14.sp,
        letterSpacing = 0.08.em,
    ),
    mono = TextStyle(
        fontFamily = PasswirdFonts.Mono,
        fontWeight = FontWeight.Normal,
        fontSize = 15.sp,
        lineHeight = 22.sp,
    ),
    monoS = TextStyle(
        fontFamily = PasswirdFonts.Mono,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 16.sp,
        letterSpacing = 0.02.em,
    ),
    numeric = TextStyle(
        fontFamily = PasswirdFonts.Sans,
        fontWeight = FontWeight.Normal,
        fontSize = 15.sp,
        lineHeight = 22.sp,
        textAlign = TextAlign.End,
    ),
)
