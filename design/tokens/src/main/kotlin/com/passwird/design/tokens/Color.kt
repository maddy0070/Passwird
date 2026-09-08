package com.passwird.design.tokens

import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.Color

/**
 * The Quiet Precision palette.
 *
 * Near-monochrome, cool, low-chroma. The interface is grey by default so that a single
 * mark of colour is unmissable — which is exactly the property a security interface needs,
 * and the opposite of what happens when everything is tinted.
 *
 * **Colour is vocabulary, not decoration.** There are only three semantic hues, and each
 * one means something specific. The consequence people notice first: our primary button is
 * near-white, not brand-coloured. The brand does not need to be on the button.
 *
 * Hard rule, enforced in review: **no state is ever expressed by colour alone.** Every
 * coloured state pairs with a glyph and a word, so a colour-blind user, a user in bright
 * sunlight, and a screen-reader user all receive the same information.
 */
@Immutable
data class PasswirdColors(
    val ground: Color,
    val surface: Color,
    val surfaceRaised: Color,
    val surfaceSunken: Color,
    val line: Color,
    val lineStrong: Color,
    val textPrimary: Color,
    val textSecondary: Color,
    val textTertiary: Color,
    val textInverse: Color,
    /** **Reserved.** Sealed, encrypted, synced, verified. Never a generic accent. */
    val signal: Color,
    val signalDim: Color,
    /** Weak, reused, ageing, needs review. Attention, not alarm. */
    val attention: Color,
    /** Destructive, failed, tampered. */
    val danger: Color,
    val focusRing: Color,
    val scrim: Color,
    val isDark: Boolean,
)

/**
 * Dark is the primary theme.
 *
 * `ground` is not pure black: true black smears on OLED during scroll and crushes the
 * hairlines that carry this system's structure.
 */
val DarkColors = PasswirdColors(
    ground = Color(0xFF0A0C0E),
    surface = Color(0xFF101317),
    surfaceRaised = Color(0xFF161A1F),
    surfaceSunken = Color(0xFF07090B),
    line = Color(0xFF232830),
    lineStrong = Color(0xFF333A44),
    textPrimary = Color(0xFFE8EBEE),
    textSecondary = Color(0xFF9BA3AD),
    textTertiary = Color(0xFF6B7480),
    textInverse = Color(0xFF0A0C0E),
    signal = Color(0xFF5FD0BC),
    signalDim = Color(0xFF2A5F58),
    attention = Color(0xFFE8B166),
    danger = Color(0xFFE8776B),
    focusRing = Color(0xFFA8C7FA),
    scrim = Color(0xCC05070A),
    isDark = true,
)

/** Light is a first-class peer, not an afterthought. Warm paper, never clinical white. */
val LightColors = PasswirdColors(
    ground = Color(0xFFF6F6F4),
    surface = Color(0xFFFFFFFF),
    surfaceRaised = Color(0xFFFFFFFF),
    surfaceSunken = Color(0xFFEFEFEC),
    line = Color(0xFFE0E1DD),
    lineStrong = Color(0xFFC6C8C2),
    textPrimary = Color(0xFF14171A),
    textSecondary = Color(0xFF5A626B),
    textTertiary = Color(0xFF868E98),
    textInverse = Color(0xFFFFFFFF),
    signal = Color(0xFF1B7F6E),
    signalDim = Color(0xFF9FD6CB),
    attention = Color(0xFF9A6414),
    danger = Color(0xFFB23B2E),
    focusRing = Color(0xFF1B63C7),
    scrim = Color(0x99202325),
    isDark = false,
)

/**
 * The curated hue wheel for generated marks.
 *
 * Twelve stops, each pre-checked for contrast against both grounds. Deliberately *not* a
 * raw HSL sweep — an unconstrained hue produces muddy olives and neon cyans that make a
 * credential list look broken. Fixed low chroma keeps the marks sitting quietly in a list
 * rather than competing with it.
 */
val MarkHues: List<Color> = listOf(
    Color(0xFF6E8BB5), Color(0xFF7C86B8), Color(0xFF8E80AE), Color(0xFFA37C9E),
    Color(0xFFB07C8A), Color(0xFFB08277), Color(0xFFA88C6E), Color(0xFF95946E),
    Color(0xFF7C9B77), Color(0xFF6C9A8C), Color(0xFF6A94A2), Color(0xFF6C8CAF),
)
