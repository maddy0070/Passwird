package com.passwird.design.tokens

import android.provider.Settings
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography as M3Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ProvidableCompositionLocal
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle

/**
 * The Quiet Precision theme.
 *
 * Tokens reach components through composition locals, never through direct imports of the
 * palette objects. That is what makes the CI gate — "no raw `Color(0x…)` outside
 * `design/tokens`" — enforceable rather than aspirational.
 *
 * A minimal Material scheme is installed underneath purely so that text selection handles,
 * ripples and the platform IME pick up sane colours. **No Material component is used in
 * its default dress anywhere in this product** (`docs/08-design-system.md` §1.1); the
 * scheme exists to stop the platform's own chrome clashing, not to style our UI.
 */
object PasswirdTheme {
    val colors: PasswirdColors
        @Composable @ReadOnlyComposable get() = LocalPasswirdColors.current

    val typography: PasswirdTypography
        @Composable @ReadOnlyComposable get() = LocalPasswirdTypography.current

    val spacing: PasswirdSpacing
        @Composable @ReadOnlyComposable get() = LocalPasswirdSpacing.current

    val shapes: PasswirdShapes
        @Composable @ReadOnlyComposable get() = LocalPasswirdShapes.current

    val elevation: PasswirdElevation
        @Composable @ReadOnlyComposable get() = LocalPasswirdElevation.current

    val motion: PasswirdMotion
        @Composable @ReadOnlyComposable get() = LocalPasswirdMotion.current
}

val LocalPasswirdColors: ProvidableCompositionLocal<PasswirdColors> =
    staticCompositionLocalOf { DarkColors }
val LocalPasswirdTypography: ProvidableCompositionLocal<PasswirdTypography> =
    staticCompositionLocalOf { DefaultTypography }
val LocalPasswirdSpacing: ProvidableCompositionLocal<PasswirdSpacing> =
    staticCompositionLocalOf { PasswirdSpacing() }
val LocalPasswirdShapes: ProvidableCompositionLocal<PasswirdShapes> =
    staticCompositionLocalOf { PasswirdShapes() }
val LocalPasswirdElevation: ProvidableCompositionLocal<PasswirdElevation> =
    staticCompositionLocalOf { PasswirdElevation() }
val LocalPasswirdMotion: ProvidableCompositionLocal<PasswirdMotion> =
    staticCompositionLocalOf { PasswirdMotion() }

@Composable
fun PasswirdTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colors = if (darkTheme) DarkColors else LightColors
    val context = LocalContext.current

    // Honour the system animation scale as well as the accessibility preference: a user who
    // has turned animations off globally has already told us what they want.
    val reduceMotion = remember(context) {
        runCatching {
            Settings.Global.getFloat(context.contentResolver, Settings.Global.TRANSITION_ANIMATION_SCALE, 1f) == 0f
        }.getOrDefault(false)
    }

    val elevation = if (darkTheme) {
        // Dark theme has no shadows: depth is surface luminance plus a hairline. Shadows on
        // near-black read as smudges.
        PasswirdElevation(sheet = androidx.compose.ui.unit.Dp(0f), dialog = androidx.compose.ui.unit.Dp(0f))
    } else {
        PasswirdElevation()
    }

    CompositionLocalProvider(
        LocalPasswirdColors provides colors,
        LocalPasswirdTypography provides DefaultTypography,
        LocalPasswirdSpacing provides PasswirdSpacing(),
        LocalPasswirdShapes provides PasswirdShapes(),
        LocalPasswirdElevation provides elevation,
        LocalPasswirdMotion provides PasswirdMotion(reduceMotion = reduceMotion),
        LocalContentColor provides colors.textPrimary,
    ) {
        MaterialTheme(
            colorScheme = if (darkTheme) {
                darkColorScheme(
                    primary = colors.textPrimary,
                    background = colors.ground,
                    surface = colors.surface,
                    onSurface = colors.textPrimary,
                    error = colors.danger,
                )
            } else {
                lightColorScheme(
                    primary = colors.textPrimary,
                    background = colors.ground,
                    surface = colors.surface,
                    onSurface = colors.textPrimary,
                    error = colors.danger,
                )
            },
            typography = M3Typography(bodyMedium = DefaultTypography.body),
            content = content,
        )
    }
}

/** Convenience for the many places that need a style plus a colour. */
@Composable
fun TextStyle.on(color: androidx.compose.ui.graphics.Color): TextStyle = copy(color = color)
