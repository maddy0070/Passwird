package com.passwird.design.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.passwird.design.tokens.MarkGenerator
import com.passwird.design.tokens.PasswirdTheme

/**
 * The identifying mark for a credential.
 *
 * Computed from the domain, entirely on device. Passwird never fetches a favicon, because
 * doing so would tell an icon CDN — and every observer on the network path — the complete
 * list of services the user holds accounts with. That is one of the most sensitive facts
 * about a vault, and it would leak without decrypting a single byte.
 *
 * The generated marks are treated as part of the visual identity rather than as a
 * degraded fallback, which is why the hue wheel is curated: the list should look composed,
 * not broken.
 *
 * Decorative by definition — the row's own title carries the meaning — so it is hidden from
 * screen readers rather than announced as "F".
 */
@Composable
fun GeneratedMarkView(
    source: String,
    modifier: Modifier = Modifier,
    size: Dp = 40.dp,
) {
    val colors = PasswirdTheme.colors
    val mark = remember(source, colors.isDark) {
        MarkGenerator.forSource(source, isDark = colors.isDark)
    }

    Box(
        modifier = modifier
            .size(size)
            .background(mark.hue, PasswirdTheme.shapes.small)
            .clearAndSetSemantics { },
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = mark.monogram,
            style = PasswirdTheme.typography.titleM,
            color = mark.onHue,
        )
    }
}

/**
 * A type glyph, for items with no meaningful domain.
 *
 * A secure note or a Wi-Fi credential has no logo to derive, so a monogram would be noise.
 * The type glyph reads immediately and keeps the row rhythm intact.
 */
@Composable
fun ItemTypeGlyph(
    icon: ImageVector,
    modifier: Modifier = Modifier,
    size: Dp = 40.dp,
) {
    val colors = PasswirdTheme.colors
    Box(
        modifier = modifier
            .size(size)
            .background(colors.surfaceRaised, PasswirdTheme.shapes.small)
            .clearAndSetSemantics { },
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = colors.textSecondary,
            modifier = Modifier.size(18.dp),
        )
    }
}
