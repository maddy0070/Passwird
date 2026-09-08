package com.passwird.design.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import com.passwird.design.tokens.PasswirdTheme

/**
 * Actions.
 *
 * The visible surprise here is that [PrimaryButton] is **near-white, not brand-coloured**.
 * In this system `signal` means *sealed / synced / verified* and nothing else; spending it
 * on a generic Continue button would destroy the one piece of vocabulary that makes
 * security state legible at a glance. The brand does not need to be on the button.
 *
 * Every button in this file: 48dp minimum height, a visible focus ring, a `Role.Button`
 * semantic, and a pressed state expressed by opacity rather than by movement.
 */
@Composable
fun PrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    loading: Boolean = false,
    icon: ImageVector? = null,
) {
    val colors = PasswirdTheme.colors
    ButtonSurface(
        onClick = onClick,
        modifier = modifier,
        enabled = enabled && !loading,
        background = colors.textPrimary,
        border = null,
    ) {
        ButtonContent(text = text, icon = icon, loading = loading, contentColor = colors.textInverse)
    }
}

/** The default for anything that is not the single most likely action on a screen. */
@Composable
fun SecondaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    loading: Boolean = false,
    icon: ImageVector? = null,
) {
    val colors = PasswirdTheme.colors
    ButtonSurface(
        onClick = onClick,
        modifier = modifier,
        enabled = enabled && !loading,
        background = Color.Transparent,
        // Not `lineStrong`: with no fill, this border is the only thing that says where the
        // button is. It has to clear 3:1, which a decorative rule deliberately does not.
        border = colors.borderInteractive,
    ) {
        ButtonContent(text = text, icon = icon, loading = loading, contentColor = colors.textPrimary)
    }
}

@Composable
fun TextButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val colors = PasswirdTheme.colors
    ButtonSurface(
        onClick = onClick,
        modifier = modifier,
        enabled = enabled,
        background = Color.Transparent,
        border = null,
    ) {
        ButtonContent(text = text, icon = null, loading = false, contentColor = colors.textPrimary)
    }
}

/**
 * Destructive actions.
 *
 * Outlined rather than filled: a solid red block invites the confident tap this component
 * exists to discourage. Colour alone never marks it as dangerous — the label always says
 * what will happen ("Delete Figma"), never just "Delete".
 */
@Composable
fun DestructiveButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val colors = PasswirdTheme.colors
    ButtonSurface(
        onClick = onClick,
        modifier = modifier,
        enabled = enabled,
        background = Color.Transparent,
        border = colors.danger,
    ) {
        ButtonContent(text = text, icon = PasswirdIcons.Delete, loading = false, contentColor = colors.danger)
    }
}

/**
 * An icon-only control.
 *
 * [contentDescription] is **required**, not nullable. Unlabelled icon buttons are endemic
 * in this product category — reveal and copy controls especially — and they render a
 * password manager unusable with a screen reader. Making the parameter mandatory means the
 * omission cannot happen by accident.
 */
@Composable
fun PasswirdIconButton(
    icon: ImageVector,
    contentDescription: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    tint: Color? = null,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val focused by interaction.collectIsFocusedAsState()

    val alpha by animateFloatAsState(
        targetValue = when {
            !enabled -> 0.38f
            pressed -> 0.6f
            else -> 1f
        },
        animationSpec = PasswirdTheme.motion.spec(PasswirdTheme.motion.quick),
        label = "iconButtonAlpha",
    )

    Box(
        modifier = modifier
            .size(spacing.touchMin) // never smaller, whatever the icon
            .focusRing(focused)
            .clickableRow(
                enabled = enabled,
                role = Role.Button,
                interactionSource = interaction,
                onClick = onClick,
            ),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = contentDescription,
            tint = (tint ?: colors.textSecondary).copy(alpha = alpha),
            modifier = Modifier.size(20.dp),
        )
    }
}

@Composable
private fun ButtonSurface(
    onClick: () -> Unit,
    modifier: Modifier,
    enabled: Boolean,
    background: Color,
    border: Color?,
    content: @Composable () -> Unit,
) {
    val spacing = PasswirdTheme.spacing
    val shapes = PasswirdTheme.shapes
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val focused by interaction.collectIsFocusedAsState()

    val alpha by animateFloatAsState(
        targetValue = when {
            !enabled -> 0.38f
            pressed -> 0.72f
            else -> 1f
        },
        animationSpec = PasswirdTheme.motion.spec(PasswirdTheme.motion.quick),
        label = "buttonAlpha",
    )

    Box(
        modifier = modifier
            .defaultMinSize(minHeight = spacing.touchMin)
            .focusRing(focused)
            .background(background.copy(alpha = background.alpha * alpha), shapes.small)
            .then(
                if (border != null) {
                    Modifier.border(shapes.hairline, border.copy(alpha = alpha), shapes.small)
                } else {
                    Modifier
                },
            )
            .clickableRow(enabled = enabled, role = Role.Button, interactionSource = interaction, onClick = onClick)
            .padding(horizontal = spacing.ml, vertical = spacing.sm)
            .alpha(alpha),
        contentAlignment = Alignment.Center,
        content = { content() },
    )
}

@Composable
private fun ButtonContent(
    text: String,
    icon: ImageVector?,
    loading: Boolean,
    contentColor: Color,
) {
    val spacing = PasswirdTheme.spacing
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(spacing.s),
    ) {
        if (loading) {
            // A hairline spinner rather than a progress bar: we do not know how long this
            // will take, and a bar that implies we do is a small lie.
            HairlineSpinner(color = contentColor, size = 16.dp)
        } else if (icon != null) {
            Icon(icon, contentDescription = null, tint = contentColor, modifier = Modifier.size(18.dp))
        }
        Text(
            text = text,
            style = PasswirdTheme.typography.titleM,
            color = contentColor,
        )
    }
}

/** A 2dp ring on the theme's focus colour. Present on every focusable element. */
@Composable
fun Modifier.focusRing(focused: Boolean): Modifier {
    if (!focused) return this
    val shapes = PasswirdTheme.shapes
    return border(shapes.focusRingWidth, PasswirdTheme.colors.focusRing, shapes.small)
}

/** Shared clickable, so every interactive surface gets identical semantics and ripple-free press. */
@Composable
internal fun Modifier.clickableRow(
    enabled: Boolean,
    role: Role,
    interactionSource: MutableInteractionSource,
    onClick: () -> Unit,
): Modifier = androidx.compose.foundation.clickable(
    interactionSource = interactionSource,
    // No ripple: this system expresses press with opacity, and a ripple would put a
    // Material fingerprint on every tap.
    indication = null,
    enabled = enabled,
    role = role,
    onClick = onClick,
)

/** Shape used by chips and other pill-free rounded affordances. */
internal val ChipShape = RoundedCornerShape(4.dp)
