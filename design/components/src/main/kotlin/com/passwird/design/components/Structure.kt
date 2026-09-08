package com.passwird.design.components

import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.passwird.design.tokens.PasswirdTheme

/**
 * Structure without containers.
 *
 * Most password managers stack rounded cards on grey. A card spends two edges, a shadow
 * and a radius to say one thing — *these items are separate* — which a single hairline
 * says for one pixel. So there is **no card component in this system**; hierarchy comes
 * from rules, spacing and luminance.
 */
@Composable
fun HairlineDivider(
    modifier: Modifier = Modifier,
    strong: Boolean = false,
    inset: Boolean = false,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing
    Box(
        modifier = modifier
            .fillMaxWidth()
            .padding(start = if (inset) spacing.rowIconColumn + spacing.rowIconGap else 0.dp)
            .height(PasswirdTheme.shapes.hairline)
            .background(if (strong) colors.lineStrong else colors.line),
    )
}

/**
 * A labelled section.
 *
 * The uppercase, widely tracked label is the system's signature texture — it performs the
 * separating job a card border would otherwise do, at a fraction of the visual weight.
 */
@Composable
fun Section(
    label: String,
    modifier: Modifier = Modifier,
    trailing: (@Composable () -> Unit)? = null,
    content: @Composable ColumnScopeAlias.() -> Unit,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    Column(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = spacing.gutter)
                .padding(top = spacing.l, bottom = spacing.s),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = label.uppercase(),
                style = PasswirdTheme.typography.label,
                color = colors.textTertiary,
                modifier = Modifier.weight(1f),
            )
            trailing?.invoke()
        }
        Column(content = { content(ColumnScopeAlias) })
    }
}

/** Marker so [Section] content reads as a scoped block without leaking Compose internals. */
object ColumnScopeAlias

/**
 * The shared list row template.
 *
 * Every row in the product uses this geometry — 40dp mark column, 12dp gap, flush content,
 * 48dp trailing affordance — so the eye tracks a single vertical rhythm down the whole app
 * rather than re-finding the alignment on each screen.
 */
@Composable
fun ItemRow(
    title: String,
    subtitle: String?,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    leading: (@Composable () -> Unit)? = null,
    trailing: (@Composable () -> Unit)? = null,
    badge: (@Composable () -> Unit)? = null,
    contentDescriptionOverride: String? = null,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val focused by interaction.collectIsFocusedAsState()

    Row(
        modifier = modifier
            .fillMaxWidth()
            .defaultMinSize(minHeight = 64.dp)
            .background(if (pressed) colors.surfaceRaised else Color.Transparent)
            .focusRing(focused)
            .clickableRow(enabled = true, role = Role.Button, interactionSource = interaction, onClick = onClick)
            .padding(horizontal = spacing.gutter, vertical = spacing.rowV)
            .then(
                if (contentDescriptionOverride != null) {
                    Modifier.clearAndSetSemantics { contentDescription = contentDescriptionOverride }
                } else {
                    Modifier
                },
            ),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (leading != null) {
            Box(
                modifier = Modifier.size(spacing.rowIconColumn),
                contentAlignment = Alignment.Center,
                content = { leading() },
            )
            Box(Modifier.width(spacing.rowIconGap))
        }

        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = title,
                    style = PasswirdTheme.typography.titleM,
                    color = colors.textPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false),
                )
                badge?.let {
                    Box(Modifier.width(spacing.s))
                    it()
                }
            }
            if (!subtitle.isNullOrBlank()) {
                Text(
                    text = subtitle,
                    style = PasswirdTheme.typography.bodyS,
                    color = colors.textSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }

        trailing?.let {
            Box(Modifier.width(spacing.s))
            it()
        }
    }
}

/**
 * A labelled value, as used throughout item detail.
 *
 * Label above value, never beside: side-by-side labels break at 200% text scale, and this
 * product has to remain fully usable there.
 */
@Composable
fun FieldRow(
    label: String,
    modifier: Modifier = Modifier,
    trailing: (@Composable () -> Unit)? = null,
    value: @Composable () -> Unit,
) {
    val spacing = PasswirdTheme.spacing
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = spacing.gutter, vertical = spacing.sm),
    ) {
        Text(
            text = label.uppercase(),
            style = PasswirdTheme.typography.label,
            color = PasswirdTheme.colors.textTertiary,
        )
        Box(Modifier.height(spacing.xs))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.weight(1f), content = { value() })
            trailing?.invoke()
        }
    }
}

/** Small, quiet metadata: timestamps, counts, provenance. */
@Composable
fun MetaRow(
    text: String,
    modifier: Modifier = Modifier,
) {
    Text(
        text = text,
        style = PasswirdTheme.typography.bodyS,
        color = PasswirdTheme.colors.textTertiary,
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = PasswirdTheme.spacing.gutter, vertical = PasswirdTheme.spacing.s),
    )
}

/** A screen header. Title left, up to two actions right, one hairline underneath. */
@Composable
fun ScreenHeader(
    title: String,
    modifier: Modifier = Modifier,
    onBack: (() -> Unit)? = null,
    actions: (@Composable RowScopeAlias.() -> Unit)? = null,
) {
    val spacing = PasswirdTheme.spacing
    Column(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = spacing.s, vertical = spacing.s),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(spacing.xs),
        ) {
            if (onBack != null) {
                PasswirdIconButton(
                    icon = PasswirdIcons.Back,
                    contentDescription = "Back",
                    onClick = onBack,
                )
            } else {
                Box(Modifier.width(spacing.sm))
            }
            Text(
                text = title,
                style = PasswirdTheme.typography.titleL,
                color = PasswirdTheme.colors.textPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            actions?.invoke(RowScopeAlias)
        }
        HairlineDivider()
    }
}

object RowScopeAlias

/** An icon plus its meaning, for states that must never rely on colour alone. */
@Composable
fun GlyphLabel(
    icon: ImageVector,
    text: String,
    color: Color,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier,
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(PasswirdTheme.spacing.xs),
    ) {
        Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(14.dp))
        Text(text = text, style = PasswirdTheme.typography.bodyS, color = color)
    }
}
