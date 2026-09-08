package com.passwird.design.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.passwird.design.tokens.PasswirdTheme

/** The six sync states. Each carries a glyph *and* a word, never colour alone. */
enum class SyncStatus(val label: String) {
    SYNCED("Synced"),
    SYNCING("Syncing"),
    OFFLINE("Offline"),
    MERGING("Merging"),
    NEEDS_REVIEW("Needs review"),
    FAILED("Sync failed"),
}

/**
 * The only persistent status surface in the product, and the only pill-shaped element.
 *
 * It never blocks, never opens a modal, and never nags. Sync is ambient: the user should be
 * able to ignore it completely and still be correct about the state of their vault.
 *
 * There is deliberately **no progress bar** for `SYNCING` — a bar implies we know how long
 * this will take, and we do not.
 */
@Composable
fun SyncIndicator(
    status: SyncStatus,
    modifier: Modifier = Modifier,
    pendingChanges: Int = 0,
    onClick: (() -> Unit)? = null,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    val (icon, tint) = when (status) {
        SyncStatus.SYNCED -> PasswirdIcons.Synced to colors.signal
        SyncStatus.SYNCING -> PasswirdIcons.Syncing to colors.textSecondary
        SyncStatus.OFFLINE -> PasswirdIcons.Offline to colors.textTertiary
        SyncStatus.MERGING -> PasswirdIcons.Syncing to colors.attention
        SyncStatus.NEEDS_REVIEW -> PasswirdIcons.Attention to colors.attention
        SyncStatus.FAILED -> PasswirdIcons.Danger to colors.danger
    }

    val label = when {
        status == SyncStatus.OFFLINE && pendingChanges > 0 ->
            "${status.label} · $pendingChanges ${if (pendingChanges == 1) "change" else "changes"} waiting"
        else -> status.label
    }

    val interaction = remember2()

    Row(
        modifier = modifier
            .background(colors.surface, PasswirdTheme.shapes.pill)
            .border(PasswirdTheme.shapes.hairline, colors.line, PasswirdTheme.shapes.pill)
            .then(
                if (onClick != null) {
                    Modifier.clickableRow(true, androidx.compose.ui.semantics.Role.Button, interaction, onClick)
                } else {
                    Modifier
                },
            )
            .padding(horizontal = spacing.s, vertical = spacing.xs)
            .semantics { contentDescription = label },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(spacing.xs),
    ) {
        if (status == SyncStatus.SYNCING || status == SyncStatus.MERGING) {
            HairlineSpinner(color = tint, size = 12.dp)
        } else {
            Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(12.dp))
        }
        Text(text = label, style = PasswirdTheme.typography.bodyS, color = tint)
    }
}

@Composable
private fun remember2() = androidx.compose.runtime.remember {
    androidx.compose.foundation.interaction.MutableInteractionSource()
}

/** A rotating hairline arc. Respects reduced motion by holding still. */
@Composable
fun HairlineSpinner(
    color: Color,
    size: Dp,
    modifier: Modifier = Modifier,
) {
    val motion = PasswirdTheme.motion
    val rotation = if (motion.reduceMotion) {
        0f
    } else {
        val transition = rememberInfiniteTransition(label = "spinner")
        val value by transition.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable(
                animation = tween(900, easing = LinearEasing),
                repeatMode = RepeatMode.Restart,
            ),
            label = "spinnerRotation",
        )
        value
    }

    Canvas(modifier = modifier.size(size).rotate(rotation)) {
        drawArc(
            color = color,
            startAngle = 0f,
            sweepAngle = 280f,
            useCenter = false,
            style = Stroke(width = 1.5.dp.toPx(), cap = StrokeCap.Square),
        )
    }
}

/**
 * Password strength, expressed honestly.
 *
 * **Not a five-bar meter.** A continuous bar, the entropy in bits, and — the part that
 * actually matters — the consequence *with the assumed attack rate stated*. A strength
 * claim without an attacker model is meaningless, and this component refuses to make one.
 *
 * @param isExact true when we generated the password and therefore know its entropy;
 *   false when the user typed it and we are inferring structure. The wording changes
 *   accordingly, because presenting an estimate with the authority of a measurement is the
 *   dishonesty this whole design avoids.
 */
@Composable
fun StrengthReadout(
    entropyBits: Double,
    isExact: Boolean,
    crackTimeDescription: String,
    attackRateDescription: String,
    modifier: Modifier = Modifier,
    weaknesses: List<String> = emptyList(),
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    // Full bar at 128 bits: beyond that the difference stops meaning anything to a person.
    val fraction = (entropyBits / 128.0).coerceIn(0.0, 1.0).toFloat()
    val tint = when {
        entropyBits < 40 -> colors.danger
        entropyBits < 60 -> colors.attention
        else -> colors.signal
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .semantics {
                contentDescription = "${entropyBits.toInt()} bits of entropy. $crackTimeDescription $attackRateDescription"
            },
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .weight(1f)
                    .height(4.dp)
                    .background(colors.surfaceSunken),
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth(fraction)
                        .height(4.dp)
                        .background(tint),
                )
            }
            Box(Modifier.width(spacing.s))
            Text(
                text = "${entropyBits.toInt()} bits",
                style = PasswirdTheme.typography.monoS,
                color = colors.textSecondary,
            )
        }

        Box(Modifier.height(spacing.xs))
        Text(
            text = buildString {
                append(if (isExact) "About " else "Roughly ")
                append(crackTimeDescription)
                append(" to guess at ")
                append(attackRateDescription)
                if (!isExact) append(" · estimated from its structure")
            },
            style = PasswirdTheme.typography.bodyS,
            color = colors.textTertiary,
        )

        if (weaknesses.isNotEmpty()) {
            Box(Modifier.height(spacing.xs))
            // Naming what is wrong is what makes this actionable rather than a verdict.
            weaknesses.forEach { GlyphLabel(PasswirdIcons.Attention, it, colors.attention) }
        }
    }
}

/** A visible promise: the clipboard will be cleared, and here is when. */
@Composable
fun ClipboardCountdown(
    secondsRemaining: Int,
    modifier: Modifier = Modifier,
) {
    if (secondsRemaining <= 0) return
    GlyphLabel(
        icon = PasswirdIcons.Copy,
        text = "Copied · clears in ${secondsRemaining}s",
        color = PasswirdTheme.colors.textSecondary,
        modifier = modifier,
    )
}

/**
 * An empty state.
 *
 * Every one states what belongs here and offers the action. None are decorative, and none
 * are a shrug — "No weak passwords. 127 credentials checked." is a genuine result the user
 * should feel good about, not an absence.
 */
@Composable
fun EmptyState(
    title: String,
    body: String,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    action: (@Composable () -> Unit)? = null,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = spacing.xl, vertical = spacing.xxl),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        icon?.let {
            Icon(it, contentDescription = null, tint = colors.textTertiary, modifier = Modifier.size(28.dp))
            Box(Modifier.height(spacing.m))
        }
        Text(
            text = title,
            style = PasswirdTheme.typography.titleM,
            color = colors.textPrimary,
            textAlign = TextAlign.Center,
        )
        Box(Modifier.height(spacing.s))
        Text(
            text = body,
            style = PasswirdTheme.typography.body,
            color = colors.textSecondary,
            textAlign = TextAlign.Center,
        )
        action?.let {
            Box(Modifier.height(spacing.l))
            it()
        }
    }
}

/**
 * An error state.
 *
 * The parameter list encodes the rule from `docs/10-error-matrix.md`: what happened, what
 * you can do, and — where the answer could be in doubt — whether the data is safe. The
 * reassurance is a first-class parameter precisely because it is the question the user is
 * actually asking.
 */
@Composable
fun ErrorState(
    what: String,
    modifier: Modifier = Modifier,
    dataSafetyStatement: String? = null,
    severity: ErrorSeverity = ErrorSeverity.WARNING,
    detail: String? = null,
    actions: (@Composable () -> Unit)? = null,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing
    val tint = when (severity) {
        ErrorSeverity.WARNING -> colors.attention
        ErrorSeverity.DANGER -> colors.danger
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(spacing.gutter),
    ) {
        GlyphLabel(
            icon = if (severity == ErrorSeverity.DANGER) PasswirdIcons.Danger else PasswirdIcons.Attention,
            text = severity.name.lowercase().replaceFirstChar(Char::uppercase),
            color = tint,
        )
        Box(Modifier.height(spacing.s))

        Text(what, style = PasswirdTheme.typography.titleM, color = colors.textPrimary)

        // Answered second, deliberately: it is the first thing the user wants to know, so
        // it must be impossible to miss, but the sentence only makes sense after the fact.
        dataSafetyStatement?.let {
            Box(Modifier.height(spacing.s))
            Text(it, style = PasswirdTheme.typography.body, color = colors.textPrimary)
        }

        detail?.let {
            Box(Modifier.height(spacing.s))
            Text(it, style = PasswirdTheme.typography.bodyS, color = colors.textSecondary)
        }

        actions?.let {
            Box(Modifier.height(spacing.l))
            it()
        }
    }
}

enum class ErrorSeverity { WARNING, DANGER }

/** A non-blocking, dismissible strip. Never a modal — sync problems must not interrupt. */
@Composable
fun Banner(
    text: String,
    modifier: Modifier = Modifier,
    severity: ErrorSeverity = ErrorSeverity.WARNING,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null,
    onDismiss: (() -> Unit)? = null,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing
    val tint = if (severity == ErrorSeverity.DANGER) colors.danger else colors.attention

    Row(
        modifier = modifier
            .fillMaxWidth()
            .background(colors.surface)
            .padding(horizontal = spacing.gutter, vertical = spacing.sm),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(spacing.s),
    ) {
        Icon(
            if (severity == ErrorSeverity.DANGER) PasswirdIcons.Danger else PasswirdIcons.Attention,
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(16.dp),
        )
        Text(
            text = text,
            style = PasswirdTheme.typography.bodyS,
            color = colors.textPrimary,
            modifier = Modifier.weight(1f),
        )
        if (actionLabel != null && onAction != null) {
            TextButton(actionLabel, onAction)
        }
        onDismiss?.let {
            PasswirdIconButton(PasswirdIcons.Close, "Dismiss", onClick = it)
        }
    }
}

/** A security fact rendered as glyph + word + colour, so it never depends on hue alone. */
@Composable
fun SecurityBadge(
    text: String,
    modifier: Modifier = Modifier,
    tone: BadgeTone = BadgeTone.NEUTRAL,
) {
    val colors = PasswirdTheme.colors
    val (icon, tint) = when (tone) {
        BadgeTone.SEALED -> PasswirdIcons.Shield to colors.signal
        BadgeTone.ATTENTION -> PasswirdIcons.Attention to colors.attention
        BadgeTone.DANGER -> PasswirdIcons.Danger to colors.danger
        BadgeTone.NEUTRAL -> PasswirdIcons.Check to colors.textSecondary
    }
    GlyphLabel(icon = icon, text = text, color = tint, modifier = modifier)
}

enum class BadgeTone { SEALED, ATTENTION, DANGER, NEUTRAL }
