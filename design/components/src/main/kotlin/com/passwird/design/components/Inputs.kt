package com.passwird.design.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
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
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import com.passwird.design.tokens.PasswirdTheme

@Composable
fun PasswirdTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    placeholder: String = "",
    enabled: Boolean = true,
    singleLine: Boolean = true,
    keyboardType: KeyboardType = KeyboardType.Text,
    imeAction: ImeAction = ImeAction.Next,
    error: String? = null,
    trailing: (@Composable () -> Unit)? = null,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing
    val interaction = remember { MutableInteractionSource() }
    val focused by interaction.collectIsFocusedAsState()

    Column(modifier = modifier.fillMaxWidth()) {
        Text(
            text = label.uppercase(),
            style = PasswirdTheme.typography.label,
            color = if (error != null) colors.danger else colors.textTertiary,
        )
        Box(Modifier.height(spacing.xs))

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .defaultMinSize(minHeight = spacing.touchMin)
                .background(colors.surfaceSunken, PasswirdTheme.shapes.small)
                .border(
                    PasswirdTheme.shapes.hairline,
                    when {
                        error != null -> colors.danger
                        focused -> colors.lineStrong
                        else -> colors.line
                    },
                    PasswirdTheme.shapes.small,
                )
                .padding(horizontal = spacing.sm),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            BasicTextField(
                value = value,
                onValueChange = onValueChange,
                enabled = enabled,
                singleLine = singleLine,
                textStyle = PasswirdTheme.typography.body.copy(color = colors.textPrimary),
                cursorBrush = SolidColor(colors.textPrimary),
                interactionSource = interaction,
                keyboardOptions = KeyboardOptions(keyboardType = keyboardType, imeAction = imeAction),
                modifier = Modifier
                    .weight(1f)
                    .padding(vertical = spacing.sm),
                decorationBox = { inner ->
                    if (value.isEmpty() && placeholder.isNotEmpty()) {
                        Text(placeholder, style = PasswirdTheme.typography.body, color = colors.textTertiary)
                    }
                    inner()
                },
            )
            trailing?.invoke()
        }

        if (error != null) {
            Box(Modifier.height(spacing.xs))
            GlyphLabel(PasswirdIcons.Attention, error, colors.danger)
        }
    }
}

/**
 * The component that handles secrets.
 *
 * Everything here is a security decision:
 *
 *  - **Masked by default, every time.** Never remembers that it was revealed. Navigating
 *    away and back re-masks, because the reason you revealed it a minute ago is gone.
 *  - **Revealed state is dropped on dispose**, so a backgrounded app cannot come back with
 *    a password on screen ready for the OS snapshot.
 *  - **Rendered in mono with grouped characters.** Reading a 20-character password aloud,
 *    or typing it into a terminal, is a real task this component is designed for — which
 *    is why digits and symbols are tinted differently from letters when revealed.
 *  - **The reveal toggle is a labelled 48dp target** that announces "password, hidden" or
 *    "password, shown". Screen readers never receive the value itself unless it is
 *    revealed on screen.
 *
 * @param revealed hoisted deliberately: the *screen* owns reveal state, so navigating away
 *   resets it, and the caller cannot accidentally persist it.
 */
@Composable
fun SecretField(
    value: String,
    label: String,
    revealed: Boolean,
    onRevealChange: (Boolean) -> Unit,
    onCopy: (() -> Unit)?,
    modifier: Modifier = Modifier,
    editable: Boolean = false,
    onValueChange: ((String) -> Unit)? = null,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    // Belt and braces: if this field leaves the composition while revealed, mask it.
    DisposableEffect(Unit) {
        onDispose { if (revealed) onRevealChange(false) }
    }

    Column(modifier = modifier.fillMaxWidth()) {
        Text(
            text = label.uppercase(),
            style = PasswirdTheme.typography.label,
            color = colors.textTertiary,
        )
        Box(Modifier.height(spacing.xs))

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .defaultMinSize(minHeight = spacing.touchMin),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .weight(1f)
                    .semantics {
                        // Announce the state, never the value.
                        contentDescription = label
                        stateDescription = if (revealed) "shown" else "hidden"
                    },
            ) {
                if (editable && onValueChange != null) {
                    BasicTextField(
                        value = value,
                        onValueChange = onValueChange,
                        singleLine = true,
                        textStyle = PasswirdTheme.typography.mono.copy(color = colors.textPrimary),
                        cursorBrush = SolidColor(colors.textPrimary),
                        visualTransformation = if (revealed) {
                            VisualTransformation.None
                        } else {
                            PasswordVisualTransformation(MASK_CHAR)
                        },
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Next,
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    )
                } else {
                    Text(
                        text = if (revealed) groupedSecret(value) else AnnotatedString(MASK_CHAR.toString().repeat(value.length.coerceAtMost(24))),
                        style = PasswirdTheme.typography.mono,
                        color = colors.textPrimary,
                    )
                }
            }

            PasswirdIconButton(
                icon = if (revealed) PasswirdIcons.Hide else PasswirdIcons.Reveal,
                contentDescription = if (revealed) "Hide $label" else "Show $label",
                onClick = { onRevealChange(!revealed) },
            )

            onCopy?.let {
                PasswirdIconButton(
                    icon = PasswirdIcons.Copy,
                    contentDescription = "Copy $label",
                    onClick = it,
                )
            }
        }
    }
}

/**
 * Groups a revealed secret in fours and tints non-letters.
 *
 * Purely to make a long random string transcribable by a human. The grouping is visual
 * only — nothing is inserted into the value, so copy still yields the exact password.
 */
@Composable
private fun groupedSecret(value: String): AnnotatedString {
    val colors = PasswirdTheme.colors
    return buildAnnotatedString {
        value.forEachIndexed { index, character ->
            if (index > 0 && index % 4 == 0) {
                withStyle(SpanStyle(color = colors.textTertiary)) { append(GROUP_SEPARATOR) }
            }
            val style = when {
                character.isDigit() -> SpanStyle(color = colors.signal)
                !character.isLetterOrDigit() -> SpanStyle(color = colors.attention)
                else -> SpanStyle(color = colors.textPrimary)
            }
            withStyle(style) { append(character) }
        }
    }
}

private const val MASK_CHAR = '•'
private const val GROUP_SEPARATOR = " " // thin space: visible grouping, no width cost

@Composable
fun SearchField(
    query: String,
    onQueryChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    placeholder: String = "Search your vault",
    trailing: (@Composable () -> Unit)? = null,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing
    val interaction = remember { MutableInteractionSource() }
    val focused by interaction.collectIsFocusedAsState()

    Row(
        modifier = modifier
            .fillMaxWidth()
            .defaultMinSize(minHeight = spacing.touchMin)
            .background(colors.surfaceSunken, PasswirdTheme.shapes.small)
            .border(
                PasswirdTheme.shapes.hairline,
                if (focused) colors.lineStrong else colors.line,
                PasswirdTheme.shapes.small,
            )
            .padding(horizontal = spacing.sm),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(spacing.s),
    ) {
        Icon(
            PasswirdIcons.Search,
            contentDescription = null,
            tint = colors.textTertiary,
            modifier = Modifier.size(18.dp),
        )
        BasicTextField(
            value = query,
            onValueChange = onQueryChange,
            singleLine = true,
            textStyle = PasswirdTheme.typography.body.copy(color = colors.textPrimary),
            cursorBrush = SolidColor(colors.textPrimary),
            interactionSource = interaction,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
            modifier = Modifier
                .weight(1f)
                .padding(vertical = spacing.sm)
                .semantics { contentDescription = placeholder },
            decorationBox = { inner ->
                if (query.isEmpty()) {
                    Text(placeholder, style = PasswirdTheme.typography.body, color = colors.textTertiary)
                }
                inner()
            },
        )
        if (query.isNotEmpty()) {
            PasswirdIconButton(PasswirdIcons.Close, "Clear search", onClick = { onQueryChange("") })
        }
        trailing?.invoke()
    }
}

@Composable
fun PasswirdToggle(
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    description: String? = null,
    enabled: Boolean = true,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing
    val interaction = remember { MutableInteractionSource() }
    val focused by interaction.collectIsFocusedAsState()

    Row(
        modifier = modifier
            .fillMaxWidth()
            .defaultMinSize(minHeight = spacing.touchMin)
            .focusRing(focused)
            .clickableRow(enabled, Role.Switch, interaction) { onCheckedChange(!checked) }
            .padding(horizontal = spacing.gutter, vertical = spacing.sm)
            .semantics { stateDescription = if (checked) "on" else "off" },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, style = PasswirdTheme.typography.body, color = colors.textPrimary)
            description?.let {
                Text(it, style = PasswirdTheme.typography.bodyS, color = colors.textSecondary)
            }
        }
        Box(Modifier.width(spacing.sm))
        // A squared track, matching the shape language. Checked state is expressed by fill
        // *and* by the knob position, so it is never colour-only.
        Box(
            modifier = Modifier
                .width(40.dp)
                .height(24.dp)
                .background(
                    if (checked) colors.signal else colors.surfaceSunken,
                    PasswirdTheme.shapes.small,
                )
                .border(PasswirdTheme.shapes.hairline, if (checked) colors.signal else colors.line, PasswirdTheme.shapes.small),
            contentAlignment = if (checked) Alignment.CenterEnd else Alignment.CenterStart,
        ) {
            Box(
                modifier = Modifier
                    .padding(3.dp)
                    .size(18.dp)
                    .background(
                        if (checked) colors.textInverse else colors.textSecondary,
                        PasswirdTheme.shapes.small,
                    ),
            )
        }
    }
}

@Composable
fun SegmentedControl(
    options: List<String>,
    selectedIndex: Int,
    onSelect: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    val colors = PasswirdTheme.colors
    Row(
        modifier = modifier
            .fillMaxWidth()
            .border(PasswirdTheme.shapes.hairline, colors.line, PasswirdTheme.shapes.small),
    ) {
        options.forEachIndexed { index, option ->
            val selected = index == selectedIndex
            val interaction = remember(index) { MutableInteractionSource() }
            Box(
                modifier = Modifier
                    .weight(1f)
                    .defaultMinSize(minHeight = PasswirdTheme.spacing.touchMin)
                    .background(if (selected) colors.surfaceRaised else Color.Transparent)
                    .clickableRow(true, Role.Tab, interaction) { onSelect(index) }
                    .semantics { stateDescription = if (selected) "selected" else "not selected" },
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    text = option,
                    style = PasswirdTheme.typography.bodyS,
                    color = if (selected) colors.textPrimary else colors.textSecondary,
                )
            }
            if (index != options.lastIndex) {
                Box(
                    Modifier
                        .width(PasswirdTheme.shapes.hairline)
                        .height(PasswirdTheme.spacing.touchMin)
                        .background(colors.line),
                )
            }
        }
    }
}

@Composable
fun TagChip(
    text: String,
    modifier: Modifier = Modifier,
    selected: Boolean = false,
    onClick: (() -> Unit)? = null,
    icon: ImageVector? = null,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing
    val interaction = remember { MutableInteractionSource() }

    Row(
        modifier = modifier
            .background(if (selected) colors.surfaceRaised else Color.Transparent, ChipShape)
            .border(
                PasswirdTheme.shapes.hairline,
                if (selected) colors.lineStrong else colors.line,
                ChipShape,
            )
            .then(
                if (onClick != null) {
                    Modifier.clickableRow(true, Role.Button, interaction, onClick)
                } else {
                    Modifier
                },
            )
            .padding(horizontal = spacing.s, vertical = spacing.xs),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(spacing.xs),
    ) {
        icon?.let {
            Icon(it, contentDescription = null, tint = colors.textSecondary, modifier = Modifier.size(12.dp))
        }
        Text(
            text = text,
            style = PasswirdTheme.typography.bodyS,
            color = if (selected) colors.textPrimary else colors.textSecondary,
        )
    }
}

@Composable
fun Stepper(
    value: Int,
    onValueChange: (Int) -> Unit,
    label: String,
    range: IntRange,
    modifier: Modifier = Modifier,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    Row(
        modifier = modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = PasswirdTheme.typography.body, color = colors.textPrimary, modifier = Modifier.weight(1f))
        PasswirdIconButton(
            icon = PasswirdIcons.Back,
            contentDescription = "Decrease $label",
            enabled = value > range.first,
            onClick = { onValueChange((value - 1).coerceIn(range)) },
        )
        Text(
            text = value.toString(),
            // Tabular figures: the number must not shift the layout as it changes.
            style = PasswirdTheme.typography.numeric,
            color = colors.textPrimary,
            modifier = Modifier.width(40.dp),
        )
        PasswirdIconButton(
            icon = PasswirdIcons.Forward,
            contentDescription = "Increase $label",
            enabled = value < range.last,
            onClick = { onValueChange((value + 1).coerceIn(range)) },
        )
    }
}

/** Convenience wrapper for screens that own reveal state locally. */
@Composable
fun rememberRevealState(): Pair<Boolean, (Boolean) -> Unit> {
    var revealed by remember { mutableStateOf(false) }
    return revealed to { next: Boolean -> revealed = next }
}
