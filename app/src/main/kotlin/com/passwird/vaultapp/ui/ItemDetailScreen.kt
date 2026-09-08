package com.passwird.vaultapp.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import com.passwird.design.components.ClipboardCountdown
import com.passwird.design.components.FieldRow
import com.passwird.design.components.HairlineDivider
import com.passwird.design.components.MetaRow
import com.passwird.design.components.PasswirdIconButton
import com.passwird.design.components.PasswirdIcons
import com.passwird.design.components.ScreenHeader
import com.passwird.design.components.SecretField
import com.passwird.design.components.SecondaryButton
import com.passwird.design.components.StrengthReadout
import com.passwird.design.components.TagChip
import com.passwird.design.tokens.PasswirdTheme
import com.passwird.model.ItemContent
import com.passwird.model.VaultItem

/**
 * Item detail.
 *
 * Design rules that are security rules in disguise:
 *
 * **The password is masked on arrival, every single time.** Reveal never persists across
 * navigation or backgrounding — the reason you revealed it a minute ago has expired.
 *
 * **Destructive actions live under the overflow**, never adjacent to Copy. A mis-tap must
 * not be able to delete a credential, and thumb-reach on a phone makes adjacency dangerous.
 *
 * **Strength and password age sit together**, because they are read together when deciding
 * whether to rotate. Age here is the *password's* age, not the record's: editing a note
 * does not reset the clock.
 */
@Composable
fun ItemDetailScreen(
    item: VaultItem,
    strengthBits: Double,
    crackTime: String,
    attackRate: String,
    weaknesses: List<String>,
    passwordAgeDescription: String?,
    clipboardSecondsRemaining: Int,
    onBack: () -> Unit,
    onEdit: () -> Unit,
    onToggleFavourite: () -> Unit,
    onCopyUsername: () -> Unit,
    onCopyPassword: () -> Unit,
    onOpenWebsite: (String) -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    // Reveal state is owned by the screen, so leaving and returning re-masks. Deliberately
    // not hoisted into a ViewModel, where it would survive navigation.
    var revealed by remember(item.id) { mutableStateOf(false) }
    var menuOpen by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.ground),
    ) {
        ScreenHeader(
            title = item.title,
            onBack = onBack,
            actions = {
                PasswirdIconButton(
                    icon = PasswirdIcons.Star,
                    contentDescription = if (item.favorite) {
                        "Remove ${item.title} from favourites"
                    } else {
                        "Add ${item.title} to favourites"
                    },
                    tint = if (item.favorite) colors.signal else colors.textSecondary,
                    onClick = onToggleFavourite,
                )
                PasswirdIconButton(
                    icon = PasswirdIcons.More,
                    contentDescription = "More actions for ${item.title}",
                    onClick = { menuOpen = true },
                )
            },
        )

        Column(
            modifier = Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState()),
        ) {
            when (val content = item.content) {
                is ItemContent.Login -> {
                    if (content.username.isNotBlank()) {
                        FieldRow(
                            label = "Username",
                            trailing = {
                                PasswirdIconButton(
                                    PasswirdIcons.Copy,
                                    "Copy username",
                                    onCopyUsername,
                                )
                            },
                        ) {
                            Text(content.username, style = PasswirdTheme.typography.body, color = colors.textPrimary)
                        }
                        HairlineDivider()
                    }

                    Column(modifier = Modifier.padding(horizontal = spacing.gutter, vertical = spacing.sm)) {
                        SecretField(
                            value = content.password.reveal(),
                            label = "Password",
                            revealed = revealed,
                            onRevealChange = { revealed = it },
                            onCopy = onCopyPassword,
                        )
                        Spacer(Modifier.height(spacing.s))
                        StrengthReadout(
                            entropyBits = strengthBits,
                            isExact = false,
                            crackTimeDescription = crackTime,
                            attackRateDescription = attackRate,
                            weaknesses = weaknesses,
                        )
                        passwordAgeDescription?.let {
                            Spacer(Modifier.height(spacing.xs))
                            Text(it, style = PasswirdTheme.typography.bodyS, color = colors.textTertiary)
                        }
                        ClipboardCountdown(clipboardSecondsRemaining)
                    }
                    HairlineDivider()

                    content.urls.forEach { url ->
                        FieldRow(
                            label = "Website",
                            trailing = {
                                PasswirdIconButton(
                                    PasswirdIcons.External,
                                    "Open $url",
                                    { onOpenWebsite(url) },
                                )
                            },
                        ) {
                            Text(url, style = PasswirdTheme.typography.body, color = colors.textPrimary)
                        }
                        HairlineDivider()
                    }
                }

                is ItemContent.SecureNote -> {
                    FieldRow(label = "Note") {
                        Text(content.body, style = PasswirdTheme.typography.body, color = colors.textPrimary)
                    }
                    HairlineDivider()
                }

                is ItemContent.RecoveryCodes -> {
                    // Per-code state is the whole point of this type: the screenshot it
                    // replaces was answering "which have I already used?".
                    FieldRow(label = "Recovery codes · ${content.remaining} unused") {
                        Column {
                            content.codes.forEach { code ->
                                Text(
                                    text = if (code.used) "— used —" else code.code.reveal(),
                                    style = PasswirdTheme.typography.mono,
                                    color = if (code.used) colors.textTertiary else colors.textPrimary,
                                )
                            }
                        }
                    }
                    HairlineDivider()
                }

                else -> {
                    FieldRow(label = "Details") {
                        Text(
                            text = "Open in the editor to view every field.",
                            style = PasswirdTheme.typography.body,
                            color = colors.textSecondary,
                        )
                    }
                    HairlineDivider()
                }
            }

            if (item.notes.isNotBlank()) {
                FieldRow(label = "Notes") {
                    Text(item.notes, style = PasswirdTheme.typography.body, color = colors.textPrimary)
                }
                HairlineDivider()
            }

            if (item.tags.isNotEmpty()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = spacing.gutter, vertical = spacing.sm),
                    horizontalArrangement = Arrangement.spacedBy(spacing.xs),
                ) {
                    item.tags.sorted().forEach { TagChip(text = it) }
                }
                HairlineDivider()
            }

            MetaRow(
                text = buildString {
                    append("Created ").append(formatDate(item.createdAt))
                    item.lastUsedAt?.let { append(" · Used ").append(formatDate(it)) }
                },
            )

            Spacer(Modifier.height(spacing.xl))
        }

        HairlineDivider()
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(spacing.gutter),
            horizontalArrangement = Arrangement.spacedBy(spacing.s),
        ) {
            SecondaryButton(
                text = "Edit",
                icon = PasswirdIcons.Edit,
                onClick = onEdit,
                modifier = Modifier.weight(1f),
            )
        }
    }

    if (menuOpen) {
        // Delete is reached only from here, two steps from the copy affordance.
        ItemOverflowSheet(
            itemTitle = item.title,
            onDismiss = { menuOpen = false },
            onDelete = {
                menuOpen = false
                onDelete()
            },
        )
    }
}

@Composable
private fun ItemOverflowSheet(
    itemTitle: String,
    onDismiss: () -> Unit,
    onDelete: () -> Unit,
) {
    ConfirmSheet(
        title = "Delete $itemTitle?",
        // The item is named, so a confirmation cannot be tapped through blind.
        body = "This will remove it from every device the next time they sync. " +
            "You'll have ten seconds to undo.",
        confirmLabel = "Delete $itemTitle",
        destructive = true,
        onConfirm = onDelete,
        onDismiss = onDismiss,
    )
}

private fun formatDate(instant: java.time.Instant): String =
    java.time.format.DateTimeFormatter
        .ofPattern("d MMM yyyy")
        .withZone(java.time.ZoneId.systemDefault())
        .format(instant)
