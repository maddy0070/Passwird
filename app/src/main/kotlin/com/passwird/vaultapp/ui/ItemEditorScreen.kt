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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.passwird.design.components.DestructiveButton
import com.passwird.design.components.HairlineDivider
import com.passwird.design.components.PasswirdTextField
import com.passwird.design.components.PrimaryButton
import com.passwird.design.components.SecondaryButton
import com.passwird.design.components.TextButton
import com.passwird.design.tokens.PasswirdTheme

/** What the editor collects. Deliberately flat — the domain type is assembled by the caller. */
data class ItemDraft(
    val title: String = "",
    val username: String = "",
    val password: String = "",
    val website: String = "",
    val notes: String = "",
)

/**
 * Add or edit one credential.
 *
 * The minimum needed to make the local vault lifecycle exercisable end to end. Deliberately
 * one screen for both cases rather than two: creating and editing differ in one label and one
 * destructive action, and splitting them would double the surface for no benefit.
 *
 * ### The password field is not masked here
 *
 * Everywhere else in this product a password is masked by default and revealing it is a
 * deliberate act. In the editor the user is *authoring* the value, and masking what someone is
 * currently typing produces exactly the silent typo this screen exists to avoid. The vault is
 * already unlocked, `FLAG_SECURE` is set, and the shoulder-surfing risk here is the same as
 * for any text field. Reveal-by-default is the right call for authoring and the wrong one for
 * retrieval, and this is the authoring case.
 */
@Composable
fun ItemEditorScreen(
    draft: ItemDraft,
    isNew: Boolean,
    onDraftChange: (ItemDraft) -> Unit,
    onSave: () -> Unit,
    onCancel: () -> Unit,
    onGeneratePassword: () -> Unit,
    modifier: Modifier = Modifier,
    onDelete: (() -> Unit)? = null,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    var confirmingDelete by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.ground)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = spacing.xl, vertical = spacing.xxl),
    ) {
        Text(
            text = if (isNew) "New credential" else "Edit credential",
            style = PasswirdTheme.typography.titleL,
            color = colors.textPrimary,
        )

        Spacer(Modifier.height(spacing.xl))

        PasswirdTextField(
            value = draft.title,
            onValueChange = { onDraftChange(draft.copy(title = it)) },
            label = "Title",
            placeholder = "What is this for?",
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.m))

        PasswirdTextField(
            value = draft.username,
            onValueChange = { onDraftChange(draft.copy(username = it)) },
            label = "Username",
            placeholder = "you@example.com",
            keyboardType = KeyboardType.Email,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.m))

        PasswirdTextField(
            value = draft.password,
            onValueChange = { onDraftChange(draft.copy(password = it)) },
            label = "Password",
            placeholder = "Type one, or generate",
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.xs))

        TextButton(text = "Generate a strong password", onClick = onGeneratePassword)

        Spacer(Modifier.height(spacing.m))

        PasswirdTextField(
            value = draft.website,
            onValueChange = { onDraftChange(draft.copy(website = it)) },
            label = "Website",
            placeholder = "https://example.com",
            keyboardType = KeyboardType.Uri,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.m))

        PasswirdTextField(
            value = draft.notes,
            onValueChange = { onDraftChange(draft.copy(notes = it)) },
            label = "Notes",
            placeholder = "Anything else worth keeping",
            singleLine = false,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.xl))

        PrimaryButton(
            text = if (isNew) "Save credential" else "Save changes",
            onClick = onSave,
            // A title is the only field the list can render, so it is the only one required.
            enabled = draft.title.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.s))

        Row(horizontalArrangement = Arrangement.spacedBy(spacing.s)) {
            TextButton(text = "Cancel", onClick = onCancel)
        }

        if (onDelete != null) {
            Spacer(Modifier.height(spacing.xl))
            HairlineDivider()
            Spacer(Modifier.height(spacing.l))

            if (confirmingDelete) {
                Text(
                    // Names the item, because "Delete?" invites a reflex yes and this is the
                    // one action in the product that destroys something the user chose to keep.
                    text = "Delete \"${draft.title}\"? Your other devices will lose it on the " +
                        "next sync. You can undo this for a few seconds afterwards.",
                    style = PasswirdTheme.typography.bodyS,
                    color = colors.textSecondary,
                )
                Spacer(Modifier.height(spacing.m))
                DestructiveButton(
                    text = "Delete \"${draft.title}\"",
                    onClick = onDelete,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(spacing.xs))
                SecondaryButton(
                    text = "Keep it",
                    onClick = { confirmingDelete = false },
                    modifier = Modifier.fillMaxWidth(),
                )
            } else {
                DestructiveButton(
                    text = "Delete this credential",
                    onClick = { confirmingDelete = true },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }

        Spacer(Modifier.height(48.dp))
    }
}
