package com.passwird.vaultapp.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.passwird.design.components.DestructiveButton
import com.passwird.design.components.PrimaryButton
import com.passwird.design.components.SecondaryButton
import com.passwird.design.tokens.PasswirdTheme

/**
 * A confirmation sheet.
 *
 * `ModalBottomSheet` is the one Material component this product uses, and only for its
 * scrim, drag and predictive-back behaviour — the platform gets those right and
 * reimplementing them would be worse. Everything visible inside is ours, and the sheet
 * itself is re-skinned to the token palette so nothing reads as stock Material.
 *
 * The confirm label always names the object ("Delete Figma", never "Delete"), so a
 * confirmation cannot be tapped through without registering what it does.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConfirmSheet(
    title: String,
    body: String,
    confirmLabel: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    destructive: Boolean = false,
    cancelLabel: String = "Cancel",
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(),
        containerColor = colors.surface,
        scrimColor = colors.scrim,
        shape = PasswirdTheme.shapes.sheet,
        dragHandle = null,
        modifier = modifier,
    ) {
        Column(modifier = Modifier.padding(spacing.gutter)) {
            Text(title, style = PasswirdTheme.typography.titleL, color = colors.textPrimary)
            Spacer(Modifier.height(spacing.s))
            Text(body, style = PasswirdTheme.typography.body, color = colors.textSecondary)
            Spacer(Modifier.height(spacing.l))

            Row(horizontalArrangement = Arrangement.spacedBy(spacing.s)) {
                SecondaryButton(cancelLabel, onDismiss, modifier = Modifier.weight(1f))
                if (destructive) {
                    DestructiveButton(confirmLabel, onConfirm, modifier = Modifier.weight(1f))
                } else {
                    PrimaryButton(confirmLabel, onConfirm, modifier = Modifier.weight(1f))
                }
            }
            Spacer(Modifier.height(spacing.l))
        }
    }
}

/** A non-blocking transient message. Never used for anything the user must act on. */
@Composable
fun Toast(
    text: String,
    modifier: Modifier = Modifier,
    action: (@Composable () -> Unit)? = null,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    Row(
        modifier = modifier
            .fillMaxWidth()
            .background(colors.surfaceRaised, PasswirdTheme.shapes.small)
            .padding(horizontal = spacing.m, vertical = spacing.sm),
        horizontalArrangement = Arrangement.spacedBy(spacing.s),
    ) {
        Text(
            text = text,
            style = PasswirdTheme.typography.bodyS,
            color = colors.textPrimary,
            modifier = Modifier.weight(1f),
        )
        action?.invoke()
    }
}
