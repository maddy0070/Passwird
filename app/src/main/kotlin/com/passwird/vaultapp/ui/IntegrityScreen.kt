package com.passwird.vaultapp.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.passwird.design.components.GlyphLabel
import com.passwird.design.components.HairlineDivider
import com.passwird.design.components.PasswirdIcons
import com.passwird.design.components.PrimaryButton
import com.passwird.design.components.SecondaryButton
import com.passwird.design.components.TextButton
import com.passwird.design.tokens.PasswirdTheme
import com.passwird.sync.IntegrityVerdict

/**
 * The rarest screen in the product, and the one that has to be perfect.
 *
 * Shown when the copy in Drive fails an integrity check — it is older than a version this
 * device already accepted (E-17), or claims a version it has already seen with different
 * contents (E-18). Under threat model T5 that can be an attacker replaying an old vault to
 * resurrect a deleted credential or undo a password change made after a breach. It can
 * equally be Drive innocently restoring a previous file version.
 *
 * We do not know which, so we **do not guess and we do not auto-resolve**. The screen
 * answers the three questions in the order the user actually asks them — what happened,
 * what can I do, is my data safe — and hands the decision over.
 *
 * The tone is deliberately calm. This is alarming enough on its own; red panels and
 * exclamation marks would push a worried user toward the fastest tap rather than the right
 * one.
 */
@Composable
fun IntegrityScreen(
    verdict: IntegrityVerdict,
    onUploadLocal: () -> Unit,
    onInspectRemote: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    val headline = when (verdict) {
        is IntegrityVerdict.Rollback -> "The copy in Google Drive is older than expected."
        is IntegrityVerdict.Fork -> "The copy in Google Drive doesn't match this phone's history."
        is IntegrityVerdict.BrokenChain -> "The copy in Google Drive doesn't follow on from the version this phone last saw."
        IntegrityVerdict.Ok -> "Everything checks out."
    }

    val explanation = when (verdict) {
        is IntegrityVerdict.Rollback ->
            "This can happen if Drive restored an old version of the file, or if someone replaced it."
        is IntegrityVerdict.Fork ->
            "Two different versions were saved with the same version number. That usually means the file was replaced rather than updated."
        is IntegrityVerdict.BrokenChain ->
            "Each saved version records a fingerprint of the one before it, and this one doesn't line up."
        IntegrityVerdict.Ok -> ""
    }

    val detail = when (verdict) {
        is IntegrityVerdict.Rollback -> "Expected version ${verdict.expectedAtLeast} or newer · found version ${verdict.found}"
        is IntegrityVerdict.Fork -> "Version ${verdict.version}"
        is IntegrityVerdict.BrokenChain -> "Version ${verdict.version}"
        IntegrityVerdict.Ok -> ""
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.ground)
            .padding(spacing.gutter),
    ) {
        Spacer(Modifier.height(spacing.xxl))

        GlyphLabel(PasswirdIcons.Attention, "Check needed", colors.attention)
        Spacer(Modifier.height(spacing.m))

        Text(headline, style = PasswirdTheme.typography.titleL, color = colors.textPrimary)
        Spacer(Modifier.height(spacing.m))

        // The reassurance, stated plainly and early, because it is the question the user is
        // really asking.
        Text(
            text = "Your vault on this phone is intact and up to date. Nothing has been lost.",
            style = PasswirdTheme.typography.body,
            color = colors.textPrimary,
        )
        Spacer(Modifier.height(spacing.m))

        Text(explanation, style = PasswirdTheme.typography.body, color = colors.textSecondary)
        Spacer(Modifier.height(spacing.l))

        HairlineDivider()
        Spacer(Modifier.height(spacing.sm))
        Text(detail, style = PasswirdTheme.typography.monoS, color = colors.textTertiary)
        Spacer(Modifier.height(spacing.sm))
        HairlineDivider()

        Spacer(Modifier.height(spacing.xl))

        PrimaryButton(
            text = "Upload my current vault",
            onClick = onUploadLocal,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(spacing.s))
        SecondaryButton(
            text = "Look at the Drive copy first",
            onClick = onInspectRemote,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(spacing.s))
        TextButton(text = "Not now", onClick = onDismiss)

        Spacer(Modifier.height(spacing.l))
        Text(
            text = "Until you choose, this phone will keep working normally and won't sync.",
            style = PasswirdTheme.typography.bodyS,
            color = colors.textTertiary,
        )
    }
}
