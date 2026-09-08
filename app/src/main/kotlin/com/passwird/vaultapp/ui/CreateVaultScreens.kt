package com.passwird.vaultapp.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import com.passwird.design.components.Banner
import com.passwird.design.components.HairlineDivider
import com.passwird.design.components.PasswirdTextField
import com.passwird.design.components.PasswirdToggle
import com.passwird.design.components.PrimaryButton
import com.passwird.design.components.SecondaryButton
import com.passwird.design.components.TextButton
import com.passwird.design.tokens.PasswirdTheme

/**
 * Choosing the master passphrase.
 *
 * The passphrase is confirmed by retyping rather than by a reveal toggle alone, because a
 * mistyped passphrase on a brand-new vault is unrecoverable in the worst way: everything
 * works until the first restart, and then nothing does.
 *
 * The explanation sits **above** the fields, not behind a help link. What the passphrase does
 * — and that nobody can reset it — is the single most important thing a user of this product
 * needs to understand, and it needs to be understood before they choose one, not after.
 */
@Composable
fun ChoosePassphraseScreen(
    onContinue: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    minimumLength: Int = 12,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    var passphrase by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }

    val tooShort = passphrase.isNotEmpty() && passphrase.length < minimumLength
    val mismatch = confirmation.isNotEmpty() && confirmation != passphrase
    val ready = passphrase.length >= minimumLength && confirmation == passphrase

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.ground)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = spacing.xl, vertical = spacing.xxl),
    ) {
        Text(
            text = "Choose your master passphrase",
            style = PasswirdTheme.typography.titleL,
            color = colors.textPrimary,
        )

        Spacer(Modifier.height(spacing.m))

        Text(
            text = "This passphrase encrypts your vault. It is the key — not a login. " +
                "It never leaves this device, and it is never sent to Google or to us.",
            style = PasswirdTheme.typography.body,
            color = colors.textSecondary,
        )

        Spacer(Modifier.height(spacing.s))

        Text(
            text = "Because we never see it, we cannot reset it. If you forget it, only " +
                "your recovery key can open your vault.",
            style = PasswirdTheme.typography.body,
            color = colors.textSecondary,
        )

        Spacer(Modifier.height(spacing.xl))

        PasswirdTextField(
            value = passphrase,
            onValueChange = { passphrase = it },
            label = "Master passphrase",
            placeholder = "At least $minimumLength characters",
            keyboardType = KeyboardType.Password,
            error = if (tooShort) "Use at least $minimumLength characters" else null,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.m))

        PasswirdTextField(
            value = confirmation,
            onValueChange = { confirmation = it },
            label = "Confirm passphrase",
            placeholder = "Type it again",
            keyboardType = KeyboardType.Password,
            error = if (mismatch) "These don't match yet" else null,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.xl))

        PrimaryButton(
            text = "Continue",
            onClick = { onContinue(passphrase) },
            enabled = ready,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.s))

        TextButton(text = "Back", onClick = onBack)
    }
}

/**
 * The recovery key, shown exactly once.
 *
 * ### Why this screen refuses to be skipped
 *
 * `ADR-0009` makes the recovery key the break-glass path: the routine way onto a new device
 * is meant to be an existing one, and this key is what covers the case where no device
 * survives. That only works if the user actually recorded it, so continuing requires
 * acknowledging in a way a reflex tap cannot satisfy.
 *
 * The key is generated by the caller and passed in, never generated here — a recovery key
 * that exists without a screen having displayed it is worse than none, because it makes the
 * vault look recoverable when it is not.
 */
@Composable
fun RecoveryKeyScreen(
    formattedKey: String,
    onContinue: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    var acknowledged by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.ground)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = spacing.xl, vertical = spacing.xxl),
    ) {
        Text(
            text = "Your recovery key",
            style = PasswirdTheme.typography.titleL,
            color = colors.textPrimary,
        )

        Spacer(Modifier.height(spacing.m))

        Text(
            text = "Write this down and keep it somewhere safe and offline. " +
                "It is shown once and never again.",
            style = PasswirdTheme.typography.body,
            color = colors.textSecondary,
        )

        Spacer(Modifier.height(spacing.xl))

        // Monospace, grouped in fours: the format the codec produces, chosen because four is
        // the span people reliably hold while moving their eyes between screen and paper.
        Text(
            text = formattedKey,
            style = PasswirdTheme.typography.mono,
            color = colors.textPrimary,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.xl))

        HairlineDivider()

        Spacer(Modifier.height(spacing.l))

        // The honest framing from 04-key-management.md section 5.2, in those words. No dark
        // pattern, no "remind me later" that quietly means never.
        Banner(
            text = "If you forget your passphrase and lose this key, your vault cannot be " +
                "recovered — not by you, not by us, not by Google. That is what makes it private.",
        )

        Spacer(Modifier.height(spacing.l))

        PasswirdToggle(
            checked = acknowledged,
            onCheckedChange = { acknowledged = it },
            label = "I have written down my recovery key",
        )

        Spacer(Modifier.height(spacing.xl))

        PrimaryButton(
            text = "Continue",
            onClick = onContinue,
            enabled = acknowledged,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.s))

        TextButton(text = "Back", onClick = onBack)
    }
}

/**
 * Verifies the user actually recorded the key, by asking for one randomly chosen group.
 *
 * A checkbox proves intent; this proves possession. Asking for one group of four rather than
 * all twenty-eight characters keeps the check honest without turning it into a transcription
 * exercise that people work around by screenshotting.
 */
@Composable
fun VerifyRecoveryKeyScreen(
    groupNumber: Int,
    onVerify: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    error: String? = null,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    var entry by remember { mutableStateOf("") }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.ground)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = spacing.xl, vertical = spacing.xxl),
    ) {
        Text(
            text = "Check your recovery key",
            style = PasswirdTheme.typography.titleL,
            color = colors.textPrimary,
        )

        Spacer(Modifier.height(spacing.m))

        Text(
            text = "So we know you have it: type group $groupNumber of your recovery key — " +
                "the ${ordinal(groupNumber)} block of four characters.",
            style = PasswirdTheme.typography.body,
            color = colors.textSecondary,
        )

        Spacer(Modifier.height(spacing.xl))

        PasswirdTextField(
            value = entry,
            onValueChange = { entry = it.uppercase() },
            label = "Group $groupNumber",
            placeholder = "4 characters",
            error = error,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.xl))

        PrimaryButton(
            text = "Create my vault",
            onClick = { onVerify(entry) },
            enabled = entry.length >= 4,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.s))

        SecondaryButton(
            text = "Show my recovery key again",
            onClick = onBack,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

private fun ordinal(n: Int): String = when (n) {
    1 -> "first"
    2 -> "second"
    3 -> "third"
    4 -> "fourth"
    5 -> "fifth"
    6 -> "sixth"
    else -> "seventh"
}

/**
 * Restoring an existing vault onto a fresh device.
 *
 * Each path is named by **what the user must have**, not by the mechanism, because that is
 * the question they can actually answer standing in a phone shop with a new handset.
 *
 * Google sign-in appears here as a way to *find the encrypted file* and is labelled as such.
 * It never decrypts anything: after the download the user still needs their passphrase or
 * recovery key, which is the whole architecture in one screen.
 */
@Composable
fun RestoreVaultScreen(
    onRestoreFromDrive: () -> Unit,
    onRestoreFromRecoveryKey: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    driveAvailable: Boolean = true,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.ground)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = spacing.xl, vertical = spacing.xxl),
    ) {
        Text(
            text = "Restore your vault",
            style = PasswirdTheme.typography.titleL,
            color = colors.textPrimary,
        )

        Spacer(Modifier.height(spacing.m))

        Text(
            text = "Your vault is encrypted, so restoring it takes two things: the encrypted " +
                "copy, and a key only you have.",
            style = PasswirdTheme.typography.body,
            color = colors.textSecondary,
        )

        Spacer(Modifier.height(spacing.xl))

        PrimaryButton(
            text = "Find my vault in Google Drive",
            onClick = onRestoreFromDrive,
            enabled = driveAvailable,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.xs))

        Text(
            text = "Signing in locates the encrypted file. You will still need your " +
                "passphrase or recovery key to open it — Google cannot.",
            style = PasswirdTheme.typography.bodyS,
            color = colors.textTertiary,
        )

        Spacer(Modifier.height(spacing.l))

        HairlineDivider()

        Spacer(Modifier.height(spacing.l))

        SecondaryButton(
            text = "I have my recovery key",
            onClick = onRestoreFromRecoveryKey,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.xs))

        Text(
            text = "Use the 28-character key you wrote down when you created your vault.",
            style = PasswirdTheme.typography.bodyS,
            color = colors.textTertiary,
        )

        Spacer(Modifier.height(spacing.l))

        // ADR-0010. Named here so the option is discoverable, and honest that it is not built.
        Text(
            text = "Setting up from another device you already use is planned, and will let " +
                "you add this phone without typing your recovery key.",
            style = PasswirdTheme.typography.bodyS,
            color = colors.textTertiary,
        )

        Spacer(Modifier.height(spacing.xl))

        TextButton(text = "Back", onClick = onBack)
    }
}
