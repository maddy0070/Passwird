package com.passwird.vaultapp.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.passwird.design.components.Banner
import com.passwird.design.components.PasswirdIcons
import com.passwird.design.components.PrimaryButton
import com.passwird.design.components.SecondaryButton
import com.passwird.design.tokens.PasswirdTheme

/**
 * The first screen a genuinely new installation sees.
 *
 * Before this existed the app showed "Your vault is locked" on a fresh install and asked for
 * a master passphrase that had never been chosen — there was no vault, no passphrase, and no
 * way to make either.
 *
 * ### Why two equal buttons rather than one
 *
 * *Create* and *Restore* are both first-class. A password manager's worst onboarding failure
 * is an existing user who taps the obvious primary action and creates an empty vault on top
 * of a real one, so the restore path is never a footnote. The wording carries the difference
 * rather than the styling: "start fresh" versus "already have one".
 *
 * @param remoteUnchecked set when the remote could not be reached, so we cannot confirm the
 *   user is new. Offline-first means this must not block — a genuinely new user with no
 *   connectivity has to be able to start — but it must be said out loud, because the wrong
 *   choice here is the expensive one.
 */
@Composable
fun WelcomeScreen(
    onCreateVault: () -> Unit,
    onRestoreVault: () -> Unit,
    modifier: Modifier = Modifier,
    remoteUnchecked: Boolean = false,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.ground)
            .padding(horizontal = spacing.xl),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            imageVector = PasswirdIcons.Shield,
            contentDescription = null,
            tint = colors.textSecondary,
            modifier = Modifier.size(40.dp),
        )

        Spacer(Modifier.height(spacing.l))

        Text(
            text = "Your private vault",
            style = PasswirdTheme.typography.displayL,
            color = colors.textPrimary,
            textAlign = TextAlign.Center,
        )

        Spacer(Modifier.height(spacing.s))

        Text(
            // Present tense about what the product does, not a claim about protection that
            // does not exist yet. There is no vault at this point, so nothing is encrypted
            // and nothing is synced, and saying otherwise would be a fake security indicator.
            text = "Your passwords are encrypted on your device. You control the key.",
            style = PasswirdTheme.typography.body,
            color = colors.textSecondary,
            textAlign = TextAlign.Center,
        )

        Spacer(Modifier.height(spacing.xl))

        if (remoteUnchecked) {
            Banner(
                text = "We couldn't check Google Drive for an existing vault. If you already " +
                    "have one, choose Restore — creating a new vault would leave it behind.",
            )
            Spacer(Modifier.height(spacing.l))
        }

        PrimaryButton(
            text = "Create new vault",
            onClick = onCreateVault,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.s))

        SecondaryButton(
            text = "Restore existing vault",
            onClick = onRestoreVault,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(spacing.l))

        Text(
            // States the architecture accurately: the vault begins here, and what leaves the
            // device is an encrypted copy. Never implies Google can read it.
            text = "Your vault starts on this device. You can securely sync an encrypted " +
                "copy to Google Drive — it never leaves unencrypted, and Google cannot read it.",
            style = PasswirdTheme.typography.bodyS,
            color = colors.textTertiary,
            textAlign = TextAlign.Center,
        )
    }
}
