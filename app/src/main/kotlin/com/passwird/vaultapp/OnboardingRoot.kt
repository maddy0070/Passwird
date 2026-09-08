package com.passwird.vaultapp

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.passwird.design.components.Banner
import com.passwird.design.components.HairlineSpinner
import com.passwird.design.components.PrimaryButton
import com.passwird.design.components.SecondaryButton
import com.passwird.design.tokens.PasswirdTheme
import com.passwird.vaultapp.ui.ChoosePassphraseScreen
import com.passwird.vaultapp.ui.RecoveryKeyScreen
import com.passwird.vaultapp.ui.RestoreVaultScreen
import com.passwird.vaultapp.ui.VerifyRecoveryKeyScreen
import com.passwird.vaultapp.ui.WelcomeScreen
import kotlinx.coroutines.launch

/**
 * The first-run tree.
 *
 * Composed only when the resolved [com.passwird.store.VaultState] permits creating a vault —
 * that is the whole safety argument. This file decides *which onboarding screen*, never
 * *whether onboarding*.
 */
@Composable
fun OnboardingRoot(
    step: OnboardingController.Step,
    controller: OnboardingController,
    remoteUnchecked: Boolean,
    onCreated: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()

    when (step) {
        is OnboardingController.Step.Welcome -> WelcomeScreen(
            modifier = modifier,
            remoteUnchecked = remoteUnchecked,
            onCreateVault = controller::startCreate,
            onRestoreVault = controller::startRestore,
        )

        is OnboardingController.Step.ChoosePassphrase -> ChoosePassphraseScreen(
            modifier = modifier,
            onContinue = controller::passphraseChosen,
            onBack = controller::cancel,
        )

        is OnboardingController.Step.ShowRecoveryKey -> RecoveryKeyScreen(
            modifier = modifier,
            formattedKey = step.formatted,
            onContinue = controller::recoveryKeyAcknowledged,
            onBack = controller::cancel,
        )

        is OnboardingController.Step.VerifyRecoveryKey -> VerifyRecoveryKeyScreen(
            modifier = modifier,
            groupNumber = step.groupNumber,
            error = step.error,
            onVerify = { entry ->
                scope.launch {
                    controller.verifyAndCreate(entry)
                    // The vault's own state decides what comes next, not this controller's.
                    onCreated()
                }
            },
            onBack = controller::showRecoveryKeyAgain,
        )

        is OnboardingController.Step.Creating -> WorkingScreen(
            modifier = modifier,
            // Argon2id at the documented floor is deliberately slow. Saying so turns half a
            // second of apparent lag into evidence that the product is doing its job.
            message = "Creating your vault. Deriving your key deliberately takes a moment.",
        )

        is OnboardingController.Step.Failed -> FailureScreen(
            modifier = modifier,
            detail = step.detail,
            onBack = controller::cancel,
        )

        is OnboardingController.Step.Restore -> RestoreVaultScreen(
            modifier = modifier,
            // Both restore paths need work that does not exist yet. They are shown because a
            // user in this state must see the route, and disabled rather than faked.
            driveAvailable = false,
            onRestoreFromDrive = {},
            onRestoreFromRecoveryKey = {},
            onBack = controller::cancel,
        )
    }
}

/**
 * A recovery situation.
 *
 * Every state that reaches this screen has one thing in common and it is the important one:
 * **none of them may create a vault.** The screen therefore offers restore and nothing else,
 * and says plainly that nothing will be overwritten.
 */
@Composable
fun RecoveryRoot(
    headline: String,
    detail: String,
    onRestore: () -> Unit,
    step: OnboardingController.Step,
    controller: OnboardingController,
    modifier: Modifier = Modifier,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    if (step is OnboardingController.Step.Restore) {
        RestoreVaultScreen(
            modifier = modifier,
            driveAvailable = false,
            onRestoreFromDrive = {},
            onRestoreFromRecoveryKey = {},
            onBack = controller::cancel,
        )
        return
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.ground)
            .padding(horizontal = spacing.xl),
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = headline,
            style = PasswirdTheme.typography.titleL,
            color = colors.textPrimary,
        )
        Spacer(Modifier.height(spacing.m))
        Text(
            text = detail,
            style = PasswirdTheme.typography.body,
            color = colors.textSecondary,
        )
        Spacer(Modifier.height(spacing.xl))
        PrimaryButton(
            text = "Restore my vault",
            onClick = onRestore,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun WorkingScreen(message: String, modifier: Modifier = Modifier) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.ground)
            .padding(horizontal = spacing.xl),
        verticalArrangement = Arrangement.Center,
    ) {
        HairlineSpinner(color = colors.textSecondary, size = 24.dp)
        Spacer(Modifier.height(spacing.l))
        Text(
            text = message,
            style = PasswirdTheme.typography.body,
            color = colors.textSecondary,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun FailureScreen(detail: String, onBack: () -> Unit, modifier: Modifier = Modifier) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.ground)
            .padding(horizontal = spacing.xl),
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = "Your vault was not created",
            style = PasswirdTheme.typography.titleL,
            color = colors.textPrimary,
        )
        Spacer(Modifier.height(spacing.m))
        Banner(text = detail)
        Spacer(Modifier.height(spacing.xl))
        SecondaryButton(
            text = "Start again",
            onClick = onBack,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}
