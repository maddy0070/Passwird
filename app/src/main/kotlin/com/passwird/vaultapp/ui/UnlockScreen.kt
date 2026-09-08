package com.passwird.vaultapp.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.passwird.design.components.GlyphLabel
import com.passwird.design.components.PasswirdIcons
import com.passwird.design.components.PasswirdTextField
import com.passwird.design.components.PrimaryButton
import com.passwird.design.components.SecondaryButton
import com.passwird.design.components.TextButton
import com.passwird.design.tokens.PasswirdTheme

/** What the unlock screen is currently showing. Each maps to a row in the error matrix. */
sealed interface UnlockUiState {
    data object Ready : UnlockUiState
    data object Authenticating : UnlockUiState

    /** E-01. */
    data class WrongPassphrase(val attempt: Int) : UnlockUiState

    /** E-02. Never a wipe — see ADR-0008. */
    data class BackedOff(val secondsRemaining: Long) : UnlockUiState

    /** E-07: a new fingerprint was enrolled, so the key was destroyed by design. */
    data object BiometricInvalidated : UnlockUiState

    /** E-29: right passphrase, damaged data. */
    data object VaultDamaged : UnlockUiState
}

/**
 * The lock screen.
 *
 * Carries the product's one signature motion. Unlock gets 420ms and a single considered
 * resolve of the lock mark — no bounce, no spring, no particles. It should feel like a
 * well-made mechanism releasing: weighty, brief, final. Everything else in the app is
 * functional feedback at 120–180ms, which is what makes this moment land.
 *
 * Two UX decisions worth defending:
 *
 * **The passphrase is an equal-weight alternative**, on the same screen, never hidden
 * behind "more options". A user whose fingerprint is wet, or whose sensor has just been
 * invalidated, is already frustrated; making them hunt is unkind.
 *
 * **Backoff states that nothing has been deleted.** In that moment the user's genuine fear
 * is that they have destroyed their own vault. Leaving that unanswered would be a design
 * failure, so E-02 answers it before anything else.
 */
@Composable
fun UnlockScreen(
    state: UnlockUiState,
    biometricAvailable: Boolean,
    onBiometricUnlock: () -> Unit,
    onPassphraseUnlock: (String) -> Unit,
    onUseRecoveryKey: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val colors = PasswirdTheme.colors
    val spacing = PasswirdTheme.spacing
    val motion = PasswirdTheme.motion

    var passphrase by remember { mutableStateOf("") }
    var showPassphraseField by remember { mutableStateOf(!biometricAvailable) }

    val unlocking = state is UnlockUiState.Authenticating
    val markScale by animateFloatAsState(
        targetValue = if (unlocking) 0.92f else 1f,
        animationSpec = motion.spec(motion.deliberate, motion.mechanism),
        label = "lockMark",
    )

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(colors.ground)
            .padding(horizontal = spacing.xl),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            imageVector = if (unlocking) PasswirdIcons.Unlocked else PasswirdIcons.Locked,
            contentDescription = if (unlocking) "Unlocking" else "Vault locked",
            tint = if (unlocking) colors.signal else colors.textSecondary,
            modifier = Modifier
                .size(40.dp)
                .scale(markScale),
        )

        Spacer(Modifier.height(spacing.l))

        Text(
            text = "Passwird",
            style = PasswirdTheme.typography.displayL,
            color = colors.textPrimary,
        )
        Spacer(Modifier.height(spacing.s))
        Text(
            text = "Your vault is locked.",
            style = PasswirdTheme.typography.body,
            color = colors.textSecondary,
            textAlign = TextAlign.Center,
        )

        Spacer(Modifier.height(spacing.xl))

        when (state) {
            is UnlockUiState.WrongPassphrase -> {
                // Specific, and never blaming: "that passphrase didn't match", not "you
                // entered the wrong passphrase".
                GlyphLabel(
                    icon = PasswirdIcons.Attention,
                    text = if (state.attempt >= 3) {
                        "That passphrase didn't match. Attempt ${state.attempt}."
                    } else {
                        "That passphrase didn't match."
                    },
                    color = colors.danger,
                )
                Spacer(Modifier.height(spacing.m))
            }

            is UnlockUiState.BackedOff -> {
                GlyphLabel(
                    icon = PasswirdIcons.Attention,
                    text = "Too many attempts. Try again in ${formatSeconds(state.secondsRemaining)}.",
                    color = colors.attention,
                )
                Spacer(Modifier.height(spacing.s))
                Text(
                    // The reassurance the user actually needs in this moment.
                    text = "Nothing has been deleted. Your vault is intact.",
                    style = PasswirdTheme.typography.bodyS,
                    color = colors.textSecondary,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(spacing.m))
            }

            is UnlockUiState.BiometricInvalidated -> {
                Text(
                    text = "Fingerprint unlock was turned off because a new fingerprint was " +
                        "added to this phone. That's a safety feature — it stops someone " +
                        "else's fingerprint from opening your vault.",
                    style = PasswirdTheme.typography.body,
                    color = colors.textPrimary,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(spacing.s))
                Text(
                    text = "Your vault is untouched. Enter your passphrase to turn it back on.",
                    style = PasswirdTheme.typography.bodyS,
                    color = colors.textSecondary,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(spacing.m))
            }

            is UnlockUiState.VaultDamaged -> {
                GlyphLabel(PasswirdIcons.Danger, "The vault data is damaged.", colors.danger)
                Spacer(Modifier.height(spacing.s))
                Text(
                    text = "Your passphrase was right, but this copy couldn't be opened. " +
                        "Your copy in Google Drive is likely unaffected.",
                    style = PasswirdTheme.typography.bodyS,
                    color = colors.textSecondary,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(spacing.m))
            }

            else -> Unit
        }

        val lockedOut = state is UnlockUiState.BackedOff

        if (showPassphraseField) {
            PasswirdTextField(
                value = passphrase,
                onValueChange = { passphrase = it },
                label = "Master passphrase",
                placeholder = "Your passphrase",
                keyboardType = KeyboardType.Password,
                enabled = !lockedOut && !unlocking,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(spacing.m))
            PrimaryButton(
                text = "Unlock",
                onClick = { onPassphraseUnlock(passphrase) },
                enabled = passphrase.isNotEmpty() && !lockedOut,
                loading = unlocking,
                modifier = Modifier.fillMaxWidth(),
            )
        } else {
            PrimaryButton(
                text = "Unlock with fingerprint",
                onClick = onBiometricUnlock,
                enabled = !lockedOut,
                loading = unlocking,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(spacing.s))
            SecondaryButton(
                text = "Use passphrase instead",
                onClick = { showPassphraseField = true },
                enabled = !lockedOut,
                modifier = Modifier.fillMaxWidth(),
            )
        }

        Spacer(Modifier.height(spacing.l))

        // Always one tap away, never buried. A user reaching for this has usually already
        // had a bad day.
        TextButton(text = "Use recovery key", onClick = onUseRecoveryKey, enabled = !lockedOut)

        Spacer(Modifier.height(spacing.xxl))

        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            GlyphLabel(
                icon = PasswirdIcons.Shield,
                text = "Everything stays on this phone until you unlock it",
                color = colors.textTertiary,
            )
        }
    }
}

private fun formatSeconds(seconds: Long): String =
    if (seconds < 60) "${seconds}s" else "${seconds / 60}:${(seconds % 60).toString().padStart(2, '0')}"
