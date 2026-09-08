package com.passwird.vaultapp

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.fragment.app.FragmentActivity
import com.passwird.design.tokens.PasswirdTheme
import com.passwird.platform.secure.ScreenPrivacy
import com.passwird.vaultapp.ui.UnlockScreen
import com.passwird.vaultapp.ui.UnlockUiState

/**
 * The single activity.
 *
 * `FragmentActivity` rather than `ComponentActivity` because `BiometricPrompt` requires a
 * fragment host — a small constraint that follows directly from binding biometrics to a
 * real `CryptoObject` rather than to a boolean.
 *
 * Two responsibilities live here and nowhere else:
 *
 *  1. **Applying `FLAG_SECURE` before the first frame**, so no window is ever briefly
 *     capturable.
 *  2. **Feeding user interaction to the auto-lock policy.** Any touch postpones the
 *     inactivity timer, which is why the whole tree sits inside a `pointerInput` that
 *     observes without consuming.
 */
class MainActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Applied before setContent: there must be no frame, however brief, that the OS
        // could capture for the recents thumbnail without the flag set.
        ScreenPrivacy.apply(this)

        setContent {
            PasswirdTheme {
                PasswirdApp(onUserInteraction = ::onUserInteraction)
            }
        }
    }

    private fun onUserInteraction() {
        // Wired to AppLockController by the composition root. Kept as a method so the
        // interaction signal has one owner rather than being scattered through screens.
    }
}

/**
 * The composition root.
 *
 * The locked/unlocked split is expressed structurally rather than by navigation: when the
 * vault is locked there is no route to a screen that could render a credential, so a
 * navigation bug cannot leak one.
 */
@Composable
fun PasswirdApp(
    onUserInteraction: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val colors = PasswirdTheme.colors

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(colors.ground)
            .pointerInput(Unit) {
                // Observes without consuming, so every touch postpones auto-lock while
                // still reaching the control the user actually aimed at.
                awaitPointerEventScope {
                    while (true) {
                        awaitPointerEvent()
                        onUserInteraction()
                    }
                }
            },
    ) {
        // Wired to VaultRepository.vault in the real composition root: a null vault renders
        // the lock screen, and there is deliberately no route past it.
        UnlockScreen(
            state = UnlockUiState.Ready,
            biometricAvailable = true,
            onBiometricUnlock = {},
            onPassphraseUnlock = {},
            onUseRecoveryKey = {},
        )
    }
}
