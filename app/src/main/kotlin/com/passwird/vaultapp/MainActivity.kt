package com.passwird.vaultapp

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.passwird.design.tokens.PasswirdTheme
import com.passwird.platform.secure.AppLockController
import com.passwird.platform.secure.ScreenPrivacy
import com.passwird.vault.lock.AutoLockSettings
import com.passwird.vaultapp.ui.UnlockScreen
import kotlinx.coroutines.launch

/**
 * The single activity.
 *
 * `FragmentActivity` rather than `ComponentActivity` because `BiometricPrompt` requires a
 * fragment host — a small constraint that follows directly from binding biometrics to a
 * real `CryptoObject` rather than to a boolean.
 *
 * Three responsibilities live here and nowhere else:
 *
 *  1. **Applying `FLAG_SECURE` before the first frame**, so no window is ever briefly
 *     capturable.
 *  2. **Feeding user interaction to the auto-lock policy**, from both the platform callback
 *     and the Compose pointer stream.
 *  3. **Handing the composition the real object graph.** Until this existed, `PasswirdApp`
 *     rendered a lock screen with five empty callbacks and no route to a vault.
 */
class MainActivity : FragmentActivity() {

    private lateinit var lockController: AppLockController
    private lateinit var unlockController: UnlockController

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Applied before setContent: there must be no frame, however brief, that the OS
        // could capture for the recents thumbnail without the flag set.
        ScreenPrivacy.apply(this)

        val container = (application as PasswirdApplication).container
        unlockController = UnlockController(container.repository)

        lockController = AppLockController(
            context = this,
            scope = lifecycleScope,
            settings = AutoLockSettings(),
            onLock = {
                // Locking zeroises the VEK and drops the decrypted document, which is what
                // makes the lock screen a real boundary rather than a painted one.
                lifecycleScope.launch { container.repository.lock() }
            },
        ).also { it.start() }

        setContent {
            PasswirdTheme {
                PasswirdApp(
                    container = container,
                    unlockController = unlockController,
                    onUserInteraction = lockController::onUserInteraction,
                )
            }
        }
    }

    override fun onDestroy() {
        lockController.stop()
        super.onDestroy()
    }

    /**
     * The framework's own idle signal.
     *
     * This was a private method of the same name, which shadowed `Activity.onUserInteraction`
     * rather than overriding it — so the framework never called it, and the only interaction
     * the auto-lock timer would ever have seen was the Compose pointer observer below. Key
     * events, trackball input and switch access would all have counted as idleness while the
     * user was actively working.
     *
     * Overriding it properly makes the platform signal and the Compose signal feed the same
     * policy.
     */
    override fun onUserInteraction() {
        super.onUserInteraction()
        if (::lockController.isInitialized) lockController.onUserInteraction()
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
    container: PasswirdContainer,
    unlockController: UnlockController,
    onUserInteraction: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val colors = PasswirdTheme.colors
    val scope = rememberCoroutineScope()

    val vault by container.repository.vault.collectAsState()
    val unlockState by unlockController.state.collectAsState()

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
        // A null vault is a locked vault, and there is deliberately no route past this
        // branch — the unlocked tree is not composed at all while locked, so no screen that
        // could render a credential exists to be navigated to by mistake.
        if (vault == null) {
            UnlockScreen(
                state = unlockState,
                // Biometric enrolment is a later step; the passphrase path is the one that
                // must work first, and claiming a biometric option that does nothing would
                // be exactly the fake affordance this product avoids.
                biometricAvailable = false,
                onBiometricUnlock = {},
                onPassphraseUnlock = { passphrase ->
                    scope.launch { unlockController.unlockWithPassphrase(passphrase) }
                },
                onUseRecoveryKey = {},
            )
        } else {
            UnlockedRoot(container = container)
        }
    }
}
