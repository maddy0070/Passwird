package com.passwird.vaultapp

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.passwird.design.tokens.PasswirdTheme
import com.passwird.platform.secure.AppLockController
import com.passwird.platform.secure.ScreenPrivacy
import com.passwird.store.VaultState
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

    val onboarding = remember(container) { OnboardingController(container.repository) }
    val step by onboarding.step.collectAsState()

    // The vault's lifecycle state, resolved from storage and the remote rather than inferred
    // from `vault == null`. That inference is what put a lock screen in front of a fresh
    // install: it means *not unlocked*, and it was being read as *locked*.
    //
    // Recomputed whenever the vault reference changes, which covers creation, unlock and lock.
    var vaultState by remember { mutableStateOf<VaultState?>(null) }
    LaunchedEffect(vault) {
        vaultState = container.repository.currentState()
    }

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
        // Routing is driven by the resolved state, not by a nullable reference. The unlocked
        // tree is composed only in the Unlocked branch, so a locked or absent vault has no
        // rendered screen that could hold a credential — the boundary stays structural.
        when (val state = vaultState) {
            // Still resolving. A blank ground for a frame or two is the honest answer; showing
            // a lock screen "meanwhile" is exactly the bug being fixed.
            null -> Unit

            is VaultState.Unlocked -> UnlockedRoot(container = container)

            is VaultState.Locked -> UnlockScreen(
                state = unlockState,
                // Biometric enrolment is a later step; the passphrase path is the one that
                // must work first, and claiming a biometric option that does nothing would
                // be exactly the fake affordance this product avoids.
                biometricAvailable = false,
                onBiometricUnlock = {},
                onPassphraseUnlock = { passphrase ->
                    scope.launch {
                        unlockController.unlockWithPassphrase(passphrase)
                        vaultState = container.repository.currentState()
                    }
                },
                onUseRecoveryKey = {},
            )

            is VaultState.FirstRun, is VaultState.FirstRunRemoteUnchecked ->
                OnboardingRoot(
                    step = step,
                    controller = onboarding,
                    remoteUnchecked = state is VaultState.FirstRunRemoteUnchecked,
                    onCreated = { scope.launch { vaultState = container.repository.currentState() } },
                )

            // Everything below is a recovery situation. None of them may offer to create a
            // vault, so none of them routes to onboarding.
            is VaultState.RemoteVaultAvailable -> RecoveryRoot(
                headline = "Your vault is in Google Drive",
                detail = "This device has no copy yet. Restore it, then unlock with your " +
                    "passphrase or recovery key — Google cannot open it for you.",
                onRestore = { onboarding.startRestore() },
                step = step,
                controller = onboarding,
            )

            is VaultState.VaultRecoveryAvailable -> RecoveryRoot(
                headline = "A recoverable copy was found",
                detail = "An upload was interrupted before it finished. Your previous vault " +
                    "is intact and can be restored — nothing has been lost.",
                onRestore = { onboarding.startRestore() },
                step = step,
                controller = onboarding,
            )

            is VaultState.RecoveryRequired -> RecoveryRoot(
                headline = "This device needs your recovery key",
                detail = "This device has held a vault, but no copy is available right now. " +
                    "We won't create a new one over it.",
                onRestore = { onboarding.startRestore() },
                step = step,
                controller = onboarding,
            )

            is VaultState.Corrupted -> RecoveryRoot(
                headline = "This copy of your vault is damaged",
                detail = "Your passphrase is not the problem. Your copy in Google Drive is " +
                    "likely unaffected, and this copy will not be overwritten.",
                onRestore = { onboarding.startRestore() },
                step = step,
                controller = onboarding,
            )
        }
    }
}
