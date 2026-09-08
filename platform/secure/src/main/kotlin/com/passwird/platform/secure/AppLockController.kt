package com.passwird.platform.secure

import android.app.KeyguardManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.passwird.vault.lock.AutoLockPolicy
import com.passwird.vault.lock.AutoLockSettings
import com.passwird.vault.lock.LockReason
import com.passwird.vault.lock.LockState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Wires the platform-free [AutoLockPolicy] to Android's lifecycle.
 *
 * The split is deliberate: all the *decisions* live in `core:vault` where they are unit
 * tested without an emulator, and this class only translates events — foreground,
 * background, screen off, a tick of the clock — into calls on that policy. There is no
 * lock logic here to get wrong.
 *
 * @param onLock invoked when the vault must be sealed: zeroise the VEK, clear the
 *   clipboard, drop decrypted state. It is called on the main thread and must be fast.
 */
class AppLockController(
    private val context: Context,
    private val scope: CoroutineScope,
    settings: AutoLockSettings,
    private val onLock: (LockReason) -> Unit,
) : DefaultLifecycleObserver {

    private var policy = AutoLockPolicy(settings)
    private val _state = MutableStateFlow<LockState>(LockState.Locked(LockReason.PROCESS_START))
    val state: StateFlow<LockState> = _state.asStateFlow()

    private var ticker: Job? = null
    private var screenReceiver: BroadcastReceiver? = null

    fun start() {
        ProcessLifecycleOwner.get().lifecycle.addObserver(this)
        registerScreenReceiver()
    }

    fun stop() {
        ProcessLifecycleOwner.get().lifecycle.removeObserver(this)
        screenReceiver?.let { runCatching { context.unregisterReceiver(it) } }
        screenReceiver = null
        ticker?.cancel()
    }

    fun updateSettings(settings: AutoLockSettings) {
        policy = AutoLockPolicy(settings)
        // Re-evaluate straight away: tightening the timeout should take effect now, not
        // after the next interaction.
        transition(policy.evaluate(_state.value, now()))
    }

    fun onUnlocked() {
        _state.value = policy.onUnlocked(now())
        startTicker()
    }

    /** Called from the UI on any user interaction, to postpone the inactivity timeout. */
    fun onUserInteraction() {
        _state.value = policy.onInteraction(_state.value, now())
    }

    fun lockNow() = transition(policy.onManualLock())

    override fun onStop(owner: LifecycleOwner) {
        // The app is leaving the foreground. This fires *before* the OS captures the
        // recents snapshot, so masking here is what keeps vault content out of it.
        transition(policy.onBackgrounded(_state.value))
    }

    override fun onStart(owner: LifecycleOwner) {
        // Returning to the foreground: an inactivity timeout may have elapsed while we were
        // away and no ticker was running.
        transition(policy.evaluate(_state.value, now()))
    }

    private fun registerScreenReceiver() {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_OFF -> transition(policy.onDeviceLocked(_state.value))
                    Intent.ACTION_USER_PRESENT -> Unit
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_USER_PRESENT)
        }
        context.registerReceiver(receiver, filter)
        screenReceiver = receiver
    }

    private fun startTicker() {
        ticker?.cancel()
        ticker = scope.launch {
            while (isActive) {
                delay(TICK_MILLIS)
                val next = policy.evaluate(_state.value, now())
                if (next != _state.value) {
                    transition(next)
                    break
                }
            }
        }
    }

    private fun transition(next: LockState) {
        val previous = _state.value
        if (previous == next) return
        _state.value = next

        if (next is LockState.Locked && previous is LockState.Unlocked) {
            ticker?.cancel()
            onLock(next.reason)
        }
    }

    /** True when the device has no secure lock screen, which weakens every guarantee here. */
    fun deviceHasSecureLockScreen(): Boolean =
        (context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager)?.isDeviceSecure == true

    private fun now(): Long = System.currentTimeMillis()

    private companion object {
        /**
         * Coarse on purpose.
         *
         * Lock timing does not need second precision, and a one-second wakeup would cost
         * battery for no user-visible benefit. Backgrounding and screen-off are handled by
         * events, so this only covers pure foreground inactivity.
         */
        const val TICK_MILLIS = 5_000L
    }
}
