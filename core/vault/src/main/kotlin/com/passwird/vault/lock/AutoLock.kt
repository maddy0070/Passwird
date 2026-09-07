package com.passwird.vault.lock

import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/** User-selectable inactivity timeout. */
enum class AutoLockTimeout(val duration: Duration?, val label: String) {
    IMMEDIATELY(Duration.ZERO, "Immediately"),
    ONE_MINUTE(1.minutes, "After 1 minute"),
    FIVE_MINUTES(5.minutes, "After 5 minutes"),
    FIFTEEN_MINUTES(15.minutes, "After 15 minutes"),
    THIRTY_MINUTES(30.minutes, "After 30 minutes"),

    /**
     * Never lock on inactivity.
     *
     * Offered, because forcing a timeout on someone who has made an informed choice is
     * paternalistic — but backgrounding and device lock still apply, so "Never" bounds the
     * exposure to the foreground session rather than removing it. The UI states that
     * plainly instead of implying the vault stays open forever.
     */
    NEVER(null, "Never"),
}

/** Why the vault locked. Surfaced so the unlock screen can explain itself. */
enum class LockReason { MANUAL, INACTIVITY, BACKGROUNDED, DEVICE_LOCKED, FAILED_ATTEMPTS, PROCESS_START }

sealed interface LockState {
    data class Locked(val reason: LockReason) : LockState
    data class Unlocked(val sinceMillis: Long, val lastInteractionMillis: Long) : LockState
}

data class AutoLockSettings(
    val timeout: AutoLockTimeout = AutoLockTimeout.FIVE_MINUTES,
    /**
     * Lock as soon as the app leaves the foreground.
     *
     * Defaults to on. Security takes precedence over convenience here, and the cost is one
     * biometric touch on return.
     */
    val lockOnBackground: Boolean = true,
    val lockOnDeviceLock: Boolean = true,
)

/**
 * The auto-lock decision logic, as a pure state machine.
 *
 * Deliberately free of Android types so the policy — the part that can actually be wrong
 * in a way that matters — is unit-testable without an emulator. `platform:secure` supplies
 * the lifecycle and clock events; this decides what they mean.
 */
class AutoLockPolicy(private val settings: AutoLockSettings) {

    fun onUnlocked(nowMillis: Long): LockState = LockState.Unlocked(nowMillis, nowMillis)

    fun onInteraction(state: LockState, nowMillis: Long): LockState = when (state) {
        is LockState.Locked -> state
        is LockState.Unlocked -> state.copy(lastInteractionMillis = nowMillis)
    }

    fun onBackgrounded(state: LockState): LockState = when {
        state is LockState.Locked -> state
        settings.lockOnBackground -> LockState.Locked(LockReason.BACKGROUNDED)
        else -> state
    }

    fun onDeviceLocked(state: LockState): LockState = when {
        state is LockState.Locked -> state
        settings.lockOnDeviceLock -> LockState.Locked(LockReason.DEVICE_LOCKED)
        else -> state
    }

    fun onManualLock(): LockState = LockState.Locked(LockReason.MANUAL)

    /** Evaluated on a timer tick and whenever the app returns to the foreground. */
    fun evaluate(state: LockState, nowMillis: Long): LockState {
        if (state !is LockState.Unlocked) return state
        val timeout = settings.timeout.duration ?: return state
        val idleMillis = nowMillis - state.lastInteractionMillis
        return if (idleMillis >= timeout.inWholeMilliseconds) {
            LockState.Locked(LockReason.INACTIVITY)
        } else {
            state
        }
    }

    fun millisUntilLock(state: LockState, nowMillis: Long): Long? {
        if (state !is LockState.Unlocked) return null
        val timeout = settings.timeout.duration ?: return null
        return (state.lastInteractionMillis + timeout.inWholeMilliseconds - nowMillis).coerceAtLeast(0)
    }
}

/**
 * Backoff after failed unlock attempts.
 *
 * **Never wipes.** See ADR-0008: wiping does not protect the vault — an attacker copies
 * the encrypted file before their first guess and grinds it offline — while it reliably
 * converts a forgetful owner into a data-loss incident and hands anyone with thirty
 * seconds of physical access a denial of service.
 *
 * The counter belongs in encrypted local storage, not `SharedPreferences`, so clearing app
 * data cannot reset it.
 */
class UnlockBackoff(
    private val freeAttempts: Int = 5,
    private val baseDelaySeconds: Long = 1,
    private val maxDelaySeconds: Long = 300,
) {
    fun delaySecondsAfter(failedAttempts: Int): Long {
        if (failedAttempts < freeAttempts) return 0
        val exponent = (failedAttempts - freeAttempts).coerceAtMost(20)
        val delay = baseDelaySeconds shl exponent.toInt()
        return delay.coerceAtMost(maxDelaySeconds)
    }

    fun isLockedOut(failedAttempts: Int, lastFailureMillis: Long, nowMillis: Long): Boolean {
        val delay = delaySecondsAfter(failedAttempts)
        if (delay == 0L) return false
        return nowMillis - lastFailureMillis < delay * 1_000
    }

    fun remainingSeconds(failedAttempts: Int, lastFailureMillis: Long, nowMillis: Long): Long {
        val delay = delaySecondsAfter(failedAttempts)
        if (delay == 0L) return 0
        val elapsed = (nowMillis - lastFailureMillis) / 1_000
        return (delay - elapsed).coerceAtLeast(0)
    }

    /** Clipboard contents are cleared on lock as well as on this timer. */
    val clipboardDefaultClear: Duration = 45.seconds
}
