package com.passwird.platform.secure

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Clipboard handling for secrets.
 *
 * The clipboard is the least defensible part of any password manager: it is a global,
 * cross-application channel, and on Android any foregrounded app can read it. We cannot
 * make it safe, so we do three things that materially shrink the exposure and, crucially,
 * make the behaviour **visible** rather than surprising:
 *
 *  1. **Flag the content as sensitive**, so the OS suppresses the clipboard preview toast
 *     that would otherwise display the password on screen (API 33+), and so keyboards and
 *     clipboard managers know not to retain it.
 *  2. **Clear automatically** after a short, user-visible countdown — and on lock, and on
 *     backgrounding, whichever comes first.
 *  3. **Clear only our own content.** Overwriting whatever the user copied from another
 *     app afterwards would be rude and occasionally destructive, so we check first.
 */
class ClipboardGuard(
    private val context: Context,
    private val scope: CoroutineScope,
) {

    private val clipboard: ClipboardManager =
        context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager

    private var clearJob: Job? = null
    private var lastCopiedToken: String? = null

    private val _secondsRemaining = MutableStateFlow(0)

    /** Drives the visible countdown, so auto-clear is a promise the user can watch. */
    val secondsRemaining: StateFlow<Int> = _secondsRemaining.asStateFlow()

    fun copySensitive(value: String, label: String, clearAfterSeconds: Int) {
        val clip = ClipData.newPlainText(label, value).apply {
            description.extras = PersistableBundle().apply {
                // Recognised from API 33; harmless below it.
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                    // The pre-33 convention some OEM clipboard managers honour.
                    putBoolean("android.content.extra.IS_SENSITIVE", true)
                }
            }
        }

        clipboard.setPrimaryClip(clip)
        lastCopiedToken = value

        clearJob?.cancel()
        if (clearAfterSeconds <= 0) return

        clearJob = scope.launch {
            for (remaining in clearAfterSeconds downTo 1) {
                _secondsRemaining.value = remaining
                delay(1_000)
            }
            _secondsRemaining.value = 0
            clearIfStillOurs()
        }
    }

    /** Copies something non-secret (a username, a URL) with no countdown and no flag. */
    fun copyPlain(value: String, label: String) {
        clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
    }

    /** Called on lock and on backgrounding. */
    fun clearNow() {
        clearJob?.cancel()
        _secondsRemaining.value = 0
        clearIfStillOurs()
    }

    private fun clearIfStillOurs() {
        val current = runCatching { clipboard.primaryClip?.getItemAt(0)?.text?.toString() }.getOrNull()
        if (current != null && current == lastCopiedToken) {
            // Replacing with an empty clip rather than calling clearPrimaryClip() keeps
            // behaviour consistent across API levels and OEM skins.
            clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
        }
        lastCopiedToken = null
    }
}
