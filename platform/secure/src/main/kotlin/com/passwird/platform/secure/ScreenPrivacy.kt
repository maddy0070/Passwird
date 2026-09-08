package com.passwird.platform.secure

import android.app.Activity
import android.app.Application
import android.os.Build
import android.os.Bundle
import android.view.WindowManager

/**
 * Keeps vault content out of screenshots, screen recordings and the recents thumbnail.
 *
 * `FLAG_SECURE` is applied to **every** window, not just the ones showing a password. The
 * alternative — toggling it per screen — has a race: the OS may capture the recents
 * snapshot during the transition, before the flag is reapplied. A blanket flag has no such
 * window, and the cost is that users cannot screenshot the app at all, which for a
 * password manager is the correct trade.
 *
 * Registered once from `Application.onCreate`, so a new screen cannot forget to opt in.
 */
object ScreenPrivacy {

    fun install(application: Application) {
        application.registerActivityLifecycleCallbacks(
            object : Application.ActivityLifecycleCallbacks {
                override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                    apply(activity)
                }

                override fun onActivityStarted(activity: Activity) = Unit
                override fun onActivityResumed(activity: Activity) = Unit
                override fun onActivityPaused(activity: Activity) = Unit
                override fun onActivityStopped(activity: Activity) = Unit
                override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
                override fun onActivityDestroyed(activity: Activity) = Unit
            },
        )
    }

    fun apply(activity: Activity) {
        activity.window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            // Belt and braces: also opt out of the screenshot-detection callback, which
            // would otherwise let us observe something we have no business observing.
            runCatching { activity.setRecentsScreenshotEnabled(false) }
        }
    }
}

/**
 * A best-effort, explicitly non-authoritative device integrity hint.
 *
 * Presented to the user as advice, never as a guarantee. Every check here is defeatable by
 * an attacker who has already won — that is the nature of asking a compromised system
 * whether it is compromised. `docs/02-threat-model.md` §5 states plainly that a rooted
 * device is outside what we can defend, and the UI copy matches.
 *
 * It exists because a user who has unknowingly installed something is better served by a
 * quiet warning than by silence.
 */
object DeviceIntegrity {

    private val suspiciousPaths = listOf(
        "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
        "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su",
    )

    /** True when the device *looks* rooted. Never treated as a security control. */
    fun looksRooted(): Boolean =
        suspiciousPaths.any { runCatching { java.io.File(it).exists() }.getOrDefault(false) } ||
            Build.TAGS?.contains("test-keys") == true
}
