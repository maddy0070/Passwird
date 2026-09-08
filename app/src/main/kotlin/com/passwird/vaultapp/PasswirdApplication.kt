package com.passwird.vaultapp

import android.app.Application
import com.passwird.platform.secure.ScreenPrivacy

/**
 * Application entry point.
 *
 * Installs the screenshot guard here rather than per-activity so a screen added later
 * cannot forget to opt in, and so there is no window during a transition where the OS
 * could capture an unprotected frame for the recents thumbnail.
 */
class PasswirdApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        ScreenPrivacy.install(this)

        // Nothing else is initialised here on purpose. There is no analytics SDK, no crash
        // reporter and no feature-flag client to start, because none of them exist in this
        // product (ADR-0005). A short Application.onCreate is a privacy property, not just
        // a startup-time one.
    }
}
