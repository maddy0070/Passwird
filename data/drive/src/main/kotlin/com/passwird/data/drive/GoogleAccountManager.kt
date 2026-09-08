package com.passwird.data.drive

import android.content.Context
import com.google.api.client.googleapis.extensions.android.gms.auth.GoogleAccountCredential
import com.google.api.client.http.javanet.NetHttpTransport
import com.google.api.client.json.gson.GsonFactory
import com.google.api.services.drive.Drive
import com.google.api.services.drive.DriveScopes
import com.passwird.platform.secure.KeystoreKeyManager
import com.passwird.platform.secure.WrappedSecret
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Google identity and Drive authorisation.
 *
 * **This class has nothing to do with encrypting the vault**, and that separation is the
 * central architectural claim of the product. Google Sign-In establishes *who the user is*
 * and grants permission to store bytes in their Drive. It never touches, derives, wraps or
 * unwraps the vault key. Signing out does not lock the vault; locking the vault does not
 * sign out. An attacker with total control of the Google account gets ciphertext.
 *
 * `NoGoogleKeyPathTest` enforces this by running a complete unlock and decrypt cycle with
 * this layer entirely absent.
 */
class GoogleAccountManager(
    private val context: Context,
    private val keyManager: KeystoreKeyManager,
) {

    private val accountFile = File(context.filesDir, "account.bin")

    /**
     * The scopes we request, and nothing more.
     *
     * `drive.file` limits us to files this app created. We cannot read the user's
     * documents, their photos, or another app's data — enforced by Google, not by our own
     * restraint. The full `drive` scope would be wildly excessive, and `drive.appdata` is
     * rejected for a different reason: Drive deletes an app-data folder when the app is
     * uninstalled, which for a password vault is a catastrophic failure mode (ADR-0003).
     */
    val scopes: List<String> = listOf(DriveScopes.DRIVE_FILE)

    /** The signed-in account's email, or null. Stored encrypted under the device key. */
    suspend fun currentAccount(): String? = withContext(Dispatchers.IO) {
        if (!accountFile.exists()) return@withContext null
        runCatching {
            keyManager.openWithDeviceKey(WrappedSecret.decode(accountFile.readBytes())).decodeToString()
        }.getOrNull()
    }

    suspend fun setAccount(email: String) = withContext(Dispatchers.IO) {
        // Even the account name is Keystore-wrapped rather than dropped into
        // SharedPreferences, where a backup or an adb pull would carry it off-device.
        accountFile.writeBytes(keyManager.sealWithDeviceKey(email.toByteArray()).encode())
    }

    /**
     * Signs out.
     *
     * Clears the account association only. The local vault is deliberately left intact and
     * fully usable offline — a sign-out that destroyed the vault would be a data-loss trap,
     * and the vault was never the session's to begin with.
     */
    suspend fun signOut() = withContext(Dispatchers.IO) {
        accountFile.delete()
        Unit
    }

    /**
     * Builds an authorised Drive client.
     *
     * `GoogleAccountCredential` handles token acquisition and refresh through Play
     * Services, so no OAuth refresh token is ever persisted by us. That is deliberate: the
     * safest token is one we do not store.
     */
    suspend fun drive(): Drive = withContext(Dispatchers.IO) {
        val email = currentAccount() ?: throw IllegalStateException("No Google account is connected")

        val credential = GoogleAccountCredential
            .usingOAuth2(context, scopes)
            .apply { selectedAccountName = email }

        Drive.Builder(NetHttpTransport(), GsonFactory.getDefaultInstance(), credential)
            .setApplicationName(APPLICATION_NAME)
            .build()
    }

    private companion object {
        const val APPLICATION_NAME = "Passwird"
    }
}
