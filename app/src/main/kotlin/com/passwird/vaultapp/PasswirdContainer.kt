package com.passwird.vaultapp

import android.content.Context
import com.passwird.data.drive.DriveTransport
import com.passwird.data.drive.GoogleAccountManager
import com.passwird.data.drive.driveTransportFor
import com.passwird.model.DeviceId
import com.passwird.platform.secure.KeystoreKeyManager
import com.passwird.platform.secure.WrappedSecret
import com.passwird.store.DeviceCipher
import com.passwird.store.FileVaultStorage
import com.passwird.store.VaultRepository
import java.io.File
import java.io.IOException
import java.util.UUID

/**
 * The composition root.
 *
 * One object graph, built once, by hand. **No dependency-injection framework**: the graph is
 * eight objects with no cycles and no scoping problem, and a framework would add an
 * annotation processor and a compile-time dependency to solve a problem this app does not
 * have. The wiring being readable top to bottom is worth more here than the indirection.
 *
 * This class is the thing whose absence was finding A-1 in the production-readiness review.
 * `VaultRepository` existed, `FileVaultStorage` existed, and nothing connected them to an
 * Android process.
 *
 * ### What is deliberately *not* here
 *
 * Nothing constructed here can decrypt a vault. [GoogleAccountManager] is built alongside the
 * vault stack, not above it: it supplies a `Drive` handle for transport and nothing else.
 * There is no field, parameter or call path from an account to a key — asserted structurally
 * by `NoGoogleKeyPathTest`, which walks every signature in `core:crypto`.
 */
class PasswirdContainer(context: Context) {

    private val appContext = context.applicationContext

    /** Android Keystore. Every key this app holds at rest is wrapped by hardware. */
    val keyManager: KeystoreKeyManager = KeystoreKeyManager()

    /**
     * Identity and Drive access. Present in the graph, absent from the key path.
     */
    val accountManager: GoogleAccountManager = GoogleAccountManager(appContext, keyManager)

    /**
     * The Drive transport, given a lazy provider rather than a `Drive`.
     *
     * Deliberate: constructing the graph must not require a signed-in account. The app has to
     * be fully usable offline and signed out — a vault is the user's, not the session's — so
     * the account is resolved at the moment of a sync attempt and its absence is a transport
     * error, not a construction failure.
     */
    val transport: DriveTransport = driveTransportFor(accountManager)

    /** Bridges the JVM storage layer to Android Keystore. */
    private val deviceCipher: DeviceCipher = KeystoreDeviceCipher(keyManager)

    val storage: FileVaultStorage = FileVaultStorage(
        root = File(appContext.filesDir, VAULT_DIRECTORY),
        cipher = deviceCipher,
        transport = transport,
    )

    val repository: VaultRepository = VaultRepository(
        storage = storage,
        deviceId = loadOrCreateDeviceId(),
    )

    /**
     * A stable per-installation identifier, used only to give merges a deterministic tiebreak.
     *
     * Random, never derived from anything that identifies the hardware or the user: no
     * `ANDROID_ID`, no advertising id, no account. It is sealed under the device key like
     * everything else at rest, and it dies with the installation.
     */
    private fun loadOrCreateDeviceId(): DeviceId {
        val file = File(appContext.filesDir, DEVICE_ID_FILE)

        if (file.exists()) {
            val existing = runCatching {
                keyManager.openWithDeviceKey(WrappedSecret.decode(file.readBytes())).decodeToString()
            }.getOrNull()
            if (!existing.isNullOrBlank()) return DeviceId(existing)
        }

        // A lost or unreadable id means a new identity, which costs a tiebreak and nothing
        // else. It must never block startup.
        val fresh = UUID.randomUUID().toString()
        runCatching {
            file.writeBytes(keyManager.sealWithDeviceKey(fresh.toByteArray()).encode())
        }
        return DeviceId(fresh)
    }

    private companion object {
        const val VAULT_DIRECTORY = "vault"
        const val DEVICE_ID_FILE = "device-id.bin"
    }
}

/**
 * [DeviceCipher] backed by a hardware-bound Keystore key.
 *
 * The whole reason `core:store` declares an interface rather than calling Keystore directly:
 * the storage layer's real bugs are atomicity and file-format bugs, and those are testable on
 * the JVM only if the one Android dependency is a seam. This is the production side of it;
 * `FakeDeviceCipher` in the tests is the other.
 *
 * Failures are translated to [IOException] because that is what the storage layer's contract
 * says an inauthentic blob raises. A `KeyPermanentlyInvalidatedException` — the Keystore entry
 * destroyed by a biometric re-enrolment — arrives here as exactly that, and `FileVaultStorage`
 * already treats it as "bookkeeping is gone, resync" rather than as a reason to refuse the
 * vault.
 */
private class KeystoreDeviceCipher(
    private val keyManager: KeystoreKeyManager,
) : DeviceCipher {

    override fun seal(plaintext: ByteArray): ByteArray =
        keyManager.sealWithDeviceKey(plaintext).encode()

    override fun open(ciphertext: ByteArray): ByteArray = try {
        keyManager.openWithDeviceKey(WrappedSecret.decode(ciphertext))
    } catch (error: Exception) {
        throw IOException("device-key blob is not authentic or the key is gone", error)
    }
}
