package com.passwird.store

import com.passwird.crypto.Aead
import com.passwird.crypto.KdfParams
import com.passwird.crypto.SecretBytes
import com.passwird.crypto.VaultCrypto
import com.passwird.model.DeviceId
import com.passwird.model.ItemContent
import com.passwird.model.Secret
import com.passwird.model.VaultDocument
import com.passwird.model.VaultItem
import com.passwird.model.codec.VaultDocumentCodec
import com.passwird.sync.BackupRef
import com.passwird.sync.RemoteObject
import com.passwird.sync.RemoteStat
import com.passwird.sync.TransportError
import com.passwird.sync.VaultTransport
import java.io.IOException
import java.security.SecureRandom
import java.time.Instant
import java.util.UUID

/**
 * An in-memory stand-in for the Android Keystore.
 *
 * Real AEAD, not a stub that returns its input: the tests below assert that a tampered blob
 * is rejected, and a fake cipher would make that assertion meaningless.
 */
class FakeDeviceCipher(
    private val key: SecretBytes = SecretBytes.adopt(ByteArray(32).also { SecureRandom().nextBytes(it) }),
) : DeviceCipher {

    /** Flipped by tests that simulate a Keystore key lost to biometric re-enrolment. */
    var broken: Boolean = false

    override fun seal(plaintext: ByteArray): ByteArray {
        val nonce = ByteArray(Aead.NONCE_BYTES).also { SecureRandom().nextBytes(it) }
        return nonce + Aead.seal(key, nonce, plaintext, aad = ByteArray(0))
    }

    override fun open(ciphertext: ByteArray): ByteArray {
        if (broken) throw IOException("device key unavailable")
        if (ciphertext.size <= Aead.NONCE_BYTES) throw IOException("blob too short")
        return try {
            Aead.open(
                key = key,
                nonce = ciphertext.copyOfRange(0, Aead.NONCE_BYTES),
                ciphertext = ciphertext.copyOfRange(Aead.NONCE_BYTES, ciphertext.size),
                aad = ByteArray(0),
                context = "device store",
            )
        } catch (error: Throwable) {
            throw IOException("not authentic", error)
        }
    }
}

/** An in-memory [VaultTransport] with the failure levers the storage tests need. */
class FakeTransport : VaultTransport {

    private var bytes: ByteArray? = null
    private var generation: Long = 0

    var failNextUpload: Boolean = false
    var uploads: Int = 0

    override suspend fun stat(): RemoteStat? =
        bytes?.let { RemoteStat(generation.toString(), it.size.toLong(), 0L) }

    override suspend fun download(): RemoteObject {
        val current = bytes ?: throw TransportError.NotFound()
        return RemoteObject(current, RemoteStat(generation.toString(), current.size.toLong(), 0L))
    }

    override suspend fun upload(bytes: ByteArray, expectedGeneration: String?): RemoteStat {
        if (failNextUpload) {
            failNextUpload = false
            throw TransportError.Offline()
        }
        val actual = this.bytes?.let { generation.toString() }
        if (expectedGeneration != actual) {
            throw TransportError.GenerationMismatch(expectedGeneration, actual)
        }
        this.bytes = bytes
        generation++
        uploads++
        return RemoteStat(generation.toString(), bytes.size.toLong(), 0L)
    }

    override suspend fun listBackups(): List<BackupRef> = emptyList()

    override suspend fun restoreBackup(ref: BackupRef): RemoteObject = download()
}

object Fixtures {

    val NOW: Instant = Instant.ofEpochMilli(1_757_000_000_000L)

    fun fastKdf() = KdfParams(memoryKib = 1024, iterations = 1, parallelism = 1, salt = VaultCrypto.randomSalt())

    fun passphrase(value: String = "correct horse battery staple"): SecretBytes =
        SecretBytes.fromPassphrase(value.toCharArray())

    val VAULT_ID: UUID = UUID.fromString("11111111-2222-3333-4444-555555555555")
    val DEVICE: DeviceId = DeviceId("device-a")

    fun document(vararg titles: String): VaultDocument = VaultDocument(
        vaultId = VAULT_ID,
        items = titles.map { title ->
            VaultItem(
                id = UUID.nameUUIDFromBytes(title.toByteArray()),
                title = title,
                content = ItemContent.Login(
                    username = "user@$title.example.invalid",
                    password = Secret.of("PW-$title-a7f3c9e1"),
                ),
                createdAt = NOW,
                updatedAt = NOW,
                originDeviceId = DEVICE,
            )
        },
    )

    /** A sealed container plus the passphrase that opens it. */
    fun sealedVault(document: VaultDocument = document("Example")): Pair<ByteArray, String> {
        val value = "correct horse battery staple"
        val created = passphrase(value).use { pass ->
            VaultCrypto.create(
                plaintext = VaultDocumentCodec.encodeToBytes(document),
                passphrase = pass,
                recoveryKey = VaultCrypto.generateRecoveryKey(),
                nowEpochMillis = NOW.toEpochMilli(),
                passphraseKdf = fastKdf(),
                recoveryKdf = fastKdf(),
            )
        }
        return created.bytes.also { created.close() } to value
    }
}
