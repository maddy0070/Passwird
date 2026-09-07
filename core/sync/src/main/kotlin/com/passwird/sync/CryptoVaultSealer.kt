package com.passwird.sync

import com.passwird.crypto.KeySlot
import com.passwird.crypto.SecretBytes
import com.passwird.crypto.VaultContainer
import com.passwird.crypto.VaultCrypto
import com.passwird.model.VaultDocument
import com.passwird.model.codec.VaultDocumentCodec

/**
 * The production [VaultSealer]: real encryption, real container format.
 *
 * Holds the VEK for the duration of an unlocked session. The sync engine itself never sees
 * key material — it calls [open] and [seal] and knows nothing about how either works, which
 * is what keeps `SyncEngine` testable and keeps cryptographic decisions in one place.
 */
class CryptoVaultSealer(
    private val vek: SecretBytes,
    private val vaultId: ByteArray,
    private val slots: List<KeySlot>,
) : VaultSealer {

    override fun open(bytes: ByteArray): VaultDocument {
        val plaintext = VaultCrypto.unsealWithVek(bytes, vek)
        return try {
            VaultDocumentCodec.decodeFromBytes(plaintext)
        } finally {
            plaintext.fill(0)
        }
    }

    override fun seal(document: VaultDocument, previousHeaderBytes: ByteArray?): ByteArray {
        // The version counter advances from whatever we are chaining onto, so it stays
        // monotonic across devices without any of them needing a shared clock.
        val nextVersion = previousHeaderBytes
            ?.let { VaultContainer.peekHeaderVersion(it) + 1 }
            ?: 1L

        val plaintext = VaultDocumentCodec.encodeToBytes(document)
        return try {
            VaultCrypto.seal(
                vek = vek,
                vaultId = vaultId,
                vaultVersion = nextVersion,
                slots = slots,
                previousHeaderBytes = previousHeaderBytes,
                plaintext = plaintext,
            ).bytes
        } finally {
            plaintext.fill(0)
        }
    }
}
