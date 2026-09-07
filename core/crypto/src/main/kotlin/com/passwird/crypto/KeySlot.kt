package com.passwird.crypto

import java.security.SecureRandom

enum class SlotType {
    /** The master passphrase. Present in the synced vault. */
    PASSPHRASE,

    /** The 128-bit recovery key. Present in the synced vault. */
    RECOVERY,

    /**
     * A hardware-backed device key.
     *
     * **Never written to the synced vault.** A Keystore-wrapped blob is meaningless on
     * any other device, so syncing it would buy nothing while leaking how many devices
     * the user owns. Enforced by [KeySlot.isSyncable] and asserted by test.
     */
    DEVICE,
    ;

    companion object {
        fun fromWire(value: String): SlotType =
            entries.firstOrNull { it.name.equals(value, ignoreCase = true) }
                ?: throw CryptoError.MalformedVault("Unknown key slot type")
    }
}

/**
 * One independent wrapping of the Vault Encryption Key.
 *
 * Slots are the LUKS model (ADR-0002): every unlock path wraps the *same* random VEK, so
 * changing the passphrase re-wraps 32 bytes instead of re-encrypting the vault, and
 * revoking a device is a slot deletion that touches nothing else.
 */
data class KeySlot(
    val id: ByteArray,
    val type: SlotType,
    val label: String,
    /** Absent for [SlotType.DEVICE], whose wrapping key comes from hardware, not a password. */
    val kdf: KdfParams?,
    val commitment: ByteArray,
    val wrapNonce: ByteArray,
    val wrapped: ByteArray,
    val createdAtEpochMillis: Long,
) {
    init {
        require(id.size == ID_BYTES) { "slot id must be $ID_BYTES bytes" }
        require(commitment.size == COMMITMENT_BYTES) { "commitment must be $COMMITMENT_BYTES bytes" }
        require(wrapNonce.size == Aead.NONCE_BYTES) { "wrap nonce must be ${Aead.NONCE_BYTES} bytes" }
        require(wrapped.size == WRAPPED_BYTES) { "wrapped key must be $WRAPPED_BYTES bytes" }
        require(label.length <= MAX_LABEL_LENGTH) { "slot label is too long" }
        if (type == SlotType.DEVICE) {
            require(kdf == null) { "device slots derive from hardware, not a password KDF" }
        } else {
            require(kdf != null) { "$type slots require KDF parameters" }
        }
    }

    /** Device slots stay local; everything else belongs in the synced artefact. */
    val isSyncable: Boolean get() = type != SlotType.DEVICE

    /**
     * Binds this wrapped key to its slot identity and type.
     *
     * Without this, a slot could be transplanted between vault files, or a recovery slot
     * relabelled as a device slot to sidestep the KDF requirement.
     */
    internal fun aad(): ByteArray =
        AadLabels.SLOT_PREFIX.toByteArray(Charsets.UTF_8) + id + type.name.toByteArray(Charsets.UTF_8)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is KeySlot) return false
        return id.contentEquals(other.id) &&
            type == other.type &&
            label == other.label &&
            kdf == other.kdf &&
            commitment.contentEquals(other.commitment) &&
            wrapNonce.contentEquals(other.wrapNonce) &&
            wrapped.contentEquals(other.wrapped) &&
            createdAtEpochMillis == other.createdAtEpochMillis
    }

    override fun hashCode(): Int {
        var result = id.contentHashCode()
        result = 31 * result + type.hashCode()
        result = 31 * result + label.hashCode()
        result = 31 * result + (kdf?.hashCode() ?: 0)
        result = 31 * result + commitment.contentHashCode()
        result = 31 * result + wrapNonce.contentHashCode()
        result = 31 * result + wrapped.contentHashCode()
        result = 31 * result + createdAtEpochMillis.hashCode()
        return result
    }

    /** No key material, no commitment — safe to log. */
    override fun toString(): String = "KeySlot(type=$type, label='$label', id=${B64.encode(id)})"

    companion object {
        const val ID_BYTES: Int = 8
        const val COMMITMENT_BYTES: Int = 32
        const val WRAPPED_BYTES: Int = Aead.KEY_BYTES + Aead.TAG_BYTES // 48
        const val MAX_LABEL_LENGTH: Int = 64
    }
}

/** Creation and unwrapping of [KeySlot]s. */
object KeySlots {

    private val random = SecureRandom()

    /**
     * Wraps [vek] under a key derived from [secret].
     *
     * @param secret passphrase or recovery key for password slots; the hardware-held
     *   32-byte key for [SlotType.DEVICE]. Not consumed — the caller still owns it.
     */
    fun create(
        vek: SecretBytes,
        secret: SecretBytes,
        type: SlotType,
        label: String,
        kdf: KdfParams?,
        nowEpochMillis: Long,
    ): KeySlot {
        require(vek.size == Aead.KEY_BYTES) { "VEK must be ${Aead.KEY_BYTES} bytes" }
        val id = ByteArray(KeySlot.ID_BYTES).also(random::nextBytes)

        return deriveKek(secret, type, kdf).use { kek ->
            val commitment = commitmentFor(kek, id)
            val nonce = Aead.randomNonce()

            // Build the slot's AAD from the same fields the finished slot will carry, so
            // wrap and unwrap cannot disagree about what was bound.
            val aad = AadLabels.SLOT_PREFIX.toByteArray(Charsets.UTF_8) +
                id + type.name.toByteArray(Charsets.UTF_8)

            val wrapped = vek.withBytes { plain -> Aead.seal(kek, nonce, plain, aad) }

            KeySlot(
                id = id,
                type = type,
                label = label,
                kdf = kdf,
                commitment = commitment,
                wrapNonce = nonce,
                wrapped = wrapped,
                createdAtEpochMillis = nowEpochMillis,
            )
        }
    }

    /**
     * Recovers the VEK from [slot].
     *
     * @throws CryptoError.WrongSecret if the commitment does not match. This check is
     *   constant-time and happens *before* any unwrap, which is what lets the UI say "that
     *   passphrase didn't match" (E-01) rather than the ambiguous "decryption failed" —
     *   and what closes partitioning-oracle attacks against the KDF (ADR-0001 §1.2).
     * @throws CryptoError.WeakKdfParameters if [enforceFloor] and the stored parameters
     *   are below the current minimum.
     */
    fun unwrap(
        slot: KeySlot,
        secret: SecretBytes,
        enforceFloor: Boolean = true,
    ): SecretBytes {
        if (enforceFloor && slot.kdf != null && !slot.kdf.meetsFloor()) {
            throw CryptoError.WeakKdfParameters(
                "slot '${slot.label}' uses m=${slot.kdf.memoryKib}KiB t=${slot.kdf.iterations} " +
                    "p=${slot.kdf.parallelism}",
            )
        }

        return deriveKek(secret, slot.type, slot.kdf).use { kek ->
            val expected = commitmentFor(kek, slot.id)
            if (!ConstantTime.equals(expected, slot.commitment)) {
                throw CryptoError.WrongSecret()
            }
            val plain = Aead.open(
                key = kek,
                nonce = slot.wrapNonce,
                ciphertext = slot.wrapped,
                aad = slot.aad(),
                context = "key slot",
            )
            SecretBytes.adopt(plain)
        }
    }

    /** The VEK, plus the slot it actually came from. */
    class Unwrapped internal constructor(val vek: SecretBytes, val slot: KeySlot)

    /**
     * Tries [secret] against every slot of [type], returning the first match.
     *
     * All candidate slots are attempted even after a match, so timing does not reveal
     * *which* slot matched and a wrong secret costs the same as a right one.
     *
     * Reporting the matching slot matters beyond bookkeeping: it is the only slot whose
     * secret the caller demonstrably holds, and therefore the only one that can be re-keyed
     * right now if its KDF parameters are stale.
     */
    fun unwrapAny(
        slots: List<KeySlot>,
        secret: SecretBytes,
        type: SlotType,
        enforceFloor: Boolean = true,
    ): Unwrapped {
        val candidates = slots.filter { it.type == type }
        if (candidates.isEmpty()) {
            throw CryptoError.SlotError("no $type slot present in this vault")
        }

        var recovered: Unwrapped? = null
        var weakParams: CryptoError.WeakKdfParameters? = null

        for (slot in candidates) {
            try {
                val vek = unwrap(slot, secret, enforceFloor)
                if (recovered == null) recovered = Unwrapped(vek, slot) else vek.close()
            } catch (_: CryptoError.WrongSecret) {
                // Keep going: no early exit, so timing does not identify the matching slot.
            } catch (e: CryptoError.WeakKdfParameters) {
                weakParams = e
            }
        }

        return recovered ?: weakParams?.let { throw it } ?: throw CryptoError.WrongSecret()
    }

    private fun deriveKek(secret: SecretBytes, type: SlotType, kdf: KdfParams?): SecretBytes =
        when (type) {
            SlotType.PASSPHRASE, SlotType.RECOVERY -> {
                val params = kdf ?: throw CryptoError.SlotError("$type slot has no KDF parameters")
                val info = if (type == SlotType.PASSPHRASE) {
                    KeyDomains.KEK_PASSPHRASE
                } else {
                    KeyDomains.KEK_RECOVERY
                }
                Argon2Kdf.deriveMuk(secret, params).use { muk -> Hkdf.derive(muk, info) }
            }
            // The hardware already did the expensive part; HKDF only separates domains.
            SlotType.DEVICE -> Hkdf.derive(secret, KeyDomains.KEK_DEVICE)
        }

    private fun commitmentFor(kek: SecretBytes, slotId: ByteArray): ByteArray =
        Hkdf.derive(
            ikm = kek,
            info = KeyDomains.SLOT_COMMITMENT,
            salt = slotId,
            length = KeySlot.COMMITMENT_BYTES,
        ).use { it.copyBytes() }
}
