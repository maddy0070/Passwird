package com.passwird.crypto

import java.security.SecureRandom
import kotlinx.serialization.json.JsonElement

/**
 * How to treat a vault whose stored KDF parameters are below the current floor.
 *
 * Note what this is *not* defending against. The header is bound as AEAD AAD, so a third
 * party cannot lower the Argon2 cost of an existing vault — any edit breaks the tag.
 * Below-floor parameters therefore mean the vault is genuinely old, not that it is under
 * attack.
 *
 * That distinction decides the default. Refusing to open a legacy vault would destroy
 * data to defend against an attack the format already prevents, and principle 1 (*never
 * lose the user's data*) outranks principle 2. So we open it, flag it, and re-key it.
 */
enum class KdfPolicy {
    /** Open the vault, set [UnsealedVault.kdfUpgradeRequired], re-key on next save. */
    UpgradeAfterUnlock,

    /** Refuse below-floor parameters outright. Used by tests and by explicit audits. */
    Strict,
}

/**
 * A decrypted vault. Holds live key material — always use it inside `use { }`.
 */
class UnsealedVault internal constructor(
    val vek: SecretBytes,
    val plaintext: ByteArray,
    val header: VaultHeader,
    val headerBytes: ByteArray,
    /** The slot this unlock actually used. */
    val unlockedWith: KeySlot,
    /**
     * True when **the slot just used** is below the KDF floor.
     *
     * Scoped to that one slot deliberately: it is the only slot whose secret the user has
     * demonstrably just supplied, so it is the only one that can be re-keyed now. A flag
     * covering every slot could never be cleared — upgrading the passphrase cannot touch
     * the recovery slot, whose key nobody has in hand.
     */
    val kdfUpgradeRequired: Boolean,
    /**
     * Every slot type still below the floor, including ones not used for this unlock.
     *
     * Informational. A weak recovery slot is only re-keyed when the user rotates their
     * recovery key, which the UI can prompt for — but it must not block or nag on unlock.
     */
    val weakSlotTypes: Set<SlotType>,
) : AutoCloseable {

    override fun close() {
        vek.close()
        plaintext.fill(0)
    }

    override fun toString(): String =
        "UnsealedVault(version=${header.vaultVersion}, ${plaintext.size} bytes, redacted)"
}

/** A freshly created vault: the bytes to store, and the live VEK. */
class CreatedVault internal constructor(
    val bytes: ByteArray,
    val vek: SecretBytes,
    val header: VaultHeader,
    val headerBytes: ByteArray,
) : AutoCloseable {
    override fun close() = vek.close()
}

/**
 * The vault sealing and unsealing API — the only entry point the rest of the app uses.
 *
 * Everything here is a composition of the primitives in this package; no caller is ever
 * expected to assemble a key hierarchy by hand.
 */
object VaultCrypto {

    private val random = SecureRandom()

    const val RECOVERY_KEY_BYTES: Int = 16 // 128 bits

    // ---------------------------------------------------------------- create

    /**
     * Creates a vault with a passphrase slot and a recovery slot wrapping one random VEK.
     *
     * The VEK is random and is *never* derived from the passphrase. That is what lets a
     * passphrase change re-wrap 32 bytes instead of re-encrypting everything, and what
     * lets biometric and recovery unlock coexist without either being able to derive the
     * other. See ADR-0002.
     */
    fun create(
        plaintext: ByteArray,
        passphrase: SecretBytes,
        recoveryKey: SecretBytes,
        nowEpochMillis: Long,
        passphraseKdf: KdfParams = KdfParams.default(randomSalt()),
        recoveryKdf: KdfParams = KdfParams.default(randomSalt()),
    ): CreatedVault {
        val vek = SecretBytes.random(Aead.KEY_BYTES)
        val vaultId = ByteArray(VaultHeader.VAULT_ID_BYTES).also(random::nextBytes)

        val slots = listOf(
            KeySlots.create(vek, passphrase, SlotType.PASSPHRASE, "Master passphrase", passphraseKdf, nowEpochMillis),
            KeySlots.create(vek, recoveryKey, SlotType.RECOVERY, "Recovery key", recoveryKdf, nowEpochMillis),
        )

        val sealed = seal(
            vek = vek,
            vaultId = vaultId,
            vaultVersion = 1,
            slots = slots,
            previousHeaderBytes = null,
            plaintext = plaintext,
        )
        return CreatedVault(sealed.bytes, vek, sealed.header, sealed.headerBytes)
    }

    /** A 128-bit recovery key. Shown to the user once and never stored by us. */
    fun generateRecoveryKey(): SecretBytes = SecretBytes.random(RECOVERY_KEY_BYTES)

    fun randomSalt(size: Int = KdfParams.DEFAULT_SALT_BYTES): ByteArray =
        ByteArray(size).also(random::nextBytes)

    // ---------------------------------------------------------------- unseal

    /**
     * Decrypts a container with [secret] against a slot of [type].
     *
     * Order matters and is deliberate:
     *  1. structural parse with every length bounds-checked (hostile input);
     *  2. constant-time slot commitment check — a wrong secret stops here, cleanly;
     *  3. unwrap the VEK;
     *  4. derive the content key and verify the payload against the full authenticated
     *     prefix.
     *
     * Because step 2 already confirmed the key, a failure at step 4 unambiguously means
     * *tampering or corruption*, never a wrong passphrase — which is what lets the UI
     * distinguish E-01 from E-29.
     */
    fun unseal(
        bytes: ByteArray,
        secret: SecretBytes,
        type: SlotType,
        kdfPolicy: KdfPolicy = KdfPolicy.UpgradeAfterUnlock,
    ): UnsealedVault {
        val parsed = VaultContainer.parse(bytes)

        val unwrapped = KeySlots.unwrapAny(
            slots = parsed.header.slots,
            secret = secret,
            type = type,
            enforceFloor = kdfPolicy == KdfPolicy.Strict,
        )
        val vek = unwrapped.vek

        val plaintext = try {
            Hkdf.derive(vek, KeyDomains.CONTENT, salt = parsed.header.fileSalt).use { contentKey ->
                val padded = Aead.open(
                    key = contentKey,
                    nonce = parsed.header.nonce,
                    ciphertext = parsed.payload,
                    aad = parsed.aad,
                    context = "vault payload",
                )
                try {
                    Padding.unpad(padded)
                } finally {
                    padded.fill(0)
                }
            }
        } catch (e: Throwable) {
            vek.close()
            throw e
        }

        return UnsealedVault(
            vek = vek,
            plaintext = plaintext,
            header = parsed.header,
            headerBytes = parsed.headerBytes,
            unlockedWith = unwrapped.slot,
            kdfUpgradeRequired = unwrapped.slot.kdf?.meetsFloor() == false,
            weakSlotTypes = parsed.header.slots
                .filter { it.kdf?.meetsFloor() == false }
                .map { it.type }
                .toSet(),
        )
    }

    /**
     * Decrypts using a VEK already in hand, with no key slot and no KDF.
     *
     * This is the sync path. Once the vault is unlocked we hold the VEK, and a file that
     * arrives from the store must be readable without asking the user for their passphrase
     * again — both because re-prompting on every background sync would be intolerable, and
     * because it would put the passphrase on screen far more often than necessary.
     *
     * The key slots are irrelevant here: the payload is encrypted under a key derived from
     * the VEK and this file's own salt, so any file belonging to this vault opens with it.
     */
    fun unsealWithVek(bytes: ByteArray, vek: SecretBytes): ByteArray {
        val parsed = VaultContainer.parse(bytes)
        return Hkdf.derive(vek, KeyDomains.CONTENT, salt = parsed.header.fileSalt).use { contentKey ->
            val padded = Aead.open(
                key = contentKey,
                nonce = parsed.header.nonce,
                ciphertext = parsed.payload,
                aad = parsed.aad,
                context = "vault payload",
            )
            try {
                Padding.unpad(padded)
            } finally {
                padded.fill(0)
            }
        }
    }

    // ------------------------------------------------------------------ seal

    class Sealed internal constructor(
        val bytes: ByteArray,
        val header: VaultHeader,
        val headerBytes: ByteArray,
    )

    /**
     * Encrypts [plaintext] into a container.
     *
     * A fresh [VaultHeader.fileSalt] on every write means a fresh content key on every
     * write, which is what removes GCM's 96-bit nonce concern — see ADR-0001.
     */
    fun seal(
        vek: SecretBytes,
        vaultId: ByteArray,
        vaultVersion: Long,
        slots: List<KeySlot>,
        previousHeaderBytes: ByteArray?,
        plaintext: ByteArray,
        extra: Map<String, JsonElement> = emptyMap(),
    ): Sealed {
        val syncableSlots = slots.filter { it.isSyncable }
        if (syncableSlots.none { it.type == SlotType.PASSPHRASE }) {
            // A vault with no passphrase slot could only ever be opened on the device
            // that made it — one lost phone from being unrecoverable.
            throw CryptoError.SlotError("refusing to seal a vault with no passphrase slot")
        }

        val header = VaultHeader(
            headerSchema = VaultHeader.CURRENT_SCHEMA,
            vaultId = vaultId,
            vaultVersion = vaultVersion,
            fileSalt = ByteArray(VaultHeader.FILE_SALT_BYTES).also(random::nextBytes),
            nonce = Aead.randomNonce(),
            chain = previousHeaderBytes?.let { Digest.sha256(it) } ?: VaultHeader.GENESIS_CHAIN,
            slots = syncableSlots,
            extra = extra,
        )

        val headerBytes = VaultContainer.encodeHeader(header)
        val aad = VaultContainer.aadFor(headerBytes)
        val padded = Padding.pad(plaintext)

        val payload = try {
            Hkdf.derive(vek, KeyDomains.CONTENT, salt = header.fileSalt).use { contentKey ->
                Aead.seal(contentKey, header.nonce, padded, aad)
            }
        } finally {
            padded.fill(0)
        }

        return Sealed(VaultContainer.serialize(headerBytes, payload), header, headerBytes)
    }

    /**
     * Re-seals an open vault with new contents, advancing the version and hash chain.
     *
     * The chain commits each version to `SHA-256(previous header)`, so a store that
     * rewrites history produces a file whose chain does not line up — detectable without
     * trusting the store's own version counter.
     */
    fun reseal(
        unsealed: UnsealedVault,
        plaintext: ByteArray,
        slots: List<KeySlot> = unsealed.header.slots,
    ): Sealed = seal(
        vek = unsealed.vek,
        vaultId = unsealed.header.vaultId,
        vaultVersion = unsealed.header.vaultVersion + 1,
        slots = slots,
        previousHeaderBytes = unsealed.headerBytes,
        plaintext = plaintext,
        extra = unsealed.header.extra,
    )

    /** True when [header] correctly chains from [previousHeaderBytes]. */
    fun verifyChain(header: VaultHeader, previousHeaderBytes: ByteArray?): Boolean {
        val expected = previousHeaderBytes?.let { Digest.sha256(it) } ?: VaultHeader.GENESIS_CHAIN
        return ConstantTime.equals(expected, header.chain)
    }

    // ------------------------------------------------------------ slot admin

    /**
     * Replaces the passphrase slot.
     *
     * Re-wraps the VEK under the new passphrase. The payload is untouched and is not
     * re-encrypted — the whole point of the key-slot design.
     */
    fun changePassphrase(
        unsealed: UnsealedVault,
        newPassphrase: SecretBytes,
        nowEpochMillis: Long,
        newKdf: KdfParams = KdfParams.default(randomSalt()),
    ): Sealed {
        val newSlot = KeySlots.create(
            vek = unsealed.vek,
            secret = newPassphrase,
            type = SlotType.PASSPHRASE,
            label = "Master passphrase",
            kdf = newKdf,
            nowEpochMillis = nowEpochMillis,
        )
        val slots = unsealed.header.slots.filterNot { it.type == SlotType.PASSPHRASE } + newSlot
        return reseal(unsealed, unsealed.plaintext, slots)
    }

    /** Replaces the recovery slot, invalidating the previous recovery key. */
    fun rotateRecoveryKey(
        unsealed: UnsealedVault,
        newRecoveryKey: SecretBytes,
        nowEpochMillis: Long,
        newKdf: KdfParams = KdfParams.default(randomSalt()),
    ): Sealed {
        val newSlot = KeySlots.create(
            vek = unsealed.vek,
            secret = newRecoveryKey,
            type = SlotType.RECOVERY,
            label = "Recovery key",
            kdf = newKdf,
            nowEpochMillis = nowEpochMillis,
        )
        val slots = unsealed.header.slots.filterNot { it.type == SlotType.RECOVERY } + newSlot
        return reseal(unsealed, unsealed.plaintext, slots)
    }

    /**
     * Generates a new VEK and re-encrypts everything under it.
     *
     * The heavy operation, offered when the user believes a secret was exposed. It
     * invalidates every device slot, so all devices must re-enrol — a cost the UI states
     * up front rather than as a surprise afterwards.
     *
     * What it cannot do: an attacker holding an older ciphertext *and* the old passphrase
     * can still open that old copy. Rotation protects future writes only, and
     * `docs/04-key-management.md` §7 says exactly that.
     */
    fun rotateVek(
        unsealed: UnsealedVault,
        passphrase: SecretBytes,
        recoveryKey: SecretBytes,
        nowEpochMillis: Long,
        passphraseKdf: KdfParams = KdfParams.default(randomSalt()),
        recoveryKdf: KdfParams = KdfParams.default(randomSalt()),
    ): Sealed = SecretBytes.random(Aead.KEY_BYTES).use { newVek ->
        val slots = listOf(
            KeySlots.create(newVek, passphrase, SlotType.PASSPHRASE, "Master passphrase", passphraseKdf, nowEpochMillis),
            KeySlots.create(newVek, recoveryKey, SlotType.RECOVERY, "Recovery key", recoveryKdf, nowEpochMillis),
        )
        seal(
            vek = newVek,
            vaultId = unsealed.header.vaultId,
            vaultVersion = unsealed.header.vaultVersion + 1,
            slots = slots,
            previousHeaderBytes = unsealed.headerBytes,
            plaintext = unsealed.plaintext,
            extra = unsealed.header.extra,
        )
    }

    /**
     * Re-keys any slot below the KDF floor at current parameters.
     *
     * Requires the corresponding secret, so it can only run for slots the user has just
     * proven they hold. This is what stops legacy weak parameters persisting silently —
     * the mechanism behind the worst outcomes of the 2022 LastPass breach.
     */
    fun upgradeKdf(
        unsealed: UnsealedVault,
        passphrase: SecretBytes,
        nowEpochMillis: Long,
        newKdf: KdfParams = KdfParams.default(randomSalt()),
    ): Sealed = changePassphrase(unsealed, passphrase, nowEpochMillis, newKdf)
}
