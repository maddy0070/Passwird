package com.passwird.crypto

/**
 * The complete registry of HKDF domain-separation strings.
 *
 * Every key derived in this product is derived under exactly one of these labels, and no
 * key is ever used for two purposes. Domain separation is what stops a key that is safe
 * in one context from being reused in another where it is not.
 *
 * Rules:
 *  - every label is versioned, so a future scheme can coexist rather than collide;
 *  - every label is unique, asserted by `KeyDomainsTest`;
 *  - labels are never constructed dynamically at a call site — a typo would silently
 *    produce a different key and a vault nobody could open.
 */
object KeyDomains {

    private const val PREFIX = "passwird/v1/"

    /** Passphrase-derived MUK → key-encryption key for the passphrase slot. */
    const val KEK_PASSPHRASE: String = PREFIX + "kek/passphrase"

    /** Recovery-key-derived MUK → key-encryption key for the recovery slot. */
    const val KEK_RECOVERY: String = PREFIX + "kek/recovery"

    /** Keystore-held device key → key-encryption key for a device slot. */
    const val KEK_DEVICE: String = PREFIX + "kek/device"

    /** KEK → per-slot commitment value. Verified before unwrap; see ADR-0001. */
    const val SLOT_COMMITMENT: String = PREFIX + "commit"

    /** VEK + per-write fileSalt → the AES-256-GCM key for one payload. */
    const val CONTENT: String = PREFIX + "content"

    /** VEK → key for the encrypted local store (sync state, watermark, snapshots). */
    const val LOCAL_DB: String = PREFIX + "localdb"

    /** VEK → key for the encrypted local search index. */
    const val SEARCH_INDEX: String = PREFIX + "index"

    /** VEK → MAC key for local sync manifests. */
    const val SYNC_MANIFEST: String = PREFIX + "manifest"

    /** Every label, for the uniqueness test. */
    val all: List<String> = listOf(
        KEK_PASSPHRASE, KEK_RECOVERY, KEK_DEVICE,
        SLOT_COMMITMENT, CONTENT, LOCAL_DB, SEARCH_INDEX, SYNC_MANIFEST,
    )
}

/**
 * Additional-authenticated-data labels.
 *
 * These bind a ciphertext to its structural position, so a slot cannot be transplanted
 * between files or reinterpreted as a different slot type.
 */
object AadLabels {
    /** Slot unwrap AAD is `"passwird/v1/slot" ‖ slotId ‖ slotType`. */
    const val SLOT_PREFIX: String = "passwird/v1/slot"
}
