package com.passwird.crypto

/**
 * Typed failures from the crypto layer.
 *
 * The distinctions here are load-bearing for the UI: `docs/10-error-matrix.md` gives
 * [WrongSecret] (E-01) and [IntegrityFailure] (E-29) very different copy, because they
 * mean genuinely different things to a user — "you mistyped" versus "your data is
 * damaged". Being able to tell them apart is exactly what the per-slot key commitment
 * buys us (ADR-0001); without it, both would surface as an indistinguishable AEAD tag
 * failure.
 *
 * Messages are for developers and are safe to surface only through the *Details*
 * affordance. They never contain key material, plaintext, or any part of a secret.
 */
sealed class CryptoError(message: String, cause: Throwable? = null) : Exception(message, cause) {

    /**
     * The supplied passphrase or recovery key did not match this slot.
     *
     * Detected by the constant-time commitment check before any unwrap is attempted, so
     * this outcome is reached in the same time regardless of *why* it failed.
     */
    class WrongSecret : CryptoError("Supplied secret does not match any usable key slot")

    /** The bytes are not a PWVAULT container, or the framing is inconsistent. */
    class MalformedVault(detail: String) : CryptoError("Malformed vault: $detail")

    /**
     * Authentication failed after the correct key was established.
     *
     * Means tampering or corruption — never a wrong passphrase.
     */
    class IntegrityFailure(detail: String) : CryptoError("Integrity check failed: $detail")

    /** The container's format version is outside the range this build supports. */
    class UnsupportedVersion(val found: Int, val min: Int, val max: Int) :
        CryptoError("Unsupported vault format version $found (supported: $min..$max)")

    /**
     * Stored KDF parameters are below the current security floor.
     *
     * Recoverable: the vault is readable, but must be re-keyed at current parameters
     * before it is written again. See `docs/03-encryption-architecture.md` §4.5.
     */
    class WeakKdfParameters(detail: String) : CryptoError("KDF parameters below floor: $detail")

    /** A required key slot is missing or the slot table is invalid. */
    class SlotError(detail: String) : CryptoError("Key slot error: $detail")

    /** Encryption failed. The caller must fail closed and never fall back to plaintext. */
    class EncryptionFailure(detail: String, cause: Throwable? = null) :
        CryptoError("Encryption failed: $detail", cause)
}
