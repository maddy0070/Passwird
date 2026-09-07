package com.passwird.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull

/**
 * The cleartext, *authenticated* header of a PWVAULT container.
 *
 * Every byte of this structure is bound as AEAD additional authenticated data, so nothing
 * here can be altered without breaking the payload's tag. That is what makes downgrade
 * attacks (lowering Argon2 cost), slot substitution and version forgery structurally
 * impossible rather than merely checked for.
 *
 * **What is deliberately absent:** item counts, titles, URLs, tags, device identifiers,
 * user identity and timestamps. Everything user-derived lives inside the ciphertext.
 * [vaultId] is random rather than derived from the Google account, so holding two vault
 * files does not reveal that they belong to the same person.
 */
data class VaultHeader(
    val headerSchema: Int,
    val vaultId: ByteArray,
    val vaultVersion: Long,
    val fileSalt: ByteArray,
    val nonce: ByteArray,
    val chain: ByteArray,
    val slots: List<KeySlot>,
    /**
     * Fields written by a newer client that this build does not understand.
     *
     * Preserved verbatim and re-emitted on write. Without this, an older client that
     * opened a newer vault would silently strip the newer client's data on its next
     * save — a cross-device data-loss bug that is invisible until it is catastrophic.
     */
    val extra: Map<String, JsonElement> = emptyMap(),
) {
    init {
        require(vaultId.size == VAULT_ID_BYTES) { "vaultId must be $VAULT_ID_BYTES bytes" }
        require(fileSalt.size == FILE_SALT_BYTES) { "fileSalt must be $FILE_SALT_BYTES bytes" }
        require(nonce.size == Aead.NONCE_BYTES) { "nonce must be ${Aead.NONCE_BYTES} bytes" }
        require(chain.size == CHAIN_BYTES) { "chain must be $CHAIN_BYTES bytes" }
        require(vaultVersion >= 1) { "vaultVersion starts at 1" }
        require(slots.size <= MAX_SLOTS) { "too many key slots" }
        require(slots.all { it.isSyncable }) { "device slots must never be written to a vault file" }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VaultHeader) return false
        return headerSchema == other.headerSchema &&
            vaultId.contentEquals(other.vaultId) &&
            vaultVersion == other.vaultVersion &&
            fileSalt.contentEquals(other.fileSalt) &&
            nonce.contentEquals(other.nonce) &&
            chain.contentEquals(other.chain) &&
            slots == other.slots &&
            extra == other.extra
    }

    override fun hashCode(): Int {
        var result = headerSchema
        result = 31 * result + vaultId.contentHashCode()
        result = 31 * result + vaultVersion.hashCode()
        result = 31 * result + fileSalt.contentHashCode()
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + chain.contentHashCode()
        result = 31 * result + slots.hashCode()
        result = 31 * result + extra.hashCode()
        return result
    }

    override fun toString(): String =
        "VaultHeader(v=$headerSchema, vaultVersion=$vaultVersion, slots=${slots.map { it.type }})"

    companion object {
        const val VAULT_ID_BYTES: Int = 16
        const val FILE_SALT_BYTES: Int = 32
        const val CHAIN_BYTES: Int = 32
        const val MAX_SLOTS: Int = 16
        const val CURRENT_SCHEMA: Int = 1

        /** Genesis chain value for a brand-new vault. */
        val GENESIS_CHAIN: ByteArray get() = ByteArray(CHAIN_BYTES)
    }
}

/**
 * Canonical JSON codec for [VaultHeader].
 *
 * "Canonical" means keys sorted lexicographically with no insignificant whitespace, so
 * that writing produces deterministic bytes.
 *
 * On *read* we never re-serialise for AAD — the raw bytes as they appeared in the file
 * are used directly. That removes any possibility of an encoder/decoder disagreement
 * turning into a spurious integrity failure, and it is why unknown-field preservation is
 * safe.
 */
internal object VaultHeaderCodec {

    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = false
        allowSpecialFloatingPointValues = false
    }

    private const val K_SCHEMA = "v"
    private const val K_VAULT_ID = "vaultId"
    private const val K_VAULT_VERSION = "vaultVersion"
    private const val K_FILE_SALT = "fileSalt"
    private const val K_NONCE = "nonce"
    private const val K_CHAIN = "chain"
    private const val K_SLOTS = "slots"

    private val KNOWN_KEYS = setOf(
        K_SCHEMA, K_VAULT_ID, K_VAULT_VERSION, K_FILE_SALT, K_NONCE, K_CHAIN, K_SLOTS,
    )

    fun encode(header: VaultHeader): ByteArray {
        val fields = sortedMapOf<String, JsonElement>()
        header.extra.forEach { (k, v) -> if (k !in KNOWN_KEYS) fields[k] = v }

        fields[K_SCHEMA] = JsonPrimitive(header.headerSchema)
        fields[K_VAULT_ID] = JsonPrimitive(B64.encode(header.vaultId))
        fields[K_VAULT_VERSION] = JsonPrimitive(header.vaultVersion)
        fields[K_FILE_SALT] = JsonPrimitive(B64.encode(header.fileSalt))
        fields[K_NONCE] = JsonPrimitive(B64.encode(header.nonce))
        fields[K_CHAIN] = JsonPrimitive(B64.encode(header.chain))
        fields[K_SLOTS] = JsonArray(header.slots.map(::encodeSlot))

        return json.encodeToString(JsonObject.serializer(), JsonObject(fields))
            .toByteArray(Charsets.UTF_8)
    }

    fun decode(bytes: ByteArray): VaultHeader {
        val root = try {
            json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
        } catch (_: Exception) {
            throw CryptoError.MalformedVault("Header is not valid JSON")
        }

        val schema = root.requireInt(K_SCHEMA)
        if (schema != VaultHeader.CURRENT_SCHEMA) {
            throw CryptoError.MalformedVault("Unsupported header schema $schema")
        }

        val slotsElement = root[K_SLOTS] ?: throw CryptoError.MalformedVault("Header has no slots")
        val slotArray = try {
            slotsElement.jsonArray
        } catch (_: Exception) {
            throw CryptoError.MalformedVault("Header 'slots' is not an array")
        }
        if (slotArray.size > VaultHeader.MAX_SLOTS) {
            throw CryptoError.MalformedVault("Header declares too many key slots")
        }

        val slots = slotArray.map(::decodeSlot)
        if (slots.any { !it.isSyncable }) {
            // A device slot in a synced file means either a buggy writer or an attacker
            // probing for a weaker unlock path. Refuse either way.
            throw CryptoError.MalformedVault("Vault file contains a device slot")
        }
        if (slots.map { B64.encode(it.id) }.toSet().size != slots.size) {
            throw CryptoError.MalformedVault("Duplicate key slot ids")
        }

        val extra = root.filterKeys { it !in KNOWN_KEYS }

        // Any remaining constructor invariant becomes a MalformedVault rather than an
        // IllegalArgumentException escaping the crypto layer. Callers handle CryptoError;
        // an unchecked exception here would surface as a crash on a hostile file.
        return try {
            VaultHeader(
                headerSchema = schema,
                vaultId = B64.decode(root.requireString(K_VAULT_ID), K_VAULT_ID, VaultHeader.VAULT_ID_BYTES),
                vaultVersion = root.requireLong(K_VAULT_VERSION).also {
                    if (it < 1) throw CryptoError.MalformedVault("vaultVersion must be at least 1")
                },
                fileSalt = B64.decode(root.requireString(K_FILE_SALT), K_FILE_SALT, VaultHeader.FILE_SALT_BYTES),
                nonce = B64.decode(root.requireString(K_NONCE), K_NONCE, Aead.NONCE_BYTES),
                chain = B64.decode(root.requireString(K_CHAIN), K_CHAIN, VaultHeader.CHAIN_BYTES),
                slots = slots,
                extra = extra,
            )
        } catch (e: IllegalArgumentException) {
            throw CryptoError.MalformedVault("Invalid header: ${e.message}")
        }
    }

    private fun encodeSlot(slot: KeySlot): JsonObject {
        val fields = sortedMapOf<String, JsonElement>(
            "commitment" to JsonPrimitive(B64.encode(slot.commitment)),
            "createdAt" to JsonPrimitive(slot.createdAtEpochMillis),
            "id" to JsonPrimitive(B64.encode(slot.id)),
            "label" to JsonPrimitive(slot.label),
            "type" to JsonPrimitive(slot.type.name.lowercase()),
            "wrapNonce" to JsonPrimitive(B64.encode(slot.wrapNonce)),
            "wrapped" to JsonPrimitive(B64.encode(slot.wrapped)),
        )
        slot.kdf?.let { fields["kdf"] = encodeKdf(it) }
        return JsonObject(fields)
    }

    private fun encodeKdf(params: KdfParams): JsonObject = JsonObject(
        sortedMapOf(
            "alg" to JsonPrimitive("argon2id"),
            "m" to JsonPrimitive(params.memoryKib),
            "p" to JsonPrimitive(params.parallelism),
            "salt" to JsonPrimitive(B64.encode(params.salt)),
            "t" to JsonPrimitive(params.iterations),
            "version" to JsonPrimitive(params.version),
        ),
    )

    private fun decodeSlot(element: JsonElement): KeySlot {
        val obj = try {
            element.jsonObject
        } catch (_: Exception) {
            throw CryptoError.MalformedVault("Key slot is not an object")
        }
        val type = SlotType.fromWire(obj.requireString("type"))
        val kdf = obj["kdf"]?.let { decodeKdf(it) }

        val label = obj.requireString("label")
        if (label.length > KeySlot.MAX_LABEL_LENGTH) {
            throw CryptoError.MalformedVault("Key slot label is too long")
        }

        return try {
            KeySlot(
                id = B64.decode(obj.requireString("id"), "slot.id", KeySlot.ID_BYTES),
                type = type,
                label = label,
                kdf = kdf,
                commitment = B64.decode(
                    obj.requireString("commitment"), "slot.commitment", KeySlot.COMMITMENT_BYTES,
                ),
                wrapNonce = B64.decode(obj.requireString("wrapNonce"), "slot.wrapNonce", Aead.NONCE_BYTES),
                wrapped = B64.decode(obj.requireString("wrapped"), "slot.wrapped", KeySlot.WRAPPED_BYTES),
                createdAtEpochMillis = obj.requireLong("createdAt"),
            )
        } catch (e: IllegalArgumentException) {
            throw CryptoError.MalformedVault("Invalid key slot: ${e.message}")
        }
    }

    private fun decodeKdf(element: JsonElement): KdfParams {
        val obj = try {
            element.jsonObject
        } catch (_: Exception) {
            throw CryptoError.MalformedVault("KDF parameters are not an object")
        }
        if (obj.requireString("alg") != "argon2id") {
            throw CryptoError.MalformedVault("Unsupported KDF algorithm")
        }
        return try {
            KdfParams(
                memoryKib = obj.requireInt("m"),
                iterations = obj.requireInt("t"),
                parallelism = obj.requireInt("p"),
                salt = B64.decode(obj.requireString("salt"), "kdf.salt"),
                version = obj.requireInt("version"),
            )
        } catch (e: IllegalArgumentException) {
            throw CryptoError.MalformedVault("Invalid KDF parameters: ${e.message}")
        }
    }

    // --- strict accessors: a hostile header must not reach a lenient coercion ---

    private fun JsonObject.requireString(key: String): String {
        val primitive = this[key] as? JsonPrimitive
            ?: throw CryptoError.MalformedVault("Header field '$key' is missing or not a string")
        // isString distinguishes "1" from 1. Accepting a bare number here would let a
        // hostile header smuggle a value past a field that is meant to be textual.
        if (!primitive.isString) {
            throw CryptoError.MalformedVault("Header field '$key' must be a string")
        }
        return primitive.contentOrNull
            ?: throw CryptoError.MalformedVault("Header field '$key' is null")
    }

    private fun JsonObject.requireLong(key: String): Long {
        val primitive = this[key] as? JsonPrimitive
            ?: throw CryptoError.MalformedVault("Header field '$key' is missing or not an integer")
        if (primitive.isString) {
            throw CryptoError.MalformedVault("Header field '$key' must be a number, not a string")
        }
        return primitive.longOrNull
            ?: throw CryptoError.MalformedVault("Header field '$key' is not an integer")
    }

    private fun JsonObject.requireInt(key: String): Int {
        val value = requireLong(key)
        if (value < Int.MIN_VALUE || value > Int.MAX_VALUE) {
            throw CryptoError.MalformedVault("Header field '$key' is out of range")
        }
        return value.toInt()
    }
}
