package com.passwird.model.codec

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.longOrNull

/** Raised when a payload cannot be decoded. Always recoverable — never destructive. */
class VaultCodecException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Strict typed accessors over the JSON DOM.
 *
 * The codec works on the DOM rather than through generated `@Serializable` classes for one
 * reason: **unknown-field preservation**. A client that opens a vault written by a newer
 * version must write it back without silently dropping fields it does not understand.
 * Generated serialisers discard unknown keys by default, and that discard is a
 * cross-device data-loss bug that stays invisible until it is catastrophic.
 */
internal object Js {

    fun obj(element: JsonElement?, field: String): JsonObject =
        element as? JsonObject ?: throw VaultCodecException("'$field' must be an object")

    fun optObj(parent: JsonObject, field: String): JsonObject? =
        parent[field]?.takeUnless { it is JsonNull }?.let { obj(it, field) }

    fun array(parent: JsonObject, field: String): List<JsonElement> =
        when (val value = parent[field]) {
            null, is JsonNull -> emptyList()
            is kotlinx.serialization.json.JsonArray -> value
            else -> throw VaultCodecException("'$field' must be an array")
        }

    fun string(parent: JsonObject, field: String): String =
        optString(parent, field) ?: throw VaultCodecException("'$field' is missing")

    fun optString(parent: JsonObject, field: String): String? {
        val primitive = parent[field]?.takeUnless { it is JsonNull } as? JsonPrimitive ?: return null
        if (!primitive.isString) throw VaultCodecException("'$field' must be a string")
        return primitive.contentOrNull
    }

    fun long(parent: JsonObject, field: String, default: Long? = null): Long {
        val primitive = parent[field]?.takeUnless { it is JsonNull } as? JsonPrimitive
            ?: return default ?: throw VaultCodecException("'$field' is missing")
        return primitive.longOrNull ?: throw VaultCodecException("'$field' must be an integer")
    }

    fun optLong(parent: JsonObject, field: String): Long? {
        val primitive = parent[field]?.takeUnless { it is JsonNull } as? JsonPrimitive ?: return null
        return primitive.longOrNull ?: throw VaultCodecException("'$field' must be an integer")
    }

    fun optInt(parent: JsonObject, field: String): Int? {
        val value = optLong(parent, field) ?: return null
        if (value < Int.MIN_VALUE || value > Int.MAX_VALUE) {
            throw VaultCodecException("'$field' is out of range")
        }
        return value.toInt()
    }

    fun int(parent: JsonObject, field: String, default: Int): Int = optInt(parent, field) ?: default

    fun bool(parent: JsonObject, field: String, default: Boolean = false): Boolean {
        val primitive = parent[field]?.takeUnless { it is JsonNull } as? JsonPrimitive ?: return default
        return primitive.booleanOrNull ?: throw VaultCodecException("'$field' must be a boolean")
    }

    fun stringList(parent: JsonObject, field: String): List<String> =
        array(parent, field).map {
            (it as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.content
                ?: throw VaultCodecException("'$field' must contain only strings")
        }

    /** Every key of [parent] not in [known], for round-trip preservation. */
    fun unknownOf(parent: JsonObject, known: Set<String>): Map<String, JsonElement> =
        parent.filterKeys { it !in known }

    /** Merges preserved unknown fields back, never letting them shadow a known key. */
    fun withUnknown(
        fields: MutableMap<String, JsonElement>,
        unknown: Map<String, JsonElement>,
    ): JsonObject {
        val merged = sortedMapOf<String, JsonElement>()
        unknown.forEach { (k, v) -> if (k !in fields) merged[k] = v }
        merged.putAll(fields)
        return JsonObject(merged)
    }

    fun nn(value: String?): JsonElement = value?.let(::JsonPrimitive) ?: JsonNull
    fun nn(value: Long?): JsonElement = value?.let(::JsonPrimitive) ?: JsonNull
    fun nn(value: Int?): JsonElement = value?.let(::JsonPrimitive) ?: JsonNull
}
