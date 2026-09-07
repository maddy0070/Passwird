package com.passwird.model.migration

import com.passwird.model.codec.VaultCodecException
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * One step in the schema evolution chain.
 *
 * Migrations operate on the **JSON tree**, never on typed model classes. That is
 * deliberate and it is the rule that keeps long-lived schemas migratable: typed classes
 * evolve with the code, so a migration written against them silently changes meaning
 * every time the classes change. A migration written against the raw shape keeps working
 * against the shape as it actually was on disk in 2026, forever.
 */
interface Migration {
    val from: Int
    val to: Int

    /** Transforms a document from [from] to [to]. Must be pure and total. */
    fun apply(document: JsonObject): JsonObject
}

/**
 * Applies migration chains.
 *
 * The registry exists from day one, with tests, even though there is nothing to migrate
 * yet. Retro-fitting a migration framework after a schema has shipped means the first
 * migration is written under time pressure against real user data — which is exactly when
 * you least want to be inventing the mechanism.
 */
object MigrationRegistry {

    /** Production migrations. Empty at schema v1; entries are appended, never edited. */
    private val migrations: List<Migration> = emptyList()

    fun migrate(document: JsonObject, from: Int, to: Int): JsonObject =
        migrate(document, from, to, migrations)

    /** Overload taking an explicit chain, so the mechanism is testable before it is needed. */
    fun migrate(
        document: JsonObject,
        from: Int,
        to: Int,
        available: List<Migration>,
    ): JsonObject {
        if (from == to) return document
        if (from > to) {
            // Downgrade is never attempted. A client that half-understands a newer schema
            // and writes it back is how vaults get silently truncated across devices.
            throw VaultCodecException(
                "Cannot downgrade a vault from schema $from to $to. Update the app instead.",
            )
        }

        val byFrom = available.associateBy(Migration::from)
        var current = document
        var version = from

        while (version < to) {
            val step = byFrom[version]
                ?: throw VaultCodecException("No migration path from schema version $version")
            current = try {
                step.apply(current)
            } catch (e: Exception) {
                // Non-destructive by contract: the caller still holds the original
                // encrypted bytes and surfaces a recoverable error (E-23), never a loss.
                throw VaultCodecException("Migration $version to ${step.to} failed", e)
            }
            require(step.to > version) { "migration must advance the schema version" }
            version = step.to
            current = JsonObject(current + ("schemaVersion" to JsonPrimitive(version)))
        }
        return current
    }
}
