package com.passwird.search

import com.passwird.model.ItemContent
import com.passwird.model.ItemType
import com.passwird.model.VaultDocument
import com.passwird.model.VaultItem
import java.text.Normalizer
import java.util.UUID
import kotlin.math.min

/** Which part of an item matched, so the UI can show why a result is present. */
enum class MatchField(val weight: Double) {
    TITLE(1.0),
    USERNAME(0.8),
    WEBSITE(0.7),
    EMAIL(0.7),
    TAG(0.6),
    TYPE(0.4),
}

enum class MatchKind(val multiplier: Double) {
    EXACT(1.0),
    PREFIX(0.85),
    WORD_PREFIX(0.75),
    SUBSTRING(0.55),
    FUZZY(0.35),
}

data class SearchResult(
    val itemId: UUID,
    val score: Double,
    val field: MatchField,
    val kind: MatchKind,
    val matchedText: String,
)

/**
 * In-memory offline search.
 *
 * Three properties, all deliberate:
 *
 * **It never touches the network.** Searching a vault is one of the most revealing things
 * a user does — the query alone discloses which account they are reaching for. It is a
 * pure function of data already in memory.
 *
 * **It never indexes a secret.** Passwords, card numbers, keys, notes and custom hidden
 * fields are excluded from the index entirely, not merely excluded from results. An index
 * is derived data that tends to get persisted, logged or dumped in a crash; the cheapest
 * way to keep secrets out of those places is for them never to enter the structure.
 * Asserted by `SearchIndexLeakTest`.
 *
 * **It is rebuilt, never stored.** Persisting the index would create a second, weaker copy
 * of vault metadata with its own lifetime. Building it for a few thousand items costs
 * single-digit milliseconds, which is far cheaper than that liability.
 */
class SearchIndex private constructor(private val entries: List<Entry>) {

    internal class Entry(
        val itemId: UUID,
        val favorite: Boolean,
        val lastUsedAtMillis: Long,
        val tokens: List<Token>,
    )

    internal class Token(val text: String, val field: MatchField, val words: List<String>)

    val size: Int get() = entries.size

    /**
     * Ranked matches for [query].
     *
     * An empty query returns favourites and recently used items — the two things someone
     * opening a search field most often wants — rather than an arbitrary alphabetical slice.
     */
    fun search(query: String, limit: Int = 50): List<SearchResult> {
        val normalised = normalise(query)
        if (normalised.isBlank()) return emptyList()

        val results = ArrayList<SearchResult>()

        for (entry in entries) {
            var best: SearchResult? = null
            for (token in entry.tokens) {
                val match = matchToken(token, normalised) ?: continue
                val score = match.second.multiplier * token.field.weight + recencyBoost(entry)
                if (best == null || score > best.score) {
                    best = SearchResult(entry.itemId, score, token.field, match.second, match.first)
                }
            }
            best?.let(results::add)
        }

        return results.sortedWith(
            compareByDescending<SearchResult> { it.score }.thenBy { it.matchedText },
        ).take(limit)
    }

    private fun matchToken(token: Token, query: String): Pair<String, MatchKind>? {
        val text = token.text
        return when {
            text == query -> text to MatchKind.EXACT
            text.startsWith(query) -> text to MatchKind.PREFIX
            token.words.any { it.startsWith(query) } -> text to MatchKind.WORD_PREFIX
            text.contains(query) -> text to MatchKind.SUBSTRING
            // Typo tolerance only for queries long enough that a near miss is meaningful.
            // Applying it to two-character queries would match almost everything.
            query.length >= 4 && token.words.any { withinEditDistance(it, query, 1) } ->
                text to MatchKind.FUZZY
            else -> null
        }
    }

    /**
     * A small nudge, not a reordering.
     *
     * Recency and favourites break ties between comparable matches; they must never float
     * a weak match above a strong one, or search stops feeling predictable.
     */
    private fun recencyBoost(entry: Entry): Double {
        var boost = 0.0
        if (entry.favorite) boost += 0.05
        if (entry.lastUsedAtMillis > 0) boost += 0.05
        return boost
    }

    companion object {

        fun build(document: VaultDocument): SearchIndex = build(document.liveItems())

        fun build(items: List<VaultItem>): SearchIndex =
            SearchIndex(items.map { item -> Entry(item.id, item.favorite, item.lastUsedAt?.toEpochMilli() ?: 0, tokensFor(item)) })

        /**
         * The indexed surface.
         *
         * Every field here is *searchable metadata*. Nothing secret is included, and the
         * omissions are the point rather than an oversight — see the class docs.
         */
        private fun tokensFor(item: VaultItem): List<Token> {
            val tokens = mutableListOf<Token>()

            fun add(text: String?, field: MatchField) {
                val value = normalise(text ?: return)
                if (value.isNotBlank()) tokens += Token(value, field, value.split(WORD_SPLIT).filter(String::isNotBlank))
            }

            add(item.title, MatchField.TITLE)
            item.tags.forEach { add(it, MatchField.TAG) }
            add(displayNameFor(item.type), MatchField.TYPE)

            when (val content = item.content) {
                is ItemContent.Login -> {
                    add(content.username, MatchField.USERNAME)
                    add(content.email, MatchField.EMAIL)
                    content.urls.forEach { add(registrableHost(it), MatchField.WEBSITE) }
                }
                is ItemContent.ApiKey -> {
                    add(content.service, MatchField.USERNAME)
                    add(content.keyId, MatchField.USERNAME)
                }
                is ItemContent.WifiCredential -> add(content.ssid, MatchField.TITLE)
                is ItemContent.SshCredential -> {
                    add(content.host, MatchField.WEBSITE)
                    add(content.user, MatchField.USERNAME)
                }
                is ItemContent.DatabaseCredential -> {
                    add(content.host, MatchField.WEBSITE)
                    add(content.username, MatchField.USERNAME)
                    add(content.database, MatchField.TITLE)
                }
                is ItemContent.PaymentCard -> add(content.cardholder, MatchField.USERNAME)
                is ItemContent.Identity -> {
                    add(content.fullName, MatchField.USERNAME)
                    add(content.email, MatchField.EMAIL)
                }
                is ItemContent.SoftwareLicense -> {
                    add(content.product, MatchField.TITLE)
                    add(content.licensedTo, MatchField.USERNAME)
                }
                is ItemContent.RecoveryCodes -> add(content.service, MatchField.WEBSITE)
                is ItemContent.Custom -> add(content.typeName, MatchField.TYPE)
                // Deliberately unindexed: the body is free text that routinely holds
                // secrets people had nowhere better to put.
                is ItemContent.SecureNote -> Unit
            }

            // Custom field *labels* are indexed; their values never are, because a Hidden
            // field is a secret by definition and a Text one may still be sensitive.
            item.customFields.forEach { add(it.label, MatchField.TAG) }

            return tokens.distinctBy { it.field to it.text }
        }

        fun displayNameFor(type: ItemType): String = when (type) {
            ItemType.LOGIN -> "login"
            ItemType.SECURE_NOTE -> "note"
            ItemType.PAYMENT_CARD -> "card payment"
            ItemType.IDENTITY -> "identity"
            ItemType.API_KEY -> "api key token"
            ItemType.WIFI -> "wifi network"
            ItemType.SSH -> "ssh key server"
            ItemType.DATABASE -> "database"
            ItemType.SOFTWARE_LICENSE -> "licence license software"
            ItemType.RECOVERY_CODES -> "recovery codes backup"
            ItemType.CUSTOM -> "custom"
        }

        private val WORD_SPLIT = Regex("[^\\p{L}\\p{N}]+")

        /**
         * Lower-cases and strips diacritics.
         *
         * Someone who saved "Café Wi-Fi" must find it by typing "cafe wifi". Search that
         * fails on an accent reads as broken, and the user blames the app rather than the
         * accent.
         */
        internal fun normalise(text: String): String =
            Normalizer.normalize(text.lowercase(), Normalizer.Form.NFD)
                .replace(DIACRITICS, "")
                .trim()

        private val DIACRITICS = Regex("\\p{InCombiningDiacriticalMarks}+")

        /** Reduces a URL to the part a person would actually type. */
        internal fun registrableHost(url: String): String {
            val withoutScheme = url.substringAfter("://", url)
            val host = withoutScheme.substringBefore('/').substringBefore(':').removePrefix("www.")
            return host.ifBlank { url }
        }

        /** Bounded Levenshtein: gives up as soon as the distance exceeds [maxDistance]. */
        internal fun withinEditDistance(a: String, b: String, maxDistance: Int): Boolean {
            if (kotlin.math.abs(a.length - b.length) > maxDistance) return false
            if (a == b) return true

            var previous = IntArray(b.length + 1) { it }
            var current = IntArray(b.length + 1)

            for (i in 1..a.length) {
                current[0] = i
                var rowMin = current[0]
                for (j in 1..b.length) {
                    val cost = if (a[i - 1] == b[j - 1]) 0 else 1
                    current[j] = min(min(current[j - 1] + 1, previous[j] + 1), previous[j - 1] + cost)
                    rowMin = min(rowMin, current[j])
                }
                if (rowMin > maxDistance) return false
                val swap = previous
                previous = current
                current = swap
            }
            return previous[b.length] <= maxDistance
        }
    }
}
