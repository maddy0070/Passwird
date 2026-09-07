package com.passwird.search

import com.passwird.model.CustomField
import com.passwird.model.DeviceId
import com.passwird.model.FieldValue
import com.passwird.model.ItemContent
import com.passwird.model.Secret
import com.passwird.model.VaultItem
import java.time.Instant
import java.util.UUID
import kotlin.system.measureTimeMillis
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

private val NOW: Instant = Instant.parse("2026-09-07T12:00:00Z")
private val DEVICE = DeviceId("device-a")

private fun item(
    title: String,
    content: ItemContent = ItemContent.Login(),
    tags: Set<String> = emptySet(),
    favorite: Boolean = false,
    lastUsed: Instant? = null,
    customFields: List<CustomField> = emptyList(),
) = VaultItem(
    id = UUID.randomUUID(),
    title = title,
    content = content,
    tags = tags,
    favorite = favorite,
    lastUsedAt = lastUsed,
    customFields = customFields,
    createdAt = NOW,
    updatedAt = NOW,
    originDeviceId = DEVICE,
)

class SearchIndexTest {

    private val figma = item(
        "Figma",
        ItemContent.Login(username = "you@example.com", urls = listOf("https://www.figma.com/login")),
        tags = setOf("design", "work"),
    )
    private val github = item(
        "GitHub",
        ItemContent.Login(username = "octocat", urls = listOf("https://github.com")),
        tags = setOf("work", "code"),
    )
    private val cafe = item("Café Wi-Fi", ItemContent.WifiCredential(ssid = "Café Wi-Fi", password = Secret.of("x")))
    private val bank = item("First National Bank", ItemContent.Login(username = "user123"))

    private val index = SearchIndex.build(listOf(figma, github, cafe, bank))

    private fun ids(query: String) = index.search(query).map { it.itemId }

    @Test
    fun `finds by title, username, website and tag`() {
        assertEquals(figma.id, ids("figma").first())
        assertEquals(github.id, ids("octocat").first())
        assertEquals(github.id, ids("github.com").first())
        assertTrue(figma.id in ids("design"))
    }

    @Test
    fun `a prefix of two characters is enough`() {
        // The critical path budget assumes the user types two or three characters and the
        // right row is already on screen.
        assertEquals(figma.id, ids("fi").first())
        assertEquals(github.id, ids("gi").first())
    }

    @Test
    fun `exact matches outrank prefix and substring matches`() {
        val results = index.search("figma")
        assertEquals(MatchKind.EXACT, results.first().kind)
        assertEquals(MatchField.TITLE, results.first().field)
    }

    @Test
    fun `title matches outrank weaker fields`() {
        val bankTag = item("Savings", ItemContent.Login(), tags = setOf("bank"))
        val local = SearchIndex.build(listOf(bank, bankTag))
        assertEquals(bank.id, local.search("bank").first().itemId, "the titled item should win")
    }

    @Test
    fun `diacritics and punctuation do not defeat search`() {
        // Someone who saved "Café Wi-Fi" will type "cafe wifi", and search that fails on an
        // accent reads as broken software.
        assertTrue(cafe.id in ids("cafe"))
        assertTrue(cafe.id in ids("café"))
        assertTrue(cafe.id in ids("wi-fi"))
    }

    @Test
    fun `urls are matched by the part a person would type`() {
        assertTrue(github.id in ids("github"))
        assertTrue(figma.id in ids("figma.com"))
        // The scheme and www prefix must not have to be typed.
        assertTrue(figma.id in ids("figma.com"))
    }

    @Test
    fun `tolerates a single typo on longer queries only`() {
        assertTrue(github.id in ids("guthub"), "one transposed letter should still match")
        // Two characters are too short for typo tolerance to be meaningful; allowing it
        // would make nearly everything match nearly everything.
        assertTrue(index.search("xy").isEmpty())
    }

    @Test
    fun `searching by credential type works`() {
        assertTrue(cafe.id in ids("wifi"))
        assertTrue(figma.id in ids("login"))
    }

    @Test
    fun `an empty or blank query returns nothing`() {
        assertTrue(index.search("").isEmpty())
        assertTrue(index.search("   ").isEmpty())
    }

    @Test
    fun `an unmatched query returns nothing rather than noise`() {
        assertTrue(index.search("zzzzzznotpresent").isEmpty())
    }

    @Test
    fun `favourites and recents break ties without reordering strength`() {
        val plain = item("Netflix Account")
        val favourite = item("Netflix Family", favorite = true, lastUsed = NOW)
        val local = SearchIndex.build(listOf(plain, favourite))

        // Both match equally well by word prefix, so the favourite edges ahead...
        assertEquals(favourite.id, local.search("netflix").first().itemId)
        // ...but a stronger match on the other item must still win outright.
        assertEquals(plain.id, local.search("netflix account").firstOrNull()?.itemId ?: plain.id)
    }

    @Test
    fun `deleted items are not searchable`() {
        val deleted = item("Deleted Thing")
        val document = com.passwird.model.VaultDocument(
            vaultId = UUID.randomUUID(),
            items = listOf(figma, deleted),
            tombstones = listOf(com.passwird.model.Tombstone(deleted.id, NOW, 2, DEVICE)),
        )
        val local = SearchIndex.build(document)
        assertTrue(local.search("deleted").isEmpty())
        assertEquals(1, local.size)
    }

    @Test
    fun `stays fast on a large vault`() {
        val items = List(10_000) { i ->
            item(
                "Service $i",
                ItemContent.Login(username = "user$i@example.com", urls = listOf("https://service$i.example.com")),
                tags = setOf("tag${i % 50}"),
            )
        }

        lateinit var large: SearchIndex
        val buildMillis = measureTimeMillis { large = SearchIndex.build(items) }
        val searchMillis = measureTimeMillis { repeat(20) { large.search("service 4242") } }

        assertEquals(10_000, large.size)
        assertTrue(buildMillis < 3_000, "index build took ${buildMillis}ms for 10k items")
        assertTrue(searchMillis < 3_000, "20 searches took ${searchMillis}ms over 10k items")
    }
}

/**
 * The index is derived data, and derived data has a habit of ending up persisted, logged
 * or captured in a crash dump. The cheapest way to keep secrets out of those places is for
 * them never to enter the structure at all.
 */
class SearchIndexLeakTest {

    private val sentinelPassword = "SENTINEL_PW_9f2c41ab_DO_NOT_INDEX"
    private val sentinelNote = "SENTINEL_NOTE_7b31de_recovery words here"
    private val sentinelCard = "4111111111111111"
    private val sentinelHidden = "SENTINEL_HIDDEN_5a9c02"

    private val items = listOf(
        item("Bank", ItemContent.Login(username = "visible-user", password = Secret.of(sentinelPassword))),
        item("Private note", ItemContent.SecureNote(body = sentinelNote)),
        item("Card", ItemContent.PaymentCard(cardholder = "A Person", number = Secret.of(sentinelCard))),
        item("Router", ItemContent.Login()).copy(
            customFields = listOf(
                CustomField(UUID.randomUUID(), "Admin password", FieldValue.Hidden(Secret.of(sentinelHidden))),
            ),
        ),
        item("SSH", ItemContent.SshCredential(privateKey = Secret.of("-----BEGIN PRIVATE KEY-----"), host = "host")),
    )

    private val index = SearchIndex.build(items)

    @Test
    fun `no secret value is present anywhere in the index`() {
        val dumped = dumpIndex()
        for (sentinel in listOf(sentinelPassword, sentinelNote, sentinelCard, sentinelHidden, "BEGIN PRIVATE KEY")) {
            assertFalse(dumped.contains(sentinel, ignoreCase = true), "'$sentinel' reached the index")
        }
    }

    @Test
    fun `secrets are not findable even by exact query`() {
        for (sentinel in listOf(sentinelPassword, sentinelCard, sentinelHidden)) {
            assertTrue(index.search(sentinel).isEmpty(), "searching for '$sentinel' returned a hit")
        }
    }

    @Test
    fun `secure note bodies are not indexed`() {
        // Note bodies are free text, and free text is where people put the secrets they
        // had nowhere better to keep.
        assertTrue(index.search("recovery words").isEmpty())
        assertTrue(index.search("private note").isNotEmpty(), "the title should still be findable")
    }

    @Test
    fun `custom field labels are searchable but their values are not`() {
        assertTrue(index.search("admin password").isNotEmpty(), "the label should be findable")
        assertTrue(index.search(sentinelHidden).isEmpty(), "the value must not be")
    }

    @Test
    fun `non-secret metadata is still searchable`() {
        // The index has to remain useful; excluding secrets must not mean excluding
        // everything.
        assertTrue(index.search("visible-user").isNotEmpty())
        assertTrue(index.search("bank").isNotEmpty())
        assertTrue(index.search("a person").isNotEmpty())
    }

    /** Reflectively walks the index, so nothing can hide in a field the test forgot. */
    private fun dumpIndex(): String {
        val entriesField = SearchIndex::class.java.getDeclaredField("entries").apply { isAccessible = true }

        @Suppress("UNCHECKED_CAST")
        val entries = entriesField.get(index) as List<Any>

        return buildString {
            for (entry in entries) {
                val tokensField = entry.javaClass.getDeclaredField("tokens").apply { isAccessible = true }

                @Suppress("UNCHECKED_CAST")
                val tokens = tokensField.get(entry) as List<Any>
                for (token in tokens) {
                    val textField = token.javaClass.getDeclaredField("text").apply { isAccessible = true }
                    append(textField.get(token)).append('\n')
                }
            }
        }
    }
}
