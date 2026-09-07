# Passwird — Data Model

**Status:** v1 · **Payload schema version:** 1 · **Last updated:** 2026-09-07

Everything in this document lives **inside** the AEAD ciphertext. There is no
"non-sensitive" tier. The only cleartext in the artefact is the structural header in
`03-encryption-architecture.md` §3.1, which contains nothing user-derived.

---

## 1. Design rules

1. **Stable UUIDs.** Records are identified by a random UUID assigned at creation and
   never reused, never derived from content. Merging by title or URL is how records get
   silently destroyed when a user renames something.
2. **Every record is mergeable.** `revision`, `originDeviceId` and per-field change
   tracking are on the base record, not bolted on later. Retro-fitting merge metadata
   into a shipped schema is close to impossible.
3. **Unknown fields survive round-trips.** An older client that opens a newer vault
   must write it back without stripping fields it does not understand. This single rule
   prevents an entire family of cross-device data-loss bugs.
4. **Deletion is a tombstone**, never an absence. Absence is indistinguishable from
   "not yet synced".
5. **One record shape, many types.** A discriminated union over a shared envelope
   rather than parallel tables — so search, merge, sync and the UI each have exactly one
   code path.

---

## 2. Document

```
VaultDocument
├── schemaVersion : Int
├── vaultId       : Uuid
├── items         : List<VaultItem>
├── tombstones    : List<Tombstone>
├── folders       : List<Folder>
├── devices       : List<DeviceRecord>       ← encrypted, not in the header
├── settings      : VaultSettings
└── unknown       : Map<String, JsonElement> ← rule 3
```

`devices` lives here, inside the ciphertext, so Drive cannot count the user's devices.

---

## 3. Item envelope

```kotlin
data class VaultItem(
    val id: Uuid,
    val type: ItemType,
    val title: String,
    val content: ItemContent,          // sealed, per-type payload
    val tags: Set<String>,
    val folderId: Uuid?,
    val favorite: Boolean,
    val customFields: List<CustomField>,
    val notes: String,
    val createdAt: Instant,
    val updatedAt: Instant,
    val lastUsedAt: Instant?,
    val revision: Long,                // increments on every local edit
    val originDeviceId: DeviceId,      // (revision, originDeviceId) ⇒ total order
    val fieldRevisions: Map<String, Long>,  // per-field, for field-level merge
    val conflicts: List<FieldConflict>,     // preserved losing values, never discarded
    val needsReview: Boolean,          // set by resurrect-on-conflict
    val unknown: Map<String, JsonElement>
)
```

`revision` + `originDeviceId` give a deterministic total order that is identical on
every device and does not depend on clocks — which matters because mobile clocks are
unreliable and, under threat model T5, influenceable.

`conflicts` is the schema-level expression of *never blindly overwrite*: a losing value
is moved here, not deleted.

---

## 4. Item types

```kotlin
sealed interface ItemContent {
    data class Login(
        val username: String, val password: Secret, val urls: List<String>,
        val email: String?, val phone: String?,
        val passwordUpdatedAt: Instant?,      // real password age, not record age
        val passwordStrength: StrengthSnapshot?
    ) : ItemContent

    data class SecureNote(val body: String) : ItemContent

    data class PaymentCard(
        val cardholder: String, val number: Secret, val brand: CardBrand?,
        val expiryMonth: Int?, val expiryYear: Int?, val cvv: Secret?, val pin: Secret?
    ) : ItemContent

    data class Identity(
        val fullName: String?, val dateOfBirth: LocalDate?, val nationalId: Secret?,
        val passportNumber: Secret?, val addresses: List<Address>,
        val email: String?, val phone: String?
    ) : ItemContent

    data class ApiKey(
        val service: String?, val keyId: String?, val secret: Secret,
        val environment: String?, val expiresAt: Instant?
    ) : ItemContent

    data class WifiCredential(
        val ssid: String, val password: Secret, val security: WifiSecurity?, val hidden: Boolean
    ) : ItemContent

    data class SshCredential(
        val privateKey: Secret, val publicKey: String?, val passphrase: Secret?,
        val host: String?, val user: String?, val fingerprint: String?
    ) : ItemContent

    data class DatabaseCredential(
        val engine: String?, val host: String?, val port: Int?, val database: String?,
        val username: String, val password: Secret, val connectionString: Secret?
    ) : ItemContent

    data class SoftwareLicense(
        val product: String?, val licenseKey: Secret, val licensedTo: String?,
        val purchasedAt: LocalDate?, val expiresAt: LocalDate?, val seats: Int?
    ) : ItemContent

    data class RecoveryCodes(
        val service: String?, val codes: List<RecoveryCode>   // each individually used/unused
    ) : ItemContent

    data class Custom(
        val typeName: String, val fields: List<CustomField>
    ) : ItemContent
}
```

### 4.1 Two type choices worth defending

**`RecoveryCodes` tracks each code's used/unused state individually.** Users currently
keep 2FA recovery codes as screenshots in their camera roll — a real, widespread and
severe leak. Storing them is good; tracking which are spent is what makes the feature
actually replace the screenshot, because the screenshot's job was "which ones have I
used?". Solving the whole job is what makes the behaviour change.

**`passwordUpdatedAt` is separate from `updatedAt`.** Password *age* is a security
signal; record age is not. Editing a note must not reset the password-age clock, or the
"old passwords" report becomes noise. Most managers conflate these.

### 4.2 `Secret`

Sensitive values are typed `Secret`, not `String`:

- backed by `CharArray`, zeroisable;
- `toString()` returns `Secret(redacted)` so it cannot leak via string interpolation
  into a log — enforced by `RedactedToStringTest`;
- excluded from `equals`/`hashCode` diagnostics;
- serialised only through the encrypted payload codec, which refuses to run outside an
  encryption context.

The type system does the work that developer discipline otherwise has to.

---

## 5. Supporting types

```kotlin
data class CustomField(
    val id: Uuid, val label: String, val value: FieldValue, val revision: Long
)
sealed interface FieldValue {
    data class Text(val v: String) : FieldValue
    data class Hidden(val v: Secret) : FieldValue      // masked, copyable, never logged
    data class Numeric(val v: String) : FieldValue
    data class DateValue(val v: LocalDate) : FieldValue
    data class Url(val v: String) : FieldValue
    data class Bool(val v: Boolean) : FieldValue
}

data class Tombstone(val id: Uuid, val deletedAt: Instant,
                     val revision: Long, val originDeviceId: DeviceId)

data class Folder(val id: Uuid, val name: String, val parentId: Uuid?,
                  val revision: Long, val originDeviceId: DeviceId)

data class DeviceRecord(val id: DeviceId, val label: String, val addedAt: Instant,
                        val lastSyncAt: Instant?, val platform: String)

data class FieldConflict(val field: String, val losingValue: FieldValue,
                         val fromDeviceId: DeviceId, val at: Instant)
```

Folders are a **single optional level of grouping**; tags carry the flexible
organisation. Deep folder trees are a migration and merge liability (moves become
ambiguous, cycles become possible) and users mostly do not build them. Tags + search +
favourites + recents cover the real behaviour without the hierarchy.

---

## 6. Schema versioning and migration

The migration framework exists from day one — retro-fitting one is what makes
long-lived schemas ossify.

```kotlin
interface Migration { val from: Int; val to: Int; fun apply(doc: JsonObject): JsonObject }

object MigrationRegistry {
    fun migrate(doc: JsonObject, from: Int, to: Int): JsonObject   // chained, ordered
}
```

Rules:

| Rule | Reason |
|---|---|
| Migrations operate on the JSON tree, not on typed classes | Typed classes evolve; historical migrations must keep working against the shape as it was |
| Every migration is registered and unit-tested against a **frozen fixture** of the old format | Fixtures are committed, never regenerated |
| Migration runs after decryption, before deserialisation | Never on ciphertext |
| Downgrade is never attempted | An older client refuses a newer schema with "update the app" — it does not guess |
| Unknown fields preserved through migration | Rule 3 |
| Migration failure is **non-destructive** | Original encrypted bytes retained; the user sees a recoverable error, not a lost vault |

---

## 7. Local storage

| Data | Location | Protection |
|---|---|---|
| Encrypted vault (canonical local copy) | App-private file | The `PWVAULT` artefact itself |
| Pre-merge safety snapshots | App-private | Same format |
| Search index | App-private | Encrypted under `indexKey` |
| Sync state (watermark, generation, dirty flag, last header hash) | App-private encrypted store | Under `localDbKey` — **not** `SharedPreferences`, so clearing app data cannot reset the rollback watermark |
| Device slot wrapping key | Android Keystore / StrongBox | Non-exportable hardware key |
| OAuth tokens | App-private, Keystore-wrapped | — |
| UI preferences (theme, sort order) | `SharedPreferences` | Non-sensitive by definition; nothing vault-derived may be written here, asserted by test |
| Decrypted vault | **RAM only** | Zeroised on lock |

The rollback watermark being inside the encrypted store rather than
`SharedPreferences` is a deliberate anti-tamper choice: an attacker who can clear app
data must not thereby be able to re-enable a rollback attack.

---

## 8. Derived, never stored

Computed at unlock or on demand, never persisted:

- password strength (recomputed so policy changes take effect retroactively)
- reuse detection (equality over hashes of passwords **in memory only**)
- age buckets
- search index (rebuilt if absent or stale)

Storing these would create a second, weaker copy of vault information and a second
thing to keep consistent. Neither is worth it.
