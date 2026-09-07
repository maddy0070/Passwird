package com.passwird.model.codec

import com.passwird.model.Address
import com.passwird.model.CardBrand
import com.passwird.model.CustomField
import com.passwird.model.DeviceId
import com.passwird.model.DeviceRecord
import com.passwird.model.FieldConflict
import com.passwird.model.FieldValue
import com.passwird.model.Folder
import com.passwird.model.ItemContent
import com.passwird.model.ItemType
import com.passwird.model.RecoveryCode
import com.passwird.model.Secret
import com.passwird.model.Tombstone
import com.passwird.model.VaultDocument
import com.passwird.model.VaultItem
import com.passwird.model.VaultSettings
import com.passwird.model.migration.MigrationRegistry
import java.time.Instant
import java.time.LocalDate
import java.time.format.DateTimeParseException
import java.util.UUID
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/**
 * Encodes and decodes the vault payload.
 *
 * Two properties matter more than elegance here:
 *
 *  1. **Unknown fields survive a round trip** (both at document and item level), so an
 *     older client cannot silently strip a newer client's data.
 *  2. **Decoding is non-destructive.** Any malformed input raises [VaultCodecException];
 *     the caller still holds the original encrypted bytes and can present a recoverable
 *     error rather than losing a vault.
 */
object VaultDocumentCodec {

    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = false
        allowSpecialFloatingPointValues = false
    }

    private val DOC_KEYS = setOf(
        "schemaVersion", "vaultId", "items", "tombstones", "folders", "devices", "settings",
    )
    private val ITEM_KEYS = setOf(
        "id", "title", "type", "content", "tags", "folderId", "favorite", "customFields",
        "notes", "createdAt", "updatedAt", "lastUsedAt", "revision", "originDeviceId",
        "fieldRevisions", "conflicts", "needsReview",
    )
    private val SETTINGS_KEYS = setOf(
        "autoLockSeconds", "lockOnBackground", "clipboardClearSeconds", "requireBiometricForReveal",
    )

    // ------------------------------------------------------------------ encode

    fun encodeToBytes(document: VaultDocument): ByteArray =
        json.encodeToString(JsonObject.serializer(), encode(document)).toByteArray(Charsets.UTF_8)

    fun encode(document: VaultDocument): JsonObject {
        val fields = mutableMapOf<String, JsonElement>(
            "schemaVersion" to JsonPrimitive(document.schemaVersion),
            "vaultId" to JsonPrimitive(document.vaultId.toString()),
            "items" to JsonArray(document.items.map(::encodeItem)),
            "tombstones" to JsonArray(document.tombstones.map(::encodeTombstone)),
            "folders" to JsonArray(document.folders.map(::encodeFolder)),
            "devices" to JsonArray(document.devices.map(::encodeDevice)),
            "settings" to encodeSettings(document.settings),
        )
        return Js.withUnknown(fields, document.unknown)
    }

    private fun encodeItem(item: VaultItem): JsonObject {
        val fields = mutableMapOf<String, JsonElement>(
            "id" to JsonPrimitive(item.id.toString()),
            "title" to JsonPrimitive(item.title),
            "type" to JsonPrimitive(item.type.wire),
            "content" to encodeContent(item.content),
            "tags" to JsonArray(item.tags.sorted().map(::JsonPrimitive)),
            "folderId" to Js.nn(item.folderId?.toString()),
            "favorite" to JsonPrimitive(item.favorite),
            "customFields" to JsonArray(item.customFields.map(::encodeCustomField)),
            "notes" to JsonPrimitive(item.notes),
            "createdAt" to JsonPrimitive(item.createdAt.toEpochMilli()),
            "updatedAt" to JsonPrimitive(item.updatedAt.toEpochMilli()),
            "lastUsedAt" to Js.nn(item.lastUsedAt?.toEpochMilli()),
            "revision" to JsonPrimitive(item.revision),
            "originDeviceId" to JsonPrimitive(item.originDeviceId.value),
            "fieldRevisions" to JsonObject(item.fieldRevisions.toSortedMap().mapValues { JsonPrimitive(it.value) }),
            "conflicts" to JsonArray(item.conflicts.map(::encodeConflict)),
            "needsReview" to JsonPrimitive(item.needsReview),
        )
        return Js.withUnknown(fields, item.unknown)
    }

    private fun encodeContent(content: ItemContent): JsonObject = when (content) {
        is ItemContent.Login -> JsonObject(
            sortedMapOf(
                "username" to JsonPrimitive(content.username),
                "password" to secret(content.password),
                "urls" to JsonArray(content.urls.map(::JsonPrimitive)),
                "email" to Js.nn(content.email),
                "phone" to Js.nn(content.phone),
                "passwordUpdatedAt" to Js.nn(content.passwordUpdatedAt?.toEpochMilli()),
            ),
        )
        is ItemContent.SecureNote -> JsonObject(sortedMapOf("body" to JsonPrimitive(content.body)))
        is ItemContent.PaymentCard -> JsonObject(
            sortedMapOf(
                "cardholder" to JsonPrimitive(content.cardholder),
                "number" to secret(content.number),
                "brand" to Js.nn(content.brand?.wire),
                "expiryMonth" to Js.nn(content.expiryMonth),
                "expiryYear" to Js.nn(content.expiryYear),
                "cvv" to optSecret(content.cvv),
                "pin" to optSecret(content.pin),
            ),
        )
        is ItemContent.Identity -> JsonObject(
            sortedMapOf(
                "fullName" to Js.nn(content.fullName),
                "dateOfBirth" to Js.nn(content.dateOfBirth?.toString()),
                "nationalId" to optSecret(content.nationalId),
                "passportNumber" to optSecret(content.passportNumber),
                "addresses" to JsonArray(content.addresses.map(::encodeAddress)),
                "email" to Js.nn(content.email),
                "phone" to Js.nn(content.phone),
            ),
        )
        is ItemContent.ApiKey -> JsonObject(
            sortedMapOf(
                "service" to Js.nn(content.service),
                "keyId" to Js.nn(content.keyId),
                "secret" to secret(content.secret),
                "environment" to Js.nn(content.environment),
                "expiresAt" to Js.nn(content.expiresAt?.toEpochMilli()),
            ),
        )
        is ItemContent.WifiCredential -> JsonObject(
            sortedMapOf(
                "ssid" to JsonPrimitive(content.ssid),
                "password" to secret(content.password),
                "security" to Js.nn(content.security?.wire),
                "hidden" to JsonPrimitive(content.hidden),
            ),
        )
        is ItemContent.SshCredential -> JsonObject(
            sortedMapOf(
                "privateKey" to secret(content.privateKey),
                "publicKey" to Js.nn(content.publicKey),
                "keyPassphrase" to optSecret(content.keyPassphrase),
                "host" to Js.nn(content.host),
                "user" to Js.nn(content.user),
                "fingerprint" to Js.nn(content.fingerprint),
            ),
        )
        is ItemContent.DatabaseCredential -> JsonObject(
            sortedMapOf(
                "engine" to Js.nn(content.engine),
                "host" to Js.nn(content.host),
                "port" to Js.nn(content.port),
                "database" to Js.nn(content.database),
                "username" to JsonPrimitive(content.username),
                "password" to secret(content.password),
                "connectionString" to optSecret(content.connectionString),
            ),
        )
        is ItemContent.SoftwareLicense -> JsonObject(
            sortedMapOf(
                "product" to Js.nn(content.product),
                "licenseKey" to secret(content.licenseKey),
                "licensedTo" to Js.nn(content.licensedTo),
                "purchasedAt" to Js.nn(content.purchasedAt?.toString()),
                "expiresAt" to Js.nn(content.expiresAt?.toString()),
                "seats" to Js.nn(content.seats),
            ),
        )
        is ItemContent.RecoveryCodes -> JsonObject(
            sortedMapOf(
                "service" to Js.nn(content.service),
                "codes" to JsonArray(
                    content.codes.map {
                        JsonObject(
                            sortedMapOf(
                                "code" to secret(it.code),
                                "used" to JsonPrimitive(it.used),
                            ),
                        )
                    },
                ),
            ),
        )
        is ItemContent.Custom -> JsonObject(
            sortedMapOf(
                "typeName" to JsonPrimitive(content.typeName),
                "fields" to JsonArray(content.fields.map(::encodeCustomField)),
            ),
        )
    }

    private fun encodeAddress(address: Address): JsonObject = JsonObject(
        sortedMapOf(
            "line1" to Js.nn(address.line1),
            "line2" to Js.nn(address.line2),
            "city" to Js.nn(address.city),
            "region" to Js.nn(address.region),
            "postalCode" to Js.nn(address.postalCode),
            "country" to Js.nn(address.country),
        ),
    )

    private fun encodeCustomField(field: CustomField): JsonObject = JsonObject(
        sortedMapOf(
            "id" to JsonPrimitive(field.id.toString()),
            "label" to JsonPrimitive(field.label),
            "revision" to JsonPrimitive(field.revision),
            "value" to encodeFieldValue(field.value),
        ),
    )

    private fun encodeFieldValue(value: FieldValue): JsonObject = when (value) {
        is FieldValue.Text -> JsonObject(sortedMapOf("kind" to JsonPrimitive("text"), "v" to JsonPrimitive(value.value)))
        is FieldValue.Hidden -> JsonObject(sortedMapOf("kind" to JsonPrimitive("hidden"), "v" to secret(value.value)))
        is FieldValue.Numeric -> JsonObject(sortedMapOf("kind" to JsonPrimitive("numeric"), "v" to JsonPrimitive(value.value)))
        is FieldValue.DateValue -> JsonObject(sortedMapOf("kind" to JsonPrimitive("date"), "v" to JsonPrimitive(value.value.toString())))
        is FieldValue.Url -> JsonObject(sortedMapOf("kind" to JsonPrimitive("url"), "v" to JsonPrimitive(value.value)))
        is FieldValue.Bool -> JsonObject(sortedMapOf("kind" to JsonPrimitive("bool"), "v" to JsonPrimitive(value.value)))
    }

    private fun encodeConflict(conflict: FieldConflict): JsonObject = JsonObject(
        sortedMapOf(
            "field" to JsonPrimitive(conflict.field),
            "losingValue" to encodeFieldValue(conflict.losingValue),
            "fromDeviceId" to JsonPrimitive(conflict.fromDeviceId.value),
            "at" to JsonPrimitive(conflict.at.toEpochMilli()),
        ),
    )

    private fun encodeTombstone(tombstone: Tombstone): JsonObject = JsonObject(
        sortedMapOf(
            "id" to JsonPrimitive(tombstone.id.toString()),
            "deletedAt" to JsonPrimitive(tombstone.deletedAt.toEpochMilli()),
            "revision" to JsonPrimitive(tombstone.revision),
            "originDeviceId" to JsonPrimitive(tombstone.originDeviceId.value),
        ),
    )

    private fun encodeFolder(folder: Folder): JsonObject = JsonObject(
        sortedMapOf(
            "id" to JsonPrimitive(folder.id.toString()),
            "name" to JsonPrimitive(folder.name),
            "revision" to JsonPrimitive(folder.revision),
            "originDeviceId" to JsonPrimitive(folder.originDeviceId.value),
        ),
    )

    private fun encodeDevice(device: DeviceRecord): JsonObject = JsonObject(
        sortedMapOf(
            "id" to JsonPrimitive(device.id.value),
            "label" to JsonPrimitive(device.label),
            "addedAt" to JsonPrimitive(device.addedAt.toEpochMilli()),
            "lastSyncAt" to Js.nn(device.lastSyncAt?.toEpochMilli()),
            "platform" to JsonPrimitive(device.platform),
        ),
    )

    private fun encodeSettings(settings: VaultSettings): JsonObject {
        val fields = mutableMapOf<String, JsonElement>(
            "autoLockSeconds" to JsonPrimitive(settings.autoLockSeconds),
            "lockOnBackground" to JsonPrimitive(settings.lockOnBackground),
            "clipboardClearSeconds" to JsonPrimitive(settings.clipboardClearSeconds),
            "requireBiometricForReveal" to JsonPrimitive(settings.requireBiometricForReveal),
        )
        return Js.withUnknown(fields, settings.unknown)
    }

    private fun secret(value: Secret): JsonElement = JsonPrimitive(value.reveal())
    private fun optSecret(value: Secret?): JsonElement = value?.let { JsonPrimitive(it.reveal()) }
        ?: kotlinx.serialization.json.JsonNull

    // ------------------------------------------------------------------ decode

    fun decodeFromBytes(bytes: ByteArray): VaultDocument {
        val root = try {
            json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
        } catch (e: Exception) {
            throw VaultCodecException("Vault payload is not valid JSON", e)
        }
        return decode(root)
    }

    fun decode(rootIn: JsonObject): VaultDocument {
        val declaredVersion = Js.int(rootIn, "schemaVersion", 1)

        // An older client must never guess at a newer schema; guessing is how a partial
        // understanding gets written back and silently truncates the newer client's data.
        if (declaredVersion > VaultDocument.CURRENT_SCHEMA_VERSION) {
            throw VaultCodecException(
                "Vault uses schema version $declaredVersion; this build supports " +
                    "${VaultDocument.CURRENT_SCHEMA_VERSION}. Update the app.",
            )
        }

        val root = MigrationRegistry.migrate(rootIn, declaredVersion, VaultDocument.CURRENT_SCHEMA_VERSION)

        return VaultDocument(
            schemaVersion = VaultDocument.CURRENT_SCHEMA_VERSION,
            vaultId = uuid(Js.string(root, "vaultId"), "vaultId"),
            items = Js.array(root, "items").map { decodeItem(Js.obj(it, "item")) },
            tombstones = Js.array(root, "tombstones").map { decodeTombstone(Js.obj(it, "tombstone")) },
            folders = Js.array(root, "folders").map { decodeFolder(Js.obj(it, "folder")) },
            devices = Js.array(root, "devices").map { decodeDevice(Js.obj(it, "device")) },
            settings = Js.optObj(root, "settings")?.let(::decodeSettings) ?: VaultSettings(),
            unknown = Js.unknownOf(root, DOC_KEYS),
        )
    }

    private fun decodeItem(obj: JsonObject): VaultItem {
        val typeWire = Js.string(obj, "type")
        val type = ItemType.fromWire(typeWire)
            ?: throw VaultCodecException("Unknown item type '$typeWire'")

        return VaultItem(
            id = uuid(Js.string(obj, "id"), "item.id"),
            title = Js.optString(obj, "title") ?: "",
            content = decodeContent(type, Js.optObj(obj, "content") ?: JsonObject(emptyMap())),
            tags = Js.stringList(obj, "tags").toSet(),
            folderId = Js.optString(obj, "folderId")?.let { uuid(it, "item.folderId") },
            favorite = Js.bool(obj, "favorite"),
            customFields = Js.array(obj, "customFields").map { decodeCustomField(Js.obj(it, "customField")) },
            notes = Js.optString(obj, "notes") ?: "",
            createdAt = instant(Js.long(obj, "createdAt", 0)),
            updatedAt = instant(Js.long(obj, "updatedAt", 0)),
            lastUsedAt = Js.optLong(obj, "lastUsedAt")?.let(::instant),
            revision = Js.long(obj, "revision", 1),
            originDeviceId = DeviceId(Js.optString(obj, "originDeviceId") ?: "unknown"),
            fieldRevisions = Js.optObj(obj, "fieldRevisions")
                ?.mapValues { (_, v) -> (v as? JsonPrimitive)?.content?.toLongOrNull() ?: 1L }
                ?: emptyMap(),
            conflicts = Js.array(obj, "conflicts").map { decodeConflict(Js.obj(it, "conflict")) },
            needsReview = Js.bool(obj, "needsReview"),
            unknown = Js.unknownOf(obj, ITEM_KEYS),
        )
    }

    private fun decodeContent(type: ItemType, c: JsonObject): ItemContent = when (type) {
        ItemType.LOGIN -> ItemContent.Login(
            username = Js.optString(c, "username") ?: "",
            password = secretOf(Js.optString(c, "password")),
            urls = Js.stringList(c, "urls"),
            email = Js.optString(c, "email"),
            phone = Js.optString(c, "phone"),
            passwordUpdatedAt = Js.optLong(c, "passwordUpdatedAt")?.let(::instant),
        )
        ItemType.SECURE_NOTE -> ItemContent.SecureNote(body = Js.optString(c, "body") ?: "")
        ItemType.PAYMENT_CARD -> ItemContent.PaymentCard(
            cardholder = Js.optString(c, "cardholder") ?: "",
            number = secretOf(Js.optString(c, "number")),
            brand = CardBrand.fromWire(Js.optString(c, "brand")),
            expiryMonth = Js.optInt(c, "expiryMonth"),
            expiryYear = Js.optInt(c, "expiryYear"),
            cvv = Js.optString(c, "cvv")?.let(Secret::of),
            pin = Js.optString(c, "pin")?.let(Secret::of),
        )
        ItemType.IDENTITY -> ItemContent.Identity(
            fullName = Js.optString(c, "fullName"),
            dateOfBirth = Js.optString(c, "dateOfBirth")?.let { localDate(it, "dateOfBirth") },
            nationalId = Js.optString(c, "nationalId")?.let(Secret::of),
            passportNumber = Js.optString(c, "passportNumber")?.let(Secret::of),
            addresses = Js.array(c, "addresses").map { decodeAddress(Js.obj(it, "address")) },
            email = Js.optString(c, "email"),
            phone = Js.optString(c, "phone"),
        )
        ItemType.API_KEY -> ItemContent.ApiKey(
            service = Js.optString(c, "service"),
            keyId = Js.optString(c, "keyId"),
            secret = secretOf(Js.optString(c, "secret")),
            environment = Js.optString(c, "environment"),
            expiresAt = Js.optLong(c, "expiresAt")?.let(::instant),
        )
        ItemType.WIFI -> ItemContent.WifiCredential(
            ssid = Js.optString(c, "ssid") ?: "",
            password = secretOf(Js.optString(c, "password")),
            security = WifiSecurityCodec.fromWire(Js.optString(c, "security")),
            hidden = Js.bool(c, "hidden"),
        )
        ItemType.SSH -> ItemContent.SshCredential(
            privateKey = secretOf(Js.optString(c, "privateKey")),
            publicKey = Js.optString(c, "publicKey"),
            keyPassphrase = Js.optString(c, "keyPassphrase")?.let(Secret::of),
            host = Js.optString(c, "host"),
            user = Js.optString(c, "user"),
            fingerprint = Js.optString(c, "fingerprint"),
        )
        ItemType.DATABASE -> ItemContent.DatabaseCredential(
            engine = Js.optString(c, "engine"),
            host = Js.optString(c, "host"),
            port = Js.optInt(c, "port"),
            database = Js.optString(c, "database"),
            username = Js.optString(c, "username") ?: "",
            password = secretOf(Js.optString(c, "password")),
            connectionString = Js.optString(c, "connectionString")?.let(Secret::of),
        )
        ItemType.SOFTWARE_LICENSE -> ItemContent.SoftwareLicense(
            product = Js.optString(c, "product"),
            licenseKey = secretOf(Js.optString(c, "licenseKey")),
            licensedTo = Js.optString(c, "licensedTo"),
            purchasedAt = Js.optString(c, "purchasedAt")?.let { localDate(it, "purchasedAt") },
            expiresAt = Js.optString(c, "expiresAt")?.let { localDate(it, "expiresAt") },
            seats = Js.optInt(c, "seats"),
        )
        ItemType.RECOVERY_CODES -> ItemContent.RecoveryCodes(
            service = Js.optString(c, "service"),
            codes = Js.array(c, "codes").map {
                val o = Js.obj(it, "recoveryCode")
                RecoveryCode(code = secretOf(Js.optString(o, "code")), used = Js.bool(o, "used"))
            },
        )
        ItemType.CUSTOM -> ItemContent.Custom(
            typeName = Js.optString(c, "typeName") ?: "",
            fields = Js.array(c, "fields").map { decodeCustomField(Js.obj(it, "customField")) },
        )
    }

    private fun decodeAddress(o: JsonObject) = Address(
        line1 = Js.optString(o, "line1"),
        line2 = Js.optString(o, "line2"),
        city = Js.optString(o, "city"),
        region = Js.optString(o, "region"),
        postalCode = Js.optString(o, "postalCode"),
        country = Js.optString(o, "country"),
    )

    private fun decodeCustomField(o: JsonObject) = CustomField(
        id = uuid(Js.string(o, "id"), "customField.id"),
        label = Js.optString(o, "label") ?: "",
        value = decodeFieldValue(Js.optObj(o, "value") ?: JsonObject(emptyMap())),
        revision = Js.long(o, "revision", 1),
    )

    private fun decodeFieldValue(o: JsonObject): FieldValue {
        // 'v' is read per-kind rather than up front: a Bool field stores a JSON boolean,
        // and eagerly coercing it to a string rejects a perfectly valid document.
        return when (val kind = Js.optString(o, "kind") ?: "text") {
            "text" -> FieldValue.Text(Js.optString(o, "v") ?: "")
            "hidden" -> FieldValue.Hidden(secretOf(Js.optString(o, "v")))
            "numeric" -> FieldValue.Numeric(Js.optString(o, "v") ?: "")
            "date" -> FieldValue.DateValue(localDate(Js.optString(o, "v") ?: "", "customField.date"))
            "url" -> FieldValue.Url(Js.optString(o, "v") ?: "")
            "bool" -> FieldValue.Bool(Js.bool(o, "v"))
            else -> throw VaultCodecException("Unknown custom field kind '$kind'")
        }
    }

    private fun decodeConflict(o: JsonObject) = FieldConflict(
        field = Js.string(o, "field"),
        losingValue = decodeFieldValue(Js.optObj(o, "losingValue") ?: JsonObject(emptyMap())),
        fromDeviceId = DeviceId(Js.optString(o, "fromDeviceId") ?: "unknown"),
        at = instant(Js.long(o, "at", 0)),
    )

    private fun decodeTombstone(o: JsonObject) = Tombstone(
        id = uuid(Js.string(o, "id"), "tombstone.id"),
        deletedAt = instant(Js.long(o, "deletedAt", 0)),
        revision = Js.long(o, "revision", 1),
        originDeviceId = DeviceId(Js.optString(o, "originDeviceId") ?: "unknown"),
    )

    private fun decodeFolder(o: JsonObject) = Folder(
        id = uuid(Js.string(o, "id"), "folder.id"),
        name = Js.optString(o, "name") ?: "",
        revision = Js.long(o, "revision", 1),
        originDeviceId = DeviceId(Js.optString(o, "originDeviceId") ?: "unknown"),
    )

    private fun decodeDevice(o: JsonObject) = DeviceRecord(
        id = DeviceId(Js.string(o, "id")),
        label = Js.optString(o, "label") ?: "",
        addedAt = instant(Js.long(o, "addedAt", 0)),
        lastSyncAt = Js.optLong(o, "lastSyncAt")?.let(::instant),
        platform = Js.optString(o, "platform") ?: "android",
    )

    private fun decodeSettings(o: JsonObject) = VaultSettings(
        autoLockSeconds = Js.int(o, "autoLockSeconds", 300),
        lockOnBackground = Js.bool(o, "lockOnBackground", default = true),
        clipboardClearSeconds = Js.int(o, "clipboardClearSeconds", 45),
        requireBiometricForReveal = Js.bool(o, "requireBiometricForReveal"),
        unknown = Js.unknownOf(o, SETTINGS_KEYS),
    )

    // ---------------------------------------------------------------- helpers

    private fun secretOf(value: String?): Secret = value?.let(Secret::of) ?: Secret.EMPTY

    private fun uuid(value: String, field: String): UUID = try {
        UUID.fromString(value)
    } catch (e: IllegalArgumentException) {
        throw VaultCodecException("'$field' is not a valid UUID", e)
    }

    private fun localDate(value: String, field: String): LocalDate = try {
        LocalDate.parse(value)
    } catch (e: DateTimeParseException) {
        throw VaultCodecException("'$field' is not a valid ISO date", e)
    }

    private fun instant(epochMillis: Long): Instant = Instant.ofEpochMilli(epochMillis)
}

/** Kept separate so the enum stays free of codec concerns. */
private object WifiSecurityCodec {
    fun fromWire(value: String?) = com.passwird.model.WifiSecurity.fromWire(value)
}
