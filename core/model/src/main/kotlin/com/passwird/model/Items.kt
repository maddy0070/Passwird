package com.passwird.model

import java.time.Instant
import java.time.LocalDate
import java.util.UUID

/** Stable identifier for a device, used for deterministic conflict ordering. */
@JvmInline
value class DeviceId(val value: String) {
    init { require(value.isNotBlank()) { "device id must not be blank" } }
    override fun toString(): String = value
}

/**
 * The item types the vault supports.
 *
 * The wire name is pinned separately from the enum constant so a Kotlin rename can never
 * silently change the serialised form and orphan every existing record.
 */
enum class ItemType(val wire: String) {
    LOGIN("login"),
    SECURE_NOTE("note"),
    PAYMENT_CARD("card"),
    IDENTITY("identity"),
    API_KEY("apiKey"),
    WIFI("wifi"),
    SSH("ssh"),
    DATABASE("database"),
    SOFTWARE_LICENSE("license"),
    RECOVERY_CODES("recoveryCodes"),
    CUSTOM("custom"),
    ;

    companion object {
        private val byWire = entries.associateBy(ItemType::wire)
        fun fromWire(value: String): ItemType? = byWire[value]
    }
}

enum class CardBrand(val wire: String) {
    VISA("visa"), MASTERCARD("mastercard"), AMEX("amex"), DISCOVER("discover"),
    JCB("jcb"), UNIONPAY("unionpay"), MAESTRO("maestro"), OTHER("other"),
    ;
    companion object {
        fun fromWire(value: String?): CardBrand? = entries.firstOrNull { it.wire == value }
    }
}

enum class WifiSecurity(val wire: String) {
    WPA3("wpa3"), WPA2("wpa2"), WPA("wpa"), WEP("wep"), OPEN("open"),
    ;
    companion object {
        fun fromWire(value: String?): WifiSecurity? = entries.firstOrNull { it.wire == value }
    }
}

/** A typed custom-field value. */
sealed interface FieldValue {
    data class Text(val value: String) : FieldValue
    /** Masked in the UI, copyable, never logged. */
    data class Hidden(val value: Secret) : FieldValue
    data class Numeric(val value: String) : FieldValue
    data class DateValue(val value: LocalDate) : FieldValue
    data class Url(val value: String) : FieldValue
    data class Bool(val value: Boolean) : FieldValue
}

/**
 * A user-defined field.
 *
 * The escape hatch that stops the schema becoming a prison: anything we failed to
 * anticipate can be stored without a schema migration.
 */
data class CustomField(
    val id: UUID,
    val label: String,
    val value: FieldValue,
    val revision: Long = 1,
)

data class Address(
    val line1: String? = null,
    val line2: String? = null,
    val city: String? = null,
    val region: String? = null,
    val postalCode: String? = null,
    val country: String? = null,
)

/** One 2FA recovery code, with its own spent/unspent state. */
data class RecoveryCode(val code: Secret, val used: Boolean = false)

/**
 * Per-type payloads.
 *
 * A discriminated union over a shared envelope rather than parallel record shapes, so
 * search, merge, sync and the UI each need exactly one code path.
 */
sealed interface ItemContent {
    val type: ItemType

    data class Login(
        val username: String = "",
        val password: Secret = Secret.EMPTY,
        val urls: List<String> = emptyList(),
        val email: String? = null,
        val phone: String? = null,
        /**
         * When the *password* last changed.
         *
         * Deliberately separate from the record's `updatedAt`: password age is a security
         * signal, record age is not. Editing a note must not reset the rotation clock, or
         * the "ageing passwords" report degrades into noise. Most managers conflate these.
         */
        val passwordUpdatedAt: Instant? = null,
    ) : ItemContent {
        override val type: ItemType get() = ItemType.LOGIN
    }

    data class SecureNote(val body: String = "") : ItemContent {
        override val type: ItemType get() = ItemType.SECURE_NOTE
    }

    data class PaymentCard(
        val cardholder: String = "",
        val number: Secret = Secret.EMPTY,
        val brand: CardBrand? = null,
        val expiryMonth: Int? = null,
        val expiryYear: Int? = null,
        val cvv: Secret? = null,
        val pin: Secret? = null,
    ) : ItemContent {
        override val type: ItemType get() = ItemType.PAYMENT_CARD
    }

    data class Identity(
        val fullName: String? = null,
        val dateOfBirth: LocalDate? = null,
        val nationalId: Secret? = null,
        val passportNumber: Secret? = null,
        val addresses: List<Address> = emptyList(),
        val email: String? = null,
        val phone: String? = null,
    ) : ItemContent {
        override val type: ItemType get() = ItemType.IDENTITY
    }

    data class ApiKey(
        val service: String? = null,
        val keyId: String? = null,
        val secret: Secret = Secret.EMPTY,
        val environment: String? = null,
        val expiresAt: Instant? = null,
    ) : ItemContent {
        override val type: ItemType get() = ItemType.API_KEY
    }

    data class WifiCredential(
        val ssid: String = "",
        val password: Secret = Secret.EMPTY,
        val security: WifiSecurity? = null,
        val hidden: Boolean = false,
    ) : ItemContent {
        override val type: ItemType get() = ItemType.WIFI
    }

    data class SshCredential(
        val privateKey: Secret = Secret.EMPTY,
        val publicKey: String? = null,
        val keyPassphrase: Secret? = null,
        val host: String? = null,
        val user: String? = null,
        val fingerprint: String? = null,
    ) : ItemContent {
        override val type: ItemType get() = ItemType.SSH
    }

    data class DatabaseCredential(
        val engine: String? = null,
        val host: String? = null,
        val port: Int? = null,
        val database: String? = null,
        val username: String = "",
        val password: Secret = Secret.EMPTY,
        val connectionString: Secret? = null,
    ) : ItemContent {
        override val type: ItemType get() = ItemType.DATABASE
    }

    data class SoftwareLicense(
        val product: String? = null,
        val licenseKey: Secret = Secret.EMPTY,
        val licensedTo: String? = null,
        val purchasedAt: LocalDate? = null,
        val expiresAt: LocalDate? = null,
        val seats: Int? = null,
    ) : ItemContent {
        override val type: ItemType get() = ItemType.SOFTWARE_LICENSE
    }

    /**
     * 2FA recovery codes, each tracked as spent or unspent.
     *
     * Users keep these as screenshots in their camera roll today — a real, widespread and
     * severe leak. Merely storing them is not enough to change that behaviour: the
     * screenshot's actual job is answering "which ones have I already used?", so tracking
     * per-code state is what makes this a replacement rather than another place to look.
     */
    data class RecoveryCodes(
        val service: String? = null,
        val codes: List<RecoveryCode> = emptyList(),
    ) : ItemContent {
        override val type: ItemType get() = ItemType.RECOVERY_CODES

        val remaining: Int get() = codes.count { !it.used }
    }

    data class Custom(
        val typeName: String = "",
        val fields: List<CustomField> = emptyList(),
    ) : ItemContent {
        override val type: ItemType get() = ItemType.CUSTOM
    }
}
