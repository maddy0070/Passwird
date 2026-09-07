plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

description = "Vault domain model, payload codec and schema migrations."

dependencies {
    // `api`, not `implementation`: JsonElement appears in the public surface of
    // VaultDocument, VaultItem and VaultSettings via their unknown-field maps, so
    // consumers must be able to see the type.
    api(libs.kotlinx.serialization.json)

    testImplementation(libs.kotlin.test)
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}
