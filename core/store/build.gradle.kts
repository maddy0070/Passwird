plugins {
    alias(libs.plugins.kotlin.jvm)
}

description = "Vault repository and on-disk storage. No Android, no Google."

dependencies {
    // `api`: VaultRepository's surface exposes VaultDocument, SecretBytes, SlotType,
    // CryptoError, SearchResult and SyncOutcome to every caller.
    api(project(":core:model"))
    api(project(":core:crypto"))
    api(project(":core:sync"))
    api(project(":core:search"))
    api(libs.kotlinx.coroutines.core)

    testImplementation(libs.kotlin.test)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.kotlinx.coroutines.test)
    testRuntimeOnly(libs.junit.platform.launcher)
}
