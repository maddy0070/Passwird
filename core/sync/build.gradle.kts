plugins {
    alias(libs.plugins.kotlin.jvm)
}

description = "Sync state machine, three-way merge and rollback defence. No Android, no Google."

dependencies {
    api(project(":core:model"))
    // `api`: CryptoVaultSealer's constructor exposes SecretBytes and KeySlot, and the
    // engine surfaces CryptoError to callers.
    api(project(":core:crypto"))
    implementation(libs.kotlinx.coroutines.core)

    testImplementation(libs.kotlin.test)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.kotlinx.coroutines.test)
    testRuntimeOnly(libs.junit.platform.launcher)
}
