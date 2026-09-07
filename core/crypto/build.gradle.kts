plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

description = "Vault cryptography: KDF, key hierarchy, key slots and the PWVAULT container."

dependencies {
    implementation(libs.kotlinx.serialization.json)

    // Argon2id and HKDF only. AEAD (AES-256-GCM), SHA-256 and SecureRandom come
    // from the platform JCE, which is hardware-accelerated on Android via
    // Conscrypt and lets this module run unmodified on the JVM. See ADR-0001.
    implementation(libs.bouncycastle)

    testImplementation(libs.kotlin.test)
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}
