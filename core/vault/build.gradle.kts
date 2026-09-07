plugins {
    alias(libs.plugins.kotlin.jvm)
}

description = "Password generation, honest strength estimation, vault analysis and auto-lock policy."

dependencies {
    api(project(":core:model"))
    implementation(project(":core:crypto"))

    testImplementation(libs.kotlin.test)
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}
