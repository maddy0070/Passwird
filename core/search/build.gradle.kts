plugins {
    alias(libs.plugins.kotlin.jvm)
}

description = "Offline search index. No network, no disk writes, no secrets indexed."

dependencies {
    api(project(":core:model"))

    testImplementation(libs.kotlin.test)
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}
