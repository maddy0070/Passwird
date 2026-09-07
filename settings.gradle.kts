pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "passwird"

// ---------------------------------------------------------------------------
// Pure Kotlin/JVM modules.
//
// These hold the entire security core, the domain model and the sync engine.
// They deliberately carry no Android and no Google dependency, which makes the
// most security-critical code in the product buildable and testable anywhere,
// including in CI with no emulator. See docs/12-testing-strategy.md §2.
// ---------------------------------------------------------------------------
include(":core:crypto")
include(":core:model")
include(":core:vault")
include(":core:search")
include(":core:sync")

// ---------------------------------------------------------------------------
// Android modules.
//
// Included only when an Android SDK is actually available. Without this guard
// Gradle fails at configuration time on a machine (or CI container) that has a
// JDK but no SDK, which would take the JVM core down with it. Guarding here
// keeps `./gradlew test` green everywhere while a full checkout on a developer
// machine still builds the complete app.
// ---------------------------------------------------------------------------
val androidSdkAvailable: Boolean = run {
    val fromEnv = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")
    val fromProps = file("local.properties")
        .takeIf { it.exists() }
        ?.let { java.util.Properties().apply { it.inputStream().use(::load) }.getProperty("sdk.dir") }
    val dir = fromProps ?: fromEnv
    !dir.isNullOrBlank() && file(dir).isDirectory
}

gradle.extra["androidSdkAvailable"] = androidSdkAvailable

if (androidSdkAvailable) {
    include(":platform:secure")
    include(":data:drive")
    include(":design:tokens")
    include(":design:components")
    include(":app")
} else {
    logger.lifecycle(
        """
        |
        |  Android SDK not found — configuring JVM modules only.
        |  Building: core:crypto, core:model, core:vault, core:search, core:sync
        |  Skipping: app, platform:secure, data:drive, design:*
        |
        |  Set ANDROID_HOME or sdk.dir in local.properties for the full build.
        |
        """.trimMargin()
    )
}
