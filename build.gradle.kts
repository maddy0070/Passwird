plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.serialization) apply false
}

// Shared configuration for the pure-JVM core modules. Kept here rather than in a
// convention plugin so the whole build stays readable in one place — the module
// count is small and deliberately staying that way.
subprojects {
    plugins.withId("org.jetbrains.kotlin.jvm") {
        extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension>("kotlin") {
            jvmToolchain(21)
            compilerOptions {
                // Security-critical code: warnings are defects.
                allWarningsAsErrors.set(true)
                freeCompilerArgs.add("-Xjvm-default=all")
            }
        }

        tasks.withType<Test>().configureEach {
            useJUnitPlatform()
            testLogging {
                events("passed", "skipped", "failed")
                exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
            }
        }
    }
}
