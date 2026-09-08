plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.passwird"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.passwird"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug {
            // Debug builds are marked so a tester can never mistake one for a release, and
            // so DebugGuard can refuse to open a production vault path.
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }

    buildFeatures { compose = true }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    packaging {
        resources.excludes += setOf(
            "META-INF/DEPENDENCIES", "META-INF/LICENSE", "META-INF/LICENSE.txt",
            "META-INF/NOTICE", "META-INF/NOTICE.txt", "META-INF/*.kotlin_module",
        )
    }
}

dependencies {
    implementation(project(":core:crypto"))
    implementation(project(":core:model"))
    implementation(project(":core:vault"))
    implementation(project(":core:search"))
    implementation(project(":core:sync"))
    implementation(project(":platform:secure"))
    implementation(project(":data:drive"))
    implementation(project(":design:tokens"))
    implementation(project(":design:components"))

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)
    // MainActivity is a FragmentActivity because BiometricPrompt requires a fragment host -
    // a direct consequence of binding biometrics to a CryptoObject rather than a boolean.
    implementation(libs.androidx.fragment)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.compose.ui.tooling.preview)
    debugImplementation(libs.androidx.compose.ui.tooling)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.lifecycle.runtime)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines.core)

    // Deliberately absent: any analytics, crash-reporting or attribution SDK. See ADR-0005.
    // The complete list of network destinations is in docs/11-privacy-model.md §2, and a CI
    // check fails the build if a new one appears without that document being updated.

    testImplementation(libs.kotlin.test)
    testImplementation(libs.junit.jupiter)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
}
