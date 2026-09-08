plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.passwird.design.tokens"
    compileSdk = 35
    defaultConfig { minSdk = 26 }

    buildFeatures { compose = true }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    // `api(platform(...))`, not `implementation`: the Compose artifacts below are exposed
    // through `api` and are versionless, so consumers need the BOM on their compile
    // classpath too or those versions never resolve.
    api(platform(libs.androidx.compose.bom))
    api(libs.androidx.compose.foundation)
    api(libs.androidx.compose.ui)
    api(libs.androidx.compose.ui.graphics)
    // PasswirdTheme installs a minimal Material scheme so platform chrome (text selection
    // handles, the IME) picks up our palette. No Material component ships in default dress.
    api(libs.androidx.compose.material3)
    implementation(libs.androidx.core.ktx)

    testImplementation(libs.kotlin.test)
    testImplementation(libs.junit.jupiter)
}
