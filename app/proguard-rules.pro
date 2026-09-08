# Passwird release rules.
#
# Two jobs: strip anything that could leak, and keep the reflection-reachable code that
# would otherwise fail at runtime rather than at build time.

# --- Strip logging from the release build ---------------------------------------
# The static scan already forbids logging in production sources. This is the second
# line of defence: if a Log call reaches main via a dependency or a future edit, R8
# removes it rather than shipping it.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int wtf(...);
}
-assumenosideeffects class java.io.PrintStream {
    public void println(...);
    public void print(...);
}

# --- Do not keep source file names or line numbers -------------------------------
# There is no crash reporter to symbolicate for (ADR-0005), so a stack trace with our
# file names is information an attacker gets for free and we gain nothing from.
-renamesourcefileattribute ""
-keepattributes !SourceFile,!LineNumberTable

# --- kotlinx.serialization -------------------------------------------------------
# Generated serialisers are reached reflectively by name.
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class kotlinx.serialization.json.** {
    *** Companion;
}
-keepclasseswithmembers class kotlinx.serialization.json.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class com.passwird.**$$serializer { *; }
-keepclassmembers class com.passwird.** {
    *** Companion;
    *** INSTANCE;
}

# --- BouncyCastle ----------------------------------------------------------------
# Argon2id and HKDF are looked up through the provider framework.
-keep class org.bouncycastle.crypto.** { *; }
-keep class org.bouncycastle.jcajce.provider.** { *; }
-dontwarn org.bouncycastle.**

# --- Google API client -----------------------------------------------------------
# The Drive model classes are populated reflectively from JSON.
-keep class com.google.api.client.util.** { *; }
-keep class com.google.api.services.drive.model.** { *; }
-keepclassmembers class * {
    @com.google.api.client.util.Key <fields>;
}
-dontwarn com.google.api.client.**
-dontwarn com.google.common.**
-dontwarn javax.naming.**
-dontwarn org.joda.time.**

# --- Compose ---------------------------------------------------------------------
-dontwarn androidx.compose.**

# --- Coroutines ------------------------------------------------------------------
-dontwarn kotlinx.coroutines.**
-keepclassmembers class kotlinx.coroutines.** { volatile <fields>; }
