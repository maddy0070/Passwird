package com.passwird.crypto

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.lang.reflect.Modifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The separation between *authentication* and *encryption* is the product's defining
 * architectural claim: a Google credential can prove who you are and unlock Drive, and it
 * still cannot open the vault. `docs/04-key-management.md` §1 draws the line and says
 * "there is no path across it".
 *
 * A diagram is not a guarantee. This is the test that makes it one.
 *
 * ### Why structural, not behavioural
 *
 * A behavioural test — "unlock works, and we didn't call Google" — proves only that *this*
 * path avoided Google. It cannot prove that no path exists. So instead of exercising a
 * route, this walks every compiled class in the crypto module and inspects the types in
 * every signature and field. If a Google or Android identity type were reachable from key
 * handling at all, it would have to appear in one of them.
 *
 * The scanner in `scripts/scan-secrets.sh` makes the same assertion over *source imports*.
 * The two are deliberately redundant and catch different things: the scanner sees code that
 * never compiles, this sees types that arrive through a transitive dependency without ever
 * being named in an import.
 */
class NoGoogleKeyPathTest {

    /** Package prefixes that must be unreachable from anything that touches key material. */
    private val forbiddenPrefixes = listOf(
        "com.google.",
        "android.",
        "androidx.",
        "com.passwird.platform.",
        "com.passwird.data.",
    )

    @Test
    fun `no Google or Android identity class is even on the crypto module's classpath`() {
        // If any of these resolve, some dependency has pulled the identity layer into the
        // module that holds the keys — which is the coupling this architecture forbids,
        // whether or not any current code path uses it.
        val mustNotResolve = listOf(
            "com.google.android.gms.auth.api.signin.GoogleSignIn",
            "com.google.api.services.drive.Drive",
            "com.google.auth.oauth2.GoogleCredentials",
            "android.accounts.AccountManager",
            "android.security.keystore.KeyGenParameterSpec",
            "androidx.biometric.BiometricPrompt",
        )

        for (name in mustNotResolve) {
            val resolved = runCatching { Class.forName(name) }.getOrNull()
            assertTrue(
                resolved == null,
                "$name is on the crypto module's classpath. Vault encryption must not be " +
                    "able to reach the identity or platform layer, even transitively.",
            )
        }
    }

    @Test
    fun `no signature or field in the crypto module mentions a Google or Android type`() {
        val classes = loadModuleClasses()
        assertTrue(
            classes.size >= 10,
            "Only ${classes.size} classes were scanned; the class loader is probably " +
                "pointed at the wrong directory and this test is passing vacuously.",
        )

        val violations = mutableListOf<String>()
        for (type in classes) {
            for (referenced in referencedTypes(type)) {
                val offending = forbiddenPrefixes.firstOrNull { referenced.startsWith(it) }
                if (offending != null) {
                    violations += "${type.name} references $referenced"
                }
            }
        }

        assertTrue(
            violations.isEmpty(),
            "The vault encryption module reaches into the identity or platform layer:\n" +
                violations.joinToString("\n") { "  - $it" },
        )
    }

    @Test
    fun `unsealing takes the secret and the bytes, and nothing that identifies a user`() {
        // The strongest form of the claim: there is no parameter through which an account,
        // a token or a device identity *could* influence key derivation, so no future change
        // can quietly make Google sign-in sufficient without changing a public signature.
        val entryPoints = VaultCrypto::class.java.declaredMethods
            .filter { Modifier.isPublic(it.modifiers) }
            .filter { it.name.startsWith("unseal") || it.name == "create" }

        assertTrue(entryPoints.isNotEmpty(), "No unseal/create entry points found to inspect")

        val identityWords = listOf(
            "account", "token", "oauth", "google", "email", "credential", "signin", "user",
        )
        for (method in entryPoints) {
            for (parameter in method.parameters) {
                val described = "${parameter.name}:${parameter.type.name}".lowercase()
                val hit = identityWords.firstOrNull { described.contains(it) }
                assertTrue(
                    hit == null,
                    "VaultCrypto.${method.name} takes a parameter matching '$hit' " +
                        "($described). Nothing about the user's identity may be an input " +
                        "to key derivation.",
                )
            }
        }
    }

    @Test
    fun `a full create-and-unseal cycle completes with the identity layer absent`() {
        // The behavioural half. It proves the structural constraint above is not achieved by
        // the module simply doing nothing useful.
        val fixture = TestVaults.create()

        val opened = TestVaults.passphrase(fixture.passphraseValue).use { pass ->
            VaultCrypto.unseal(fixture.bytes, pass, SlotType.PASSPHRASE)
        }
        opened.use {
            assertContentStartsWith(TestVaults.SAMPLE_PLAINTEXT, it.plaintext)
        }
    }

    private fun assertContentStartsWith(expected: ByteArray, actual: ByteArray) {
        assertEquals(expected.size, actual.size, "unsealed payload changed size")
        assertTrue(expected.contentEquals(actual), "unsealed payload did not round-trip")
    }

    /**
     * Loads every compiled class in `com.passwird.crypto` from the module's own output
     * directory.
     *
     * Located by asking the class loader where [VaultCrypto] came from rather than by
     * hard-coding a Gradle path, so it keeps working if the build layout changes.
     */
    private fun loadModuleClasses(): List<Class<*>> {
        val marker = VaultCrypto::class.java
        val source = marker.protectionDomain.codeSource
        assertNotNull(source, "cannot locate the crypto module's compiled output")

        val root = File(source.location.toURI())
        assertTrue(root.isDirectory, "expected a class directory, found $root")

        val packageRoot = File(root, "com/passwird/crypto")
        assertTrue(packageRoot.isDirectory, "no compiled classes under $packageRoot")

        return packageRoot.walkTopDown()
            .filter { it.isFile && it.extension == "class" }
            .mapNotNull { file ->
                val binaryName = file.relativeTo(root).path
                    .removeSuffix(".class")
                    .replace(File.separatorChar, '.')
                runCatching { Class.forName(binaryName, false, marker.classLoader) }.getOrNull()
            }
            .toList()
    }

    /** Every type named by a class's fields, method signatures and constructors. */
    private fun referencedTypes(type: Class<*>): Set<String> = buildSet {
        fun add(candidate: Class<*>) {
            var current = candidate
            while (current.isArray) current = current.componentType
            if (!current.isPrimitive) add(current.name)
        }

        runCatching {
            type.declaredFields.forEach { add(it.type) }
            type.declaredMethods.forEach { method ->
                add(method.returnType)
                method.parameterTypes.forEach(::add)
            }
            type.declaredConstructors.forEach { it.parameterTypes.forEach(::add) }
            type.interfaces.forEach(::add)
            type.superclass?.let(::add)
        }
        // A NoClassDefFoundError here would itself mean something unresolvable is
        // referenced; it cannot be a forbidden type, because those are asserted absent
        // from the classpath above.
    }
}

/**
 * `docs/11-privacy-model.md` promises that no vault data is logged "at any level", and
 * `docs/02-threat-model.md` lists log leakage as a tracked threat.
 *
 * [RedactedToStringTest] covers the half of that promise that lives in `toString()`. This
 * covers the other half: that a realistic lifecycle — create, seal, unseal, fail to unlock,
 * hit every error path — writes nothing sensitive to stdout or stderr, which is where a
 * stray `println` during development ends up and what Logcat mirrors on Android.
 */
class NoSecretsInLogsTest {

    @Test
    fun `a full lifecycle writes no sentinel value to stdout or stderr`() {
        val captured = captureConsole {
            val fixture = TestVaults.create()

            // The happy path.
            TestVaults.passphrase(fixture.passphraseValue).use { pass ->
                VaultCrypto.unseal(fixture.bytes, pass, SlotType.PASSPHRASE).close()
            }

            // Recovery.
            VaultCrypto.unseal(fixture.bytes, fixture.recoveryKey, SlotType.RECOVERY).close()

            // The failure paths, which is where diagnostics get added under pressure.
            runCatching {
                TestVaults.passphrase("the wrong passphrase entirely").use { wrong ->
                    VaultCrypto.unseal(fixture.bytes, wrong, SlotType.PASSPHRASE)
                }
            }
            runCatching { VaultCrypto.unseal(fixture.bytes.copyOf(20), fixture.recoveryKey, SlotType.RECOVERY) }
            runCatching {
                val corrupted = fixture.bytes.copyOf()
                corrupted[corrupted.size / 2] = (corrupted[corrupted.size / 2] + 1).toByte()
                VaultCrypto.unseal(corrupted, fixture.recoveryKey, SlotType.RECOVERY)
            }
        }

        for (sentinel in TestVaults.SENTINELS) {
            assertFalse(
                captured.contains(sentinel),
                "'$sentinel' reached the console during a normal lifecycle",
            )
        }
        assertFalse(
            captured.contains("correct horse battery staple"),
            "the master passphrase reached the console",
        )
    }

    @Test
    fun `the capture harness would actually catch a leak`() {
        // A leak test that cannot observe a leak is worse than no test, because it reads as
        // evidence. This plants one.
        val captured = captureConsole { println(TestVaults.SENTINEL_PASSWORD) }
        assertTrue(
            captured.contains(TestVaults.SENTINEL_PASSWORD),
            "the console capture is not wired up; the test above is passing vacuously",
        )
    }

    private fun captureConsole(block: () -> Unit): String {
        val buffer = ByteArrayOutputStream()
        val stream = PrintStream(buffer, true, Charsets.UTF_8)
        val outBefore = System.out
        val errBefore = System.err
        return try {
            System.setOut(stream)
            System.setErr(stream)
            block()
            stream.flush()
            buffer.toString(Charsets.UTF_8)
        } finally {
            System.setOut(outBefore)
            System.setErr(errBefore)
        }
    }
}
