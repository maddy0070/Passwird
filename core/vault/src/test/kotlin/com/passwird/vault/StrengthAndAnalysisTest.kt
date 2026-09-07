package com.passwird.vault

import com.passwird.model.DeviceId
import com.passwird.model.ItemContent
import com.passwird.model.Secret
import com.passwird.model.VaultDocument
import com.passwird.model.VaultItem
import com.passwird.vault.analysis.VaultAnalyser
import com.passwird.vault.generator.PassphraseGenerator
import com.passwird.vault.generator.PassphrasePolicy
import com.passwird.vault.generator.PasswordGenerator
import com.passwird.vault.generator.PasswordPolicy
import com.passwird.vault.lock.AutoLockPolicy
import com.passwird.vault.lock.AutoLockSettings
import com.passwird.vault.lock.AutoLockTimeout
import com.passwird.vault.lock.LockReason
import com.passwird.vault.lock.LockState
import com.passwird.vault.lock.UnlockBackoff
import com.passwird.vault.strength.AttackRates
import com.passwird.vault.strength.CrackTimeFormatter
import com.passwird.vault.strength.StrengthEstimate
import com.passwird.vault.strength.StrengthEstimator
import com.passwird.vault.strength.Weakness
import java.time.Duration
import java.time.Instant
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StrengthEstimatorTest {

    private fun bits(password: String) = StrengthEstimator.estimate(password).entropyBits

    @Test
    fun `notorious passwords are recognised as near worthless`() {
        for (password in listOf("password", "123456", "qwerty", "letmein", "dragon", "p@ssw0rd")) {
            val estimate = StrengthEstimator.estimate(password)
            assertTrue(
                estimate.entropyBits < 25,
                "'$password' scored ${estimate.entropyBits} bits, which is far too generous",
            )
            assertTrue(estimate.weaknesses.isNotEmpty(), "'$password' produced no explanation")
        }
    }

    @Test
    fun `structure is detected and named so the user can act on it`() {
        val estimate = StrengthEstimator.estimate("dragon2019")
        val kinds = estimate.weaknesses.map { it.kind }

        // "dragon" is both a wordlist entry and a top-200 password. The estimator must
        // take the cheaper reading, so either naming is correct - what matters is that the
        // word is identified and reported rather than silently priced as random characters.
        assertTrue(
            Weakness.Kind.DICTIONARY_WORD in kinds || Weakness.Kind.COMMON_PASSWORD in kinds,
            "should identify the word component, got $kinds",
        )
        assertTrue(Weakness.Kind.YEAR in kinds, "should spot the year")
        assertTrue(estimate.entropyBits < 30)
    }

    @Test
    fun `sequences repeats and keyboard runs are all cheap`() {
        assertTrue(bits("abcdefgh") < 20, "an alphabet run should be cheap")
        assertTrue(bits("aaaaaaaa") < 20, "a repeat should be cheap")
        assertTrue(bits("qwertyui") < 25, "a keyboard run should be cheap")
        assertTrue(bits("12345678") < 20, "a digit run should be cheap")
    }

    @Test
    fun `an attacker takes the cheapest reading of a password`() {
        // Longer must never mean weaker, and padding a known word with structure must not
        // buy much: minimum-cost segmentation is what enforces both.
        assertTrue(bits("password") <= bits("passwordX"))
        assertTrue(bits("password123") < bits("kx7Qp2mVr9") , "structure should lose to randomness")
    }

    @Test
    fun `random passwords are rated strong`() {
        repeat(20) {
            val generated = PasswordGenerator.generate(PasswordPolicy(length = 16))
            val estimated = StrengthEstimator.estimate(generated.value.reveal())
            assertTrue(
                estimated.entropyBits > 70,
                "a random 16-character password estimated at only ${estimated.entropyBits} bits",
            )
        }
    }

    @Test
    fun `the estimator under-counts rather than over-counts generated passwords`() {
        // Deliberate asymmetry: overstating strength leaves a bad password in place, while
        // understating it costs one unnecessary rotation.
        repeat(20) {
            val generated = PasswordGenerator.generate(PasswordPolicy(length = 20))
            val estimated = StrengthEstimator.estimate(generated.value.reveal())
            assertTrue(
                estimated.entropyBits <= generated.entropyBits,
                "estimate ${estimated.entropyBits} exceeded the true ${generated.entropyBits}",
            )
        }
    }

    @Test
    fun `generated entropy is reported as exact and typed entropy as an estimate`() {
        assertTrue(StrengthEstimator.exact(128.0).isExact)
        assertFalse(StrengthEstimator.estimate("anything").isExact)
    }

    @Test
    fun `a generated passphrase is genuinely strong`() {
        val passphrase = PassphraseGenerator.generate(PassphrasePolicy.RECOMMENDED)
        assertTrue(passphrase.entropyBits > 64)
        // Even scored as ordinary text, five random words hold up.
        assertTrue(StrengthEstimator.estimate(passphrase.value.reveal()).entropyBits > 55)
    }

    @Test
    fun `crack time depends on the stated attacker model`() {
        val estimate = StrengthEstimate(60.0, isExact = true, weaknesses = emptyList())

        val fast = estimate.secondsToCrack(AttackRates.OFFLINE_FAST)
        val argon = estimate.secondsToCrack(AttackRates.OFFLINE_ARGON2ID)
        val online = estimate.secondsToCrack(AttackRates.ONLINE_THROTTLED)

        assertTrue(fast < argon, "a faster attacker must crack sooner")
        assertTrue(argon < online)
        // The same password is 'hours' or 'millennia' depending on the model, which is
        // exactly why the rate is always stated alongside the number.
        assertFalse(CrackTimeFormatter.describe(fast) == CrackTimeFormatter.describe(online))
    }

    @Test
    fun `crack times are described in human terms`() {
        assertEquals("instantly", CrackTimeFormatter.describe(0.4))
        assertTrue(CrackTimeFormatter.describe(120.0).contains("minutes"))
        assertTrue(CrackTimeFormatter.describe(1e12).contains("years"))
        assertEquals("longer than the age of the universe", CrackTimeFormatter.describe(1e30))
    }

    @Test
    fun `an empty password is zero bits and does not crash`() {
        assertEquals(0.0, bits(""))
    }
}

class VaultAnalyserTest {

    private val now: Instant = Instant.parse("2026-09-07T12:00:00Z")
    private val device = DeviceId("device-a")

    private fun login(title: String, password: String, passwordAge: Duration? = null) = VaultItem(
        id = UUID.randomUUID(),
        title = title,
        content = ItemContent.Login(
            username = "u",
            password = Secret.of(password),
            passwordUpdatedAt = passwordAge?.let { now.minus(it) },
        ),
        createdAt = now,
        updatedAt = now,
        originDeviceId = device,
    )

    private fun document(vararg items: VaultItem) =
        VaultDocument(vaultId = UUID.randomUUID(), items = items.toList())

    @Test
    fun `finds weak reused and ageing passwords separately`() {
        val findings = VaultAnalyser.analyse(
            document(
                login("Weak", "password"),
                login("ReusedA", "SharedButLongish!42"),
                login("ReusedB", "SharedButLongish!42"),
                login("Old", "Zt7#qLm2Vx9pRw4K", passwordAge = Duration.ofDays(900)),
                login("Fine", "Qw8!zRt5&nHy2LpX"),
            ),
            now,
        )

        assertEquals(listOf("Weak"), findings.weak.map { it.title })
        assertEquals(1, findings.reused.size)
        assertEquals(setOf("ReusedA", "ReusedB"), findings.reused.single().titles.toSet())
        assertEquals(listOf("Old"), findings.ageing.map { it.title })
        assertEquals(5, findings.totalChecked)
    }

    @Test
    fun `reports counts rather than a single score`() {
        // There is deliberately no overall score on this type: compressing unrelated risks
        // into one number produces something decorative rather than actionable.
        val findings = VaultAnalyser.analyse(document(login("Weak", "123456")), now)
        assertEquals(1, findings.actionableCount)
        assertTrue(findings.hasFindings)
    }

    @Test
    fun `a healthy vault produces a genuine all-clear`() {
        val findings = VaultAnalyser.analyse(
            document(login("A", "Qw8!zRt5&nHy2LpX"), login("B", "Mk3@vBn7*cFd1JgQ")),
            now,
        )
        assertFalse(findings.hasFindings)
        assertEquals(2, findings.totalChecked)
    }

    @Test
    fun `a single item is never reported as reused`() {
        val findings = VaultAnalyser.analyse(document(login("Only", "Qw8!zRt5&nHy2LpX")), now)
        assertTrue(findings.reused.isEmpty())
    }

    @Test
    fun `empty passwords are ignored rather than flagged as weak`() {
        val findings = VaultAnalyser.analyse(document(login("Blank", ""), login("Blank2", "")), now)
        assertTrue(findings.weak.isEmpty())
        assertTrue(findings.reused.isEmpty(), "blank passwords must not be grouped as reuse")
    }

    @Test
    fun `password age is tracked separately from record age`() {
        // Editing a note must not reset the rotation clock, so an item that has never
        // recorded a password change is excluded rather than assumed fresh or assumed old.
        val neverRecorded = login("NoTimestamp", "Qw8!zRt5&nHy2LpX", passwordAge = null)
        assertTrue(VaultAnalyser.analyse(document(neverRecorded), now).ageing.isEmpty())

        val recorded = login("Recorded", "Qw8!zRt5&nHy2LpX", passwordAge = Duration.ofDays(1000))
        assertEquals(1, VaultAnalyser.analyse(document(recorded), now).ageing.size)
    }

    @Test
    fun `deleted items are excluded from analysis`() {
        val deleted = login("Deleted", "password")
        val findings = VaultAnalyser.analyse(
            VaultDocument(
                vaultId = UUID.randomUUID(),
                items = listOf(deleted),
                tombstones = listOf(com.passwird.model.Tombstone(deleted.id, now, 2, device)),
            ),
            now,
        )
        assertTrue(findings.weak.isEmpty())
        assertEquals(0, findings.totalChecked)
    }
}

class AutoLockTest {

    private val start = 1_000_000L

    private fun policy(timeout: AutoLockTimeout, background: Boolean = true) =
        AutoLockPolicy(AutoLockSettings(timeout = timeout, lockOnBackground = background))

    @Test
    fun `locks after the configured period of inactivity`() {
        val autoLock = policy(AutoLockTimeout.FIVE_MINUTES)
        val unlocked = autoLock.onUnlocked(start)

        assertTrue(autoLock.evaluate(unlocked, start + 4 * 60_000) is LockState.Unlocked)

        val locked = autoLock.evaluate(unlocked, start + 5 * 60_000)
        assertTrue(locked is LockState.Locked)
        assertEquals(LockReason.INACTIVITY, locked.reason)
    }

    @Test
    fun `interaction postpones the timeout`() {
        val autoLock = policy(AutoLockTimeout.ONE_MINUTE)
        var state = autoLock.onUnlocked(start)
        state = autoLock.onInteraction(state, start + 50_000)
        assertTrue(autoLock.evaluate(state, start + 100_000) is LockState.Unlocked)
        assertTrue(autoLock.evaluate(state, start + 111_000) is LockState.Locked)
    }

    @Test
    fun `backgrounding locks immediately by default`() {
        val autoLock = policy(AutoLockTimeout.THIRTY_MINUTES)
        val locked = autoLock.onBackgrounded(autoLock.onUnlocked(start))
        assertTrue(locked is LockState.Locked)
        assertEquals(LockReason.BACKGROUNDED, locked.reason)
    }

    @Test
    fun `never still locks on backgrounding and device lock`() {
        // "Never" bounds exposure to the foreground session; it does not mean the vault
        // stays open indefinitely, and the UI says so.
        val autoLock = policy(AutoLockTimeout.NEVER)
        val unlocked = autoLock.onUnlocked(start)

        assertTrue(autoLock.evaluate(unlocked, start + 86_400_000) is LockState.Unlocked)
        assertTrue(autoLock.onBackgrounded(unlocked) is LockState.Locked)
        assertTrue(autoLock.onDeviceLocked(unlocked) is LockState.Locked)
    }

    @Test
    fun `immediately means immediately`() {
        val autoLock = policy(AutoLockTimeout.IMMEDIATELY)
        assertTrue(autoLock.evaluate(autoLock.onUnlocked(start), start) is LockState.Locked)
    }

    @Test
    fun `a locked vault stays locked`() {
        val autoLock = policy(AutoLockTimeout.FIVE_MINUTES)
        val locked = autoLock.onManualLock()
        assertEquals(locked, autoLock.onInteraction(locked, start))
        assertEquals(locked, autoLock.onBackgrounded(locked))
        assertEquals(locked, autoLock.evaluate(locked, start + 10_000_000))
    }

    @Test
    fun `reports the time remaining before locking`() {
        val autoLock = policy(AutoLockTimeout.ONE_MINUTE)
        val unlocked = autoLock.onUnlocked(start)
        assertEquals(60_000, autoLock.millisUntilLock(unlocked, start))
        assertEquals(20_000, autoLock.millisUntilLock(unlocked, start + 40_000))
        assertEquals(0, autoLock.millisUntilLock(unlocked, start + 120_000))
        assertEquals(null, policy(AutoLockTimeout.NEVER).millisUntilLock(unlocked, start))
    }
}

class UnlockBackoffTest {

    private val backoff = UnlockBackoff()

    @Test
    fun `the first few attempts are free`() {
        for (attempt in 0..4) assertEquals(0L, backoff.delaySecondsAfter(attempt))
    }

    @Test
    fun `delay grows exponentially and is capped`() {
        assertEquals(1L, backoff.delaySecondsAfter(5))
        assertEquals(2L, backoff.delaySecondsAfter(6))
        assertEquals(4L, backoff.delaySecondsAfter(7))
        assertEquals(8L, backoff.delaySecondsAfter(8))
        assertEquals(300L, backoff.delaySecondsAfter(50), "must cap at five minutes")
        assertEquals(300L, backoff.delaySecondsAfter(10_000), "must not overflow")
    }

    @Test
    fun `lockout expires as time passes`() {
        val now = 1_000_000L
        assertTrue(backoff.isLockedOut(failedAttempts = 8, lastFailureMillis = now, nowMillis = now + 1_000))
        assertFalse(backoff.isLockedOut(failedAttempts = 8, lastFailureMillis = now, nowMillis = now + 9_000))
        assertEquals(7L, backoff.remainingSeconds(8, now, now + 1_000))
    }

    @Test
    fun `backoff never destroys anything`() {
        // ADR-0008. There is deliberately no wipe path here at all: the API cannot express
        // one, so it cannot be reached by accident.
        val methods = UnlockBackoff::class.java.methods.map { it.name.lowercase() }
        assertTrue(
            methods.none { "wipe" in it || "erase" in it || "destroy" in it || "reset" in it },
            "the backoff API must not expose a destructive operation",
        )
    }
}
