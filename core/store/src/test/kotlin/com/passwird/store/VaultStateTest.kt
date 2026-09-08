package com.passwird.store

import com.passwird.crypto.SlotType
import com.passwird.crypto.VaultCrypto
import com.passwird.sync.LocalSyncState
import com.passwird.sync.RemoteVaultState
import java.io.File
import java.io.IOException
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/**
 * The vault state machine.
 *
 * ### The defect this replaces
 *
 * The app routed its first screen on `repository.vault == null`. That means *not unlocked*.
 * It was read as *locked*, so a fresh installation — no vault, no passphrase ever chosen —
 * was shown "Your vault is locked" and a passphrase field, with no way forward.
 *
 * A boolean cannot distinguish the seven situations this product has to tell apart, and the
 * distinctions are not cosmetic: exactly one of them permits creating a vault, and creating
 * one in any of the others can overwrite a real vault.
 *
 * These tests cover the resolver directly, where every branch is reachable, and then the
 * repository against real crypto and a real filesystem.
 */
class VaultStateResolverTest {

    private val vaultBytes = "not-really-a-vault".toByteArray()

    // -------------------------------------------------------------- 1. FIRST_RUN

    @Test
    fun `nothing local and a remote that confirms it is empty is FIRST_RUN`() = runTest {
        val state = VaultStateResolver.resolve(
            unlocked = null,
            localVault = null,
            localEvidence = false,
            remote = RemoteVaultState.Empty,
        )
        assertIs<VaultState.FirstRun>(state)
        assertTrue(state.mayCreateVault)
    }

    @Test
    fun `FIRST_RUN is the only state that fully permits creating a vault`() = runTest {
        // The property that matters most. Every state is enumerated so a state added later
        // cannot quietly acquire permission to create a vault.
        val permitting = listOf<VaultState>(
            VaultState.FirstRun,
            VaultState.FirstRunRemoteUnchecked("offline"),
        )
        val refusing = listOf(
            VaultState.Locked,
            VaultState.Unlocked(Fixtures.document("Bank")),
            VaultState.RemoteVaultAvailable,
            VaultState.RecoveryRequired("x"),
            VaultState.Corrupted("x"),
            VaultState.VaultRecoveryAvailable(listOf(".tmp-1.pwv")),
        )

        assertTrue(permitting.all { it.mayCreateVault })
        assertTrue(
            refusing.none { it.mayCreateVault },
            "a state that is not a first run offered to create a vault",
        )
    }

    // ------------------------------------------------ 4. Drive unreachable is NOT first run

    @Test
    fun `no local vault and an unreachable remote is NOT FIRST_RUN`() = runTest {
        // The explicit requirement. An existing user reinstalling on a plane must not be one
        // tap from publishing an empty vault over their real one.
        val state = VaultStateResolver.resolve(
            unlocked = null,
            localVault = null,
            localEvidence = false,
            remote = RemoteVaultState.Unavailable("no network"),
        )

        assertFalse(state is VaultState.FirstRun, "an unreachable Drive was read as a first run")
        val unchecked = assertIs<VaultState.FirstRunRemoteUnchecked>(state)
        assertEquals("no network", unchecked.reason)
    }

    @Test
    fun `an unreachable remote on a device that has held a vault is RECOVERY_REQUIRED`() = runTest {
        val state = VaultStateResolver.resolve(
            unlocked = null,
            localVault = null,
            localEvidence = true,
            remote = RemoteVaultState.Unavailable("no network"),
        )
        assertIs<VaultState.RecoveryRequired>(state)
        assertFalse(state.mayCreateVault)
    }

    // ---------------------------------------------------------- 2, 3. LOCKED / UNLOCKED

    @Test
    fun `a readable local vault is LOCKED`() = runTest {
        val state = VaultStateResolver.resolve(
            unlocked = null,
            localVault = vaultBytes,
            localEvidence = true,
            remote = RemoteVaultState.Empty,
            parses = { true },
        )
        assertIs<VaultState.Locked>(state)
    }

    @Test
    fun `an open session is UNLOCKED and outranks everything the remote says`() = runTest {
        val document = Fixtures.document("Bank")
        val state = VaultStateResolver.resolve(
            unlocked = document,
            localVault = null,
            localEvidence = false,
            remote = RemoteVaultState.Empty,
        )
        val unlocked = assertIs<VaultState.Unlocked>(state)
        assertEquals(document, unlocked.document)
    }

    @Test
    fun `a local vault stays LOCKED even when the remote is unreachable`() = runTest {
        // An ordinary unlock must never depend on the network.
        val state = VaultStateResolver.resolve(
            unlocked = null,
            localVault = vaultBytes,
            localEvidence = true,
            remote = RemoteVaultState.Unavailable("no network"),
            parses = { true },
        )
        assertIs<VaultState.Locked>(state)
    }

    // --------------------------------------------------------- 5. REMOTE_VAULT_AVAILABLE

    @Test
    fun `no local vault but a live remote one is REMOTE_VAULT_AVAILABLE`() = runTest {
        val state = VaultStateResolver.resolve(
            unlocked = null,
            localVault = null,
            localEvidence = false,
            remote = RemoteVaultState.Present,
        )
        assertIs<VaultState.RemoteVaultAvailable>(state)
        assertFalse(state.mayCreateVault, "the restore path must not offer creation")
    }

    // --------------------------------------------------------------- 6. CORRUPTED

    @Test
    fun `a local vault file that is not a vault is CORRUPTED, never FIRST_RUN`() = runTest {
        val state = VaultStateResolver.resolve(
            unlocked = null,
            localVault = vaultBytes,
            localEvidence = true,
            remote = RemoteVaultState.Empty,
            parses = { false },
        )
        assertIs<VaultState.Corrupted>(state)
    }

    // ----------------------------------------------- 7. RECOVERY_AVAILABLE / REQUIRED

    @Test
    fun `an interrupted remote publish is VAULT_RECOVERY_AVAILABLE`() = runTest {
        val state = VaultStateResolver.resolve(
            unlocked = null,
            localVault = null,
            localEvidence = false,
            remote = RemoteVaultState.Interrupted(listOf("superseded-001.pwv")),
        )
        val recoverable = assertIs<VaultState.VaultRecoveryAvailable>(state)
        assertEquals(listOf("superseded-001.pwv"), recoverable.sources)
    }

    @Test
    fun `local history with an empty remote is RECOVERY_REQUIRED`() = runTest {
        // The device has held a vault and nothing corroborates it. Something was lost;
        // offering to create a new vault here would paper over it.
        val state = VaultStateResolver.resolve(
            unlocked = null,
            localVault = null,
            localEvidence = true,
            remote = RemoteVaultState.Empty,
        )
        assertIs<VaultState.RecoveryRequired>(state)
    }

    @Test
    fun `a transport failure never becomes Empty`() = runTest {
        val mapped = VaultStateResolver.remoteFailure(IOException("connection reset"))
        assertIs<RemoteVaultState.Unavailable>(mapped)
        assertEquals("connection reset", mapped.reason)
    }
}

/**
 * The same machine driven through the repository, against real crypto, a real filesystem and
 * a real sync engine — the JVM half of the vertical slice.
 */
class VaultRepositoryStateTest {

    private val root: File = Files.createTempDirectory("passwird-state").toFile()
    private val cipher = FakeDeviceCipher()
    private val transport = FakeTransport()
    private val storage = FileVaultStorage(root, cipher, transport)

    @AfterTest
    fun cleanUp() {
        root.deleteRecursively()
    }

    private fun repository() = VaultRepository(storage, Fixtures.DEVICE, clock = { Fixtures.NOW })

    // --------------------------------------------------------------- 1. fresh install

    @Test
    fun `a fresh installation is FIRST_RUN, not LOCKED`() = runTest {
        // The reported bug, at the level that caused it. Before the state machine existed,
        // this situation produced a lock screen asking for a passphrase that had never been
        // chosen.
        transport.state = RemoteVaultState.Empty

        val state = repository().currentState()

        assertIs<VaultState.FirstRun>(state)
        assertTrue(state.mayCreateVault)
    }

    // ------------------------------------------------------- 2, 8, 9. create then restart

    @Test
    fun `creating a vault leaves it UNLOCKED`() = runTest {
        val repo = repository()
        val recovery = VaultCrypto.generateRecoveryKey()

        val result = Fixtures.passphrase("a fresh master passphrase").use { pass ->
            repo.createVault(pass, recovery, kdf = Fixtures.fastKdf())
        }

        assertIs<CreateResult.Created>(result)
        assertIs<VaultState.Unlocked>(repo.currentState())
        assertTrue(repo.isUnlocked)
    }

    @Test
    fun `restarting after creating a vault is LOCKED, not FIRST_RUN`() = runTest {
        // Requirement 8. A second `repository()` models a process restart: same storage on
        // disk, no in-memory session.
        val recovery = VaultCrypto.generateRecoveryKey()
        Fixtures.passphrase("a fresh master passphrase").use { pass ->
            repository().createVault(pass, recovery, kdf = Fixtures.fastKdf())
        }

        val afterRestart = repository().currentState()

        assertIs<VaultState.Locked>(afterRestart)
        assertFalse(afterRestart.mayCreateVault, "a restart offered to create a second vault")
    }

    @Test
    fun `a successful unlock moves LOCKED to UNLOCKED`() = runTest {
        // Requirement 9.
        val recovery = VaultCrypto.generateRecoveryKey()
        val passphraseValue = "a fresh master passphrase"
        Fixtures.passphrase(passphraseValue).use { pass ->
            repository().createVault(pass, recovery, kdf = Fixtures.fastKdf())
        }

        val fresh = repository()
        assertIs<VaultState.Locked>(fresh.currentState())

        val result = Fixtures.passphrase(passphraseValue).use { pass ->
            fresh.unlock(pass, SlotType.PASSPHRASE)
        }

        assertIs<UnlockResult.Success>(result)
        assertIs<VaultState.Unlocked>(fresh.currentState())
    }

    @Test
    fun `the recovery key generated at creation opens the vault`() = runTest {
        // Recovery is designed in, not bolted on: a vault created without a working recovery
        // slot would be unrecoverable the moment the passphrase is forgotten.
        val recovery = VaultCrypto.generateRecoveryKey()
        val recoveryCopy = com.passwird.crypto.SecretBytes.copyOf(recovery.copyBytes())

        Fixtures.passphrase("a fresh master passphrase").use { pass ->
            repository().createVault(pass, recovery, kdf = Fixtures.fastKdf())
        }

        val result = repository().unlock(recoveryCopy, SlotType.RECOVERY)
        assertIs<UnlockResult.Success>(result)
    }

    @Test
    fun `creating a vault twice is refused`() = runTest {
        // The backstop behind the state machine, not a substitute for it.
        val first = Fixtures.passphrase("first").use { pass ->
            repository().createVault(pass, VaultCrypto.generateRecoveryKey(), kdf = Fixtures.fastKdf())
        }
        assertIs<CreateResult.Created>(first)

        val second = Fixtures.passphrase("second").use { pass ->
            repository().createVault(pass, VaultCrypto.generateRecoveryKey(), kdf = Fixtures.fastKdf())
        }
        assertIs<CreateResult.VaultAlreadyExists>(second)
    }

    // ------------------------------------------------------------ 4. Drive unreachable

    @Test
    fun `an unreachable Drive with no local vault is never FIRST_RUN`() = runTest {
        transport.failProbe = true

        val state = repository().currentState()

        assertFalse(state is VaultState.FirstRun)
        assertIs<VaultState.FirstRunRemoteUnchecked>(state)
    }

    // ------------------------------------------------------------------ 5. restore

    @Test
    fun `a remote vault with no local one is the RESTORE path`() = runTest {
        transport.state = RemoteVaultState.Present

        assertIs<VaultState.RemoteVaultAvailable>(repository().currentState())
    }

    // ---------------------------------------------------------------- 6. corrupted

    @Test
    fun `a damaged local vault file is CORRUPTED`() = runTest {
        storage.writeVault(Fixtures.sealedVault().first)
        // Overwrite the container's magic so it is no longer parseable as a vault, without
        // going through writeVault - which validates the framing.
        val file = File(root, "vault.pwv")
        val bytes = file.readBytes()
        for (i in 0 until 8) bytes[i] = 0
        file.writeBytes(bytes)

        assertIs<VaultState.Corrupted>(repository().currentState())
    }

    // ------------------------------------------------------- 7. recovery available

    @Test
    fun `an interrupted remote publish routes to recovery, not onboarding`() = runTest {
        transport.state = RemoteVaultState.Interrupted(listOf("superseded-001.pwv"))

        val state = repository().currentState()

        assertIs<VaultState.VaultRecoveryAvailable>(state)
        assertFalse(state.mayCreateVault)
    }

    @Test
    fun `local sync history with an empty remote is RECOVERY_REQUIRED`() = runTest {
        storage.syncStateStore().save(LocalSyncState(highestSeenVersion = 7))
        transport.state = RemoteVaultState.Empty

        assertIs<VaultState.RecoveryRequired>(repository().currentState())
    }

    // ------------------------------------------------- 10. signing out keeps the vault

    @Test
    fun `losing the Google account does not destroy the local vault`() = runTest {
        // Requirement 10. The vault is the user's, not the session's. Signing out is modelled
        // as the transport losing all access - which is exactly what a revoked token looks
        // like to everything above it.
        val recovery = VaultCrypto.generateRecoveryKey()
        val passphraseValue = "a fresh master passphrase"
        Fixtures.passphrase(passphraseValue).use { pass ->
            repository().createVault(pass, recovery, kdf = Fixtures.fastKdf())
        }

        // "Sign out": no account, so every remote call fails.
        transport.failProbe = true
        transport.failNextUpload = true

        val afterSignOut = repository()
        assertIs<VaultState.Locked>(
            afterSignOut.currentState(),
            "signing out of Google changed the vault's state",
        )

        val result = Fixtures.passphrase(passphraseValue).use { pass ->
            afterSignOut.unlock(pass, SlotType.PASSPHRASE)
        }
        assertIs<UnlockResult.Success>(result)
        assertNotNull(afterSignOut.vault.value, "the vault could not be opened without Google")
    }
}

/**
 * The biometric unlock path, exercised without a device.
 *
 * The Keystore is the only part that cannot run here, so it is the only part faked: the
 * "wrap" is an in-memory AEAD rather than a hardware-gated key. Everything else — the device
 * slot, the VEK it wraps, the container it opens — is real.
 *
 * What this cannot prove is the part that matters most on a device: that the hardware refuses
 * to release the key until it has observed a biometric. That is `CryptoObject` behaviour and
 * it is Android-runtime-unverified by definition.
 */
class DeviceSlotEnrolmentTest {

    private val root: File = Files.createTempDirectory("passwird-enrol").toFile()
    private val cipher = FakeDeviceCipher()
    private val transport = FakeTransport()
    private val storage = FileVaultStorage(root, cipher, transport)

    /** Stands in for `BiometricUnlock.enrol`: wraps the device key, hands back a blob. */
    private val keystore = FakeDeviceCipher()

    @AfterTest
    fun cleanUp() {
        root.deleteRecursively()
    }

    private fun repository() = VaultRepository(storage, Fixtures.DEVICE, clock = { Fixtures.NOW })

    private suspend fun createdVault(): Pair<VaultRepository, String> {
        val value = "a fresh master passphrase"
        val repo = repository()
        val result = Fixtures.passphrase(value).use { pass ->
            repo.createVault(pass, VaultCrypto.generateRecoveryKey(), kdf = Fixtures.fastKdf())
        }
        assertIs<CreateResult.Created>(result)
        return repo to value
    }

    @Test
    fun `enrolling requires an unlocked vault`() = runTest {
        // The security property: biometrics can only be added by someone who has already
        // proven the passphrase. A locked vault has no VEK to build a slot from.
        val result = repository().enrolDeviceSlot("Test device") { keystore.seal(it.copyBytes()) }
        assertIs<EnrolResult.VaultLocked>(result)
        assertFalse(storage.readDeviceSlot() != null, "a locked vault produced an enrolment")
    }

    @Test
    fun `an enrolled device unlocks with the device key alone`() = runTest {
        val (repo, _) = createdVault()

        val enrolled = repo.enrolDeviceSlot("Pixel") { keystore.seal(it.copyBytes()) }
        assertIs<EnrolResult.Enrolled>(enrolled)
        assertTrue(repo.hasDeviceSlot())

        repo.lock()

        // What the platform does after a successful biometric: unwrap, then hand the key over.
        val wrapped = assertNotNull(repo.wrappedDeviceKey())
        val deviceKey = com.passwird.crypto.SecretBytes.adopt(keystore.open(wrapped))

        val fresh = repository()
        val result = fresh.unlockWithDeviceKey(deviceKey)

        assertIs<UnlockResult.Success>(result)
        assertIs<VaultState.Unlocked>(fresh.currentState())
    }

    @Test
    fun `a wrong device key is refused`() = runTest {
        val (repo, _) = createdVault()
        repo.enrolDeviceSlot("Pixel") { keystore.seal(it.copyBytes()) }
        repo.lock()

        val wrong = com.passwird.crypto.SecretBytes.random(32)
        val result = repository().unlockWithDeviceKey(wrong)

        assertFalse(result is UnlockResult.Success, "an arbitrary key opened the vault")
    }

    @Test
    fun `the device slot never reaches the vault file`() = runTest {
        // VaultHeader refuses to serialise a device slot at all; this asserts the whole path
        // honours that, because a device slot in a synced file is a weaker unlock path an
        // attacker could probe for.
        val (repo, _) = createdVault()
        repo.enrolDeviceSlot("Pixel") { keystore.seal(it.copyBytes()) }

        val vaultBytes = assertNotNull(storage.readVault())
        val header = com.passwird.crypto.VaultContainer.parse(vaultBytes).header

        assertTrue(
            header.slots.none { it.type == SlotType.DEVICE },
            "a device slot was written into the vault file",
        )
        assertTrue(header.slots.all { it.isSyncable })
    }

    @Test
    fun `an enrolment is stored sealed, not in the clear`() = runTest {
        val (repo, _) = createdVault()
        repo.enrolDeviceSlot("Pixel") { keystore.seal(it.copyBytes()) }

        val onDisk = File(root, "device-slot.bin").readBytes()

        // The slot's JSON shape would be obvious if it were stored unsealed.
        for (marker in listOf("commitment", "wrapNonce", "device", "Pixel")) {
            assertFalse(
                onDisk.toString(Charsets.ISO_8859_1).contains(marker),
                "'$marker' is readable in device-slot.bin",
            )
        }
    }

    @Test
    fun `clearing the enrolment leaves the vault openable by passphrase`() = runTest {
        // Turning off biometrics must never be a way to lose a vault.
        val (repo, passphrase) = createdVault()
        repo.enrolDeviceSlot("Pixel") { keystore.seal(it.copyBytes()) }
        repo.clearDeviceSlot()
        repo.lock()

        assertFalse(repo.hasDeviceSlot())

        val fresh = repository()
        assertIs<VaultState.Locked>(fresh.currentState())
        val result = Fixtures.passphrase(passphrase).use { fresh.unlock(it, SlotType.PASSPHRASE) }
        assertIs<UnlockResult.Success>(result)
    }

    @Test
    fun `a device slot alone is evidence of a vault`() = runTest {
        // Part of the FIRST_RUN defence: a device that has enrolled biometrics is not new,
        // whatever else is missing.
        val (repo, _) = createdVault()
        repo.enrolDeviceSlot("Pixel") { keystore.seal(it.copyBytes()) }
        assertTrue(storage.hasEvidenceOfVault())
    }
}
