package io.github.miron404.apksigner

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.miron404.apksigner.core.AuthPolicy
import io.github.miron404.apksigner.core.MasterKey
import io.github.miron404.apksigner.core.SystemAuthenticator
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Exercises the real AndroidKeyStore.
 *
 * The unit tests substitute a software key store, so nothing else checks that the
 * [android.security.keystore.KeyGenParameterSpec] this app builds is one Keymaster will actually
 * accept — and a rejected spec would make the app unusable on a device. These tests only create and
 * describe keys: using one requires a genuine authentication event, which an emulator cannot stage.
 */
@RunWith(AndroidJUnit4::class)
class MasterKeyInstrumentedTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val masterKey = MasterKey(SystemAuthenticator())
    private val created = mutableListOf<String>()

    @Before
    fun requireSecureLockScreen() {
        assumeTrue(
            "Device has no secure lock screen",
            SystemAuthenticator.canAuthenticate(context, allowDeviceCredential = true),
        )
    }

    @After
    fun cleanUp() {
        created.forEach(masterKey::delete)
    }

    private fun newKey(policy: AuthPolicy): String =
        masterKey.newAlias().also {
            created += it
            masterKey.create(it, policy)
        }

    @Test
    fun timedPolicyIsStoredOnTheKeyItself() {
        val alias = newKey(AuthPolicy(timeoutSeconds = 300, allowDeviceCredential = true))

        val state = masterKey.state(alias)

        assertTrue(state.exists)
        assertEquals(300, state.policy.timeoutSeconds)
        assertTrue(state.policy.allowDeviceCredential)
    }

    @Test
    fun perOperationPolicyIsAcceptedByKeymaster() {
        val alias = newKey(AuthPolicy(timeoutSeconds = 0, allowDeviceCredential = true))

        val state = masterKey.state(alias)

        assertEquals(0, state.policy.timeoutSeconds)
        assertTrue(state.policy.perOperation)
    }

    @Test
    fun everyOfferedTimeoutIsAValidSpec() {
        AuthPolicy.TIMEOUT_CHOICES.forEach { seconds ->
            val alias = newKey(AuthPolicy(timeoutSeconds = seconds, allowDeviceCredential = true))

            assertEquals(
                "timeout $seconds was not stored on the key",
                seconds,
                masterKey.state(alias).policy.timeoutSeconds,
            )
        }
    }

    @Test
    fun biometricOnlyPolicyExcludesTheDeviceCredential() {
        assumeTrue(
            "No enrolled biometric",
            SystemAuthenticator.canAuthenticate(context, allowDeviceCredential = false),
        )

        val alias = newKey(AuthPolicy(timeoutSeconds = 60, allowDeviceCredential = false))

        assertFalse(masterKey.state(alias).policy.allowDeviceCredential)
    }

    @Test
    fun creationFallsBackWhenThereIsNoSecureElement() {
        val alias = masterKey.newAlias().also { created += it }

        val strongBox = masterKey.create(alias, AuthPolicy.DEFAULT)

        // Whichever branch the device takes, the key must exist and report itself consistently.
        assertTrue(masterKey.exists(alias))
        assertEquals(strongBox, masterKey.state(alias).strongBoxBacked)
    }

    @Test
    fun orphanedAliasesAreCleanedUpButTheCurrentOneSurvives() {
        val keep = newKey(AuthPolicy.DEFAULT)
        val orphan = newKey(AuthPolicy.DEFAULT)

        masterKey.deleteOrphans(setOf(keep))

        assertTrue(masterKey.exists(keep))
        assertFalse(masterKey.exists(orphan))
    }

    @Test
    fun deletingIsIdempotent() {
        val alias = newKey(AuthPolicy.DEFAULT)

        masterKey.delete(alias)
        masterKey.delete(alias)

        assertFalse(masterKey.exists(alias))
    }
}
