package io.github.miron404.apksigner

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.miron404.apksigner.core.Bc
import io.github.miron404.apksigner.core.DistinguishedName
import io.github.miron404.apksigner.core.KeyAlgorithm
import io.github.miron404.apksigner.core.KeyMaterial
import io.github.miron404.apksigner.core.NewIdentityRequest
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import kotlin.system.measureTimeMillis

/**
 * Guards the cost of creating an identity, which is the one operation a user waits on.
 *
 * These run on ART, so they catch the thing a JVM benchmark would hide: BouncyCastle does its
 * modular arithmetic in Java `BigInteger`, which is dramatically slower here than the platform's
 * native BoringSSL. The bounds are deliberately loose — an emulator on a shared runner is far
 * slower than a phone, and the point is to catch a return to the pathological path, not to track
 * small regressions.
 */
@RunWith(AndroidJUnit4::class)
class KeyGenerationTimingTest {

    private fun request(algorithm: KeyAlgorithm) = NewIdentityRequest(
        label = "timing",
        alias = "timing",
        dn = DistinguishedName(commonName = "timing"),
        validityYears = 30,
        algorithm = algorithm,
    )

    @Test
    fun platformProviderBacksKeyGeneration() {
        listOf("RSA", "EC").forEach { algorithm ->
            val provider = KeyPairGenerator.getInstance(algorithm).provider.name
            Log.i(TAG, "KeyPairGenerator.$algorithm resolves to $provider")
            assertTrue(
                "$algorithm key generation fell through to BouncyCastle",
                provider != "BC",
            )
        }
    }

    @Test
    fun rsaKeyGenerationIsNativeSpeed() {
        val platform = measureTimeMillis { KeyMaterial.generate(request(KeyAlgorithm.RSA_2048)) }

        val bouncyCastle = measureTimeMillis {
            KeyPairGenerator.getInstance("RSA", Bc.provider).apply { initialize(2048) }
                .generateKeyPair()
        }

        Log.i(TAG, "RSA 2048 key pair + certificate: platform ${platform}ms, BouncyCastle ${bouncyCastle}ms")
        assertTrue("RSA 2048 identity took ${platform}ms", platform < 30_000)
    }

    @Test
    fun internalKeystoreWriteIsCheap() {
        val material = KeyMaterial.generate(request(KeyAlgorithm.EC_P256))
        val password = KeyMaterial.randomKeystorePassword()

        val internal = measureTimeMillis {
            KeyMaterial.writePkcs12("t", material.keyPair.private, material.certificate, password)
        }
        val export = measureTimeMillis {
            KeyMaterial.writePkcs12(
                "t",
                material.keyPair.private,
                material.certificate,
                password,
                iterations = KeyMaterial.EXPORT_KDF_ITERATIONS,
            )
        }

        Log.i(TAG, "PKCS#12 write: internal ${internal}ms, export-strength ${export}ms")
        assertTrue("internal keystore write took ${internal}ms", internal < 2_000)
    }

    @Test
    fun ecIdentityIsEssentiallyInstant() {
        val elapsed = measureTimeMillis { KeyMaterial.generate(request(KeyAlgorithm.EC_P256)) }

        Log.i(TAG, "EC P-256 key pair + certificate: ${elapsed}ms")
        assertTrue("EC P-256 identity took ${elapsed}ms", elapsed < 10_000)
    }

    companion object {
        private const val TAG = "ApkSignerTiming"

        /**
         * Measures what a user waits for, not the one-off class loading that precedes it.
         *
         * First contact with BouncyCastle's PKCS#12 code costs seconds of loading and verification
         * on ART. The app absorbs that with [KeyMaterial.warmUp] when the create screen opens, so
         * these tests do the same; leaving it in would make every bound a measurement of the
         * runner's disk instead of the crypto.
         */
        @BeforeClass
        @JvmStatic
        fun installProviderAndWarmUp() {
            Bc.install()
            val cold = measureTimeMillis { KeyMaterial.warmUp() }
            Log.i(TAG, "BouncyCastle PKCS#12 warm-up: ${cold}ms")
        }
    }
}
