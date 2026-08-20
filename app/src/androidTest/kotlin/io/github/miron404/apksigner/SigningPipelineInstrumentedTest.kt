package io.github.miron404.apksigner

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.miron404.apksigner.core.ApkSigningService
import io.github.miron404.apksigner.core.Bc
import io.github.miron404.apksigner.core.DistinguishedName
import io.github.miron404.apksigner.core.IdentityMeta
import io.github.miron404.apksigner.core.KeyAlgorithm
import io.github.miron404.apksigner.core.KeyMaterial
import io.github.miron404.apksigner.core.NewIdentityRequest
import io.github.miron404.apksigner.core.SignOptions
import io.github.miron404.apksigner.core.SignatureSchemes
import io.github.miron404.apksigner.core.UnlockedIdentity
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID
import kotlin.system.measureTimeMillis

/**
 * Runs the whole signing pipeline on a device, using the app's own installed APK as the fixture.
 *
 * The JVM tests cover the same code but with the JDK's providers. Here the key comes from
 * Conscrypt, the PKCS#12 round trip goes through BouncyCastle, and the signature is produced on
 * ART — the exact combination a user's phone runs, and the one place a provider mismatch between
 * those three would show up.
 */
@RunWith(AndroidJUnit4::class)
class SigningPipelineInstrumentedTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var workDir: File

    @Before
    fun setUp() {
        workDir = File(context.cacheDir, "pipeline-test").apply { mkdirs() }
    }

    @After
    fun tearDown() {
        workDir.deleteRecursively()
    }

    @Test
    fun signsAndVerifiesTheInstalledApk() {
        val source = File(context.applicationInfo.sourceDir)
        assertTrue("Installed APK is not readable", source.canRead())

        val output = File(workDir, "signed.apk")
        val identity = identity(KeyAlgorithm.RSA_2048)

        val elapsed = measureTimeMillis {
            identity.use {
                ApkSigningService.sign(
                    identity = it,
                    input = source,
                    output = output,
                    v4Output = null,
                    options = SignOptions(
                        schemes = SignatureSchemes(v1 = false, v2 = true, v3 = true, v4 = false),
                    ),
                )
            }
        }
        Log.i(TAG, "signed ${source.length() / 1024}KB APK in ${elapsed}ms")

        val report = ApkSigningService.verify(output, null)
        assertTrue(report.errors.joinToString(" | "), report.verified)
        assertTrue(report.v3)
    }

    @Test
    fun conscryptKeysSurviveTheKeystoreRoundTrip() {
        // Generation is Conscrypt, storage is BouncyCastle: the two must agree on the encoding.
        listOf(KeyAlgorithm.RSA_2048, KeyAlgorithm.EC_P256).forEach { algorithm ->
            val material = KeyMaterial.generate(request(algorithm))
            val password = KeyMaterial.randomKeystorePassword()

            val encoded = KeyMaterial.writePkcs12(
                "roundtrip",
                material.keyPair.private,
                material.certificate,
                password,
            )
            val loaded = KeyMaterial.readPkcs12(encoded, password, "roundtrip")

            assertEquals(
                "$algorithm certificate changed across the keystore",
                material.certificate,
                loaded.chain.first(),
            )
        }
    }

    @Test
    fun inspectReadsTheInstalledApkManifest() {
        val info = ApkSigningService.inspect(File(context.applicationInfo.sourceDir))

        assertEquals(context.packageName, info.packageName)
        assertTrue(info.minSdkVersion >= 33)
    }

    private fun request(algorithm: KeyAlgorithm) = NewIdentityRequest(
        label = "pipeline",
        alias = "pipeline",
        dn = DistinguishedName(commonName = "pipeline"),
        validityYears = 30,
        algorithm = algorithm,
    )

    private fun identity(algorithm: KeyAlgorithm): UnlockedIdentity {
        val material = KeyMaterial.generate(request(algorithm))
        val password = KeyMaterial.randomKeystorePassword()
        val pkcs12 = KeyMaterial.writePkcs12(
            "pipeline",
            material.keyPair.private,
            material.certificate,
            password,
        )
        val meta = IdentityMeta(
            id = UUID.randomUUID().toString(),
            label = "pipeline",
            alias = "pipeline",
            dn = DistinguishedName(commonName = "pipeline").withDefaults(),
            algorithm = algorithm.jcaName,
            keySize = algorithm.keySize,
            signatureAlgorithm = algorithm.signatureAlgorithm,
            serialNumberHex = material.certificate.serialNumber.toString(16),
            createdAt = 0,
            notBefore = material.certificate.notBefore.time,
            notAfter = material.certificate.notAfter.time,
            certificatePem = KeyMaterial.toPem(material.certificate),
            fingerprintSha256 = KeyMaterial.fingerprintSha256(material.certificate),
        )
        return UnlockedIdentity(meta, password, pkcs12)
    }

    companion object {
        private const val TAG = "ApkSignerTiming"

        @BeforeClass
        @JvmStatic
        fun installProvider() {
            Bc.install()
        }
    }
}
