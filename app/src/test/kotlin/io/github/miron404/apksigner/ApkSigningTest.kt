package io.github.miron404.apksigner

import io.github.miron404.apksigner.core.ApkSigningService
import io.github.miron404.apksigner.core.DistinguishedName
import io.github.miron404.apksigner.core.IdentityMeta
import io.github.miron404.apksigner.core.KeyAlgorithm
import io.github.miron404.apksigner.core.KeyMaterial
import io.github.miron404.apksigner.core.NewIdentityRequest
import io.github.miron404.apksigner.core.SignOptions
import io.github.miron404.apksigner.core.SignatureSchemes
import io.github.miron404.apksigner.core.UnlockedIdentity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.UUID

/**
 * Signs a real APK end to end.
 *
 * The fixture is this app's own debug build, so the test only runs after `assembleDebug` has
 * produced one; it is skipped otherwise rather than shipping a binary blob in the repository.
 */
class ApkSigningTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun `signs and verifies with the modern schemes`() {
        val output = signFixture(SignatureSchemes(v1 = false, v2 = true, v3 = true, v4 = false))
            ?: return

        val report = ApkSigningService.verify(output, null)

        assertTrue(report.errors.joinToString(" | "), report.verified)
        assertTrue(report.v2)
        assertTrue(report.v3)
        assertEquals(1, report.signers.size)
    }

    @Test
    fun `signs and verifies with the jar scheme as well`() {
        val output = signFixture(SignatureSchemes(v1 = true, v2 = true, v3 = true, v4 = false))
            ?: return

        // The fixture targets API 33, where the verifier ignores v1 entirely. Check from API 24 so
        // the JAR signature is actually exercised.
        val report = ApkSigningService.verify(output, null, minSdkOverride = 24)

        assertTrue(report.errors.joinToString(" | "), report.verified)
        assertTrue("v1 signature was not verified", report.v1)
        assertTrue(report.v2)
        assertTrue(report.v3)
    }

    @Test
    fun `reads package metadata out of the binary manifest`() {
        val source = findDebugApk()
        assumeTrue("No debug APK built yet", source != null)
        requireNotNull(source)

        val info = ApkSigningService.inspect(source)

        assertEquals("io.github.miron404.apksigner.debug", info.packageName)
        assertTrue(info.minSdkVersion >= 33)
    }

    @Test
    fun `signed output carries the identity certificate`() {
        val source = findDebugApk()
        assumeTrue("No debug APK built yet", source != null)
        requireNotNull(source)

        val input = temporaryFolder.newFile("in.apk").also { source.copyTo(it, overwrite = true) }
        val output = File(temporaryFolder.root, "out.apk")
        val unlocked = identity("mine")
        val expected = KeyMaterial.fingerprintSha256(
            KeyMaterial.readPkcs12(unlocked.pkcs12, unlocked.keystorePassword, "mine").chain.first()
        )

        unlocked.use {
            ApkSigningService.sign(
                identity = it,
                input = input,
                output = output,
                v4Output = null,
                options = SignOptions(schemes = SignatureSchemes(v1 = false, v2 = true, v3 = true, v4 = false)),
            )
        }

        assertEquals(expected, ApkSigningService.verify(output, null).signers.single().fingerprintSha256)
    }

    /** Signs the debug-build fixture, or returns null (test skipped) when there is not one. */
    private fun signFixture(schemes: SignatureSchemes): File? {
        val source = findDebugApk()
        assumeTrue("No debug APK built yet", source != null)
        requireNotNull(source)

        val input = temporaryFolder.newFile("in-${schemes.hashCode()}.apk")
            .also { source.copyTo(it, overwrite = true) }
        val output = File(temporaryFolder.root, "out-${schemes.hashCode()}.apk")
        identity("release").use { unlocked ->
            ApkSigningService.sign(
                identity = unlocked,
                input = input,
                output = output,
                v4Output = null,
                options = SignOptions(schemes = schemes),
            )
        }
        return output
    }

    private fun identity(alias: String): UnlockedIdentity {
        val material = KeyMaterial.generate(
            NewIdentityRequest(
                label = alias,
                alias = alias,
                dn = DistinguishedName(commonName = alias),
                validityYears = 30,
                algorithm = KeyAlgorithm.RSA_2048,
            )
        )
        val password = KeyMaterial.randomKeystorePassword()
        val pkcs12 = KeyMaterial.writePkcs12(alias, material.keyPair.private, material.certificate, password)
        val meta = IdentityMeta(
            id = UUID.randomUUID().toString(),
            label = alias,
            alias = alias,
            dn = DistinguishedName(commonName = alias).withDefaults(),
            algorithm = "RSA",
            keySize = 2048,
            signatureAlgorithm = KeyAlgorithm.RSA_2048.signatureAlgorithm,
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
        @BeforeClass
        @JvmStatic
        fun installProvider() {
            io.github.miron404.apksigner.core.Bc.install()
        }

        /** Unit tests run with the module directory as their working directory. */
        private fun findDebugApk(): File? =
            File("build/outputs/apk/debug")
                .listFiles { file -> file.extension == "apk" }
                ?.firstOrNull()
    }
}
