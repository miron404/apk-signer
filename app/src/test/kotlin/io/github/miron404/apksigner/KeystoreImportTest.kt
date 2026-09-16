package io.github.miron404.apksigner

import io.github.miron404.apksigner.core.Bc
import io.github.miron404.apksigner.core.DistinguishedName
import io.github.miron404.apksigner.core.KeyAlgorithm
import io.github.miron404.apksigner.core.KeyMaterial
import io.github.miron404.apksigner.core.KeystoreFormat
import io.github.miron404.apksigner.core.KeystoreReadException
import io.github.miron404.apksigner.core.NewIdentityRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate

/**
 * Exercises the keystore reader against files written by the JDK's own implementations.
 *
 * That matters most for JKS: neither Android nor BouncyCastle can read it, so this app parses the
 * format itself. Writing the fixture with `KeyStore.getInstance("JKS")` and reading it back with
 * the hand-written parser is the closest thing to a conformance test available without shipping
 * binary fixtures.
 */
class KeystoreImportTest {

    @Test
    fun `reads a JKS written by the JDK`() {
        val identity = generate(KeyAlgorithm.RSA_2048, "release")
        val password = "storepass".toCharArray()
        val jks = writeJks(identity, "release", password, password)

        val entries = KeyMaterial.readKeystoreEntries(jks, password)

        assertEquals(1, entries.size)
        assertEquals("release", entries.single().alias)
        assertEquals(identity.certificate, entries.single().certificate)
        assertSigns(entries.single().privateKey, identity.certificate, "SHA256withRSA")
    }

    @Test
    fun `reads an elliptic curve key out of a JKS`() {
        val identity = generate(KeyAlgorithm.EC_P256, "ec")
        val password = "storepass".toCharArray()

        val entries = KeyMaterial.readKeystoreEntries(
            writeJks(identity, "ec", password, password),
            password,
        )

        assertEquals(identity.certificate, entries.single().certificate)
        assertSigns(entries.single().privateKey, identity.certificate, "SHA256withECDSA")
    }

    @Test
    fun `honours a key password that differs from the store password`() {
        val identity = generate(KeyAlgorithm.RSA_2048, "split")
        val storePassword = "store-secret".toCharArray()
        val keyPassword = "key-secret".toCharArray()
        val jks = writeJks(identity, "split", storePassword, keyPassword)

        val entries = KeyMaterial.readKeystoreEntries(jks, storePassword, keyPassword)

        assertEquals(identity.certificate, entries.single().certificate)
    }

    @Test
    fun `rejects the wrong store password before touching any key`() {
        val identity = generate(KeyAlgorithm.EC_P256, "a")
        val jks = writeJks(identity, "a", "right".toCharArray(), "right".toCharArray())

        val failure = assertThrows(KeystoreReadException::class.java) {
            KeyMaterial.readKeystoreEntries(jks, "wrong".toCharArray())
        }
        assertTrue(failure.message!!.contains("keystore password"))
    }

    @Test
    fun `rejects the wrong key password`() {
        val identity = generate(KeyAlgorithm.EC_P256, "a")
        val jks = writeJks(identity, "a", "store".toCharArray(), "key".toCharArray())

        val failure = assertThrows(KeystoreReadException::class.java) {
            KeyMaterial.readKeystoreEntries(jks, "store".toCharArray(), "wrong".toCharArray())
        }
        assertTrue(failure.message!!.contains("key password"))
    }

    @Test
    fun `reads every signing key and ignores trusted certificates`() {
        val first = generate(KeyAlgorithm.EC_P256, "one")
        val second = generate(KeyAlgorithm.EC_P256, "two")
        val bystander = generate(KeyAlgorithm.EC_P256, "three")
        val password = "storepass".toCharArray()

        val store = KeyStore.getInstance("JKS").apply { load(null, null) }
        store.setKeyEntry("one", first.privateKey, password, arrayOf(first.certificate))
        store.setKeyEntry("two", second.privateKey, password, arrayOf(second.certificate))
        store.setCertificateEntry("three", bystander.certificate)
        val jks = ByteArrayOutputStream().apply { store.store(this, password) }.toByteArray()

        val entries = KeyMaterial.readKeystoreEntries(jks, password)

        assertEquals(listOf("one", "two"), entries.map { it.alias }.sorted())
    }

    @Test
    fun `reads a PKCS12 through the same entry point`() {
        val identity = generate(KeyAlgorithm.RSA_2048, "p12")
        val password = "pkcs12-secret".toCharArray()
        val pkcs12 = KeyMaterial.writePkcs12("p12", identity.privateKey, identity.certificate, password)

        val entries = KeyMaterial.readKeystoreEntries(pkcs12, password)

        assertEquals(identity.certificate, entries.single().certificate)
        assertSigns(entries.single().privateKey, identity.certificate, "SHA256withRSA")
    }

    @Test
    fun `identifies formats from their header`() {
        val identity = generate(KeyAlgorithm.EC_P256, "x")
        val password = "p".toCharArray()

        assertEquals(
            KeystoreFormat.JKS,
            KeyMaterial.detectKeystoreFormat(writeJks(identity, "x", password, password)),
        )
        assertEquals(
            KeystoreFormat.PKCS12,
            KeyMaterial.detectKeystoreFormat(
                KeyMaterial.writePkcs12("x", identity.privateKey, identity.certificate, password)
            ),
        )
        // JCEKS reuses the JKS layout but protects keys differently, so it must not be mistaken
        // for one and reported as corrupt.
        assertNull(
            KeyMaterial.detectKeystoreFormat(
                byteArrayOf(0xCE.toByte(), 0xCE.toByte(), 0xCE.toByte(), 0xCE.toByte(), 0, 0, 0, 2)
            )
        )
        assertNull(KeyMaterial.detectKeystoreFormat(ByteArray(2)))
    }

    @Test
    fun `refuses a file that is not a keystore at all`() {
        assertThrows(KeystoreReadException::class.java) {
            KeyMaterial.readKeystoreEntries("hello there".toByteArray(), "p".toCharArray())
        }
    }

    @Test
    fun `reads the subject back out of a certificate without double escaping`() {
        val subject = DistinguishedName(
            commonName = "Acme, Inc.",
            organizationalUnit = "Mobile",
            organization = "Acme",
            locality = "Delft",
            state = "ZH",
            country = "NL",
        )
        val material = KeyMaterial.generate(
            NewIdentityRequest("x", "x", subject, 30, KeyAlgorithm.EC_P256)
        )

        val recovered = KeyMaterial.subjectOf(material.certificate)

        assertEquals("Acme, Inc.", recovered.commonName)
        assertEquals(subject.withDefaults(), recovered)
    }

    @Test
    fun `describes the key behind a certificate`() {
        val rsa = generate(KeyAlgorithm.RSA_2048, "r")
        val ec = generate(KeyAlgorithm.EC_P256, "e")

        assertEquals("RSA" to 2048, KeyMaterial.describeKey(rsa.certificate.publicKey))
        assertEquals("EC" to 256, KeyMaterial.describeKey(ec.certificate.publicKey))
    }

    @Test
    fun `renders a partial subject without empty components`() {
        val rendered = DistinguishedName(commonName = "only-cn", country = "NL").rfc2253()

        assertEquals("CN=only-cn, C=NL", rendered)
    }

    private class Fixture(val privateKey: PrivateKey, val certificate: X509Certificate)

    companion object {
        @BeforeClass
        @JvmStatic
        fun installProvider() {
            Bc.install()
        }

        private fun generate(algorithm: KeyAlgorithm, name: String): Fixture {
            val material = KeyMaterial.generate(
                NewIdentityRequest(
                    label = name,
                    alias = name,
                    dn = DistinguishedName(commonName = name),
                    validityYears = 30,
                    algorithm = algorithm,
                )
            )
            return Fixture(material.keyPair.private, material.certificate)
        }

        private fun writeJks(
            fixture: Fixture,
            alias: String,
            storePassword: CharArray,
            keyPassword: CharArray,
        ): ByteArray {
            val store = KeyStore.getInstance("JKS").apply { load(null, null) }
            store.setKeyEntry(alias, fixture.privateKey, keyPassword, arrayOf(fixture.certificate))
            return ByteArrayOutputStream().apply { store.store(this, storePassword) }.toByteArray()
        }

        /** Proves the recovered key is the one the certificate belongs to. */
        private fun assertSigns(
            privateKey: PrivateKey,
            certificate: X509Certificate,
            algorithm: String,
        ) {
            val payload = "apk contents".toByteArray()
            val signature = Signature.getInstance(algorithm).run {
                initSign(privateKey)
                update(payload)
                sign()
            }
            val verified = Signature.getInstance(algorithm).run {
                initVerify(certificate.publicKey)
                update(payload)
                verify(signature)
            }
            assertTrue("recovered key does not match the certificate", verified)
        }
    }
}
