package io.github.miron404.apksigner.core

import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.EOFException
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/** Raised when a keystore cannot be read: wrong password, wrong format, or truncated. */
class KeystoreReadException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Read-only reader for Sun's JKS keystores.
 *
 * Neither Android nor BouncyCastle ships a JKS implementation, and JKS is what `keytool` produced
 * by default for years — so it is the format most existing Android signing keys are in. The format
 * and its key protection are stable and fully specified, and this parser is verified in CI against
 * keystores written by the JDK's own implementation.
 *
 * JKS protects keys with a SHA-1 keystream and checks integrity with a SHA-1 digest, both far below
 * what would be acceptable for new storage. That is not a reason to refuse to read one: the point
 * of importing is to move the key into this app's AES-256-GCM envelope under a hardware key, which
 * is an upgrade. Nothing is ever written back in this format.
 */
object JksKeystore {

    private const val MAGIC = 0xFEEDFEED.toInt()
    private const val TAG_PRIVATE_KEY = 1
    private const val TAG_TRUSTED_CERT = 2
    private const val DIGEST_LENGTH = 20

    /** Sun mixes this literal into the store digest; it is part of the format, not a secret. */
    private val DIGEST_SALT = "Mighty Aphrodite".toByteArray(Charsets.UTF_8)

    fun looksLikeJks(bytes: ByteArray): Boolean =
        bytes.size > 4 &&
            ((bytes[0].toInt() and 0xFF) shl 24 or
                ((bytes[1].toInt() and 0xFF) shl 16) or
                ((bytes[2].toInt() and 0xFF) shl 8) or
                (bytes[3].toInt() and 0xFF)) == MAGIC

    fun read(
        bytes: ByteArray,
        storePassword: CharArray,
        keyPassword: CharArray,
    ): List<KeystoreEntry> {
        verifyStoreDigest(bytes, storePassword)

        val input = DataInputStream(ByteArrayInputStream(bytes, 0, bytes.size - DIGEST_LENGTH))
        try {
            input.readInt() // magic, already checked by the digest
            val version = input.readInt()
            if (version != 1 && version != 2) {
                throw KeystoreReadException("Unsupported JKS version $version")
            }
            val count = input.readInt()
            if (count < 0) throw KeystoreReadException("Malformed keystore")

            val factory = CertificateFactory.getInstance("X.509")
            val entries = mutableListOf<KeystoreEntry>()
            repeat(count) {
                when (val tag = input.readInt()) {
                    TAG_PRIVATE_KEY -> entries += readPrivateKeyEntry(input, version, factory, keyPassword)
                    // Trusted certificates carry no private key, so there is nothing to sign with.
                    TAG_TRUSTED_CERT -> skipCertificate(input, version)
                    else -> throw KeystoreReadException("Unrecognised keystore entry type $tag")
                }
            }
            return entries
        } catch (e: EOFException) {
            throw KeystoreReadException("Keystore is truncated", e)
        }
    }

    private fun readPrivateKeyEntry(
        input: DataInputStream,
        version: Int,
        factory: CertificateFactory,
        keyPassword: CharArray,
    ): KeystoreEntry {
        val alias = input.readUTF()
        input.readLong() // creation date
        val protectedKey = ByteArray(input.readInt()).also { input.readFully(it) }

        val chainLength = input.readInt()
        if (chainLength <= 0) throw KeystoreReadException("Entry '$alias' has no certificate")
        val chain = (0 until chainLength).map {
            if (version == 2) input.readUTF() // certificate type, always X.509 in practice
            val encoded = ByteArray(input.readInt()).also { bytes -> input.readFully(bytes) }
            factory.generateCertificate(ByteArrayInputStream(encoded)) as X509Certificate
        }

        val pkcs8 = recoverKey(protectedKey, keyPassword, alias)
        val privateKey = try {
            BouncyCastleProvider.getPrivateKey(PrivateKeyInfo.getInstance(pkcs8))
        } finally {
            pkcs8.wipe()
        }
        return KeystoreEntry(alias, privateKey, chain)
    }

    private fun skipCertificate(input: DataInputStream, version: Int) {
        input.readUTF()
        input.readLong()
        if (version == 2) input.readUTF()
        input.skipBytes(input.readInt())
    }

    /**
     * Undoes Sun's "JavaSoft proprietary key protection".
     *
     * The key is XORed with a keystream of chained SHA-1 digests seeded from the password and a
     * per-entry salt, followed by a digest of the plaintext that doubles as the password check.
     */
    private fun recoverKey(protectedKey: ByteArray, password: CharArray, alias: String): ByteArray {
        val encrypted = try {
            EncryptedPrivateKeyInfo.getInstance(protectedKey).encryptedData
        } catch (e: Exception) {
            throw KeystoreReadException("Entry '$alias' is not a JKS protected key", e)
        }
        if (encrypted.size < 2 * DIGEST_LENGTH) {
            throw KeystoreReadException("Entry '$alias' is malformed")
        }

        val passwordBytes = utf16Be(password)
        try {
            val salt = encrypted.copyOfRange(0, DIGEST_LENGTH)
            val bodyLength = encrypted.size - 2 * DIGEST_LENGTH
            val expectedDigest = encrypted.copyOfRange(DIGEST_LENGTH + bodyLength, encrypted.size)

            val sha1 = MessageDigest.getInstance("SHA-1")
            val plain = ByteArray(bodyLength)
            var chained = salt
            var written = 0
            while (written < bodyLength) {
                sha1.update(passwordBytes)
                sha1.update(chained)
                chained = sha1.digest()
                val take = minOf(DIGEST_LENGTH, bodyLength - written)
                for (i in 0 until take) {
                    plain[written + i] = (encrypted[DIGEST_LENGTH + written + i].toInt() xor
                        chained[i].toInt()).toByte()
                }
                written += take
            }

            sha1.update(passwordBytes)
            sha1.update(plain)
            if (!MessageDigest.isEqual(sha1.digest(), expectedDigest)) {
                plain.wipe()
                throw KeystoreReadException("Wrong key password for entry '$alias'")
            }
            return plain
        } finally {
            passwordBytes.wipe()
        }
    }

    /** The trailing digest covers the whole file and is keyed by the store password. */
    private fun verifyStoreDigest(bytes: ByteArray, storePassword: CharArray) {
        if (bytes.size < DIGEST_LENGTH + 12) throw KeystoreReadException("Keystore is truncated")
        val passwordBytes = utf16Be(storePassword)
        val actual = try {
            MessageDigest.getInstance("SHA-1").apply {
                update(passwordBytes)
                update(DIGEST_SALT)
                update(bytes, 0, bytes.size - DIGEST_LENGTH)
            }.digest()
        } finally {
            passwordBytes.wipe()
        }
        val expected = bytes.copyOfRange(bytes.size - DIGEST_LENGTH, bytes.size)
        if (!MessageDigest.isEqual(actual, expected)) {
            throw KeystoreReadException("Wrong keystore password, or the file is damaged")
        }
    }

    /** JKS hashes passwords as big-endian UTF-16 code units, not as UTF-8. */
    private fun utf16Be(password: CharArray): ByteArray {
        val out = ByteArray(password.size * 2)
        password.forEachIndexed { index, ch ->
            out[index * 2] = (ch.code shr 8).toByte()
            out[index * 2 + 1] = ch.code.toByte()
        }
        return out
    }
}
