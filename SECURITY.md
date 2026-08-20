# Threat model

This document states what the design protects against, and — more usefully — what it does not.

## Assets

1. The private keys of every signing identity.
2. The random keystore password that protects each PKCS#12 blob.
3. The contents of an exported backup archive.

Certificate metadata (subject, serial, validity, fingerprint) is **not** an asset. It is published
in every APK the identity signs, so it is stored in cleartext and the identity list renders without
an authentication prompt.

## What the design defends against

**Offline attack on the device's storage.** Sealed identity files are AES-256-GCM ciphertext. The
data key is wrapped by a StrongBox key that never leaves the secure element, so a copy of
`/data/data/io.github.miron404.apksigner` is inert on any other machine, and inert on this one
without a successful user authentication.

**A root-level attacker outside the authentication window.** Unwrapping goes through Keymaster,
which enforces `setUserAuthenticationRequired` and the configured validity duration in the secure
element. Root can invoke the key but cannot make Keymaster authorise it, cannot extract it, and
cannot extend the window. `setUnlockedDeviceRequired(true)` additionally refuses use while the
device is locked.

**A repackaged or patched build of this app.** The authentication window is a property of the key,
established at creation time and immutable thereafter. Removing the prompt from the app's code
would only cause `UserNotAuthenticatedException`. This is the reason the window is implemented as
`setUserAuthenticationParameters` rather than as a timestamp the app compares against.

**Cross-entry confusion.** Each envelope authenticates the identity's UUID as associated data, so a
sealed blob cannot be moved from one identity's slot to another's, and a stale blob cannot be
replayed under a different entry.

**Hostile input from other apps.** The launcher activity also accepts an APK through `ACTION_VIEW`
and `ACTION_SEND`. Both filters are narrowed to the APK media type, and the handler ignores any URI
that is not `content://`, so the app cannot be pointed at its own storage and only ever acts on a
grant the sender made deliberately. An incoming APK is parsed and copied, nothing more; producing a
signature from it still requires the user to choose an identity and authenticate. What this does
not prevent is a person being talked into signing something they did not inspect — see the note on
malicious payloads below.

**Exfiltration by the app itself.** There is no `INTERNET` permission in the manifest, so the app's
sandbox has no network capability. A compromise of the app can misuse keys locally but cannot send
them anywhere. Combined with `allowBackup="false"` and the empty data-extraction rules, nothing
leaves the device except through a file the user explicitly saves.

**Shoulder-surfing and screenshot capture.** The activity sets `FLAG_SECURE`, which also blanks the
recents thumbnail. The optional app lock covers the UI whenever the app has been in the background
for longer than the configured window, measured on a monotonic clock so changing the device time
cannot extend it. That lock is only a convenience: it guards the identity list, which holds nothing
secret. Key material is protected by the hardware key regardless of whether the lock is enabled.

**Downgrade of backup parameters.** The Argon2id cost parameters live in the archive's cleartext
header but are authenticated as GCM associated data, so an attacker cannot rewrite them to make a
brute-force cheaper without invalidating the tag.

## What it does not defend against

**A compromised device inside the authentication window.** Once the user authenticates, the key is
usable for the configured duration by anything with the app's UID. If that matters to you, set the
window to *every operation*: each unseal is then bound to its own `CryptoObject`, and one
authentication authorises exactly one cryptographic operation.

**An attacker who knows the device credential.** The default policy accepts the device PIN,
pattern or password as an alternative to a biometric, because a biometric-only key is destroyed by
routine fingerprint re-enrollment. Someone with the PIN can unlock the vault. Turning off *Allow
device PIN as fallback* in Settings makes the key biometric-only and restores
`setInvalidatedByBiometricEnrollment(true)`; the trade-off is that re-enrolling a fingerprint then
permanently destroys every identity, and the encrypted backup is the only way back.

**A weak backup passphrase.** The archive is deliberately independent of this device's secure
element — that is what makes it portable — so its only protection is the passphrase. Argon2id at
64 MiB / 4 passes raises the cost per guess but does not rescue a short passphrase. The dialog
requires at least 16 characters; use more.

**A weak PKCS#12 export passphrase.** Same reasoning. Exports use PBES2 with AES-256-CBC and
PBKDF2-HMAC-SHA256 at 600,000 iterations rather than the 3DES/RC2 defaults the PKCS#12 keystore SPI
still emits, but the passphrase remains the weakest link. Prefer the encrypted backup archive for
device-to-device transfer and reserve PKCS#12 for interoperability with `apksigner` or Gradle.

**Memory disclosure.** Key material is wiped from `ByteArray` and `CharArray` buffers as soon as it
is finished with, and `android:memtagMode="async"` is requested to catch heap corruption. But
passphrase entry goes through Compose text fields, which are `String`-backed and therefore
immutable — that one copy cannot be wiped and remains until garbage collection. Java's `PrivateKey`
objects likewise cannot be reliably scrubbed.

**A malicious or backdoored APK being signed.** The app signs what you give it. It reports whether
the input is marked debuggable, and verifies its own output, but it does not inspect the payload.

**Physical extraction attacks on the secure element itself.** Out of scope; that is Titan M2's
problem, and it is the reason StrongBox is preferred over the TEE.

## Cryptographic choices

| Purpose | Algorithm |
| --- | --- |
| Master key | AES-256-GCM in StrongBox, user-auth bound, non-exportable |
| Identity envelope | AES-256-GCM, fresh 256-bit data key per identity, 96-bit random nonce |
| Backup key derivation | Argon2id, 64 MiB, 4 passes, 2 lanes, 128-bit salt |
| Backup encryption | AES-256-GCM, header authenticated as associated data |
| PKCS#12 export | PBES2 / AES-256-CBC, PBKDF2-HMAC-SHA256, 600,000 iterations, SHA-256 MAC |
| PKCS#12 inside the vault | same, at 10,000 iterations — see below |
| Signing keys | RSA 2048/3072/4096 or ECDSA P-256/P-384 |
| Certificate signature | SHA-256 or SHA-512 with RSA; SHA-256/384 with ECDSA |

The keystore held inside the vault uses a much lower PBKDF2 cost than an export does. Its password
is 256 bits of CSPRNG output, so there is no guessing attack for a KDF to slow down, and the file is
already sealed in the hardware-backed envelope; charging 600,000 rounds there would add seconds to
every create, sign and export while buying nothing. Exports, whose passphrase a human chooses, keep
the full cost.

Randomness comes from a single `SecureRandom` seeded by the kernel. The full BouncyCastle provider
replaces Android's stripped-down `BC` at startup, because the platform build omits the PKCS#12
writer and certificate builder this app needs. It is used only for those parts: key generation and
signature operations go to the platform provider, which on Android is BoringSSL through Conscrypt
and is orders of magnitude faster than BouncyCastle's Java implementation on ART.

## Reporting

This is a personal-use application with no support commitment. If you find a flaw, open an issue on
the repository.
