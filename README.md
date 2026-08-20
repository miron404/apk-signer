# APK Signer

An offline APK signing app for Android, built for GrapheneOS on Pixel hardware.

It generates and stores multiple signing identities, keeps every private key sealed behind the
Titan M2 secure element, and signs APKs on the device with Google's `apksig` (v1 through v4).

## What it does

- **Multiple signing identities.** Each one is an RSA or ECDSA key pair with a self-signed
  certificate. Certificate metadata (CN, OU, O, L, ST, C) is entered by hand; every field left
  blank is certified as `Unknown`, and a blank validity means 30 years — the same defaults
  `keytool` uses.
- **Random keystore passwords, sealed in hardware.** Each keystore gets a 256-bit password from the
  system CSPRNG. It is never shown and never stored in the clear: it lives inside an AES-256-GCM
  envelope whose key is a StrongBox (Titan M2) key that cannot leave the secure element.
- **System authentication with a hardware-enforced window.** Biometric or device credential, with a
  re-authentication interval you choose in Settings. The same interval also governs the optional
  app lock: the identity list re-locks once the app has been in the background for longer than the
  window.
- **Signing and verification.** v1 (JAR), v2, v3 and v4 signature schemes, optional re-alignment,
  and every result is verified with `ApkVerifier` before you are offered the file to save.
- **Encrypted backup.** A single passphrase-protected archive (Argon2id + AES-256-GCM) moves every
  identity to another device. Individual identities can also be exported as PKCS#12 for use with
  `apksigner` or Gradle.
- **No network.** The app declares no `INTERNET` permission, so the sandbox has no socket
  capability at all.

## Authentication model

The app asks for one setting — how long an authentication stays valid — and derives everything
else from it. The choice is not a flag in the app; it is compiled into the master key:

```
KeyGenParameterSpec.Builder(alias, ENCRYPT | DECRYPT)
    .setIsStrongBoxBacked(true)                  // Titan M2
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(n, BIOMETRIC_STRONG | DEVICE_CREDENTIAL)
    .setUnlockedDeviceRequired(true)
```

Keymaster refuses to use the key once `n` seconds have elapsed. A patched or repackaged build of
this app gains nothing: the secure element, not the Kotlin code, holds the timer.

Setting the window to **0** turns it into per-operation authentication — every single unseal is
bound to its own `BiometricPrompt.CryptoObject`. That is the strictest mode, and it is the same
slider position rather than a separate feature.

Because the window is part of the key, changing it means minting a replacement key and re-sealing
the vault against it. Settings does that explicitly and can resume it after an interruption.

## Key hierarchy

```
Titan M2 / StrongBox
└── master AES-256-GCM key            user-auth bound, non-exportable, never sees bulk data
    └── per-identity data key (32 B)  wrapped by the master key, stored with the identity
        └── identity envelope         AES-256-GCM over { random keystore password, PKCS#12 }
```

Only 32 bytes ever pass through the secure element, which matters because StrongBox is slow for
bulk data. The envelope's associated data binds each blob to its identity, so sealed files cannot
be swapped between entries.

Certificate metadata is stored in cleartext next to the sealed blob. That is deliberate: it is
exactly what every APK signed by the identity already publishes, and it lets the identity list
render without an authentication prompt.

## Building

The project builds with Gradle and the Android Gradle Plugin; CI runs on GitHub Actions
(`.github/workflows/build.yml`) and uploads both the debug and release APKs.

```
./gradlew :app:assembleDebug
./gradlew :app:testDebugUnitTest
```

The end-to-end signing test uses the debug APK as its fixture, so run `assembleDebug` first; it is
skipped otherwise.

To get a signed release build out of CI, add these repository secrets:

| Secret | Meaning |
| --- | --- |
| `SIGNING_KEYSTORE_B64` | base64 of a JKS or PKCS#12 keystore |
| `SIGNING_KEYSTORE_PASSWORD` | keystore password |
| `SIGNING_KEY_ALIAS` | key alias |
| `SIGNING_KEY_PASSWORD` | key password |

You can create that keystore with this app and export it as PKCS#12.

## Requirements

- Android 13 (API 33) or newer
- A secure lock screen; a StrongBox-backed device (Pixel 3 and later) for hardware key protection

On a device without StrongBox the app still works, falling back to TEE-backed keys, and says so on
the identity list.

See [SECURITY.md](SECURITY.md) for the threat model and the limits of what this design protects
against.
