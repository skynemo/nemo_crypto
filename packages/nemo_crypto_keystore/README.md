# 🔑 nemo_crypto_keystore

[![pub package](https://img.shields.io/pub/v/nemo_crypto_keystore.svg)](https://pub.dev/packages/nemo_crypto_keystore)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

A cross-platform, OS-level `MasterKeyCache` adapter for the **[Nemo Crypto](https://pub.dev/packages/nemo_crypto)** ecosystem.

This package enables silent and biometric unlock (FaceID / TouchID / Fingerprint) by securely caching the raw master key within the operating system's native secure storage. Built on top of `flutter_secure_storage`.

## 🌍 Platform Support

Because it relies on native OS APIs, the exact security guarantees depend on the platform:

| Platform        | Native Backend    | Supported Access Policies                                                                                                                                    |
| --------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **iOS / macOS** | Keychain          | Full (accessibility levels, iCloud sync, User Presence / Biometrics).                                                                                        |
| **Android**     | Keystore          | Hardware-backed Biometrics / Device Credential prompt.                                                                                                       |
| **Linux**       | Secret Service    | Silent unlock only. No explicit access policy API.                                                                                                           |
| **Windows**     | Credential Locker | Silent unlock only. No explicit access policy API.                                                                                                           |
| **Web**         | IndexedDB         | ⚠️ _Warning: Data goes to IndexedDB behind a wrap key in the page. Treat caching a master key on the web as roughly equivalent to storing it in plain text._ |

## 🛡️ About Nemo Crypto

Nemo Crypto is an architecture for local-first, end-to-end encrypted (E2EE) applications. By default, unlocking a Nemo `Keyring` requires passing the user's passphrase through a heavy Argon2id derivation function.

This package (`nemo_crypto_keystore`) provides the `MasterKeyCache` interface, allowing you to bypass the passphrase prompt for returning users by delegating the security trust to the operating system's hardware protection (like the Secure Enclave or Trusted Execution Environment).

## 🚀 Installation

```yaml
dependencies:
  nemo_crypto: ^0.1.0
  nemo_crypto_keystore: ^0.1.0
```

## 🛠️ Usage

Pass the `KeystoreMasterKeyCache` to your `Keyring` during initialization.

### Strict Biometric Unlock

This configuration generates the key with hardware-backed biometric requirements. The OS automatically handles the prompt UI and enforcement.

```dart
import 'package:nemo_crypto/nemo_crypto.dart';
import 'package:nemo_crypto_keystore/nemo_crypto_keystore.dart';

void main() async {
  await Nemo.initialize();

  // 1. Configure the Cache Adapter
  final cache = KeystoreMasterKeyCache.biometric(
    android: const AndroidBiometricOptions(
      title: 'Unlock Secure Store',
      subtitle: 'Verify your identity to access your encryption keys',
      cancel: 'Cancel',
    ),
  );

  // 2. Plug the cache into the Keyring
  final keyring = Keyring(myWrapStore, cache: cache);

  // 3. Attempt silent unlock (Triggers OS biometric prompt)
  await keyring.init(trySilentUnlock: true);

  if (keyring.isUnlocked) {
    print('Store unlocked via Biometrics!');
  } else {
    print('Access denied or cache empty. Fallback to passphrase prompt.');
  }
}
```

### Silent Device Unlock (Default)

If you don't require explicit biometric confirmation every time the app opens, use the default constructor. The OS will automatically release the key as long as the device itself is unlocked.

```dart
final cache = KeystoreMasterKeyCache();
final keyring = Keyring(myWrapStore, cache: cache);
```

### Manual Cache Management

You can programmatically revoke biometric access (e.g., when a user logs out, or disables the "Use FaceID" toggle in your app's settings):

```dart
await keyring.forgetCachedKey();
```

To re-enable it later after verifying their passphrase:

```dart
await keyring.cacheMasterKey();
```

## 📖 Further Reading

For full documentation on how to encrypt data, manage the Vault, and configure the core Keyring, visit the [Main Workspace Repository](https://github.com/skynemo/nemo_crypto).
