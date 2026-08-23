# 🛡️ nemo_crypto

[![pub package](https://img.shields.io/pub/v/nemo_crypto.svg)](https://pub.dev/packages/nemo_crypto)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

The core cryptography engine for the **Nemo Crypto** ecosystem. It provides a production-ready key hierarchy, Argon2id key stretching, and authenticated encryption (XChaCha20-Poly1305) built on [libsodium](https://doc.libsodium.org/).

Built on Dart. Without Flutter dependency and enforced storage engine.

_Core of the [Nemo Crypto](https://github.com/skynemo/nemo_crypto)._

## 📦 Ecosystem Adapters

While `nemo_crypto` provides the cryptographic primitives, it requires external storage interfaces to persist data. Check out the official adapters for Flutter apps:

- 🔑 **[`nemo_crypto_keystore`](https://pub.dev/packages/nemo_crypto_keystore):** Enable biometric/silent unlock using iOS Keychain, Android Keystore, and other OS-level secure storage.
- 🐝 **[`nemo_crypto_hive`](https://pub.dev/packages/nemo_crypto_hive):** Persist your wrapped keys using a Hive box.

## 🚀 Installation

```yaml
dependencies:
  nemo_crypto: ^0.1.0
```

## 🛠️ Usage Guide

### 1. Initialize the Engine

Initialization must occur once before interacting with any cryptographic functions.

```dart
import 'package:nemo_crypto/nemo_crypto.dart';

await Nemo.initialize();
```

### 2. Configure the Keyring

The `Keyring` manages the key hierarchy and lifecycle state. It requires a `WrapStore` to persist encrypted keys (use `HiveWrapStore` in production).

```dart
final store = InMemoryWrapStore();
final keyring = Keyring(store);

await keyring.init(trySilentUnlock: false);
```

### 3. Create or Unlock a Store

```dart
if (keyring.status == NemoStatus.none) {
  // Calibrates Argon2id to the device hardware and creates the master key
  final recoveryKey = await keyring.create(passphrase: 'correct horse battery staple');
  print('Save this recovery key: $recoveryKey');
} else {
  // Unlocks an existing store
  final success = await keyring.unlockWithPassphrase('correct horse battery staple');
}
```

### 4. Encrypt and Decrypt Records

Every record gets its own 32-byte content key. `sealPadded` implements ISO/IEC 7816-4 padding to mask the true length of your plaintext.

```dart
// --- Encrypt ---
final contentKey = keyring.newContentKey();
final sealed = NemoCipher.sealPadded(plainTextBytes, contentKey);
// We wrap the content key for storage, not the data itself
final wrap = keyring.wrapContentKey(contentKey);
contentKey.dispose(); // Always dispose of keys after use

// --- Decrypt ---
final unlockedKey = keyring.unwrapContentKey(wrap, WrapSource.primary);
final decrypted = NemoCipher.openPadded(sealed, unlockedKey);
unlockedKey.dispose();
```

## 🔒 Security Architecture

- **Key Wrapping:** Master keys are encrypted under KEKs (Key Encryption Keys), enabling multiple independent unlock paths (passphrase, recovery key, biometrics).
- **Length Obfuscation:** Ciphertext sizes are rounded to predefined buckets to prevent metadata leaks based on payload length.
- **The Vault:** An isolated inner compartment with its own passphrase. Opening the primary keyring does not unlock the Vault, making it perfect for highly sensitive records.
- **Memory Hygiene:** Long-lived key material is stored in libsodium `SecureKey` instances, utilizing guarded native memory pages that zero out automatically upon `dispose()`.

For detailed information on the Threat Model and architecture, refer to the [Main Workspace Repository](https://github.com/skynemo/nemo_crypto).
