# 🐝 nemo_crypto_hive

[![pub package](https://img.shields.io/pub/v/nemo_crypto_hive.svg)](https://pub.dev/packages/nemo_crypto_hive)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

A `WrapStore` storage adapter for the **[Nemo Crypto](https://pub.dev/packages/nemo_crypto)** ecosystem, backed by [Hive](https://pub.dev/packages/hive_ce).

## 🛡️ About Nemo Crypto

Nemo Crypto is a suite of pure Dart primitives for local-first, end-to-end encrypted (E2EE) applications. It manages complex key hierarchies (Argon2id, XChaCha20-Poly1305) so you don't have to.

This package (`nemo_crypto_hive`) is the official adapter that connects Nemo Crypto's `Keyring` to a physical database (Hive) to persist your wrapped Master Keys safely on disk.

_Note: Since Nemo Crypto ensures all stored keys are authenticated ciphertext, the underlying Hive box does not require its own encryption._

## 🚀 Installation

```yaml
dependencies:
  nemo_crypto: ^0.1.0
  nemo_crypto_hive: ^0.1.0
  hive_ce: ^2.0.0
```

## 🛠️ Usage

Provide an opened Hive box to the `HiveWrapStore`. The store uses a default `nemo_` prefix for its keys, allowing you to safely share the same Hive box with other application metadata.

```dart
import 'package:hive_ce/hive.dart';
import 'package:nemo_crypto/nemo_crypto.dart';
import 'package:nemo_crypto_hive/nemo_crypto_hive.dart';

void main() async {
  // 1. Initialize Nemo Crypto core
  await Nemo.initialize();

  // 2. Initialize Hive and open a metadata box
  Hive.init('./hive_data'); // Use Hive.initFlutter() in a Flutter app
  final box = await Hive.openBox<dynamic>('app_metadata');

  // 3. Plug the Hive adapter into the Keyring
  final store = HiveWrapStore(box);
  final keyring = Keyring(store);

  // 4. Proceed with your crypto logic
  await keyring.init();
}
```

### Isolating Multiple Keyrings

If you are building a multi-account app and need to store multiple separate keyrings in the exact same Hive box, simply provide a custom prefix:

```dart
final user1Store = HiveWrapStore(box, prefix: 'user_1_');
final user2Store = HiveWrapStore(box, prefix: 'user_2_');
```

## 📖 Further Reading

For full documentation on how to encrypt data, manage the Vault, and generate recovery keys, visit the [Main Workspace Repository](https://github.com/skynemo/nemo_crypto).
