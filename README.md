# 🛡️ Nemo Crypto Workspace

[![Dart CI](https://github.com/skynemo/nemo_crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/skynemo/nemo_crypto/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

> **A suite of pure Dart primitives for local-first, end-to-end encrypted (E2EE) applications.**

Nemo Crypto provides a production-ready key hierarchy and authenticated encryption architecture built on [libsodium](https://doc.libsodium.org/). It is designed from the ground up for Zero-Knowledge synchronization, meaning your servers never see the keys, the data, or even the exact size of the payloads.

## 📦 The Ecosystem

This repository is a monorepo containing the following packages. You can use the core package on its own, or plug in the official adapters for instant Flutter integration.

| Package                                                          | Version                                                                                                                | Description                                                                                                                                                                                        |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 🔐 **[`nemo_crypto`](./packages/nemo_crypto)**                   | [![pub package](https://img.shields.io/pub/v/nemo_crypto.svg)](https://pub.dev/packages/nemo_crypto)                   | The core cryptography engine. Manages the key hierarchy, Argon2id stretching, and AEAD encryption. Pure Dart.                                                                                      |
| 🔑 **[`nemo_crypto_keystore`](./packages/nemo_crypto_keystore)** | [![pub package](https://img.shields.io/pub/v/nemo_crypto_keystore.svg)](https://pub.dev/packages/nemo_crypto_keystore) | A `MasterKeyCache` implementation backed by OS-level secure storage (Keychain, Keystore, Secret Service, etc.) via `flutter_secure_storage`. Supports cross-platform silent unlock and biometrics. |
| 🐝 **[`nemo_crypto_hive`](./packages/nemo_crypto_hive)**         | [![pub package](https://img.shields.io/pub/v/nemo_crypto_hive.svg)](https://pub.dev/packages/nemo_crypto_hive)         | A `WrapStore` implementation backed by [Hive CE](https://pub.dev/packages/hive_ce). Handles persistent storage of wrapped keys.                                                                    |

## 💡 Why Nemo Crypto?

Building a secure E2EE local database is hard. Developers often string together raw AES and SHA functions, leaving themselves vulnerable to metadata leaks, padding oracles, and brute-force attacks. Nemo Crypto solves the architectural challenges out of the box:

- **Zero-Knowledge Ready:** `NemoPadding` dynamically obfuscates the true length of your payloads before encryption (using ISO/IEC 7816-4). Attackers cannot guess if a record is a 4-digit PIN or a large essay based on ciphertext size.
- **Hardware-Calibrated Brute-Force Protection:** Uses **Argon2id** to stretch user passphrases. Nemo dynamically calibrates the memory cost to the specific device it's running on, deterring GPU/ASIC attacks while remaining fast for legitimate users.
- **Compartmentalized Vault:** Features a two-tier architecture. You can protect standard app data under the primary key, while locking highly sensitive records behind a secondary "Vault" passphrase. Unlocking the app doesn't automatically unlock the Vault.
- **Tamper-Proof Sync:** Ed25519 manifest signing and deterministic subkey derivation (BLAKE2b) ensure your local database hasn't been maliciously rolled back by a sync server.

## 🚀 Quick Start

To dive into the code, check out the `/example` folders inside each package directory or visit the [**Core Package Documentation**](./packages/nemo_crypto).

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/skynemo/nemo_crypto/issues). If you want to contribute code, please read our [Contributing Guidelines](CONTRIBUTING.md).

## 📄 License

This workspace is open-sourced software licensed under the [MIT license](LICENSE).
