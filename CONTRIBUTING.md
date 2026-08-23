# Contributing to nemo_crypto

We welcome contributions! Here is how you can help

## Development Setup

1. Fork and clone the repository.
2. Run `dart pub get` in each package directory (`nemo_crypto`, `nemo_crypto_hive`, `nemo_crypto_keystore`).
3. Ensure you have the required native dependencies for `libsodium` if testing on desktop platforms.

## Pull Request Process

1. **Tests:** All code changes must be accompanied by relevant unit or integration tests. Run `dart test` before submitting.
2. **Formatting:** Run `dart format .` to adhere to Dart styling standards.
3. **Analysis:** Code must pass the strict linting rules. Run `dart analyze` and ensure zero warnings.
4. **Golden Vectors:** Do not modify the frozen constants in `NemoKdf` unless explicitly bumping a major cryptographic schema version. Tests will fail if vectors change.
