import 'dart:typed_data';

import 'crypto_utils.dart';

/// Defines a storage interface for caching the master key to enable silent unlock.
///
/// Implementations should return null rather than throw if no key is found.
/// Exceptions should be reserved for denied access (e.g., failed biometric prompt).
abstract interface class MasterKeyCache {
  /// Retrieves the stored key, or null if none exists.
  ///
  /// The caller must wipe the returned buffer.
  Future<Uint8List?> read();

  /// Stores the [key].
  ///
  /// Implementations must not retain the provided buffer. The caller is
  /// responsible for wiping its own copy.
  Future<void> write(Uint8List key);

  /// Deletes the stored key, disabling silent unlock.
  Future<void> delete();
}

/// An in-memory [MasterKeyCache] implementation for testing.
class InMemoryMasterKeyCache implements MasterKeyCache {
  Uint8List? _key;

  @override
  Future<Uint8List?> read() async {
    final key = _key;
    return key == null ? null : Uint8List.fromList(key);
  }

  @override
  Future<void> write(Uint8List key) async {
    CryptoUtils.wipe(_key);
    _key = Uint8List.fromList(key);
  }

  @override
  Future<void> delete() async {
    CryptoUtils.wipe(_key);
    _key = null;
  }
}
