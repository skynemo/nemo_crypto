import 'key_wrap.dart';

/// Identifiers for the storage slots in a [WrapStore].
enum WrapSlot {
  /// Master key wrapped under the passphrase-derived key.
  passphrase,

  /// Master key wrapped under the recovery key.
  recovery,

  /// Vault key wrapped under the vault passphrase.
  vault,
}

/// Defines the persistent storage interface for wrapped keys.
abstract interface class WrapStore {
  /// Returns true if a keyring has been created in this store.
  Future<bool> get isInitialized;

  /// Marks the store as initialized after wraps are successfully written.
  Future<void> markInitialized();

  /// Retrieves the wrap from the specified [slot], or null if absent.
  Future<KeyWrap?> read(WrapSlot slot);

  /// Stores or overwrites [wrap] in the specified [slot].
  Future<void> write(WrapSlot slot, KeyWrap wrap);

  /// Removes the wrap from the specified [slot].
  Future<void> delete(WrapSlot slot);

  /// Irreversibly deletes all stored wraps.
  Future<void> clear();
}

/// An in-memory [WrapStore] implementation for testing
class InMemoryWrapStore implements WrapStore {
  final Map<WrapSlot, KeyWrap> _wraps = {};
  bool _initialized = false;

  @override
  Future<bool> get isInitialized async => _initialized;

  @override
  Future<void> markInitialized() async => _initialized = true;

  @override
  Future<KeyWrap?> read(WrapSlot slot) async => _wraps[slot];

  @override
  Future<void> write(WrapSlot slot, KeyWrap wrap) async => _wraps[slot] = wrap;

  @override
  Future<void> delete(WrapSlot slot) async {
    _wraps.remove(slot);
  }

  @override
  Future<void> clear() async {
    _wraps.clear();
    _initialized = false;
  }
}
