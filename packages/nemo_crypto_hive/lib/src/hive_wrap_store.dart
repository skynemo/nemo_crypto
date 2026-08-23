import 'dart:typed_data';

import 'package:hive_ce/hive.dart';
import 'package:nemo_crypto/nemo_crypto.dart';

/// A [WrapStore] implementation backed by a Hive box.
///
/// Stores wrapped keys and schema metadata. Box lifecycle is managed by the
/// caller. Keys are prefixed to allow sharing the box with other application data.
/// Since all stored data is ciphertext, the Hive box does not require encryption.
///
/// ```dart
/// final box = await Hive.openBox<dynamic>('app_meta');
/// final keyring = Keyring(HiveWrapStore(box), cache: cache);
/// ```
class HiveWrapStore implements WrapStore {
  final Box<dynamic> _box;
  final String _prefix;

  /// Initializes the store with an opened Hive [box].
  ///
  /// The optional [prefix] isolates multiple keyrings within the same box.
  HiveWrapStore(this._box, {this._prefix = 'nemo_'});

  String get _schemaKey => '${_prefix}schema';
  String _slotKey(WrapSlot slot) => '${_prefix}wrap_${slot.name}';

  /// The current schema version written by [markInitialized].
  static const currentSchema = 1;

  @override
  Future<bool> get isInitialized async => _box.get(_schemaKey) != null;

  @override
  Future<void> markInitialized() => _box.put(_schemaKey, currentSchema);

  @override
  Future<KeyWrap?> read(WrapSlot slot) async {
    final raw = _box.get(_slotKey(slot));
    if (raw == null) return null;
    return _fromMap((raw as Map).cast<dynamic, dynamic>());
  }

  @override
  Future<void> write(WrapSlot slot, KeyWrap wrap) =>
      _box.put(_slotKey(slot), _toMap(wrap));

  @override
  Future<void> delete(WrapSlot slot) => _box.delete(_slotKey(slot));

  @override
  Future<void> clear() async {
    for (final slot in WrapSlot.values) {
      await _box.delete(_slotKey(slot));
    }
    await _box.delete(_schemaKey);
  }

  /// Serializes [wrap] to a map for Hive storage.
  ///
  /// Utilizes native byte array storage instead of base64 encoding.
  static Map<String, dynamic> _toMap(KeyWrap wrap) => {
    if (wrap.params != null) 'kdf': wrap.params!.toJson(),
    'n': wrap.sealed.nonce,
    'c': wrap.sealed.cipherText,
  };

  /// Deserializes a [KeyWrap] from a Hive storage map.
  static KeyWrap _fromMap(Map<dynamic, dynamic> map) => KeyWrap(
    params: map['kdf'] == null
        ? null
        : KdfParams.fromJson((map['kdf'] as Map).cast<String, dynamic>()),
    sealed: KeyWrap.checked(
      SealedBytes(
        nonce: Uint8List.fromList((map['n'] as List).cast<int>()),
        cipherText: Uint8List.fromList((map['c'] as List).cast<int>()),
      ),
    ),
  );
}
