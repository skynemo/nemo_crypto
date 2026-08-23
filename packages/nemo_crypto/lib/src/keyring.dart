import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium/sodium_sumo.dart';

import 'cipher.dart';
import 'crypto_utils.dart';
import 'kdf.dart';
import 'key_wrap.dart';
import 'master_key_cache.dart';
import 'sodium_provider.dart';
import 'wrap_store.dart';

/// Indicates the current access state of the keyring.
enum NemoStatus {
  /// The keyring has not been created in the store.
  none,

  /// The keyring exists but key material is not in memory.
  locked,

  /// Keys are in memory and the store can be read or written.
  unlocked,
}

/// Represents the result of a backup restoration attempt.
class NemoRestore {
  /// True if the backup was successfully opened and restored.
  final bool ok;

  /// The newly minted recovery key, if one was generated during restore.
  final String? newRecoveryKey;

  const NemoRestore._(this.ok, this.newRecoveryKey);
}

/// Callback triggered when a non-fatal cache operation fails.
typedef NemoErrorHandler = void Function(Object error, StackTrace stackTrace);

/// Manages the key hierarchy and the lock/unlock lifecycle for the encrypted store.
///
/// For architectural details on the key hierarchy and the vault compartment,
/// refer to the package README.
class Keyring {
  final WrapStore _store;
  final MasterKeyCache? _cache;

  /// Optional callback for intercepting non-fatal cache errors.
  final NemoErrorHandler? onError;

  final StreamController<NemoStatus> _statusChanges =
      StreamController<NemoStatus>.broadcast();
  final StreamController<bool> _vaultChanges =
      StreamController<bool>.broadcast();

  NemoStatus _status = NemoStatus.none;
  bool _vaultOpen = false;
  bool _cacheSuppressed = false;

  SecureKey? _master;
  SecureKey? _contentKey;
  KeyPair? _signPair;
  SecureKey? _vaultKey;

  /// Initializes a keyring over the given [store].
  Keyring(this._store, {this._cache, this.onError});

  static const _masterAad = 'nemo:wrap:master:v1';
  static const _vaultAad = 'nemo:wrap:vault:v1';
  static const contentKeyAad = 'nemo:wrap:content:v1';
  static const manifestContext = 'nemo:manifest:v1';
  static const backupVersion = 1;

  /// The current state of the keyring.
  NemoStatus get status => _status;

  /// True if the primary key material is currently in memory.
  bool get isUnlocked => _status == NemoStatus.unlocked;

  /// True if the secondary vault compartment is currently open.
  bool get isVaultOpen => _vaultOpen;

  /// Emits the current status upon subscription, followed by all future changes.
  Stream<NemoStatus> get statusChanges =>
      _seeded(() => _status, _statusChanges.stream);

  /// Emits the current vault state upon subscription, followed by all future changes.
  Stream<bool> get vaultChanges =>
      _seeded(() => _vaultOpen, _vaultChanges.stream);

  static Stream<T> _seeded<T>(T Function() current, Stream<T> changes) =>
      Stream<T>.multi((controller) {
        controller.add(current());
        final sub = changes.listen(
          controller.add,
          onError: controller.addError,
          onDone: controller.close,
        );
        controller.onCancel = sub.cancel;
      });

  /// True if a vault passphrase has been configured in the store.
  Future<bool> get vaultConfigured async =>
      await _store.read(WrapSlot.vault) != null;

  /// True if a primary passphrase has been configured in the store.
  Future<bool> get passphraseSet async =>
      await _store.read(WrapSlot.passphrase) != null;

  /// True if the instance is currently configured to use a [MasterKeyCache].
  bool get cacheInUse => _cache != null && !_cacheSuppressed;

  /// The key used to wrap per-record content keys.
  SecureKey get contentKey => _require(_contentKey);

  /// Derives an application-specific subkey from the master key.
  ///
  /// The caller owns the returned [SecureKey] and must call `dispose()` on it.
  /// [id] must be equal to or greater than [NemoKdf.firstAppSubkeyId].
  SecureKey appSubkey(int id) {
    if (id < NemoKdf.firstAppSubkeyId) {
      throw NemoCryptoException(
        'subkey id $id is reserved; use ${NemoKdf.firstAppSubkeyId} or above',
      );
    }
    return NemoKdf.subKey(_require(_master), id);
  }

  SecureKey _require(SecureKey? key) {
    if (key == null) throw NemoLockedException();
    return key;
  }

  /// Determines the initial status and attempts silent unlock if enabled.
  Future<NemoStatus> init({bool trySilentUnlock = true}) async {
    if (!await _store.isInitialized) {
      return _setStatus(NemoStatus.none);
    }
    if (trySilentUnlock && cacheInUse) {
      if (await _tryCacheUnlock()) return _setStatus(NemoStatus.unlocked);
    }
    return _setStatus(NemoStatus.locked);
  }

  /// Generates a master key, wraps it, and initializes the keyring.
  ///
  /// Returns the generated recovery key formatted for display.
  /// Throws [StateError] if the store is already initialized.
  Future<String> create({required String passphrase, KdfParams? params}) async {
    if (await _store.isInitialized) {
      throw StateError('create() requires an empty store; call wipe() first');
    }
    final master = SecureKey.random(SodiumProvider.sodium, NemoCipher.keyBytes);
    var installed = false;
    try {
      final kdfParams = params ?? await NemoKdf.calibrateAsync();
      final kek = await NemoKdf.deriveAsync(passphrase, kdfParams);
      try {
        await _store.write(
          WrapSlot.passphrase,
          KeyWrap(
            params: kdfParams,
            sealed: NemoCipher.wrapKey(master, kek, _masterAad),
          ),
        );
      } finally {
        kek.dispose();
      }

      final recoveryKey = await _mintRecoveryKey(master);
      await _cacheMaster(master);
      await _store.markInitialized();
      _install(master);
      installed = true;
      _setStatus(NemoStatus.unlocked);
      return recoveryKey;
    } finally {
      if (!installed) master.dispose();
    }
  }

  /// Unlocks the keyring using the primary [passphrase].
  Future<bool> unlockWithPassphrase(String passphrase) async {
    final wrap = await _store.read(WrapSlot.passphrase);
    if (wrap?.params == null) return false;
    final kek = await NemoKdf.deriveAsync(passphrase, wrap!.params!);
    try {
      return await _unlockWith(wrap, kek);
    } finally {
      kek.dispose();
    }
  }

  /// Unlocks the keyring using the [recoveryKey].
  Future<bool> unlockWithRecoveryKey(String recoveryKey) async {
    final wrap = await _store.read(WrapSlot.recovery);
    if (wrap == null) return false;
    final Uint8List bytes;
    try {
      bytes = CryptoUtils.base32Decode(recoveryKey);
    } on NemoCryptoException {
      return false;
    }
    try {
      if (bytes.length < NemoCipher.keyBytes) return false;
      final key = SecureKey.fromList(
        SodiumProvider.sodium,
        Uint8List.sublistView(bytes, 0, NemoCipher.keyBytes),
      );
      try {
        return await _unlockWith(wrap, key);
      } finally {
        key.dispose();
      }
    } finally {
      CryptoUtils.wipe(bytes);
    }
  }

  /// Attempts to unlock the keyring using the [MasterKeyCache].
  Future<bool> unlockFromCache() async {
    final ok = await _tryCacheUnlock();
    if (ok) _setStatus(NemoStatus.unlocked);
    return ok;
  }

  Future<bool> _unlockWith(KeyWrap wrap, SecureKey wrappingKey) async {
    final SecureKey master;
    try {
      master = NemoCipher.unwrapKey(wrap.sealed, wrappingKey, _masterAad);
    } on NemoCryptoException {
      return false;
    }
    var installed = false;
    try {
      _install(master);
      installed = true;
      _setStatus(NemoStatus.unlocked);
      await _cacheMaster(master);
      return true;
    } finally {
      if (!installed) master.dispose();
    }
  }

  Future<bool> _tryCacheUnlock() async {
    if (!cacheInUse) return false;
    final cache = _cache!;
    try {
      final bytes = await cache.read();
      if (bytes == null) return false;
      try {
        if (bytes.length != NemoCipher.keyBytes) return false;
        _install(SecureKey.fromList(SodiumProvider.sodium, bytes));
        return true;
      } finally {
        CryptoUtils.wipe(bytes);
      }
    } catch (e, s) {
      onError?.call(e, s);
      return false;
    }
  }

  Future<void> _cacheMaster(SecureKey master) async {
    if (!cacheInUse) return;
    final cache = _cache!;
    final bytes = master.extractBytes();
    try {
      await cache.write(bytes);
    } catch (e, s) {
      onError?.call(e, s);
    } finally {
      CryptoUtils.wipe(bytes);
    }
  }

  /// Rewraps the master key under a new [passphrase].
  Future<void> setPassphrase(String passphrase, {KdfParams? params}) async {
    final master = _require(_master);
    final kdfParams = params ?? await NemoKdf.calibrateAsync();
    final kek = await NemoKdf.deriveAsync(passphrase, kdfParams);
    try {
      await _store.write(
        WrapSlot.passphrase,
        KeyWrap(
          params: kdfParams,
          sealed: NemoCipher.wrapKey(master, kek, _masterAad),
        ),
      );
    } finally {
      kek.dispose();
    }
  }

  /// Generates and wraps a new recovery key, returning it formatted for display.
  Future<String> rotateRecoveryKey() => _mintRecoveryKey(_require(_master));

  Future<String> _mintRecoveryKey(SecureKey master) async {
    final bytes = CryptoUtils.randomBytes(NemoCipher.keyBytes);
    try {
      final key = SecureKey.fromList(SodiumProvider.sodium, bytes);
      try {
        await _store.write(
          WrapSlot.recovery,
          KeyWrap(sealed: NemoCipher.wrapKey(master, key, _masterAad)),
        );
      } finally {
        key.dispose();
      }
      return CryptoUtils.groupForDisplay(CryptoUtils.base32Encode(bytes));
    } finally {
      CryptoUtils.wipe(bytes);
    }
  }

  /// Modifies or sets the passphrase for the vault compartment.
  ///
  /// Throws [NemoCryptoException] if the vault is configured but currently closed.
  Future<void> setVaultPassphrase(
    String passphrase, {
    KdfParams? params,
  }) async {
    final existing = _vaultKey;
    if (existing == null && await vaultConfigured) {
      throw NemoCryptoException(
        'vault is closed: open it with the current vault passphrase before '
        'changing it, otherwise locked records become unrecoverable',
      );
    }
    final vaultKey =
        existing ??
        SecureKey.random(SodiumProvider.sodium, NemoCipher.keyBytes);
    var adopted = false;
    try {
      final kdfParams = params ?? await NemoKdf.calibrateAsync();
      final kek = await NemoKdf.deriveAsync(passphrase, kdfParams);
      try {
        await _store.write(
          WrapSlot.vault,
          KeyWrap(
            params: kdfParams,
            sealed: NemoCipher.wrapKey(vaultKey, kek, _vaultAad),
          ),
        );
      } finally {
        kek.dispose();
      }
      _vaultKey = vaultKey;
      adopted = true;
      _setVaultOpen(true);
    } finally {
      if (!adopted && existing == null) vaultKey.dispose();
    }
  }

  /// Unlocks the vault compartment using [passphrase].
  Future<bool> openVault(String passphrase) async {
    final wrap = await _store.read(WrapSlot.vault);
    if (wrap?.params == null) return false;
    final kek = await NemoKdf.deriveAsync(passphrase, wrap!.params!);
    try {
      final key = NemoCipher.unwrapKey(wrap.sealed, kek, _vaultAad);
      _vaultKey?.dispose();
      _vaultKey = key;
      _setVaultOpen(true);
      return true;
    } on NemoCryptoException {
      return false;
    } finally {
      kek.dispose();
    }
  }

  /// Locks the vault compartment without locking the primary keyring.
  void closeVault() {
    _vaultKey?.dispose();
    _vaultKey = null;
    _setVaultOpen(false);
  }

  /// Generates a new random key intended for encrypting a single record.
  SecureKey newContentKey() =>
      SecureKey.random(SodiumProvider.sodium, NemoCipher.keyBytes);

  /// Encrypts [key] for storage using the specified [source] branch.
  SealedBytes wrapContentKey(
    SecureKey key, {
    WrapSource source = WrapSource.primary,
  }) => NemoCipher.wrapKey(key, _keyFor(source), contentKeyAad);

  /// Decrypts a stored content key from the specified [source] branch.
  SecureKey unwrapContentKey(SealedBytes sealed, WrapSource source) =>
      NemoCipher.unwrapKey(sealed, _keyFor(source), contentKeyAad);

  SecureKey _keyFor(WrapSource source) => switch (source) {
    WrapSource.primary => contentKey,
    WrapSource.vault => _requireVaultKey(),
  };

  SecureKey _requireVaultKey() {
    final key = _vaultKey;
    if (key == null) {
      throw NemoCryptoException('vault is closed: locked records unavailable');
    }
    return key;
  }

  /// The Ed25519 public key used for manifest signature verification.
  Uint8List get manifestPublicKey {
    final pair = _signPair;
    if (pair == null) throw NemoLockedException();
    return Uint8List.fromList(pair.publicKey);
  }

  /// Generates a digest of [bytes] bound to the sequence number [seq].
  Uint8List hashManifest(List<int> bytes, {required int seq}) {
    if (seq < 0) throw NemoCryptoException('manifest seq must not be negative');
    final header = utf8.encode('$manifestContext:$seq:');
    final message = Uint8List(header.length + bytes.length)
      ..setRange(0, header.length, header)
      ..setRange(header.length, header.length + bytes.length, bytes);
    return SodiumProvider.sodium.crypto.genericHash(
      message: message,
      outLen: 32,
    );
  }

  /// Signs a [digest] generated by [hashManifest].
  Uint8List signManifest(Uint8List digest) {
    final pair = _signPair;
    if (pair == null) throw NemoLockedException();
    return SodiumProvider.sodium.crypto.sign.detached(
      message: digest,
      secretKey: pair.secretKey,
    );
  }

  /// Verifies a detached manifest [signature] against the provided [digest].
  bool verifyManifest(
    Uint8List digest,
    Uint8List signature, {
    Uint8List? publicKey,
  }) => SodiumProvider.sodium.crypto.sign.verifyDetached(
    message: digest,
    signature: signature,
    publicKey: publicKey ?? manifestPublicKey,
  );

  /// Deletes the master key from the cache to disable silent unlock.
  Future<void> forgetCachedKey() async {
    if (!await passphraseSet) {
      throw StateError('Set a passphrase before dropping the cached key');
    }
    _cacheSuppressed = true;
    await _cache?.delete();
  }

  /// Writes the current master key back to the cache, re-enabling silent unlock.
  Future<void> cacheMasterKey() async {
    final master = _require(_master);
    _cacheSuppressed = false;
    await _cacheMaster(master);
  }

  /// Zeroes all key material in memory and locks the keyring.
  void lock() {
    closeVault();
    _disposeKeys();
    _setStatus(NemoStatus.locked);
  }

  /// Irreversibly deletes all stored wraps, cached keys, and active keys in memory.
  Future<void> wipe() async {
    closeVault();
    _disposeKeys();
    await _cache?.delete();
    await _store.clear();
    _setStatus(NemoStatus.none);
  }

  /// Zeroes key material and closes all broadcast streams.
  Future<void> dispose() async {
    _vaultKey?.dispose();
    _vaultKey = null;
    _disposeKeys();
    await _statusChanges.close();
    await _vaultChanges.close();
  }

  /// Exports all wrapped keys into a serializable map.
  Future<Map<String, dynamic>> exportBackup() async {
    final passphrase = await _store.read(WrapSlot.passphrase);
    if (passphrase == null) {
      throw StateError('no passphrase wrap to export; set a passphrase first');
    }
    final recovery = await _store.read(WrapSlot.recovery);
    final vault = await _store.read(WrapSlot.vault);
    return {
      'v': backupVersion,
      'passphrase': passphrase.toJson(),
      if (recovery != null) 'recovery': recovery.toJson(),
      if (vault != null) 'vault': vault.toJson(),
    };
  }

  /// Restores a keyring state from an exported [backup] map.
  Future<NemoRestore> restoreFromBackup({
    required Map<String, dynamic> backup,
    required String passphrase,
  }) async {
    if (await _store.isInitialized) {
      throw StateError('restoreFromBackup requires an empty store');
    }
    final passphraseJson = backup['passphrase'] ?? backup;
    final wrap = KeyWrap.fromJson(
      (passphraseJson as Map).cast<String, dynamic>(),
    );
    if (wrap.params == null) return const NemoRestore._(false, null);

    final kek = await NemoKdf.deriveAsync(passphrase, wrap.params!);
    final SecureKey master;
    try {
      master = NemoCipher.unwrapKey(wrap.sealed, kek, _masterAad);
    } on NemoCryptoException {
      return const NemoRestore._(false, null);
    } finally {
      kek.dispose();
    }

    var installed = false;
    try {
      await _store.write(WrapSlot.passphrase, wrap);

      final recoveryJson = backup['recovery'];
      String? newRecoveryKey;
      if (recoveryJson != null) {
        await _store.write(
          WrapSlot.recovery,
          KeyWrap.fromJson((recoveryJson as Map).cast<String, dynamic>()),
        );
      } else {
        newRecoveryKey = await _mintRecoveryKey(master);
      }

      final vaultJson = backup['vault'];
      if (vaultJson != null) {
        await _store.write(
          WrapSlot.vault,
          KeyWrap.fromJson((vaultJson as Map).cast<String, dynamic>()),
        );
      }

      await _cacheMaster(master);
      await _store.markInitialized();
      _install(master);
      installed = true;
      _setStatus(NemoStatus.unlocked);
      return NemoRestore._(true, newRecoveryKey);
    } finally {
      if (!installed) master.dispose();
    }
  }

  NemoStatus _setStatus(NemoStatus status) {
    _status = status;
    if (!_statusChanges.isClosed) _statusChanges.add(status);
    return status;
  }

  void _setVaultOpen(bool open) {
    _vaultOpen = open;
    if (!_vaultChanges.isClosed) _vaultChanges.add(open);
  }

  void _install(SecureKey master) {
    _disposeKeys();
    try {
      _master = master;
      _contentKey = NemoKdf.subKey(master, NemoKdf.subContent);
      final seed = NemoKdf.subKey(master, NemoKdf.subSigning);
      try {
        _signPair = SodiumProvider.sodium.crypto.sign.seedKeyPair(seed);
      } finally {
        seed.dispose();
      }
    } catch (_) {
      _disposeKeys();
      rethrow;
    }
  }

  void _disposeKeys() {
    _master?.dispose();
    _contentKey?.dispose();
    _signPair?.dispose();
    _master = null;
    _contentKey = null;
    _signPair = null;
  }
}
