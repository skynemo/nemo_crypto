import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nemo_crypto/nemo_crypto.dart';
import 'package:nemo_crypto_keystore/nemo_crypto_keystore.dart';

class _FakePlatform extends FlutterSecureStoragePlatform {
  final Map<String, String> data = {};
  Map<String, String>? lastWriteOptions;
  Map<String, String>? lastReadOptions;
  Object? failNextReadWith;

  @override
  Future<void> write({
    required String key,
    required String value,
    required Map<String, String> options,
  }) async {
    lastWriteOptions = options;
    data[key] = value;
  }

  @override
  Future<String?> read({
    required String key,
    required Map<String, String> options,
  }) async {
    lastReadOptions = options;
    final failure = failNextReadWith;
    if (failure != null) {
      failNextReadWith = null;
      throw failure;
    }
    return data[key];
  }

  @override
  Future<bool> containsKey({
    required String key,
    required Map<String, String> options,
  }) async => data.containsKey(key);

  @override
  Future<void> delete({
    required String key,
    required Map<String, String> options,
  }) async {
    data.remove(key);
  }

  @override
  Future<Map<String, String>> readAll({
    required Map<String, String> options,
  }) async => Map.of(data);

  @override
  Future<void> deleteAll({required Map<String, String> options}) async =>
      data.clear();
}

KdfParams _fast() => KdfParams(
  salt: Uint8List.fromList(List<int>.generate(16, (i) => i + 1)),
  opsLimit: 1,
  memLimit: 8192,
);

void main() {
  late _FakePlatform platform;

  setUpAll(() async {
    TestWidgetsFlutterBinding.ensureInitialized();
    await Nemo.initialize();
  });

  setUp(() {
    platform = _FakePlatform();
    FlutterSecureStoragePlatform.instance = platform;
  });

  group('through Keyring', () {
    test('supports silent unlock, and stops when disabled', () async {
      final store = InMemoryWrapStore();
      final keyring = Keyring(store, cache: KeystoreMasterKeyCache());
      await keyring.create(passphrase: 'pw', params: _fast());
      expect(platform.data, isNotEmpty);

      keyring.lock();
      expect(await keyring.init(), NemoStatus.unlocked);

      await keyring.forgetCachedKey();
      expect(platform.data, isEmpty);
      keyring.lock();
      expect(await keyring.init(), NemoStatus.locked);
      await keyring.dispose();
    });

    test('a denied prompt is reported, not thrown', () async {
      final store = InMemoryWrapStore();
      final errors = <Object>[];
      final keyring = Keyring(
        store,
        cache: KeystoreMasterKeyCache(),
        onError: (e, _) => errors.add(e),
      );
      await keyring.create(passphrase: 'pw', params: _fast());
      keyring.lock();

      platform.failNextReadWith = PlatformException(code: 'AuthCancelled');
      expect(await keyring.init(), NemoStatus.locked);
      expect(errors, hasLength(1));

      expect(await keyring.init(), NemoStatus.unlocked);
      await keyring.dispose();
    });

    test('the stored key really is the master key', () async {
      final store = InMemoryWrapStore();
      final cache = KeystoreMasterKeyCache();
      final keyring = Keyring(store, cache: cache);
      await keyring.create(passphrase: 'pw', params: _fast());

      final raw = base64Decode(platform.data.values.single);
      expect(raw, hasLength(NemoCipher.keyBytes));
      expect(await cache.read(), equals(raw));
      await keyring.dispose();
    });
  });
}
