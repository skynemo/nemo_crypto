import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:nemo_crypto/nemo_crypto.dart';
import 'package:nemo_crypto_keystore/nemo_crypto_keystore.dart';

class _FakePlatform extends FlutterSecureStoragePlatform {
  final Map<String, String> data = {};
  Map<String, String>? lastWriteOptions;
  Map<String, String>? lastReadOptions;

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

  group('MasterKeyCache contract', () {
    test('read returns null before anything is written', () async {
      expect(await KeystoreMasterKeyCache().read(), isNull);
    });

    test('round-trips a key', () async {
      final cache = KeystoreMasterKeyCache();
      final key = Uint8List.fromList(List<int>.generate(32, (i) => i));
      await cache.write(key);
      expect(await cache.read(), equals(key));
    });

    test('delete removes the entry', () async {
      final cache = KeystoreMasterKeyCache();
      await cache.write(Uint8List(32));
      await cache.delete();
      expect(await cache.read(), isNull);
    });

    test('does not retain the buffer it was handed', () async {
      final cache = KeystoreMasterKeyCache();
      final key = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
      await cache.write(key);
      CryptoUtils.wipe(key);
      expect(await cache.read(), isNot(everyElement(0)));
    });

    test('separate entry names do not collide', () async {
      await KeystoreMasterKeyCache(entryName: 'a').write(Uint8List(32));
      expect(await KeystoreMasterKeyCache(entryName: 'b').read(), isNull);
    });
  });

  group('options', () {
    test('the silent constructor asks for no user presence', () {
      final cache = KeystoreMasterKeyCache();
      expect(cache.iosOptions.accessControlFlags, isEmpty);
      expect(cache.macOsOptions.accessControlFlags, isEmpty);
      expect(
        cache.iosOptions.accessibility,
        KeychainAccessibility.first_unlock_this_device,
      );
    });

    test('the biometric constructor requires user presence', () {
      final cache = KeystoreMasterKeyCache.biometric(
        android: const AndroidBiometricOptions(
          title: 'Unlock',
          subtitle: 'Confirm it is you',
          cancel: 'Cancel',
        ),
      );
      expect(
        cache.iosOptions.accessControlFlags,
        contains(AccessControlFlag.userPresence),
      );
      expect(
        cache.macOsOptions.accessControlFlags,
        contains(AccessControlFlag.userPresence),
      );
    });

    test('biometric and silent options differ on every platform', () {
      final silent = KeystoreMasterKeyCache();
      final biometric = KeystoreMasterKeyCache.biometric(
        android: const AndroidBiometricOptions(
          title: 'Unlock',
          subtitle: 'Confirm it is you',
          cancel: 'Cancel',
        ),
      );

      expect(
        biometric.androidOptions.toMap(),
        isNot(equals(silent.androidOptions.toMap())),
      );
      expect(
        biometric.iosOptions.toMap(),
        isNot(equals(silent.iosOptions.toMap())),
      );
    });

    test('the default Apple policy survives a reboot but stays on-device', () {
      final cache = KeystoreMasterKeyCache();
      expect(
        cache.iosOptions.accessibility,
        KeychainAccessibility.first_unlock_this_device,
      );
      expect(cache.iosOptions.synchronizable, isFalse);
    });

    test('AppleKeychainPolicy.whileUnlocked is stricter than the default', () {
      expect(
        AppleKeychainPolicy.silent.accessibility,
        KeychainAccessibility.first_unlock_this_device,
      );
      expect(
        AppleKeychainPolicy.whileUnlocked.accessibility,
        KeychainAccessibility.unlocked_this_device,
      );
      expect(
        AppleKeychainPolicy.whileUnlockedMacOs.accessibility,
        KeychainAccessibility.unlocked_this_device,
      );
    });

    test('AppleKeychainPolicy.synchronized opts into iCloud Keychain', () {
      expect(AppleKeychainPolicy.synchronized.synchronizable, isTrue);
      expect(AppleKeychainPolicy.synchronizedMacOs.synchronizable, isTrue);
      expect(
        AppleKeychainPolicy.synchronized.accessibility,
        KeychainAccessibility.first_unlock,
      );
      expect(AppleKeychainPolicy.silent.synchronizable, isFalse);
    });

    test('every Apple policy is a distinct set of options', () {
      final maps = {
        AppleKeychainPolicy.silent.toMap().toString(),
        AppleKeychainPolicy.whileUnlocked.toMap().toString(),
        AppleKeychainPolicy.synchronized.toMap().toString(),
        AppleKeychainPolicy.biometric.toMap().toString(),
      };
      expect(maps, hasLength(4));
    });

    test('biometric is the one policy that also binds Android', () {
      final silent = KeystoreMasterKeyCache();
      final biometric = KeystoreMasterKeyCache.biometric(
        android: const AndroidBiometricOptions(
          title: 'Unlock',
          subtitle: 'Confirm it is you',
          cancel: 'Cancel',
        ),
      );
      expect(biometric.androidOptions.toMap()['enforceBiometrics'], 'true');
      expect(silent.androidOptions.toMap()['enforceBiometrics'], 'false');
      expect(
        biometric.androidOptions.toMap(),
        isNot(equals(silent.androidOptions.toMap())),
      );
    });

    test('an Apple policy can be handed to the plain constructor', () {
      final cache = KeystoreMasterKeyCache(
        iosOptions: AppleKeychainPolicy.whileUnlocked,
        macOsOptions: AppleKeychainPolicy.whileUnlockedMacOs,
      );
      expect(
        cache.iosOptions.accessibility,
        KeychainAccessibility.unlocked_this_device,
      );
    });

    test('options for every platform are carried, not just Apple', () {
      final cache = KeystoreMasterKeyCache(
        windowsOptions: const WindowsOptions(useBackwardCompatibility: true),
        webOptions: const WebOptions(dbName: 'custom_db'),
      );
      expect(cache.windowsOptions.toMap()['useBackwardCompatibility'], 'true');
      expect(cache.webOptions.toMap()['dbName'], 'custom_db');
      expect(cache.linuxOptions, isNotNull);
    });

    test('biometric still lets the other platforms be configured', () {
      final cache = KeystoreMasterKeyCache.biometric(
        android: const AndroidBiometricOptions(
          title: 'Unlock',
          subtitle: 'Confirm it is you',
          cancel: 'Cancel',
        ),
        windowsOptions: const WindowsOptions(useBackwardCompatibility: true),
        webOptions: const WebOptions(dbName: 'my_app'),
      );

      expect(cache.androidOptions.toMap()['enforceBiometrics'], 'true');
      expect(
        cache.iosOptions.accessControlFlags,
        contains(AccessControlFlag.userPresence),
      );
      expect(cache.windowsOptions.toMap()['useBackwardCompatibility'], 'true');
      expect(cache.webOptions.toMap()['dbName'], 'my_app');
    });

    test('AndroidBiometricOptions carries the Android tuning', () {
      final strong = KeystoreMasterKeyCache.biometric(
        android: const AndroidBiometricOptions(
          title: 'Unlock',
          subtitle: 'Fingerprint only',
          cancel: 'Cancel',
          biometricType: AndroidBiometricType.strongBiometricOnly,
          requireConfirmation: false,
          storageNamespace: 'my_app',
        ),
      );
      final map = strong.androidOptions.toMap();
      expect(map['biometricType'], 'strongBiometricOnly');
      expect(map['requireBiometricConfirmation'], 'false');
      expect(map['storageNamespace'], 'my_app');
    });

    test('the policies compose through the default constructor', () {
      final mixed = KeystoreMasterKeyCache(
        androidOptions: AndroidKeystorePolicy.biometric(
          const AndroidBiometricOptions(
            title: 'Unlock',
            subtitle: 'Confirm it is you',
            cancel: 'Cancel',
          ),
        ),
        iosOptions: AppleKeychainPolicy.synchronized,
        macOsOptions: AppleKeychainPolicy.synchronizedMacOs,
      );
      expect(mixed.androidOptions.toMap()['enforceBiometrics'], 'true');
      expect(mixed.iosOptions.synchronizable, isTrue);
    });

    test('AndroidKeystorePolicy.silent requires no authentication', () {
      expect(
        AndroidKeystorePolicy.silent.toMap()['enforceBiometrics'],
        'false',
      );
    });

    test('raw options override the defaults on any platform', () {
      final custom = KeystoreMasterKeyCache(
        iosOptions: const IOSOptions(
          accessibility: KeychainAccessibility.passcode,
          synchronizable: false,
        ),
        androidOptions: const AndroidOptions(storageNamespace: 'ns'),
      );
      expect(custom.iosOptions.accessibility, KeychainAccessibility.passcode);
      expect(custom.androidOptions.toMap()['storageNamespace'], 'ns');
    });

    test('the same options are used for write and read', () async {
      final cache = KeystoreMasterKeyCache();
      await cache.write(Uint8List(32));
      await cache.read();
      expect(platform.lastReadOptions, equals(platform.lastWriteOptions));
    });
  });
}
