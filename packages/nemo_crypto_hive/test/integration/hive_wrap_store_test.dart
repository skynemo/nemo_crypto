import 'dart:io';
import 'dart:typed_data';

import 'package:hive_ce/hive.dart';
import 'package:nemo_crypto/nemo_crypto.dart';
import 'package:nemo_crypto_hive/nemo_crypto_hive.dart';
import 'package:test/test.dart';

KdfParams _fast() => KdfParams(
  salt: Uint8List.fromList(List<int>.generate(16, (i) => i + 1)),
  opsLimit: 1,
  memLimit: 8192,
);

void main() {
  late Directory tempDir;
  late Box<dynamic> box;
  late HiveWrapStore store;

  setUpAll(() async => Nemo.initialize());

  setUp(() async {
    tempDir = await Directory.systemTemp.createTemp('nemo_crypto_hive_test');
    Hive.init(tempDir.path);
    box = await Hive.openBox<dynamic>('meta');
    store = HiveWrapStore(box);
  });

  tearDown(() async {
    await box.close();
    await tempDir.delete(recursive: true);
  });

  group('WrapStore contract', () {
    test('starts empty', () async {
      expect(await store.isInitialized, isFalse);
      expect(await store.read(WrapSlot.passphrase), isNull);
    });

    test('round-trips a wrap through Hive, params included', () async {
      final key = CryptoUtils.randomKey(NemoCipher.keyBytes);
      final kek = CryptoUtils.randomKey(NemoCipher.keyBytes);
      try {
        final params = _fast();
        await store.write(
          WrapSlot.passphrase,
          KeyWrap(
            params: params,
            sealed: NemoCipher.wrapKey(key, kek, 'nemo:test'),
          ),
        );

        final back = await store.read(WrapSlot.passphrase);
        expect(back, isNotNull);
        expect(back!.params!.salt, params.salt);
        expect(back.params!.opsLimit, params.opsLimit);
        expect(back.params!.memLimit, params.memLimit);

        final unwrapped = NemoCipher.unwrapKey(back.sealed, kek, 'nemo:test');
        try {
          expect(unwrapped.extractBytes(), equals(key.extractBytes()));
        } finally {
          unwrapped.dispose();
        }
      } finally {
        key.dispose();
        kek.dispose();
      }
    });

    test('a wrap without params round-trips too', () async {
      final key = CryptoUtils.randomKey(NemoCipher.keyBytes);
      final kek = CryptoUtils.randomKey(NemoCipher.keyBytes);
      try {
        await store.write(
          WrapSlot.recovery,
          KeyWrap(sealed: NemoCipher.wrapKey(key, kek, 'nemo:test')),
        );
        expect((await store.read(WrapSlot.recovery))!.params, isNull);
      } finally {
        key.dispose();
        kek.dispose();
      }
    });

    test('slots are independent', () async {
      final key = CryptoUtils.randomKey(NemoCipher.keyBytes);
      try {
        for (final slot in WrapSlot.values) {
          await store.write(
            slot,
            KeyWrap(sealed: NemoCipher.wrapKey(key, key, slot.name)),
          );
        }
        await store.delete(WrapSlot.vault);
        expect(await store.read(WrapSlot.passphrase), isNotNull);
        expect(await store.read(WrapSlot.recovery), isNotNull);
        expect(await store.read(WrapSlot.vault), isNull);
      } finally {
        key.dispose();
      }
    });

    test('persists across reopening the box', () async {
      final key = CryptoUtils.randomKey(NemoCipher.keyBytes);
      try {
        await store.markInitialized();
        await store.write(
          WrapSlot.passphrase,
          KeyWrap(sealed: NemoCipher.wrapKey(key, key, 'nemo:test')),
        );
        await box.close();

        box = await Hive.openBox<dynamic>('meta');
        final reopened = HiveWrapStore(box);
        expect(await reopened.isInitialized, isTrue);
        expect(await reopened.read(WrapSlot.passphrase), isNotNull);
      } finally {
        key.dispose();
      }
    });

    test('clear removes everything it owns', () async {
      final key = CryptoUtils.randomKey(NemoCipher.keyBytes);
      try {
        await store.markInitialized();
        await store.write(
          WrapSlot.passphrase,
          KeyWrap(sealed: NemoCipher.wrapKey(key, key, 'nemo:test')),
        );

        await store.clear();
        expect(await store.isInitialized, isFalse);
        expect(await store.read(WrapSlot.passphrase), isNull);
      } finally {
        key.dispose();
      }
    });

    test('leaves unrelated box entries alone', () async {
      await box.put('app_theme', 'dark');
      await store.markInitialized();
      await store.clear();
      expect(box.get('app_theme'), 'dark');
    });

    test('a prefix keeps two keyrings apart in one box', () async {
      final other = HiveWrapStore(box, prefix: 'second_');
      await store.markInitialized();
      expect(await store.isInitialized, isTrue);
      expect(await other.isInitialized, isFalse);
    });

    test('rejects a structurally impossible stored wrap', () async {
      await box.put('nemo_wrap_passphrase', {
        'n': Uint8List(24),
        'c': Uint8List(0),
      });
      expect(
        () => store.read(WrapSlot.passphrase),
        throwsA(isA<NemoCryptoException>()),
      );
    });
  });

  group('end to end through Keyring', () {
    test('a keyring survives a full restart on this store', () async {
      final cache = InMemoryMasterKeyCache();
      final keyring = Keyring(store, cache: cache);
      final recovery = await keyring.create(passphrase: 'pw', params: _fast());
      final content = keyring.contentKey.extractBytes();
      await keyring.dispose();
      await box.close();

      box = await Hive.openBox<dynamic>('meta');
      final revived = Keyring(HiveWrapStore(box), cache: cache);
      expect(await revived.init(trySilentUnlock: false), NemoStatus.locked);
      expect(await revived.unlockWithPassphrase('pw'), isTrue);
      expect(revived.contentKey.extractBytes(), equals(content));

      revived.lock();
      expect(await revived.unlockWithRecoveryKey(recovery), isTrue);
      await revived.dispose();
    });
  });
}
