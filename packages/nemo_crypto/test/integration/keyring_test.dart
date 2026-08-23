import 'dart:typed_data';

import 'package:nemo_crypto/nemo_crypto.dart';
import 'package:test/test.dart';

KdfParams _fast() => KdfParams(
  salt: Uint8List.fromList(List<int>.generate(16, (i) => i + 1)),
  opsLimit: 1,
  memLimit: 8192,
);

void main() {
  late InMemoryWrapStore store;
  late InMemoryMasterKeyCache cache;
  late Keyring keyring;

  setUpAll(() async => Nemo.initialize());

  setUp(() {
    store = InMemoryWrapStore();
    cache = InMemoryMasterKeyCache();
    keyring = Keyring(store, cache: cache);
  });

  tearDown(() async => keyring.dispose());

  group('create', () {
    test('leaves keyring unlocked with derived subkeys', () async {
      await keyring.create(passphrase: 'pw', params: _fast());

      expect(keyring.status, NemoStatus.unlocked);
      expect(keyring.isUnlocked, isTrue);
      expect(keyring.contentKey.extractBytes(), hasLength(32));
      expect(keyring.manifestPublicKey, hasLength(32));
    });

    test('rejects overwriting an existing keyring', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      await expectLater(
        keyring.create(passphrase: 'other', params: _fast()),
        throwsA(isA<StateError>()),
      );
      expect(keyring.status, NemoStatus.unlocked);
    });

    test('lock zeroes key material', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      keyring.lock();
      expect(keyring.status, NemoStatus.locked);
      expect(() => keyring.contentKey, throwsA(isA<NemoLockedException>()));
    });
  });

  group('app subkeys', () {
    test('are deterministic, distinct, and caller-owned', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      final a = keyring.appSubkey(NemoKdf.firstAppSubkeyId);
      final again = keyring.appSubkey(NemoKdf.firstAppSubkeyId);
      final other = keyring.appSubkey(NemoKdf.firstAppSubkeyId + 1);
      try {
        expect(a.extractBytes(), equals(again.extractBytes()));
        expect(a.extractBytes(), isNot(equals(other.extractBytes())));
        expect(
          a.extractBytes(),
          isNot(equals(keyring.contentKey.extractBytes())),
        );
      } finally {
        a.dispose();
        again.dispose();
        other.dispose();
      }
    });

    test('rejects reserved ids', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      for (final id in [NemoKdf.subContent, NemoKdf.subSigning, 15]) {
        expect(
          () => keyring.appSubkey(id),
          throwsA(isA<NemoCryptoException>()),
          reason: 'id $id',
        );
      }
    });

    test('persist across lock/unlock cycles', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      final before = keyring.appSubkey(20);
      final bytes = Uint8List.fromList(before.extractBytes());
      before.dispose();
      keyring.lock();
      await keyring.unlockWithPassphrase('pw');
      final after = keyring.appSubkey(20);
      try {
        expect(after.extractBytes(), equals(bytes));
      } finally {
        after.dispose();
      }
    });
  });

  group('unlock paths', () {
    test('passphrase reproduces matching subkeys', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      final before = keyring.contentKey.extractBytes();
      keyring.lock();

      expect(await keyring.unlockWithPassphrase('pw'), isTrue);
      expect(keyring.contentKey.extractBytes(), equals(before));
    });

    test('rejects wrong passphrase', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      keyring.lock();
      expect(await keyring.unlockWithPassphrase('nope'), isFalse);
      expect(keyring.status, NemoStatus.locked);
    });

    test('recovery key reproduces matching subkeys', () async {
      final recovery = await keyring.create(passphrase: 'pw', params: _fast());
      final before = keyring.contentKey.extractBytes();
      keyring.lock();

      expect(await keyring.unlockWithRecoveryKey(recovery), isTrue);
      expect(keyring.contentKey.extractBytes(), equals(before));
    });

    test('recovery key tolerates case formatting', () async {
      final recovery = await keyring.create(passphrase: 'pw', params: _fast());
      keyring.lock();
      expect(await keyring.unlockWithRecoveryKey(recovery.toLowerCase()), true);
      keyring.lock();
      expect(
        await keyring.unlockWithRecoveryKey(recovery.replaceAll('-', '')),
        isTrue,
      );
    });

    test('rejects malformed recovery key silently', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      keyring.lock();
      expect(await keyring.unlockWithRecoveryKey('not!a!key'), isFalse);
      expect(await keyring.unlockWithRecoveryKey(''), isFalse);
    });

    test('init unlocks silently from valid cache', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      keyring.lock();
      expect(await keyring.init(), NemoStatus.unlocked);
    });

    test('init bypasses cache if trySilentUnlock is false', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      keyring.lock();
      expect(await keyring.init(trySilentUnlock: false), NemoStatus.locked);
    });

    test('init reports none for empty stores', () async {
      expect(await keyring.init(), NemoStatus.none);
    });

    test('gracefully handles missing cache', () async {
      final cacheless = Keyring(store);
      await cacheless.create(passphrase: 'pw', params: _fast());
      cacheless.lock();
      expect(await cacheless.init(), NemoStatus.locked);
      expect(await cacheless.unlockFromCache(), isFalse);
      expect(await cacheless.unlockWithPassphrase('pw'), isTrue);
      await cacheless.dispose();
    });
  });

  group('master key cache', () {
    test('forgetCachedKey disables silent unlock', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      expect(await cache.read(), isNotNull);
      expect(keyring.cacheInUse, isTrue);

      await keyring.forgetCachedKey();
      expect(await cache.read(), isNull);
      expect(keyring.cacheInUse, isFalse);

      keyring.lock();
      expect(await keyring.init(), NemoStatus.locked);
      expect(await keyring.unlockFromCache(), isFalse);
    });

    test('unlocking preserves forgotten cache state', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      await keyring.forgetCachedKey();
      keyring.lock();

      expect(await keyring.unlockWithPassphrase('pw'), isTrue);
      expect(await cache.read(), isNull);
    });

    test('cacheMasterKey reinstates silent unlock', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      await keyring.forgetCachedKey();
      await keyring.cacheMasterKey();
      expect(await cache.read(), isNotNull);
      expect(keyring.cacheInUse, isTrue);
    });

    test('forgetCachedKey throws if no passphrase exists', () async {
      final bare = Keyring(InMemoryWrapStore(), cache: cache);
      await expectLater(bare.forgetCachedKey(), throwsA(isA<StateError>()));
      await bare.dispose();
    });

    test('keyring gracefully bypasses writes if cache is null', () async {
      final cacheless = Keyring(store);
      await cacheless.create(passphrase: 'pw', params: _fast());

      expect(cacheless.cacheInUse, isFalse);
      expect(await cache.read(), isNull);
      cacheless.lock();
      expect(await cacheless.init(), NemoStatus.locked);
      expect(await cacheless.unlockFromCache(), isFalse);
      expect(await cacheless.unlockWithPassphrase('pw'), isTrue);
      await cacheless.cacheMasterKey();
      expect(await cache.read(), isNull);
      await cacheless.dispose();
    });
  });

  group('vault compartment', () {
    test('locked content keys round-trip', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      await keyring.setVaultPassphrase('vault-pw', params: _fast());
      expect(keyring.isVaultOpen, isTrue);

      final content = keyring.newContentKey();
      final raw = content.extractBytes();
      final wrapped = keyring.wrapContentKey(content, source: WrapSource.vault);

      expect(
        keyring.unwrapContentKey(wrapped, WrapSource.vault).extractBytes(),
        equals(raw),
      );
    });

    test('closing vault revokes locked access', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      await keyring.setVaultPassphrase('vault-pw', params: _fast());
      final wrapped = keyring.wrapContentKey(
        keyring.newContentKey(),
        source: WrapSource.vault,
      );
      keyring.closeVault();

      expect(keyring.isVaultOpen, isFalse);
      expect(
        () => keyring.unwrapContentKey(wrapped, WrapSource.vault),
        throwsA(isA<NemoCryptoException>()),
      );
      expect(await keyring.openVault('vault-pw'), isTrue);
      expect(await keyring.openVault('wrong'), isFalse);
    });

    test('rejects vault passphrase modification if closed', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      await keyring.setVaultPassphrase('vault-pw', params: _fast());
      keyring.closeVault();

      await expectLater(
        keyring.setVaultPassphrase('new-pw', params: _fast()),
        throwsA(isA<NemoCryptoException>()),
      );
      expect(await keyring.openVault('vault-pw'), isTrue);
    });

    test('modifying vault passphrase preserves records', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      await keyring.setVaultPassphrase('vault-pw', params: _fast());

      final content = keyring.newContentKey();
      final raw = content.extractBytes();
      final wrapped = keyring.wrapContentKey(content, source: WrapSource.vault);

      await keyring.setVaultPassphrase('new-pw', params: _fast());
      keyring.closeVault();

      expect(await keyring.openVault('new-pw'), isTrue);
      expect(
        keyring.unwrapContentKey(wrapped, WrapSource.vault).extractBytes(),
        equals(raw),
      );
    });

    test('primary keys bypass vault locks', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      final content = keyring.newContentKey();
      final raw = content.extractBytes();
      final wrapped = keyring.wrapContentKey(content);

      expect(
        keyring.unwrapContentKey(wrapped, WrapSource.primary).extractBytes(),
        equals(raw),
      );
    });
  });

  group('recovery key rotation', () {
    test('invalidates old key on rotation', () async {
      final original = await keyring.create(passphrase: 'pw', params: _fast());
      final rotated = await keyring.rotateRecoveryKey();
      expect(rotated, isNot(equals(original)));

      keyring.lock();
      expect(await keyring.unlockWithRecoveryKey(original), isFalse);
      expect(await keyring.unlockWithRecoveryKey(rotated), isTrue);
    });
  });

  group('backup and restore', () {
    test('preserves recovery key functionality', () async {
      final recovery = await keyring.create(passphrase: 'pw', params: _fast());
      await keyring.setVaultPassphrase('vault-pw', params: _fast());
      final content = keyring.contentKey.extractBytes();
      final backup = await keyring.exportBackup();

      await keyring.wipe();
      expect(keyring.status, NemoStatus.none);

      final result = await keyring.restoreFromBackup(
        backup: backup,
        passphrase: 'pw',
      );
      expect(result.ok, isTrue);
      expect(result.newRecoveryKey, isNull);
      expect(keyring.contentKey.extractBytes(), equals(content));
      expect(await keyring.vaultConfigured, isTrue);
      expect(await keyring.openVault('vault-pw'), isTrue);

      keyring.lock();
      expect(await keyring.unlockWithRecoveryKey(recovery), isTrue);
    });

    test('mints new recovery key for legacy wraps', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      final bare =
          (await keyring.exportBackup())['passphrase'] as Map<String, dynamic>;

      await keyring.wipe();
      final result = await keyring.restoreFromBackup(
        backup: bare,
        passphrase: 'pw',
      );

      expect(result.ok, isTrue);
      expect(result.newRecoveryKey, isNotNull);
      keyring.lock();
      expect(
        await keyring.unlockWithRecoveryKey(result.newRecoveryKey!),
        isTrue,
      );
    });

    test('aborts safely on wrong passphrase', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      final backup = await keyring.exportBackup();
      await keyring.wipe();

      final result = await keyring.restoreFromBackup(
        backup: backup,
        passphrase: 'wrong',
      );
      expect(result.ok, isFalse);
      expect(await store.isInitialized, isFalse);
      expect(keyring.status, NemoStatus.none);
    });

    test('rejects overwrite on populated store', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      final backup = await keyring.exportBackup();
      await expectLater(
        keyring.restoreFromBackup(backup: backup, passphrase: 'pw'),
        throwsA(isA<StateError>()),
      );
    });
  });

  group('manifest signing', () {
    test('verifies signature against designated sequence', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      final body = Uint8List.fromList([1, 2, 3, 4]);
      final digest = keyring.hashManifest(body, seq: 7);
      expect(
        keyring.verifyManifest(digest, keyring.signManifest(digest)),
        isTrue,
      );
    });

    test('binds sequence number to digest to prevent replays', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      final body = Uint8List.fromList([1, 2, 3, 4]);
      final signature = keyring.signManifest(
        keyring.hashManifest(body, seq: 7),
      );

      expect(
        keyring.verifyManifest(keyring.hashManifest(body, seq: 8), signature),
        isFalse,
      );
    });

    test('detects tampered body', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      expect(
        keyring.hashManifest(Uint8List.fromList([1, 2]), seq: 1),
        isNot(equals(keyring.hashManifest(Uint8List.fromList([1, 3]), seq: 1))),
      );
    });

    test('rejects signing when locked', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      final digest = keyring.hashManifest(Uint8List(4), seq: 1);
      keyring.lock();
      expect(
        () => keyring.signManifest(digest),
        throwsA(isA<NemoLockedException>()),
      );
    });

    test('rejects negative sequence IDs', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      expect(
        () => keyring.hashManifest(Uint8List(4), seq: -1),
        throwsA(isA<NemoCryptoException>()),
      );
    });
  });

  group('streams', () {
    test('broadcasts state transitions accurately', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      final seen = <NemoStatus>[];
      final sub = keyring.statusChanges.listen(seen.add);
      await Future<void>.delayed(Duration.zero);
      keyring.lock();
      await Future<void>.delayed(Duration.zero);
      await sub.cancel();
      expect(seen, [NemoStatus.unlocked, NemoStatus.locked]);
    });

    test('broadcasts vault access toggles', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      final seen = <bool>[];
      final sub = keyring.vaultChanges.listen(seen.add);
      await Future<void>.delayed(Duration.zero);
      await keyring.setVaultPassphrase('v', params: _fast());
      keyring.closeVault();
      await Future<void>.delayed(Duration.zero);
      await sub.cancel();
      expect(seen, [false, true, false]);
    });
  });

  group('wipe and dispose', () {
    test('wipe resets core interfaces', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      await keyring.wipe();

      expect(keyring.status, NemoStatus.none);
      expect(await cache.read(), isNull);
      expect(await store.isInitialized, isFalse);
      expect(() => keyring.contentKey, throwsA(isA<NemoLockedException>()));
    });

    test('dispose handles duplicate calls cleanly', () async {
      await keyring.create(passphrase: 'pw', params: _fast());
      await keyring.dispose();
      await expectLater(keyring.statusChanges, emitsThrough(emitsDone));
      await expectLater(keyring.vaultChanges, emitsThrough(emitsDone));
      await keyring.dispose();
    });
  });
}
