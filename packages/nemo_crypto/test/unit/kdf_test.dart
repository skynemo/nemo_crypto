import 'dart:convert';
import 'dart:typed_data';

import 'package:nemo_crypto/nemo_crypto.dart';
import 'package:sodium/sodium_sumo.dart';
import 'package:test/test.dart';

/// Golden master key: bytes 0x00..0x1F.
SecureKey _goldenMaster() => SecureKey.fromList(
  SodiumProvider.sodium,
  Uint8List.fromList(List<int>.generate(32, (i) => i)),
);

KdfParams _fastParams() => KdfParams(
  salt: Uint8List.fromList(List<int>.generate(16, (i) => i + 1)),
  opsLimit: 1,
  memLimit: 8192,
);

void main() {
  setUpAll(() async => Nemo.initialize());

  group('subkey derivation goldens', () {
    const expected = {
      NemoKdf.subContent: 'bELK+UGpAbu+FZzcLgUwo8yNLh+i4KQGz3sKCIdCYBU=',
      NemoKdf.subSigning: '1xYE7OfQlL7TUs3sdhTukqG6Iyyt+5vGdRbDdZNtf8I=',
      16: 'tjtE33GZeMp+Fdl97XMtc18U4hUBotkiM2qqu8WYEk4=',
      17: 'cAiV1cDrwTVmVer5TkoUI3seaUFzsl2d+vquwjIvV1A=',
    };

    test('context string matches libsodium strict length', () {
      expect(
        NemoKdf.rootContext.length,
        SodiumProvider.sodium.crypto.kdf.contextBytes,
      );
    });

    test('derives exact pinned subkeys', () {
      final master = _goldenMaster();
      try {
        expected.forEach((id, golden) {
          final key = NemoKdf.subKey(master, id);
          try {
            expect(base64Encode(key.extractBytes()), golden, reason: 'id $id');
          } finally {
            key.dispose();
          }
        });
      } finally {
        master.dispose();
      }
    });

    test('signing subkey seeds a stable Ed25519 pair', () {
      final master = _goldenMaster();
      final seed = NemoKdf.subKey(master, NemoKdf.subSigning);
      try {
        final pair = SodiumProvider.sodium.crypto.sign.seedKeyPair(seed);
        try {
          expect(
            base64Encode(pair.publicKey),
            'hl5H4L2ihR9qjAnUjiB8Oht9W2oy9PBd6QBqVDXC+sw=',
          );
        } finally {
          pair.dispose();
        }
      } finally {
        seed.dispose();
        master.dispose();
      }
    });

    test('distinct subkey ids produce distinct keys', () {
      final master = _goldenMaster();
      try {
        final seen = <String>{};
        for (final id in expected.keys) {
          final key = NemoKdf.subKey(master, id);
          try {
            expect(seen.add(base64Encode(key.extractBytes())), isTrue);
          } finally {
            key.dispose();
          }
        }
      } finally {
        master.dispose();
      }
    });

    test('deriveLabelledKey is deterministic and label-sensitive', () {
      final master = _goldenMaster();
      try {
        final a = NemoKdf.deriveLabelledKey('sha256:abc', master);
        final b = NemoKdf.deriveLabelledKey('sha256:abc', master);
        final c = NemoKdf.deriveLabelledKey('sha256:abd', master);
        try {
          expect(
            base64Encode(a.extractBytes()),
            '9fLSF/4mUOfmWhPQTNKXQPrMYhKHfNdH3ooe0VAKf4I=',
          );
          expect(a.extractBytes(), equals(b.extractBytes()));
          expect(a.extractBytes(), isNot(equals(c.extractBytes())));
        } finally {
          a.dispose();
          b.dispose();
          c.dispose();
        }
      } finally {
        master.dispose();
      }
    });
  });

  group('Argon2id', () {
    test('matches pinned vector', () {
      final key = NemoKdf.derive('correct horse battery staple', _fastParams());
      try {
        expect(
          base64Encode(key.extractBytes()),
          'rES6BU4UbxsOn1EiDGbewpb5NghpLMq6iqvnrcXUtks=',
        );
      } finally {
        key.dispose();
      }
    });

    test('different passphrase yields different key', () {
      final a = NemoKdf.derive('passphrase-a', _fastParams());
      final b = NemoKdf.derive('passphrase-b', _fastParams());
      try {
        expect(a.extractBytes(), isNot(equals(b.extractBytes())));
      } finally {
        a.dispose();
        b.dispose();
      }
    });

    test('different salt yields different key', () {
      final params = _fastParams();
      final other = KdfParams(
        salt: Uint8List.fromList(List<int>.generate(16, (i) => i + 99)),
        opsLimit: params.opsLimit,
        memLimit: params.memLimit,
      );
      final a = NemoKdf.derive('same', params);
      final b = NemoKdf.derive('same', other);
      try {
        expect(a.extractBytes(), isNot(equals(b.extractBytes())));
      } finally {
        a.dispose();
        b.dispose();
      }
    });

    test('rejects invalid parameters', () {
      for (final params in [
        KdfParams(salt: Uint8List(16), opsLimit: 0, memLimit: 8192),
        KdfParams(salt: Uint8List(16), opsLimit: 1, memLimit: 1),
        KdfParams(salt: Uint8List(0), opsLimit: 1, memLimit: 8192),
      ]) {
        expect(
          () => NemoKdf.derive('x', params),
          throwsA(isA<NemoCryptoException>()),
        );
      }
    });
  });

  group('KdfParams serialization', () {
    test('round-trips through JSON', () {
      final params = _fastParams();
      final back = KdfParams.fromJson(params.toJson());
      expect(back.salt, params.salt);
      expect(back.opsLimit, params.opsLimit);
      expect(back.memLimit, params.memLimit);
      expect(back.algId, params.algId);
      expect(back.version, params.version);
    });

    test('rejects unknown algorithm name', () {
      final json = _fastParams().toJson()..['algo'] = 'scrypt';
      expect(
        () => KdfParams.fromJson(json),
        throwsA(isA<NemoCryptoException>()),
      );
    });

    test('rejects out-of-range memory limit', () {
      final json = _fastParams().toJson()..['mem'] = 1 << 40;
      expect(
        () => KdfParams.fromJson(json),
        throwsA(isA<NemoCryptoException>()),
      );
    });
  });
}
