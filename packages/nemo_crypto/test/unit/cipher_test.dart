import 'dart:typed_data';

import 'package:nemo_crypto/nemo_crypto.dart';
import 'package:sodium/sodium_sumo.dart';
import 'package:test/test.dart';

Uint8List _bytes(int length) =>
    Uint8List.fromList(List<int>.generate(length, (i) => i & 0xFF));

/// A deterministic key for reproducible tests.
SecureKey _key(int seed) => SecureKey.fromList(
  SodiumProvider.sodium,
  Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + seed) & 0xFF)),
);

void main() {
  late SecureKey key;

  setUpAll(() async => Nemo.initialize());
  setUp(() => key = _key(1));
  tearDown(() => key.dispose());

  group('seal/open', () {
    test('round-trips with and without AAD', () {
      final plain = _bytes(100);
      expect(NemoCipher.open(NemoCipher.seal(plain, key), key), equals(plain));
      expect(
        NemoCipher.open(
          NemoCipher.seal(plain, key, aad: 'ctx'),
          key,
          aad: 'ctx',
        ),
        equals(plain),
      );
    });

    test('round-trips an empty plaintext', () {
      final plain = Uint8List(0);
      expect(NemoCipher.open(NemoCipher.seal(plain, key), key), equals(plain));
    });

    test('draws a fresh nonce per seal', () {
      final plain = _bytes(64);
      final a = NemoCipher.seal(plain, key);
      final b = NemoCipher.seal(plain, key);
      expect(a.nonce, isNot(equals(b.nonce)));
      expect(a.cipherText, isNot(equals(b.cipherText)));
    });

    test('binds AAD correctly', () {
      final sealed = NemoCipher.seal(_bytes(32), key, aad: 'nemo:a');
      expect(
        () => NemoCipher.open(sealed, key, aad: 'nemo:b'),
        throwsA(isA<NemoCryptoException>()),
      );
      expect(
        () => NemoCipher.open(sealed, key),
        throwsA(isA<NemoCryptoException>()),
      );
    });

    test('rejects tampered ciphertext', () {
      final sealed = NemoCipher.seal(_bytes(32), key);
      final tampered = SealedBytes(
        nonce: sealed.nonce,
        cipherText: Uint8List.fromList(sealed.cipherText)..[0] ^= 0x01,
      );
      expect(
        () => NemoCipher.open(tampered, key),
        throwsA(isA<NemoCryptoException>()),
      );
    });

    test('rejects tampered nonce', () {
      final sealed = NemoCipher.seal(_bytes(32), key);
      final tampered = SealedBytes(
        nonce: Uint8List.fromList(sealed.nonce)..[0] ^= 0x01,
        cipherText: sealed.cipherText,
      );
      expect(
        () => NemoCipher.open(tampered, key),
        throwsA(isA<NemoCryptoException>()),
      );
    });

    test('rejects wrong key', () {
      final sealed = NemoCipher.seal(_bytes(32), key);
      final other = _key(2);
      try {
        expect(
          () => NemoCipher.open(sealed, other),
          throwsA(isA<NemoCryptoException>()),
        );
      } finally {
        other.dispose();
      }
    });
  });

  group('padded seal/open', () {
    test('round-trips', () {
      for (final length in [0, 1, 500, 1024, 5000]) {
        final plain = _bytes(length);
        expect(
          NemoCipher.openPadded(NemoCipher.sealPadded(plain, key), key),
          equals(plain),
          reason: 'length $length',
        );
      }
    });

    test('reveals only the bucket length', () {
      final lengths = [1, 200, 900]
          .map((n) => NemoCipher.sealPadded(_bytes(n), key).cipherText.length)
          .toSet();
      expect(lengths, hasLength(1));
    });

    test('binds AAD through the padded path', () {
      final sealed = NemoCipher.sealPadded(_bytes(10), key, aad: 'a');
      expect(
        () => NemoCipher.openPadded(sealed, key, aad: 'b'),
        throwsA(isA<NemoCryptoException>()),
      );
    });
  });

  group('key wrapping', () {
    test('round-trips a key under its wrapping key', () {
      final content = _key(3);
      final kek = _key(4);
      try {
        final sealed = NemoCipher.wrapKey(content, kek, 'nemo:test');
        final unwrapped = NemoCipher.unwrapKey(sealed, kek, 'nemo:test');
        try {
          expect(unwrapped.extractBytes(), equals(content.extractBytes()));
        } finally {
          unwrapped.dispose();
        }
      } finally {
        content.dispose();
        kek.dispose();
      }
    });

    test('rejects unwrap under a different AAD', () {
      final content = _key(3);
      final kek = _key(4);
      try {
        final sealed = NemoCipher.wrapKey(content, kek, 'nemo:wrap:master');
        expect(
          () => NemoCipher.unwrapKey(sealed, kek, 'nemo:wrap:vault'),
          throwsA(isA<NemoCryptoException>()),
        );
      } finally {
        content.dispose();
        kek.dispose();
      }
    });
  });

  group('SealedBytes framing', () {
    test('joined and split are inverse', () {
      final sealed = NemoCipher.seal(_bytes(48), key);
      final split = SealedBytes.split(sealed.joined);
      expect(split.nonce, equals(sealed.nonce));
      expect(split.cipherText, equals(sealed.cipherText));
      expect(NemoCipher.open(split, key), equals(_bytes(48)));
    });

    test('split defaults to cipher nonce length', () {
      expect(NemoCipher.nonceBytes, 24);
      expect(
        SealedBytes.split(Uint8List(NemoCipher.nonceBytes + 5)).nonce,
        hasLength(24),
      );
    });

    test('rejects blob lacking room for ciphertext', () {
      expect(
        () => SealedBytes.split(Uint8List(NemoCipher.nonceBytes)),
        throwsA(isA<NemoCryptoException>()),
      );
    });

    test('round-trips through JSON', () {
      final sealed = NemoCipher.seal(_bytes(48), key);
      expect(
        NemoCipher.open(SealedBytes.fromJson(sealed.toJson()), key),
        equals(_bytes(48)),
      );
    });
  });

  group('KeyWrap', () {
    test('round-trips through JSON with and without KDF params', () {
      final content = _key(3);
      final kek = _key(4);
      try {
        final params = NemoKdf.freshParams(opsLimit: 1, memLimit: 8192);
        final wrap = KeyWrap(
          params: params,
          sealed: NemoCipher.wrapKey(content, kek, 'nemo:test'),
        );
        final back = KeyWrap.fromJson(wrap.toJson());
        expect(back.params!.salt, params.salt);
        expect(back.params!.opsLimit, params.opsLimit);
        final unwrapped = NemoCipher.unwrapKey(back.sealed, kek, 'nemo:test');
        try {
          expect(unwrapped.extractBytes(), content.extractBytes());
        } finally {
          unwrapped.dispose();
        }

        final bare = KeyWrap(
          sealed: NemoCipher.wrapKey(content, kek, 'nemo:test'),
        );
        expect(KeyWrap.fromJson(bare.toJson()).params, isNull);
      } finally {
        content.dispose();
        kek.dispose();
      }
    });

    test('rejects structurally impossible wrap', () {
      expect(
        () => KeyWrap.checked(
          SealedBytes(nonce: Uint8List(24), cipherText: Uint8List(0)),
        ),
        throwsA(isA<NemoCryptoException>()),
      );
    });
  });
}
