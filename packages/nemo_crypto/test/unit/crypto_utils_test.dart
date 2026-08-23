import 'dart:typed_data';

import 'package:nemo_crypto/nemo_crypto.dart';
import 'package:test/test.dart';

void main() {
  group('base32', () {
    test('round-trips arbitrary byte patterns', () {
      for (final bytes in [
        <int>[],
        [0],
        [0xFF],
        [0x00, 0x01, 0x02, 0x03, 0x04],
        List<int>.generate(32, (i) => (i * 7 + 13) & 0xFF),
      ]) {
        final input = Uint8List.fromList(bytes);
        final decoded = CryptoUtils.base32Decode(
          CryptoUtils.base32Encode(input),
        );
        expect(
          Uint8List.sublistView(decoded, 0, input.length),
          equals(input),
          reason: 'failed for $bytes',
        );
      }
    });

    test('omits ambiguous letters I, L, O, U', () {
      final encoded = CryptoUtils.base32Encode(
        Uint8List.fromList(List<int>.generate(256, (i) => i)),
      );
      expect(encoded, isNot(matches(RegExp('[ILOU]'))));
    });

    test('normalizes Crockford look-alikes', () {
      expect(CryptoUtils.base32Decode('OO'), CryptoUtils.base32Decode('00'));
      expect(CryptoUtils.base32Decode('II'), CryptoUtils.base32Decode('11'));
      expect(CryptoUtils.base32Decode('LL'), CryptoUtils.base32Decode('11'));
    });

    test('ignores separators', () {
      expect(
        CryptoUtils.base32Decode('ABCD-EFGH JKMN_PQRS'),
        CryptoUtils.base32Decode('ABCDEFGHJKMNPQRS'),
      );
    });

    test('rejects invalid characters', () {
      expect(
        () => CryptoUtils.base32Decode('ABCU'),
        throwsA(isA<NemoCryptoException>()),
      );
    });

    test('omits input from exception messages', () {
      try {
        CryptoUtils.base32Decode('SECRET!KEY');
        fail('expected a NemoCryptoException');
      } on NemoCryptoException catch (e) {
        expect(e.toString(), isNot(contains('SECRET')));
        expect(e.toString(), isNot(contains('!')));
      }
    });

    test('round-trips grouped displays', () {
      final key = Uint8List.fromList(
        List<int>.generate(32, (i) => (i * 31 + 5) & 0xFF),
      );
      final formatted = CryptoUtils.groupForDisplay(
        CryptoUtils.base32Encode(key),
      );
      expect(formatted, contains('-'));
      expect(
        Uint8List.sublistView(CryptoUtils.base32Decode(formatted), 0, 32),
        equals(key),
      );
    });
  });

  group('constantTimeEquals', () {
    test('compares by content and length', () {
      expect(CryptoUtils.constantTimeEquals([1, 2, 3], [1, 2, 3]), isTrue);
      expect(CryptoUtils.constantTimeEquals([1, 2, 3], [1, 2, 4]), isFalse);
      expect(CryptoUtils.constantTimeEquals([1, 2, 3], [1, 2]), isFalse);
      expect(CryptoUtils.constantTimeEquals([], []), isTrue);
    });
  });

  group('wipe', () {
    test('zeroes Uint8List and Int8List buffers', () {
      final unsigned = Uint8List.fromList([1, 2, 3]);
      final signed = Int8List.fromList([-1, 2, -3]);
      CryptoUtils.wipe(unsigned);
      CryptoUtils.wipe(signed);
      expect(unsigned, everyElement(0));
      expect(signed, everyElement(0));
    });
  });

  group('NemoPadding', () {
    test('buckets at standard boundaries', () {
      expect(NemoPadding.bucketFor(0), 1024);
      expect(NemoPadding.bucketFor(1023), 1024);
      expect(NemoPadding.bucketFor(1024), 2048);
      expect(NemoPadding.bucketFor(65535), 65536);
      expect(NemoPadding.bucketFor(65536), 131072);
    });

    test('bucket size scales monotonically', () {
      var previous = 0;
      for (var length = 0; length < 200000; length += 997) {
        final bucket = NemoPadding.bucketFor(length);
        expect(bucket, greaterThan(length));
        expect(bucket, greaterThanOrEqualTo(previous));
        previous = bucket;
      }
    });

    test('round-trips across bucket boundaries', () {
      for (final length in [0, 1, 1023, 1024, 65535, 65536, 70000]) {
        final plain = Uint8List.fromList(
          List<int>.generate(length, (i) => i & 0xFF),
        );
        final padded = NemoPadding.pad(plain);
        expect(padded.length, NemoPadding.bucketFor(length));
        expect(NemoPadding.unpad(padded), equals(plain));
      }
    });

    test('round-trips edge case payload tails', () {
      for (final tail in [
        [0x80],
        [0x00],
        [0x80, 0x00, 0x00],
        [0x00, 0x80],
      ]) {
        final plain = Uint8List.fromList([1, 2, 3, ...tail]);
        expect(NemoPadding.unpad(NemoPadding.pad(plain)), equals(plain));
      }
    });

    test('unpad returns a decoupled copy', () {
      final plain = Uint8List.fromList([9, 8, 7]);
      final padded = NemoPadding.pad(plain);
      final recovered = NemoPadding.unpad(padded);
      CryptoUtils.wipe(padded);
      expect(recovered, equals(plain));
    });

    test('rejects un-terminated buffers', () {
      expect(
        () => NemoPadding.unpad(Uint8List(1024)),
        throwsA(isA<NemoCryptoException>()),
      );
      expect(
        () => NemoPadding.unpad(Uint8List.fromList([1, 2, 3])),
        throwsA(isA<NemoCryptoException>()),
      );
    });
  });

  group('WrapSource', () {
    test('validates stable IDs', () {
      expect(WrapSource.primary.id, 0);
      expect(WrapSource.vault.id, 1);
      expect(WrapSource.fromId(0), WrapSource.primary);
      expect(WrapSource.fromId(1), WrapSource.vault);
      expect(() => WrapSource.fromId(2), throwsA(isA<NemoCryptoException>()));
    });
  });
}
