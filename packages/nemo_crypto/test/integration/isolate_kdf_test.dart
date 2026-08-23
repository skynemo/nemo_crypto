import 'dart:typed_data';

import 'package:nemo_crypto/nemo_crypto.dart';
import 'package:test/test.dart';

KdfParams _fastParams() => KdfParams(
  salt: Uint8List.fromList(List<int>.generate(16, (i) => i + 1)),
  opsLimit: 1,
  memLimit: 8192,
);

void main() {
  setUpAll(() async => Nemo.initialize());

  group('Argon2id isolates', () {
    test('deriveAsync matches synchronous output', () async {
      final sync = NemoKdf.derive('shared secret', _fastParams());
      final async = await NemoKdf.deriveAsync('shared secret', _fastParams());
      try {
        expect(async.extractBytes(), equals(sync.extractBytes()));
      } finally {
        sync.dispose();
        async.dispose();
      }
    });
  });

  group('calibrateAsync', () {
    test('honors memory floor constraints', () async {
      final params = await NemoKdf.calibrateAsync(
        budgetMillis: 1,
        maxMemLimit: NemoKdf.minMemLimit,
      );
      expect(params.memLimit, lessThanOrEqualTo(NemoKdf.minMemLimit));
      expect(params.opsLimit, NemoKdf.minOpsLimit);
      expect(params.salt, isNotEmpty);
      params.validate();
    });

    test('respects arbitrary ceiling caps', () async {
      final params = await NemoKdf.calibrateAsync(
        budgetMillis: 1,
        maxMemLimit: 16 * 1024 * 1024,
      );
      expect(params.memLimit, lessThanOrEqualTo(16 * 1024 * 1024));
    });
  });
}
