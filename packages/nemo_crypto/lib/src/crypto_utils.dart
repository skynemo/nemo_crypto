import 'dart:typed_data';

import 'package:sodium/sodium_sumo.dart';

import 'sodium_provider.dart';

/// Thrown when key material is requested but the keyring is locked.
class NemoLockedException implements Exception {
  @override
  String toString() => 'Keyring is locked: no key material in memory';
}

/// Generic exception for cryptographic failures.
class NemoCryptoException implements Exception {
  /// The specific failure reason.
  final String message;

  NemoCryptoException(this.message);

  @override
  String toString() => 'NemoCryptoException: $message';
}

/// Utility functions for randomness, encoding, and memory hygiene.
class CryptoUtils {
  const CryptoUtils._();

  /// Generates [length] random bytes using libsodium's CSPRNG
  static Uint8List randomBytes(int length) =>
      SodiumProvider.sodium.randombytes.buf(length);

  /// Generates a random key in guarded native memory.
  static SecureKey randomKey(int length) =>
      SecureKey.random(SodiumProvider.sodium, length);

  /// Generates a random 128-bit identifier encoded as base32.
  static String newId() => base32Encode(randomBytes(16));

  static const _alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  static const _separators = ' -_';

  /// Encodes [bytes] to Crockford's base32 format.
  static String base32Encode(Uint8List bytes) {
    final out = StringBuffer();
    var buffer = 0;
    var bits = 0;
    for (final b in bytes) {
      buffer = (buffer << 8) | b;
      bits += 8;
      while (bits >= 5) {
        out.write(_alphabet[(buffer >> (bits - 5)) & 31]);
        bits -= 5;
      }
    }
    if (bits > 0) out.write(_alphabet[(buffer << (5 - bits)) & 31]);
    return out.toString();
  }

  /// Decodes Crockford's base32 format string.
  ///
  /// Converts input to uppercase, ignores separators, and normalizes
  /// look-alike characters (O->0, I/L->1).
  static Uint8List base32Decode(String input) {
    var buffer = 0;
    var bits = 0;
    final out = <int>[];
    for (final ch in input.toUpperCase().split('')) {
      if (_separators.contains(ch)) continue;
      final value = _decodeChar(ch);
      if (value < 0) {
        throw NemoCryptoException('invalid base32 character');
      }
      buffer = (buffer << 5) | value;
      bits += 5;
      if (bits >= 8) {
        out.add((buffer >> (bits - 8)) & 0xFF);
        bits -= 8;
      }
    }
    return Uint8List.fromList(out);
  }

  static int _decodeChar(String ch) => switch (ch) {
    'O' => 0,
    'I' || 'L' => 1,
    _ => _alphabet.indexOf(ch),
  };

  /// Formats a base32 string into blocks of [groupSize] separated by dashes.
  static String groupForDisplay(String raw, {int groupSize = 4}) {
    final groups = <String>[];
    for (var i = 0; i < raw.length; i += groupSize) {
      final end = i + groupSize;
      groups.add(raw.substring(i, end > raw.length ? raw.length : end));
    }
    return groups.join('-');
  }

  /// Compares [a] and [b] in constant time.
  static bool constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  /// Overwrites [bytes] with zeroes in memory.
  static void wipe(List<int>? bytes) {
    if (bytes == null) return;
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = 0;
    }
  }
}

/// Implements ISO/IEC 7816-4 padding to obscure plaintext length.
class NemoPadding {
  const NemoPadding._();

  static const _minBucket = 1024;
  static const _maxPowerBucket = 64 * 1024;

  /// Calculates the padded target size for a plaintext of [length] bytes.
  static int bucketFor(int length) {
    final needed = length + 1; // +1 for the 0x80 marker
    if (needed <= _minBucket) return _minBucket;
    if (needed <= _maxPowerBucket) {
      var bucket = _minBucket;
      while (bucket < needed) {
        bucket <<= 1;
      }
      return bucket;
    }
    return ((needed + _maxPowerBucket - 1) ~/ _maxPowerBucket) *
        _maxPowerBucket;
  }

  /// Returns [plain] padded to the boundary determined by [bucketFor].
  static Uint8List pad(Uint8List plain) {
    final out = Uint8List(bucketFor(plain.length))
      ..setRange(0, plain.length, plain);
    out[plain.length] = 0x80;
    return out;
  }

  /// Recovers and returns a copy of the plaintext from a [pad]ded buffer.
  static Uint8List unpad(Uint8List padded) {
    var i = padded.length - 1;
    while (i >= 0 && padded[i] == 0) {
      i--;
    }
    if (i < 0 || padded[i] != 0x80) {
      throw NemoCryptoException('malformed padding');
    }
    return Uint8List.fromList(Uint8List.sublistView(padded, 0, i));
  }
}
