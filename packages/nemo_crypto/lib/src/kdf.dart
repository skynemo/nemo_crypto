import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium/sodium_sumo.dart';

import 'crypto_utils.dart';
import 'sodium_provider.dart';

/// Defines the cost parameters and salt used during key derivation.
class KdfParams {
  /// The 16-byte random salt.
  final Uint8List salt;

  /// The Argon2id time cost (passes over memory).
  final int opsLimit;

  /// The Argon2id memory cost in bytes.
  final int memLimit;

  /// The derivation algorithm identifier ([argon2id] or [argon2i]).
  final int algId;

  /// The schema version for future migrations.
  final int version;

  const KdfParams({
    required this.salt,
    required this.opsLimit,
    required this.memLimit,
    this.algId = 2,
    this.version = 1,
  });

  /// Identifier for Argon2i.
  static const argon2i = 1;

  /// Identifier for Argon2id.
  static const argon2id = 2;

  static const maxOpsLimit = 64;
  static const maxMemLimit = 1024 * 1024 * 1024;
  static const minValidMemLimit = 8 * 1024;

  /// Returns the corresponding libsodium [CryptoPwhashAlgorithm].
  CryptoPwhashAlgorithm get alg => algId == argon2id
      ? CryptoPwhashAlgorithm.argon2id13
      : CryptoPwhashAlgorithm.argon2i13;

  /// Validates the parameter bounds. Throws [NemoCryptoException] if invalid.
  void validate() {
    if (algId != argon2i && algId != argon2id) {
      throw NemoCryptoException('unknown KDF algorithm');
    }
    if (salt.isEmpty) {
      throw NemoCryptoException('KDF salt is empty');
    }
    if (opsLimit < 1 || opsLimit > maxOpsLimit) {
      throw NemoCryptoException('KDF opsLimit out of range');
    }
    if (memLimit < minValidMemLimit || memLimit > maxMemLimit) {
      throw NemoCryptoException('KDF memLimit out of range');
    }
  }

  /// Serializes the parameters to JSON.
  Map<String, dynamic> toJson() => {
    'algo': algId == argon2id ? 'argon2id' : 'argon2i',
    'salt': base64Encode(salt),
    'ops': opsLimit,
    'mem': memLimit,
    'v': version,
  };

  /// Deserializes and validates the parameters from JSON.
  static KdfParams fromJson(Map<String, dynamic> json) => KdfParams(
    salt: base64Decode(json['salt'] as String),
    opsLimit: json['ops'] as int,
    memLimit: json['mem'] as int,
    algId: _algIdFromName(json['algo'] as String?),
    version: json['v'] as int? ?? 1,
  )..validate();

  static int _algIdFromName(String? name) => switch (name) {
    'argon2id' || null => argon2id,
    'argon2i' => argon2i,
    _ => throw NemoCryptoException('unknown KDF algorithm'),
  };
}

/// Provides key derivation functions for passphrases and subkeys.
class NemoKdf {
  const NemoKdf._();

  static const minMemLimit = 64 * 1024 * 1024;
  static const minOpsLimit = 3;
  static const targetMillis = 900;
  static const defaultMaxMemLimit = 256 * 1024 * 1024;

  /// Generates new [KdfParams] with a random salt.
  static KdfParams freshParams({int? opsLimit, int? memLimit}) {
    final pw = SodiumProvider.sodium.crypto.pwhash;
    return KdfParams(
      salt: CryptoUtils.randomBytes(pw.saltBytes),
      opsLimit: opsLimit ?? minOpsLimit,
      memLimit: memLimit ?? minMemLimit,
    );
  }

  /// Determines the optimal memory limit for the current hardware.
  static Future<KdfParams> calibrateAsync({
    int budgetMillis = targetMillis,
    int maxMemLimit = defaultMaxMemLimit,
    int opsLimit = minOpsLimit,
  }) async {
    var mem = maxMemLimit < minMemLimit ? maxMemLimit : minMemLimit;
    const probe = 'calibration-probe';
    while (true) {
      final params = freshParams(memLimit: mem, opsLimit: opsLimit);
      final sw = Stopwatch()..start();
      (await deriveAsync(probe, params)).dispose();
      sw.stop();
      final elapsed = sw.elapsedMilliseconds;

      if (elapsed >= budgetMillis) break;
      if (mem >= maxMemLimit) break;
      if (elapsed * 2 > budgetMillis) break;

      final doubled = mem * 2;
      mem = doubled > maxMemLimit ? maxMemLimit : doubled;
    }
    return freshParams(memLimit: mem, opsLimit: opsLimit);
  }

  /// Derives a 32-byte key from [secret] synchronously.
  static SecureKey derive(String secret, KdfParams params) {
    params.validate();
    final pw = SodiumProvider.sodium.crypto.pwhash;
    final password = Int8List.fromList(utf8.encode(secret));
    try {
      return pw.call(
        outLen: SodiumProvider.sodium.crypto.aeadXChaCha20Poly1305IETF.keyBytes,
        password: password,
        salt: params.salt,
        opsLimit: params.opsLimit,
        memLimit: params.memLimit,
        alg: params.alg,
      );
    } finally {
      CryptoUtils.wipe(password);
    }
  }

  /// Derives a 32-byte key from [secret] on a background isolate.
  static Future<SecureKey> deriveAsync(String secret, KdfParams params) async {
    params.validate();
    final sodium = SodiumProvider.sodium;
    final outLen = sodium.crypto.aeadXChaCha20Poly1305IETF.keyBytes;
    final password = Int8List.fromList(utf8.encode(secret));
    final salt = params.salt;
    final opsLimit = params.opsLimit;
    final memLimit = params.memLimit;
    final alg = params.alg;
    try {
      return await sodium.runIsolated<SecureKey>(
        (_, _) => sodium.crypto.pwhash.call(
          outLen: outLen,
          password: password,
          salt: salt,
          opsLimit: opsLimit,
          memLimit: memLimit,
          alg: alg,
        ),
      );
    } finally {
      CryptoUtils.wipe(password);
    }
  }

  /// Derives a deterministic subkey from [master] using [subkeyId].
  static SecureKey subKey(SecureKey master, int subkeyId) {
    final kdf = SodiumProvider.sodium.crypto.kdf;
    if (rootContext.length != kdf.contextBytes) {
      throw NemoCryptoException(
        'KDF context must be exactly ${kdf.contextBytes} bytes',
      );
    }
    return kdf.deriveFromKey(
      masterKey: master,
      context: rootContext,
      subkeyId: BigInt.from(subkeyId),
      subkeyLen: 32,
    );
  }

  /// Derives a deterministic key from [label] under [key] using keyed BLAKE2b.
  static SecureKey deriveLabelledKey(String label, SecureKey key) {
    final bytes = SodiumProvider.sodium.crypto.genericHash(
      message: Uint8List.fromList(utf8.encode(label)),
      outLen: NemoKdfLimits.subkeyBytes,
      key: key,
    );
    try {
      return SecureKey.fromList(SodiumProvider.sodium, bytes);
    } finally {
      CryptoUtils.wipe(bytes);
    }
  }

  /// The domain separator mixed into all subkey derivations.
  static const rootContext = 'nemo:rt1';

  /// Subkey ID reserved for content keys.
  static const subContent = 1;

  /// Subkey ID reserved for manifest signing seeds.
  static const subSigning = 2;

  /// The lowest subkey ID available for application-specific use.
  static const firstAppSubkeyId = 16;
}

/// Constants defining static key derivation limits.
class NemoKdfLimits {
  const NemoKdfLimits._();

  /// The fixed size in bytes for all derived subkeys.
  static const subkeyBytes = 32;
}
