import 'dart:convert';
import 'dart:typed_data';

import 'package:sodium/sodium_sumo.dart';

import 'crypto_utils.dart';
import 'sodium_provider.dart';

/// Defines the branch under which a record's content key is wrapped.
///
/// Values are persisted and must not be renumbered.
enum WrapSource {
  /// Wrapped under the content subkey. Available when the keyring is unlocked.
  primary(0),

  /// Wrapped under the vault key. Requires the vault compartment to be open.
  vault(1);

  const WrapSource(this.id);

  /// The persisted integer identifier for this source.
  final int id;

  /// Resolves a [WrapSource] from its persisted identifier.
  ///
  /// Throws [NemoCryptoException] if the [id] is unknown.
  static WrapSource fromId(int id) => switch (id) {
    0 => WrapSource.primary,
    1 => WrapSource.vault,
    _ => throw NemoCryptoException('unknown wrap source'),
  };
}

/// A nonce and ciphertext pair produced by [NemoCipher.seal].
class SealedBytes {
  /// The 24-byte nonce used during encryption.
  final Uint8List nonce;

  /// The ciphertext with the appended Poly1305 authentication tag.
  final Uint8List cipherText;

  const SealedBytes({required this.nonce, required this.cipherText});

  /// Returns the nonce followed by the ciphertext as a single continuous blob.
  Uint8List get joined => Uint8List(nonce.length + cipherText.length)
    ..setRange(0, nonce.length, nonce)
    ..setRange(nonce.length, nonce.length + cipherText.length, cipherText);

  /// Splits a continuous blob into its [nonce] and [cipherText] components.
  ///
  /// Throws [NemoCryptoException] if the blob is shorter than [nonceLength].
  static SealedBytes split(Uint8List joined, {int? nonceLength}) {
    final length = nonceLength ?? NemoCipher.nonceBytes;
    if (joined.length <= length) {
      throw NemoCryptoException('sealed blob too short');
    }
    return SealedBytes(
      nonce: Uint8List.sublistView(joined, 0, length),
      cipherText: Uint8List.sublistView(joined, length),
    );
  }

  /// Serializes to JSON. Both fields are base64 encoded.
  Map<String, dynamic> toJson() => {
    'n': base64Encode(nonce),
    'c': base64Encode(cipherText),
  };

  /// Deserializes from JSON.
  static SealedBytes fromJson(Map<String, dynamic> json) => SealedBytes(
    nonce: base64Decode(json['n'] as String),
    cipherText: base64Decode(json['c'] as String),
  );
}

/// Provides authenticated encryption using XChaCha20-Poly1305 (IETF).
class NemoCipher {
  const NemoCipher._();

  static Aead get _aead =>
      SodiumProvider.sodium.crypto.aeadXChaCha20Poly1305IETF;

  /// The required key size in bytes (32).
  static int get keyBytes => _aead.keyBytes;

  /// The required nonce size in bytes (24).
  static int get nonceBytes => _aead.nonceBytes;

  /// Encrypts [plain] under [key] using a randomly generated nonce.
  ///
  /// The optional [aad] (Associated Data) is authenticated but not encrypted.
  static SealedBytes seal(Uint8List plain, SecureKey key, {String? aad}) {
    final nonce = CryptoUtils.randomBytes(_aead.nonceBytes);
    final cipherText = _aead.encrypt(
      message: plain,
      nonce: nonce,
      key: key,
      additionalData: aad == null ? null : Uint8List.fromList(utf8.encode(aad)),
    );
    return SealedBytes(nonce: nonce, cipherText: cipherText);
  }

  /// Decrypts and verifies [sealed].
  ///
  /// Throws [NemoCryptoException] if the key, nonce, ciphertext, or [aad] fails authentication.
  static Uint8List open(SealedBytes sealed, SecureKey key, {String? aad}) {
    try {
      return _aead.decrypt(
        cipherText: sealed.cipherText,
        nonce: sealed.nonce,
        key: key,
        additionalData: aad == null
            ? null
            : Uint8List.fromList(utf8.encode(aad)),
      );
    } on SodiumException {
      throw NemoCryptoException('authentication failed');
    }
  }

  /// Pads [plain] using [NemoPadding] prior to encryption.
  static SealedBytes sealPadded(Uint8List plain, SecureKey key, {String? aad}) {
    final padded = NemoPadding.pad(plain);
    try {
      return seal(padded, key, aad: aad);
    } finally {
      CryptoUtils.wipe(padded);
    }
  }

  /// Decrypts [sealed] and strips the padding applied by [sealPadded].
  static Uint8List openPadded(
    SealedBytes sealed,
    SecureKey key, {
    String? aad,
  }) {
    final padded = open(sealed, key, aad: aad);
    try {
      return NemoPadding.unpad(padded);
    } finally {
      CryptoUtils.wipe(padded);
    }
  }

  /// Encrypts [key] under [wrappingKey] for storage.
  static SealedBytes wrapKey(SecureKey key, SecureKey wrappingKey, String aad) {
    final bytes = key.extractBytes();
    try {
      return seal(bytes, wrappingKey, aad: aad);
    } finally {
      CryptoUtils.wipe(bytes);
    }
  }

  /// Decrypts a wrapped key and loads it into guarded memory.
  ///
  /// The caller owns the returned [SecureKey] and must call `dispose()` on it.
  static SecureKey unwrapKey(
    SealedBytes sealed,
    SecureKey wrappingKey,
    String aad,
  ) {
    final bytes = open(sealed, wrappingKey, aad: aad);
    try {
      return SecureKey.fromList(SodiumProvider.sodium, bytes);
    } finally {
      CryptoUtils.wipe(bytes);
    }
  }
}
