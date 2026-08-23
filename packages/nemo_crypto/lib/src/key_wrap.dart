import 'cipher.dart';
import 'crypto_utils.dart';
import 'kdf.dart';

/// Represents an encrypted key and the parameters required to unwrap it.
class KeyWrap {
  /// The KDF settings required to derive the wrapping key.
  ///
  /// Null if the wrapping key is a raw recovery key rather than passphrase-derived.
  final KdfParams? params;

  /// The encrypted key blob.
  final SealedBytes sealed;

  const KeyWrap({required this.sealed, this.params});

  /// Serializes to JSON. Includes the cipher name for format versioning.
  Map<String, dynamic> toJson() => {
    if (params != null) 'kdf': params!.toJson(),
    'cipher': 'xchacha20poly1305-ietf',
    ...sealed.toJson(),
  };

  static KeyWrap fromJson(Map<String, dynamic> json) => KeyWrap(
    params: json['kdf'] == null
        ? null
        : KdfParams.fromJson((json['kdf'] as Map).cast<String, dynamic>()),
    sealed: checked(SealedBytes.fromJson(json)),
  );

  /// Validates that the sealed blob is structurally sound
  static SealedBytes checked(SealedBytes sealed) {
    if (sealed.nonce.isEmpty || sealed.cipherText.isEmpty) {
      throw NemoCryptoException('malformed key wrap');
    }
    return sealed;
  }
}
