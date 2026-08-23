import 'package:sodium/sodium_sumo.dart';

import 'sodium_provider.dart';

/// The main entry point for the Nemo Crypto library.
class Nemo {
  const Nemo._();

  /// Initializes the underlying cryptography engine.
  ///
  /// Must be called once before interacting with [Keyring] or any cryptographic functions.
  static Future<void> initialize() => SodiumProvider.init();

  /// Adopts an externally initialized libsodium handle.
  static void adopt(SodiumSumo sodium) => SodiumProvider.adopt(sodium);
}
