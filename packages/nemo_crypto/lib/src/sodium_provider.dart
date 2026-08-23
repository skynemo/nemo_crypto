import 'package:sodium/sodium_sumo.dart';

/// Provides global access to the initialized libsodium handle
class SodiumProvider {
  SodiumProvider._();

  static SodiumSumo? _sodium;

  /// Initializes libsodium or returns the existing handle
  static Future<SodiumSumo> init() async =>
      _sodium ??= await SodiumSumoInit.init();

  /// Assigns an externally initialized [SodiumSumo] handle
  static void adopt(SodiumSumo sodium) => _sodium = sodium;

  /// The initialized [SodiumSumo] handle
  ///
  /// Throws [StateError] if [init] has not completed
  static SodiumSumo get sodium {
    final s = _sodium;
    if (s == null) {
      throw StateError('SodiumProvider.init() has not been awaited yet');
    }
    return s;
  }

  /// Indicates whether the handle is initialized on the current isolate
  static bool get isReady => _sodium != null;
}
