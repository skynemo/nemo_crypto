import 'package:nemo_crypto/nemo_crypto.dart';
import 'package:nemo_crypto_keystore/nemo_crypto_keystore.dart';

void main() async {
  await SodiumProvider.init();

  // 1. Configure the OS-level Master Key Cache
  // This setup forces biometric authentication (FaceID/TouchID) where supported.
  final cache = KeystoreMasterKeyCache.biometric(
    android: const AndroidBiometricOptions(
      title: 'Unlock Secure Store',
      subtitle: 'Verify your identity to access keys',
      cancel: 'Cancel',
    ),
  );

  // 2. Pass the cache adapter to the Keyring
  final store = InMemoryWrapStore(); // Usually HiveWrapStore in production
  final keyring = Keyring(store, cache: cache);

  // 3. Attempt silent unlock on launch
  await keyring.init(trySilentUnlock: true);

  if (keyring.isUnlocked) {
    // Keyring unlocked silently via OS Keystore/Keychain
  } else {
    // Cache empty or biometric prompt denied. Fallback to passphrase
  }
}
