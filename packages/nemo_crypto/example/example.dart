import 'dart:convert';
import 'dart:typed_data';

import 'package:nemo_crypto/nemo_crypto.dart';

void main() async {
  // 1. Initialize the Nemo cryptography engine once
  await Nemo.initialize();

  // 2. Setup an in-memory store for demonstration
  final store = InMemoryWrapStore();
  final keyring = Keyring(store);

  await keyring.init(trySilentUnlock: false);

  // 3. Create the keyring with a user passphrase
  final recoveryKey = await keyring.create(
    passphrase: 'correct horse battery staple',
  );
  print('Recovery key generated: $recoveryKey\n');

  // 4. Encrypt user content
  final contentKey = keyring.newContentKey();
  final plainText = Uint8List.fromList(utf8.encode('Top secret user data'));

  final sealed = NemoCipher.sealPadded(plainText, contentKey);
  final wrap = keyring.wrapContentKey(contentKey);
  contentKey.dispose(); // Always dispose of keys when done

  print(
    'Encrypted payload size: ${sealed.joined.length} bytes (length obfuscated by padding)',
  );

  // 5. Decrypt the content later using the wrap
  final unlockedKey = keyring.unwrapContentKey(wrap, WrapSource.primary);
  final decrypted = NemoCipher.openPadded(sealed, unlockedKey);
  unlockedKey.dispose();

  print('Decrypted message: ${utf8.decode(decrypted)}');
}
