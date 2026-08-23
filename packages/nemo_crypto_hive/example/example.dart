import 'package:hive_ce/hive.dart';
import 'package:nemo_crypto/nemo_crypto.dart';
import 'package:nemo_crypto_hive/nemo_crypto_hive.dart';

void main() async {
  await SodiumProvider.init();

  // 1. Initialize Hive (In a real app, provide a path via Hive.initFlutter())
  Hive.init('./hive_data');
  final box = await Hive.openBox<dynamic>('crypto_metadata');

  // 2. Plug the Hive box into the Keyring architecture
  final store = HiveWrapStore(box);
  final keyring = Keyring(store);

  // 3. Initialize the keyring state
  await keyring.init();

  if (keyring.status == NemoStatus.none) {
    print('Store is empty. Ready for keyring.create()');
  } else {
    print('Store exists. Ready for keyring.unlockWithPassphrase()');
  }
}
