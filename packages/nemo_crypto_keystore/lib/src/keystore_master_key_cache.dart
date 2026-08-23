import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:nemo_crypto/nemo_crypto.dart';

/// Defines access policies specific to Apple Keychain.
class AppleKeychainPolicy {
  const AppleKeychainPolicy._();

  /// Allows access after the first device unlock following a reboot. Does not synchronize to iCloud.
  static const IOSOptions silent = IOSOptions(
    accessibility: KeychainAccessibility.first_unlock_this_device,
    synchronizable: false,
  );

  /// Allows access after the first device unlock following a reboot on macOS. Does not synchronize to iCloud.
  static const MacOsOptions silentMacOs = MacOsOptions(
    accessibility: KeychainAccessibility.first_unlock_this_device,
    synchronizable: false,
  );

  /// Requires the device to be unlocked for access. Prevents background access.
  static const IOSOptions whileUnlocked = IOSOptions(
    accessibility: KeychainAccessibility.unlocked_this_device,
    synchronizable: false,
  );

  /// Requires the macOS device to be unlocked for access. Prevents background access.
  static const MacOsOptions whileUnlockedMacOs = MacOsOptions(
    accessibility: KeychainAccessibility.unlocked_this_device,
    synchronizable: false,
  );

  /// Synchronizes the key across devices via iCloud Keychain. Allows access after the first unlock.
  static const IOSOptions synchronized = IOSOptions(
    accessibility: KeychainAccessibility.first_unlock,
    synchronizable: true,
  );

  /// Synchronizes the key across macOS devices via iCloud Keychain. Allows access after the first unlock.
  static const MacOsOptions synchronizedMacOs = MacOsOptions(
    accessibility: KeychainAccessibility.first_unlock,
    synchronizable: true,
  );

  /// Requires biometric authentication or device passcode for every access.
  static const IOSOptions biometric = IOSOptions(
    accessibility: KeychainAccessibility.first_unlock_this_device,
    synchronizable: false,
    accessControlFlags: [AccessControlFlag.userPresence],
  );

  /// Requires biometric authentication or device password for every access on macOS.
  static const MacOsOptions biometricMacOs = MacOsOptions(
    accessibility: KeychainAccessibility.first_unlock_this_device,
    synchronizable: false,
    accessControlFlags: [AccessControlFlag.userPresence],
  );
}

/// Configures biometric authentication prompts and behavior for Android Keystore.
class AndroidBiometricOptions {
  /// The title displayed on the biometric prompt.
  final String title;

  /// The subtitle displayed on the biometric prompt.
  final String subtitle;

  /// The label for the negative/cancel button on the biometric prompt.
  final String cancel;

  /// Defines the allowed authentication methods (biometric, credential, or both).
  final AndroidBiometricType biometricType;

  /// Requires explicit user confirmation after a passive biometric match (e.g., face recognition).
  final bool requireConfirmation;

  /// An optional namespace to isolate keystore aliases and preference keys.
  final String? storageNamespace;

  const AndroidBiometricOptions({
    required this.title,
    required this.subtitle,
    required this.cancel,
    this.biometricType = AndroidBiometricType.biometricOrDeviceCredential,
    this.requireConfirmation = true,
    this.storageNamespace,
  });

  /// Converts these settings into an [AndroidOptions] instance.
  AndroidOptions toOptions() => AndroidOptions.biometric(
    enforceBiometrics: true,
    biometricType: biometricType,
    requireBiometricConfirmation: requireConfirmation,
    storageNamespace: storageNamespace,
    biometricPromptTitle: title,
    biometricPromptSubtitle: subtitle,
    biometricPromptNegativeButton: cancel,
  );
}

/// Defines access policies specific to Android Keystore.
class AndroidKeystorePolicy {
  const AndroidKeystorePolicy._();

  /// Allows access without user authentication.
  static const AndroidOptions silent = AndroidOptions();

  /// Requires user authentication via the provided [options] before granting access.
  static AndroidOptions biometric(AndroidBiometricOptions options) =>
      options.toOptions();
}

/// A [MasterKeyCache] implementation backed by the platform's secure storage (OS Keystore/Keychain).
class KeystoreMasterKeyCache implements MasterKeyCache {
  final String _entryName;
  final FlutterSecureStorage _storage;
  final AndroidOptions _aOptions;
  final AppleOptions _iOptions;
  final AppleOptions _mOptions;
  final LinuxOptions _lOptions;
  final WindowsOptions _wOptions;
  final WebOptions _webOptions;

  /// Initializes the cache with silent access policies by default.
  KeystoreMasterKeyCache({
    this._entryName = 'nemo_master_key_v1',
    FlutterSecureStorage? storage,
    AndroidOptions? androidOptions,
    AppleOptions? iosOptions,
    AppleOptions? macOsOptions,
    LinuxOptions? linuxOptions,
    WindowsOptions? windowsOptions,
    WebOptions? webOptions,
  }) : _storage = storage ?? const FlutterSecureStorage(),
       _aOptions = androidOptions ?? AndroidKeystorePolicy.silent,
       _iOptions = iosOptions ?? AppleKeychainPolicy.silent,
       _mOptions = macOsOptions ?? AppleKeychainPolicy.silentMacOs,
       _lOptions = linuxOptions ?? const LinuxOptions(),
       _wOptions = windowsOptions ?? const WindowsOptions(),
       _webOptions = webOptions ?? const WebOptions();

  /// Initializes the cache with strict biometric authentication requirements on supported platforms.
  KeystoreMasterKeyCache.biometric({
    required AndroidBiometricOptions android,
    String entryName = 'nemo_master_key_v1',
    FlutterSecureStorage? storage,
    LinuxOptions? linuxOptions,
    WindowsOptions? windowsOptions,
    WebOptions? webOptions,
  }) : this(
         entryName: entryName,
         storage: storage,
         androidOptions: AndroidKeystorePolicy.biometric(android),
         iosOptions: AppleKeychainPolicy.biometric,
         macOsOptions: AppleKeychainPolicy.biometricMacOs,
         linuxOptions: linuxOptions,
         windowsOptions: windowsOptions,
         webOptions: webOptions,
       );

  /// The [AndroidOptions] applied to all storage operations.
  AndroidOptions get androidOptions => _aOptions;

  /// The iOS [AppleOptions] applied to all storage operations.
  AppleOptions get iosOptions => _iOptions;

  /// The macOS [AppleOptions] applied to all storage operations.
  AppleOptions get macOsOptions => _mOptions;

  /// The [LinuxOptions] applied to all storage operations.
  LinuxOptions get linuxOptions => _lOptions;

  /// The [WindowsOptions] applied to all storage operations.
  WindowsOptions get windowsOptions => _wOptions;

  /// The [WebOptions] applied to all storage operations.
  WebOptions get webOptions => _webOptions;

  @override
  Future<Uint8List?> read() async {
    final raw = await _storage.read(
      key: _entryName,
      aOptions: _aOptions,
      iOptions: _iOptions,
      mOptions: _mOptions,
      lOptions: _lOptions,
      wOptions: _wOptions,
      webOptions: _webOptions,
    );
    if (raw == null) return null;
    return base64Decode(raw);
  }

  /// Writes the [key] to secure storage.
  ///
  /// The key is temporarily encoded as a base64 string during platform channel transmission.
  @override
  Future<void> write(Uint8List key) => _storage.write(
    key: _entryName,
    value: base64Encode(key),
    aOptions: _aOptions,
    iOptions: _iOptions,
    mOptions: _mOptions,
    lOptions: _lOptions,
    wOptions: _wOptions,
    webOptions: _webOptions,
  );

  @override
  Future<void> delete() => _storage.delete(
    key: _entryName,
    aOptions: _aOptions,
    iOptions: _iOptions,
    mOptions: _mOptions,
    lOptions: _lOptions,
    wOptions: _wOptions,
    webOptions: _webOptions,
  );
}
