import 'package:flutter/services.dart';

/// Providers supported by the mobile key-vault metadata contract.
///
/// This enum does not enable provider calls. A provider adapter is a separate
/// feature and must apply the evidence-selection and consent flow.
enum MobileCredentialProvider {
  googleGemini('google_gemini'),
  openAiCompatible('openai_compatible');

  const MobileCredentialProvider(this.wireId);

  final String wireId;

  static MobileCredentialProvider fromWireId(String value) {
    for (final provider in values) {
      if (provider.wireId == value) return provider;
    }
    throw const CredentialVaultException('invalid_response');
  }
}

/// Non-secret metadata returned by Android. Secret values are deliberately
/// absent from this type and from every read/list method in this API.
class MobileCredentialMetadata {
  const MobileCredentialMetadata({
    required this.provider,
    required this.configured,
    required this.updatedAtEpochMs,
  });

  final MobileCredentialProvider provider;
  final bool configured;
  final int updatedAtEpochMs;

  factory MobileCredentialMetadata.fromChannelValue(Object? value) {
    if (value is! Map) {
      throw const CredentialVaultException('invalid_response');
    }
    final normalized = <String, Object?>{};
    for (final entry in value.entries) {
      if (entry.key is! String) {
        throw const CredentialVaultException('invalid_response');
      }
      final key = entry.key as String;
      if (_looksLikeSecretField(key)) {
        // Fail closed if a native contract regression attempts to cross the
        // bridge with secret material.
        throw const CredentialVaultException('secret_returned_by_native');
      }
      normalized[key] = entry.value;
    }

    final providerId = normalized['providerId'];
    final configured = normalized['configured'];
    final updatedAt = normalized['updatedAtEpochMs'];
    if (normalized.length != 3 ||
        providerId is! String ||
        configured is! bool ||
        updatedAt is! int ||
        updatedAt < 0 ||
        (configured && updatedAt == 0)) {
      throw const CredentialVaultException('invalid_response');
    }
    return MobileCredentialMetadata(
      provider: MobileCredentialProvider.fromWireId(providerId),
      configured: configured,
      updatedAtEpochMs: updatedAt,
    );
  }
}

/// Stable error categories that never include the submitted secret or the raw
/// native error message/details.
class CredentialVaultException implements Exception {
  const CredentialVaultException(this.code);

  final String code;

  @override
  String toString() => 'CredentialVaultException($code)';
}

abstract interface class MobileCredentialVault {
  Future<MobileCredentialMetadata> storeKey({
    required MobileCredentialProvider provider,
    required String secret,
  });

  Future<MobileCredentialMetadata> replaceKey({
    required MobileCredentialProvider provider,
    required String secret,
  });

  Future<bool> deleteKey({required MobileCredentialProvider provider});

  Future<List<MobileCredentialMetadata>> listKeyMetadata();
}

/// Dart wrapper for `com.svscyber.mobile/credential_vault.v1`.
///
/// This adapter sends a secret to the Android side only for store/replace. It
/// has no method that retrieves a stored secret and does not call a provider.
class MethodChannelMobileCredentialVault implements MobileCredentialVault {
  MethodChannelMobileCredentialVault({MethodChannel? channel})
      : _channel = channel ?? const MethodChannel(channelName);

  static const channelName = 'com.svscyber.mobile/credential_vault.v1';
  static const _maxSecretCharacters = 8192;

  final MethodChannel _channel;

  @override
  Future<MobileCredentialMetadata> storeKey({
    required MobileCredentialProvider provider,
    required String secret,
  }) =>
      _write(method: 'storeKey', provider: provider, secret: secret);

  @override
  Future<MobileCredentialMetadata> replaceKey({
    required MobileCredentialProvider provider,
    required String secret,
  }) =>
      _write(method: 'replaceKey', provider: provider, secret: secret);

  Future<MobileCredentialMetadata> _write({
    required String method,
    required MobileCredentialProvider provider,
    required String secret,
  }) async {
    if (secret.trim().isEmpty || secret.length > _maxSecretCharacters) {
      throw const CredentialVaultException('invalid_secret');
    }
    try {
      final response = await _channel.invokeMethod<Object?>(method, {
        'providerId': provider.wireId,
        'secret': secret,
      });
      return MobileCredentialMetadata.fromChannelValue(response);
    } on PlatformException catch (error) {
      throw CredentialVaultException(_safeErrorCode(error.code));
    } on MissingPluginException {
      throw const CredentialVaultException('unavailable');
    }
  }

  @override
  Future<bool> deleteKey({required MobileCredentialProvider provider}) async {
    try {
      final response = await _channel.invokeMethod<Object?>('deleteKey', {
        'providerId': provider.wireId,
      });
      if (response is! Map ||
          response.length != 1 ||
          response['deleted'] is! bool) {
        throw const CredentialVaultException('invalid_response');
      }
      return response['deleted'] as bool;
    } on PlatformException catch (error) {
      throw CredentialVaultException(_safeErrorCode(error.code));
    } on MissingPluginException {
      throw const CredentialVaultException('unavailable');
    }
  }

  @override
  Future<List<MobileCredentialMetadata>> listKeyMetadata() async {
    try {
      final response = await _channel.invokeMethod<Object?>('listKeyMetadata');
      if (response is! List) {
        throw const CredentialVaultException('invalid_response');
      }
      return List<MobileCredentialMetadata>.unmodifiable(
        response.map(MobileCredentialMetadata.fromChannelValue),
      );
    } on PlatformException catch (error) {
      throw CredentialVaultException(_safeErrorCode(error.code));
    } on MissingPluginException {
      throw const CredentialVaultException('unavailable');
    }
  }
}

bool _looksLikeSecretField(String key) {
  final normalized = key.toLowerCase().replaceAll(RegExp(r'[^a-z]'), '');
  return normalized.contains('secret') ||
      normalized.contains('credentialvalue') ||
      normalized == 'apikey' ||
      normalized == 'token';
}

String _safeErrorCode(String nativeCode) {
  const allowed = {
    'INVALID_ARGUMENTS',
    'INVALID_PROVIDER_ID',
    'INVALID_SECRET',
    'CREDENTIAL_ALREADY_EXISTS',
    'CREDENTIAL_NOT_FOUND',
    'EMPTY_SECRET',
    'SECRET_TOO_LARGE',
    'CREDENTIAL_VAULT_FAILED',
  };
  if (!allowed.contains(nativeCode)) return 'native_error';
  return nativeCode.toLowerCase();
}
