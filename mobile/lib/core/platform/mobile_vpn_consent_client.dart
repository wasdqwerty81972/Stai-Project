import 'package:flutter/services.dart';

import 'mobile_platform_client.dart';

/// Read-only status and explicit consent operations for the VPN prototype.
/// Consent never starts a tunnel or enables traffic monitoring.
class MobileVpnConsentClient {
  MobileVpnConsentClient({MethodChannel? methodChannel})
      : _channel = methodChannel ??
            const MethodChannel(mobilePlatformMethodChannelName);

  final MethodChannel _channel;

  Future<MobileVpnConsentStatus> getVpnStatus() =>
      _invoke('getVpnStatus');

  /// Requests the Android system consent flow after an explicit user action.
  Future<MobileVpnConsentStatus> requestVpnConsent() =>
      _invoke('requestVpnConsent');

  Future<MobileVpnConsentStatus> _invoke(String method) async {
    final Object? raw;
    try {
      raw = await _channel.invokeMethod<Object?>(method);
    } on PlatformException catch (_) {
      throw const MobilePlatformException(
        'vpn_consent_failed',
        'VPN consent status could not be read from Android.',
      );
    } on MissingPluginException catch (_) {
      throw const MobilePlatformException(
        'platform_unavailable',
        'The Android platform service is unavailable.',
      );
    }
    return MobileVpnConsentStatus.fromMap(_objectMap(raw));
  }
}

enum MobileVpnConsentState {
  unavailable,
  consentRequired,
  backendUnavailable,
}

enum MobileVpnConsentReason {
  userDenied,
  consentUnavailable,
  torDataPlaneNotIntegrated,
  vpnNotEnabledForBuild,
}

/// Immutable, strictly parsed status from the native platform channel.
class MobileVpnConsentStatus {
  const MobileVpnConsentStatus._({
    required this.contractVersion,
    required this.enabledForBuild,
    required this.consentGranted,
    required this.state,
    required this.reasonCode,
    required this.torState,
    required this.bridgeReady,
    required this.dnsReady,
    required this.coverage,
  });

  final int contractVersion;
  final bool enabledForBuild;
  final bool consentGranted;
  final MobileVpnConsentState state;
  final MobileVpnConsentReason? reasonCode;
  final String torState;
  final bool bridgeReady;
  final bool dnsReady;
  final String coverage;

  /// This scaffold never starts a VPN service or monitors traffic.
  bool get tunnelActive => false;

  /// This scaffold never inspects, forwards, or blocks traffic.
  bool get monitoringActive => false;

  /// Consent alone never means traffic is routed or protected.
  bool get trafficProtected => false;

  factory MobileVpnConsentStatus.fromMap(Map<String, Object?> map) {
    final version = map['contractVersion'];
    final enabled = map['enabledForBuild'];
    final consent = map['consentGranted'];
    final tunnel = map['tunnelActive'];
    final monitoring = map['monitoringActive'];
    final torState = map['torState'];
    final bridgeReady = map['bridgeReady'];
    final dnsReady = map['dnsReady'];
    final coverage = map['coverage'];
    if (version is! int || version != mobilePlatformContractVersion) {
      throw const FormatException('Unsupported VPN status contract version.');
    }
    if (enabled is! bool || consent is! bool || tunnel is! bool || monitoring is! bool) {
      throw const FormatException('VPN status contains a field with the wrong type.');
    }
    if (torState is! String ||
        bridgeReady is! bool ||
        dnsReady is! bool ||
        coverage is! String) {
      throw const FormatException('VPN backend status contains a field with the wrong type.');
    }
    if (tunnel ||
        monitoring ||
        bridgeReady ||
        dnsReady ||
        torState != 'unavailable' ||
        coverage != 'none') {
      throw const FormatException(
        'VPN status must not report an active or protected backend.',
      );
    }

    final rawState = map['state'];
    final state = switch (rawState) {
      'unavailable' => MobileVpnConsentState.unavailable,
      'consent_required' => MobileVpnConsentState.consentRequired,
      'backend_unavailable' => MobileVpnConsentState.backendUnavailable,
      _ => throw const FormatException('VPN status contains an unknown state.'),
    };
    final rawReason = map['reasonCode'];
    final reason = switch (rawReason) {
      null => null,
      'user_denied' => MobileVpnConsentReason.userDenied,
      'consent_unavailable' => MobileVpnConsentReason.consentUnavailable,
      'tor_data_plane_not_integrated' => MobileVpnConsentReason.torDataPlaneNotIntegrated,
      'vpn_not_enabled_for_build' => MobileVpnConsentReason.vpnNotEnabledForBuild,
      _ => throw const FormatException('VPN status contains an unknown reason code.'),
    };

    if (state == MobileVpnConsentState.unavailable &&
        (consent ||
            (enabled && reason != MobileVpnConsentReason.consentUnavailable) ||
            (!enabled &&
                reason != MobileVpnConsentReason.vpnNotEnabledForBuild &&
                reason != MobileVpnConsentReason.consentUnavailable))) {
      throw const FormatException('Unavailable VPN status is inconsistent.');
    }
    if (state == MobileVpnConsentState.consentRequired &&
        (!enabled || consent ||
            (reason != null && reason != MobileVpnConsentReason.userDenied))) {
      throw const FormatException('Consent-required VPN status is inconsistent.');
    }
    if (state == MobileVpnConsentState.backendUnavailable &&
        (!enabled || !consent || reason != MobileVpnConsentReason.torDataPlaneNotIntegrated)) {
      throw const FormatException('Backend-unavailable VPN status is inconsistent.');
    }

    return MobileVpnConsentStatus._(
      contractVersion: version,
      enabledForBuild: enabled,
      consentGranted: consent,
      state: state,
      reasonCode: reason,
      torState: torState,
      bridgeReady: bridgeReady,
      dnsReady: dnsReady,
      coverage: coverage,
    );
  }
}

Map<String, Object?> _objectMap(Object? value) {
  if (value is! Map<Object?, Object?>) {
    throw const FormatException('VPN status response must be an object.');
  }
  final result = <String, Object?>{};
  for (final entry in value.entries) {
    if (entry.key is! String) {
      throw const FormatException('VPN status response has a non-string key.');
    }
    result[entry.key! as String] = entry.value;
  }
  return result;
}
