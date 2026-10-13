import 'dart:async';

import 'package:flutter/services.dart';

import '../apps/visible_application.dart';
import '../detection/detection_models.dart';
import '../files/selected_file_inspection.dart';

const mobilePlatformMethodChannelName = 'svs_cyber/mobile/platform/v1';
const mobilePlatformEventChannelName = 'svs_cyber/mobile/events/v1';
const mobileCredentialVaultChannelName =
    'com.svscyber.mobile/credential_vault.v1';
const mobilePlatformContractVersion = 1;

typedef NativeMethodInvoker = Future<Object?> Function(
  String method,
  Object? arguments,
);
typedef NativeEventReceiver = Stream<Object?> Function();

abstract interface class MobilePlatformClient {
  Future<SelectedFileInspection?> selectAndInspectFile({required bool apk});
  Future<NativePlatformContract> getContract();
  Future<BaselineCollection> collectDeviceBaseline();
  Future<VisibleApplicationCollection> collectVisibleApplicationInventory({int limit = 100});
  Future<List<MobileEvent>> readEvents({DateTime? after, int limit = 100});
  Future<MobileJournalStatus> getJournalStatus();
  Stream<MobileEvent> get events;
}

class MethodChannelMobilePlatformClient implements MobilePlatformClient {
  MethodChannelMobilePlatformClient({
    MethodChannel? methodChannel,
    EventChannel? eventChannel,
  })  : _invokeMethod = ((method, arguments) =>
            (methodChannel ??
                    const MethodChannel(mobilePlatformMethodChannelName))
                .invokeMethod<Object?>(method, arguments)),
        _receiveEvents = () =>
            (eventChannel ?? const EventChannel(mobilePlatformEventChannelName))
                .receiveBroadcastStream();

  /// Injectable transport seam for contract tests and local replay fixtures.
  MethodChannelMobilePlatformClient.withTransports({
    required NativeMethodInvoker invokeMethod,
    required NativeEventReceiver receiveEvents,
  })  : _invokeMethod = invokeMethod,
        _receiveEvents = receiveEvents;

  final NativeMethodInvoker _invokeMethod;
  final NativeEventReceiver _receiveEvents;

  @override
  Future<SelectedFileInspection?> selectAndInspectFile({required bool apk}) async {
    final raw = await _invoke('selectAndInspectFile', {'apk': apk});
    if (raw == null) return null;
    final map = _objectMap(raw, 'selected file response');
    _requireVersion(map);
    final result = SelectedFileInspection.fromMap(map);
    if (result.apkRequested != apk) {
      throw const FormatException('Selected file response does not match the requested mode.');
    }
    return result;
  }

  @override
  Future<NativePlatformContract> getContract() async {
    final raw = await _invoke('getContract');
    final map = _objectMap(raw, 'platform contract');
    _requireVersion(map);
    final continuous = _strictBool(map, 'continuousMonitoring');
    if (continuous) {
      throw const MobilePlatformException(
        'invalid_contract',
        'The native platform contract does not match the supported v1 behavior.',
      );
    }
    final contract = NativePlatformContract.fromMap(map);
    if (contract.platform != 'android' ||
        contract.methodChannel != mobilePlatformMethodChannelName ||
        contract.eventChannel != mobilePlatformEventChannelName ||
        contract.credentialVaultChannel != mobileCredentialVaultChannelName ||
        !contract.methods.containsAll(const {
          'getContract',
          'collectDeviceBaseline',
          'collectVisibleApplicationInventory',
          'selectAndInspectFile',
          'readEvents',
          'getJournalStatus',
        })) {
      throw const MobilePlatformException(
        'invalid_contract',
        'The native platform contract does not match the supported v1 interface.',
      );
    }
    return contract;
  }

  @override
  Future<BaselineCollection> collectDeviceBaseline() async {
    final raw = await _invoke('collectDeviceBaseline');
    final map = _objectMap(raw, 'baseline response');
    _requireVersion(map);
    if (_strictBool(map, 'continuousMonitoring')) {
      throw const MobilePlatformException(
        'invalid_response',
        'The baseline response must describe a point-in-time collection.',
      );
    }
    return BaselineCollection(
      contractVersion: mobilePlatformContractVersion,
      collectedAt: _epochDate(map, 'collectedAtEpochMs'),
      continuousMonitoring: false,
      events: List<MobileEvent>.unmodifiable(
        _objectList(map, 'events').map(_parseEvent),
      ),
    );
  }

  @override
  Future<VisibleApplicationCollection> collectVisibleApplicationInventory(
      {int limit = 100}) async {
    final clampedLimit = limit.clamp(1, VisibleApplicationCollection.maxApplications);
    final raw = await _invoke('collectVisibleApplicationInventory', {'limit': clampedLimit});
    final map = _objectMap(raw, 'application inventory response');
    _requireVersion(map);
    return VisibleApplicationCollection.fromMap(map);
  }

  @override
  Future<List<MobileEvent>> readEvents({DateTime? after, int limit = 100}) async {
    final clampedLimit = limit.clamp(1, 500);
    final arguments = <String, Object?>{'limit': clampedLimit};
    if (after != null) {
      arguments['afterEpochMs'] = after.toUtc().millisecondsSinceEpoch;
    }
    final raw = await _invoke('readEvents', arguments);
    final map = _objectMap(raw, 'event journal response');
    _requireVersion(map);
    return List<MobileEvent>.unmodifiable(
      _objectList(map, 'events').map(_parseEvent),
    );
  }

  @override
  Future<MobileJournalStatus> getJournalStatus() async {
    final raw = await _invoke('getJournalStatus');
    final map = _objectMap(raw, 'journal status');
    _requireVersion(map);
    return MobileJournalStatus.fromMap(map);
  }

  @override
  Stream<MobileEvent> get events => _receiveEvents()
      .transform<MobileEvent>(StreamTransformer<Object?, MobileEvent>.fromHandlers(
        handleData: (value, sink) {
          try {
            sink.add(_parseEvent(value));
          } on FormatException catch (error, stackTrace) {
            sink.addError(error, stackTrace);
          }
        },
        handleError: (error, stackTrace, sink) {
          if (error is PlatformException || error is MissingPluginException) {
            sink.addError(_sanitizePlatformError(error), stackTrace);
          } else {
            sink.addError(error, stackTrace);
          }
        },
      ));

  Future<Object?> _invoke(String method, [Object? arguments]) async {
    try {
      return await _invokeMethod(method, arguments);
    } on PlatformException catch (error) {
      throw _sanitizePlatformError(error);
    } on MissingPluginException catch (error) {
      throw _sanitizePlatformError(error);
    }
  }
}

class NativePlatformContract {
  const NativePlatformContract({
    required this.contractVersion,
    required this.platform,
    required this.methodChannel,
    required this.eventChannel,
    required this.credentialVaultChannel,
    required this.methods,
    required this.continuousMonitoring,
  });

  final int contractVersion;
  final String platform;
  final String methodChannel;
  final String eventChannel;
  final String credentialVaultChannel;
  final List<String> methods;
  final bool continuousMonitoring;

  factory NativePlatformContract.fromMap(Map<String, Object?> map) =>
      NativePlatformContract(
        contractVersion: _strictInt(map, 'contractVersion'),
        platform: _strictString(map, 'platform'),
        methodChannel: _strictString(map, 'methodChannel'),
        eventChannel: _strictString(map, 'eventChannel'),
        credentialVaultChannel: _strictString(map, 'credentialVaultChannel'),
        methods: List<String>.unmodifiable(_strictStringList(map, 'methods')),
        continuousMonitoring: _strictBool(map, 'continuousMonitoring'),
      );
}

class BaselineCollection {
  const BaselineCollection({
    required this.contractVersion,
    required this.collectedAt,
    required this.continuousMonitoring,
    required this.events,
  });

  final int contractVersion;
  final DateTime collectedAt;
  final bool continuousMonitoring;
  final List<MobileEvent> events;
}

class MobileJournalStatus {
  const MobileJournalStatus({
    required this.contractVersion,
    required this.available,
    required this.eventCount,
    required this.sizeBytes,
    required this.encryptedAtRest,
    required this.retentionDays,
    required this.maxBytes,
    required this.warning,
  });

  final int contractVersion;
  final bool available;
  final int eventCount;
  final int sizeBytes;
  final bool encryptedAtRest;
  final int retentionDays;
  final int maxBytes;
  final String? warning;

  factory MobileJournalStatus.fromMap(Map<String, Object?> map) {
    final result = MobileJournalStatus(
      contractVersion: _strictInt(map, 'contractVersion'),
      available: _strictBool(map, 'available'),
      eventCount: _strictInt(map, 'eventCount'),
      sizeBytes: _strictInt(map, 'sizeBytes'),
      encryptedAtRest: _strictBool(map, 'encryptedAtRest'),
      retentionDays: _strictInt(map, 'retentionDays'),
      maxBytes: _strictInt(map, 'maxBytes'),
      warning: _nullableString(map, 'warning'),
    );
    if (result.eventCount < -1 ||
        result.sizeBytes < 0 ||
        result.retentionDays < 0 ||
        result.maxBytes <= 0) {
      throw const FormatException('Journal status contains an invalid numeric value.');
    }
    return result;
  }
}

class MobilePlatformException implements Exception {
  const MobilePlatformException(this.code, this.message);

  final String code;
  final String message;

  @override
  String toString() => 'MobilePlatformException($code): $message';
}

MobileEvent _parseEvent(Object? raw) {
  final event = MobileEvent.fromJson(_objectMap(raw, 'native event'));
  if (event.continuous) {
    throw const FormatException('Native v1 events must be point-in-time observations.');
  }
  return event;
}

void _requireVersion(Map<String, Object?> map) {
  final version = _strictInt(map, 'contractVersion');
  if (version != mobilePlatformContractVersion) {
    throw MobilePlatformException(
      'unsupported_contract_version',
      'The native platform contract version $version is not supported.',
    );
  }
}

Map<String, Object?> _objectMap(Object? value, String label) {
  if (value is! Map<Object?, Object?>) {
    throw FormatException('$label must be an object.');
  }
  final result = <String, Object?>{};
  for (final entry in value.entries) {
    if (entry.key is! String) throw FormatException('$label has a non-string key.');
    result[entry.key! as String] = entry.value;
  }
  return result;
}

List<Object?> _objectList(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is List<Object?>) return value;
  throw FormatException('Field "$key" must be a list.');
}

String _strictString(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is String && value.isNotEmpty) return value;
  throw FormatException('Field "$key" must be a non-empty string.');
}

String? _nullableString(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value == null || value is String) return value as String?;
  throw FormatException('Field "$key" must be a string or null.');
}

int _strictInt(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is int) return value;
  throw FormatException('Field "$key" must be an integer.');
}

bool _strictBool(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is bool) return value;
  throw FormatException('Field "$key" must be a boolean.');
}

List<String> _strictStringList(Map<String, Object?> map, String key) {
  final values = _objectList(map, key);
  if (values.every((value) => value is String && value.isNotEmpty)) {
    return values.cast<String>();
  }
  throw FormatException('Field "$key" must be a list of non-empty strings.');
}

DateTime _epochDate(Map<String, Object?> map, String key) =>
    DateTime.fromMillisecondsSinceEpoch(_strictInt(map, key), isUtc: true);

MobilePlatformException _sanitizePlatformError(Object error) {
  if (error is MissingPluginException) {
    return const MobilePlatformException(
      'platform_unavailable',
      'The Android platform service is unavailable.',
    );
  }
  if (error is PlatformException) {
    final code = switch (error.code) {
      'JOURNAL_WRITE_FAILED' => 'journal_write_failed',
      'JOURNAL_READ_FAILED' => 'journal_read_failed',
      'JOURNAL_STATUS_FAILED' => 'journal_status_failed',
      'BASELINE_COLLECTION_FAILED' => 'baseline_collection_failed',
      'APP_INVENTORY_COLLECTION_FAILED' => 'application_inventory_failed',
      'FILE_INSPECTION_FAILED' => 'file_inspection_failed',
      'FILE_SELECTION_UNAVAILABLE' => 'file_selection_unavailable',
      'FILE_INSPECTION_BUSY' => 'file_inspection_busy',
      _ => 'platform_call_failed',
    };
    final message = switch (code) {
      'journal_write_failed' => 'The event could not be saved locally.',
      'journal_read_failed' => 'Saved local events could not be read.',
      'journal_status_failed' => 'Local event storage status is unavailable.',
      'baseline_collection_failed' => 'The device baseline could not be collected.',
      'application_inventory_failed' => 'The visible app inventory could not be collected.',
      'file_inspection_failed' => 'The selected document could not be read or inspected.',
      'file_selection_unavailable' => 'Document selection is unavailable on this device.',
      'file_inspection_busy' => 'A document selection or inspection is already in progress.',
      _ => 'The Android platform request failed.',
    };
    return MobilePlatformException(code, message);
  }
  return const MobilePlatformException(
    'platform_call_failed',
    'The Android platform request failed.',
  );
}
