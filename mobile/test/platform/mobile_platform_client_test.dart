import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:svs_cyber_mobile/core/detection/detection_models.dart';
import 'package:svs_cyber_mobile/core/platform/mobile_platform_client.dart';

const _nativeEvent = <String, Object?>{
  'contractVersion': 1,
  'eventId': 'native-event-008',
  'capabilityId': 'AND-008',
  'eventType': 'observation',
  'occurredAtEpochMs': 1791763200000,
  'observedAtEpochMs': 1791763200000,
  'availability': 'available',
  'operation': 'completed',
  'freshness': 'fresh',
  'continuous': false,
  'evidence': {'secureLockConfigured': false},
};

void main() {
  late _FakeTransport transport;
  late MethodChannelMobilePlatformClient client;

  setUp(() {
    transport = _FakeTransport();
    client = MethodChannelMobilePlatformClient.withTransports(
      invokeMethod: transport.invoke,
      receiveEvents: transport.receive,
    );
  });

  test('validates the native v1 contract and rejects version mismatch', () async {
    transport.responses['getContract'] = _contract();
    expect((await client.getContract()).contractVersion, 1);

    transport.responses['getContract'] = _contract()..['contractVersion'] = 2;
    await expectLater(client.getContract(), throwsA(isA<MobilePlatformException>()));
  });

  test('requires native point-in-time monitoring status to be false', () async {
    transport.responses['getContract'] = _contract()
      ..['continuousMonitoring'] = true;

    await expectLater(client.getContract(), throwsA(isA<MobilePlatformException>()));
  });

  test('parses baseline response and validates its non-continuous contract', () async {
    transport.responses['collectDeviceBaseline'] = {
      'contractVersion': 1,
      'collectedAtEpochMs': 1791763200000,
      'continuousMonitoring': false,
      'events': [_nativeEvent],
    };

    final result = await client.collectDeviceBaseline();

    expect(result.continuousMonitoring, isFalse);
    expect(result.events.single, isA<MobileEvent>());
    expect(result.events.single.evidence['secureLockConfigured'], isFalse);
  });

  test('parses a bounded visible-app inventory and its durable observation events',
      () async {
    transport.responses['collectVisibleApplicationInventory'] = {
      'contractVersion': 1,
      'observedAtEpochMs': 1791763200000,
      'scope': 'launchable_packages_visible_to_this_app',
      'visibilityMayBeFiltered': true,
      'truncated': false,
      'applications': [
        {
          'packageName': 'com.example.reader',
          'label': 'Reader',
          'versionName': '2.4',
          'versionCode': 24,
          'installerPackageName': 'com.android.vending',
          'isSystemApp': false,
          'requestedPermissions': ['android.permission.CAMERA'],
          'grantedPermissions': [],
        },
      ],
      'events': [
        {
          ..._nativeEvent,
          'eventId': 'inventory-package-identifiers',
          'capabilityId': 'AND-012',
          'evidence': {
            'scope': 'launchable_packages_visible_to_this_app',
            'packageCount': 1,
          },
        },
      ],
    };

    final inventory = await client.collectVisibleApplicationInventory(limit: 300);

    expect(transport.lastArguments, {'limit': 200});
    expect(inventory.scope, 'launchable_packages_visible_to_this_app');
    expect(inventory.visibilityMayBeFiltered, isTrue);
    expect(inventory.applications.single.packageName, 'com.example.reader');
    expect(inventory.applications.single.requestedPermissions,
        ['android.permission.CAMERA']);
    expect(inventory.events.single.capabilityId, 'AND-012');
  });

  test('rejects inventory records with granted permissions not requested', () async {
    transport.responses['collectVisibleApplicationInventory'] = {
      'contractVersion': 1,
      'observedAtEpochMs': 1791763200000,
      'scope': 'launchable_packages_visible_to_this_app',
      'visibilityMayBeFiltered': true,
      'truncated': false,
      'applications': [
        {
          'packageName': 'com.example.reader',
          'label': 'Reader',
          'versionName': null,
          'versionCode': 0,
          'installerPackageName': null,
          'isSystemApp': false,
          'requestedPermissions': [],
          'grantedPermissions': ['android.permission.CAMERA'],
        },
      ],
      'events': [],
    };

    await expectLater(
      client.collectVisibleApplicationInventory(),
      throwsA(isA<FormatException>()),
    );
  });

  test('rejects baseline responses that claim continuous monitoring', () async {
    transport.responses['collectDeviceBaseline'] = {
      'contractVersion': 1,
      'collectedAtEpochMs': 1791763200000,
      'continuousMonitoring': true,
      'events': [_nativeEvent],
    };

    await expectLater(
      client.collectDeviceBaseline(),
      throwsA(isA<MobilePlatformException>()),
    );
  });

  test('clamps journal read limits and parses native event maps', () async {
    transport.responses['readEvents'] = {
      'contractVersion': 1,
      'events': [_nativeEvent],
    };

    final events = await client.readEvents(limit: 900);

    expect(transport.lastArguments, {'limit': 500});
    expect(events.single.capabilityId, 'AND-008');
  });

  test('rejects a malformed journal status instead of fabricating defaults', () async {
    transport.responses['getJournalStatus'] = {
      'contractVersion': 1,
      'available': true,
      'eventCount': 'zero',
      'sizeBytes': 0,
      'encryptedAtRest': true,
      'retentionDays': 30,
      'maxBytes': 8388608,
      'warning': null,
    };

    await expectLater(
      client.getJournalStatus(),
      throwsA(isA<FormatException>()),
    );
  });

  test('parses event-channel items through the strict MobileEvent contract', () async {
    final event = await client.events.first;

    expect(event.eventId, 'native-event-008');
    expect(event.continuous, isFalse);
    expect(event.observedAt, DateTime.utc(2026, 10, 12));
  });

  test('sanitizes platform exceptions without exposing native details', () async {
    transport.error = PlatformException(
      code: 'JOURNAL_READ_FAILED',
      message: 'private path and token=secret',
      details: 'do not surface',
    );

    await expectLater(
      client.readEvents(),
      throwsA(
        isA<MobilePlatformException>()
            .having((error) => error.code, 'code', 'journal_read_failed')
            .having((error) => error.message, 'message', isNot(contains('secret'))),
      ),
    );
  });
}

Map<String, Object?> _contract() => {
      'contractVersion': 1,
      'platform': 'android',
      'methodChannel': 'svs_cyber/mobile/platform/v1',
      'eventChannel': 'svs_cyber/mobile/events/v1',
      'credentialVaultChannel': 'com.svscyber.mobile/credential_vault.v1',
      'methods': [
        'getContract',
        'collectDeviceBaseline',
        'readEvents',
        'getJournalStatus',
      ],
      'continuousMonitoring': false,
    };

class _FakeTransport {
  final Map<String, Object?> responses = {};
  Object? error;
  Object? lastArguments;

  Future<Object?> invoke(String method, Object? arguments) async {
    lastArguments = arguments;
    if (error != null) throw error!;
    return responses[method];
  }

  Stream<Object?> receive() => Stream<Object?>.value(_nativeEvent);
}
