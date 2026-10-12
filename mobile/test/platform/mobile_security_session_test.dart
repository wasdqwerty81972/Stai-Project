import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:svs_cyber_mobile/core/detection/detection_models.dart';
import 'package:svs_cyber_mobile/core/detection/local_detection_engine.dart';
import 'package:svs_cyber_mobile/core/platform/mobile_platform_client.dart';
import 'package:svs_cyber_mobile/core/platform/mobile_security_session.dart';

void main() {
  late _FakePlatformClient client;
  late DateTime now;
  late MobileSecuritySession session;

  setUp(() {
    client = _FakePlatformClient();
    now = DateTime.utc(2026, 10, 12, 12);
    session = MobileSecuritySession(
      platform: client,
      detectionEngine: LocalDetectionEngine(rules: builtInPostureRules),
      clock: () => now,
    );
  });

  tearDown(() => session.dispose());

  test('construction does not collect a baseline or subscribe to native events', () {
    expect(client.baselineCalls, 0);
    expect(client.eventStreamSubscriptions, 0);
    expect(session.events, isEmpty);
    expect(session.findings, isEmpty);
  });

  test('collects a one-shot baseline only when explicitly requested', () async {
    client.baseline = BaselineCollection(
      contractVersion: 1,
      collectedAt: now,
      continuousMonitoring: false,
      events: [_event('baseline', now)],
    );

    await session.collectBaseline();

    expect(client.baselineCalls, 1);
    expect(session.events.single.eventId, 'baseline');
    expect(session.findings.single.status, FindingStatus.open);
    expect(session.lastError, isNull);
  });

  test('collects visible applications only after request and publishes journal events',
      () async {
    client.visibleAppInventory = VisibleApplicationCollection(
      contractVersion: 1,
      observedAt: now,
      scope: 'launchable_packages_visible_to_this_app',
      visibilityMayBeFiltered: true,
      truncated: false,
      applications: const [
        VisibleApplication(
          packageName: 'com.example.reader',
          label: 'Reader',
          versionName: '2.4',
          versionCode: 24,
          installerPackageName: 'com.android.vending',
          isSystemApp: false,
          requestedPermissions: ['android.permission.CAMERA'],
          grantedPermissions: [],
        ),
      ],
      events: [_event('inventory', now, capabilityId: 'AND-012')],
    );

    expect(client.visibleApplicationInventoryCalls, 0);
    await session.collectVisibleApplications();

    expect(client.visibleApplicationInventoryCalls, 1);
    expect(session.visibleApplications.single.packageName, 'com.example.reader');
    expect(session.visibleApplicationsObservedAt, now);
    expect(session.events.single.capabilityId, 'AND-012');
    expect(session.lastError, isNull);
  });

  test('visible-app collection failure leaves no fabricated inventory', () async {
    client.visibleApplicationInventoryError = const MobilePlatformException(
      'platform_call_failed',
      'The Android platform request failed.',
    );

    await session.collectVisibleApplications();

    expect(client.visibleApplicationInventoryCalls, 1);
    expect(session.visibleApplications, isEmpty);
    expect(session.events, isEmpty);
    expect(session.lastError, isNotNull);
  });

  test('baseline failure exposes an error without fabricating events or findings', () async {
    client.baselineError = const MobilePlatformException(
      'platform_call_failed',
      'The Android platform request failed.',
    );

    await session.collectBaseline();

    expect(session.lastError, isNotNull);
    expect(session.events, isEmpty);
    expect(session.findings, isEmpty);
  });

  test('restores only journal evidence within the rolling 24 hour window', () async {
    client.journal = const MobileJournalStatus(
      contractVersion: 1,
      available: true,
      eventCount: 3,
      sizeBytes: 1024,
      encryptedAtRest: true,
      retentionDays: 30,
      maxBytes: 8388608,
      warning: null,
    );
    client.eventsToRead = [
      _event('in-window', now.subtract(const Duration(hours: 23))),
      _event('too-old', now.subtract(const Duration(hours: 24, seconds: 1))),
      _event('future', now.add(const Duration(minutes: 1))),
    ];

    await session.restoreJournal();

    expect(client.journalStatusCalls, 1);
    expect(client.readAfter, now.subtract(const Duration(hours: 24)));
    expect(client.readLimit, 500);
    expect(session.events.map((event) => event.eventId), ['in-window']);
    expect(session.findings.single.evidenceReferences.single.eventId, 'in-window');
  });

  test('unavailable journal reports an error and keeps state empty', () async {
    client.journal = const MobileJournalStatus(
      contractVersion: 1,
      available: false,
      eventCount: -1,
      sizeBytes: 0,
      encryptedAtRest: false,
      retentionDays: 0,
      maxBytes: 8388608,
      warning: 'Unavailable',
    );

    await session.restoreJournal();

    expect(client.readEventsCalls, 0);
    expect(session.lastError, isNotNull);
    expect(session.events, isEmpty);
    expect(session.findings, isEmpty);
  });

  test('journal read failure does not publish partial events or findings', () async {
    client.journal = const MobileJournalStatus(
      contractVersion: 1,
      available: true,
      eventCount: 1,
      sizeBytes: 128,
      encryptedAtRest: true,
      retentionDays: 30,
      maxBytes: 8388608,
      warning: null,
    );
    client.readError = const MobilePlatformException(
      'journal_read_failed',
      'Saved local events could not be read.',
    );

    await session.restoreJournal();

    expect(session.lastError, isNotNull);
    expect(session.events, isEmpty);
    expect(session.findings, isEmpty);
  });
}

MobileEvent _event(String id, DateTime observedAt,
        {String capabilityId = 'AND-008'}) =>
    MobileEvent(
      contractVersion: 1,
      eventId: id,
      capabilityId: capabilityId,
      eventType: 'observation',
      occurredAt: observedAt,
      observedAt: observedAt,
      availability: 'available',
      operation: 'completed',
      freshness: 'fresh',
      continuous: false,
      evidence: const {'secureLockConfigured': false},
    );

class _FakePlatformClient implements MobilePlatformClient {
  int baselineCalls = 0;
  int visibleApplicationInventoryCalls = 0;
  int journalStatusCalls = 0;
  int readEventsCalls = 0;
  int eventStreamSubscriptions = 0;
  DateTime? readAfter;
  int? readLimit;
  BaselineCollection? baseline;
  Object? baselineError;
  VisibleApplicationCollection? visibleAppInventory;
  Object? visibleApplicationInventoryError;
  MobileJournalStatus? journal;
  Object? journalError;
  List<MobileEvent> eventsToRead = [];
  Object? readError;

  @override
  Stream<MobileEvent> get events {
    eventStreamSubscriptions++;
    return const Stream<MobileEvent>.empty();
  }

  @override
  Future<NativePlatformContract> getContract() => throw UnimplementedError();

  @override
  Future<BaselineCollection> collectDeviceBaseline() async {
    baselineCalls++;
    if (baselineError != null) throw baselineError!;
    return baseline!;
  }

  @override
  Future<VisibleApplicationCollection> collectVisibleApplicationInventory(
      {int limit = 100}) async {
    visibleApplicationInventoryCalls++;
    if (visibleApplicationInventoryError != null) {
      throw visibleApplicationInventoryError!;
    }
    return visibleAppInventory!;
  }

  @override
  Future<List<MobileEvent>> readEvents({DateTime? after, int limit = 100}) async {
    readEventsCalls++;
    readAfter = after;
    readLimit = limit;
    if (readError != null) throw readError!;
    return eventsToRead;
  }

  @override
  Future<MobileJournalStatus> getJournalStatus() async {
    journalStatusCalls++;
    if (journalError != null) throw journalError!;
    return journal!;
  }
}
