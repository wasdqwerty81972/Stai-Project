import 'package:flutter_test/flutter_test.dart';
import 'package:svs_cyber_mobile/core/apps/application_permission_detection.dart';
import 'package:svs_cyber_mobile/core/apps/visible_application.dart';
import 'package:svs_cyber_mobile/core/detection/detection_models.dart';

void main() {
  const detector = ApplicationPermissionCombinationDetector();
  final observedAt = DateTime.utc(2026, 10, 13);

  VisibleApplication app({
    String packageName = 'org.example.app',
    List<String> requested = const [],
  }) => VisibleApplication(
    packageName: packageName,
    label: 'Example',
    versionName: '1',
    versionCode: 1,
    installerPackageName: 'com.android.vending',
    isSystemApp: false,
    requestedPermissions: requested,
    grantedPermissions: const [],
    permissionGrantStateAvailable: true,
  );

  MobileEvent inventoryEvent(List<VisibleApplication> apps) => MobileEvent(
    contractVersion: 1,
    eventId: 'event-inventory',
    capabilityId: 'AND-012',
    eventType: 'observation',
    occurredAt: observedAt,
    observedAt: observedAt,
    availability: 'available',
    operation: 'completed',
    freshness: 'fresh',
    continuous: false,
    evidence: {
      'scope': VisibleApplicationCollection.supportedScope,
      'packageCount': apps.length,
      'applications': apps.map((app) => {
        'packageName': app.packageName,
        'requestedPermissions': app.requestedPermissions,
      }).toList(),
    },
  );

  VisibleApplicationCollection collection(
    List<VisibleApplication> apps, {
    bool visibilityMayBeFiltered = false,
    bool truncated = false,
    bool permissionsTruncated = false,
  }) => VisibleApplicationCollection(
    contractVersion: 1,
    observedAt: observedAt,
    scope: VisibleApplicationCollection.supportedScope,
    visibilityMayBeFiltered: visibilityMayBeFiltered,
    truncated: truncated,
    permissionsTruncated: permissionsTruncated,
    applications: apps,
    events: [inventoryEvent(apps)],
  );

  test('detects a reviewed permission combination and points to source event evidence', () {
    final permissions = [
      'android.permission.READ_SMS',
      'android.permission.SEND_SMS',
    ];
    final result = detector.detect(collection([
      app(requested: permissions),
    ]));

    expect(result, hasLength(1));
    final detection = result.single;
    expect(detection.ruleId, 'APP-PERM-SMS-READ-SEND');
    expect(detection.ruleVersion, ApplicationPermissionCombinationDetector.ruleVersion);
    expect(detection.packageName, 'org.example.app');
    expect(detection.evidenceReferences, hasLength(1));
    expect(detection.evidenceReferences.single.eventId, 'event-inventory');
    expect(detection.evidenceReferences.single.capabilityId, 'AND-012');
    expect(detection.evidenceReferences.single.path,
        'applications.0.requestedPermissions');
    expect(detection.evidenceReferences.single.value, permissions);
    expect(detection.title.toLowerCase(), contains('review'));
    expect(detection.verdict, isNull);
  });

  test('does not combine permissions across different applications', () {
    final result = detector.detect(collection([
      app(packageName: 'org.example.reader', requested: const [
        'android.permission.READ_SMS',
      ]),
      app(packageName: 'org.example.sender', requested: const [
        'android.permission.SEND_SMS',
      ]),
    ]));

    expect(result, isEmpty);
  });

  test('reports visible scope and snapshot truncation as detection caveats', () {
    final result = detector.detect(collection(
      [app(requested: const [
        'android.permission.READ_SMS',
        'android.permission.SEND_SMS',
      ])],
      visibilityMayBeFiltered: true,
      truncated: true,
      permissionsTruncated: true,
    ));

    expect(result.single.caveats, containsAll([
      ApplicationPermissionDetectionCaveat.packageVisibilityMayBeFiltered,
      ApplicationPermissionDetectionCaveat.applicationListTruncated,
      ApplicationPermissionDetectionCaveat.permissionListTruncated,
    ]));
    expect(result.single.explanation.toLowerCase(), contains('visible'));
  });

  test('does not emit package detections without matching inventory source evidence', () {
    final apps = [app(requested: const [
      'android.permission.READ_SMS',
      'android.permission.SEND_SMS',
    ])];
    final snapshot = collection(apps);
    final noInventoryEvidence = VisibleApplicationCollection(
      contractVersion: snapshot.contractVersion,
      observedAt: snapshot.observedAt,
      scope: snapshot.scope,
      visibilityMayBeFiltered: snapshot.visibilityMayBeFiltered,
      truncated: snapshot.truncated,
      permissionsTruncated: snapshot.permissionsTruncated,
      applications: apps,
      events: const [],
    );

    expect(detector.detect(noInventoryEvidence), isEmpty);
  });

  test('uses restrained review language and never gives a safety verdict', () {
    final result = detector.detect(collection([
      app(requested: const [
        'android.permission.READ_CONTACTS',
        'android.permission.ACCESS_FINE_LOCATION',
      ]),
    ]));

    expect(result, isNotEmpty);
    for (final detection in result) {
      final copy = '${detection.title} ${detection.explanation}'.toLowerCase();
      expect(copy, contains('review'));
      expect(copy, isNot(contains('malicious')));
      expect(copy, isNot(contains('safe')));
      expect(detection.verdict, isNull);
    }
  });
}
