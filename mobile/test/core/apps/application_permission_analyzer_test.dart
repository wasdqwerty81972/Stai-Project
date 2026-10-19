import 'package:flutter_test/flutter_test.dart';
import 'package:svs_cyber_mobile/core/apps/application_permission_analyzer.dart';
import 'package:svs_cyber_mobile/core/apps/visible_application.dart';
import 'package:svs_cyber_mobile/core/detection/detection_models.dart';

void main() {
  const analyzer = ApplicationPermissionAnalyzer();

  VisibleApplication app({
    List<String> requested = const [],
    List<String> granted = const [],
    bool grantStateAvailable = true,
    String? installer = 'com.android.vending',
  }) => VisibleApplication(
    packageName: 'org.example.app',
    label: 'Example',
    versionName: '1',
    versionCode: 1,
    installerPackageName: installer,
    isSystemApp: false,
    requestedPermissions: requested,
    grantedPermissions: granted,
    permissionGrantStateAvailable: grantStateAvailable,
  );

  VisibleApplicationCollection collection(
    VisibleApplication application, {
    bool visibilityMayBeFiltered = false,
    bool truncated = false,
    bool permissionsTruncated = false,
  }) => VisibleApplicationCollection(
    contractVersion: 1,
    observedAt: DateTime.utc(2026),
    scope: VisibleApplicationCollection.supportedScope,
    visibilityMayBeFiltered: visibilityMayBeFiltered,
    truncated: truncated,
    permissionsTruncated: permissionsTruncated,
    applications: [application],
    events: const <MobileEvent>[],
  );

  test('reports explainable signals for requested sensitive permission groups', () {
    final result = analyzer.analyze(collection(app(
      requested: const [
        'android.permission.CAMERA',
        'android.permission.READ_CONTACTS',
        'android.permission.ACCESS_FINE_LOCATION',
      ],
      granted: const ['android.permission.CAMERA'],
    )));

    final review = result.applications.single;
    expect(review.signals.map((signal) => signal.groupId), containsAll([
      'camera_microphone', 'contacts', 'location',
    ]));
    final camera = review.signals.singleWhere((signal) => signal.groupId == 'camera_microphone');
    expect(camera.grantState, PermissionGrantState.granted);
    expect(camera.ruleId, isNotEmpty);
    expect(camera.explanation, isNotEmpty);
  });

  test('empty declarations do not produce permission group signals', () {
    final result = analyzer.analyze(collection(app()));
    expect(result.applications.single.signals, isEmpty);
  });

  test('preserves unavailable grant state as unknown', () {
    final result = analyzer.analyze(collection(app(
      requested: const ['android.permission.READ_SMS'],
      grantStateAvailable: false,
    )));
    expect(result.applications.single.signals.single.grantState,
        PermissionGrantState.unknown);
    expect(result.applications.single.caveats,
        contains(ApplicationPermissionCaveat.grantStateUnavailable));
  });

  test('does not infer special app access from runtime permission flags', () {
    final result = analyzer.analyze(collection(app(
      requested: const [
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.MANAGE_EXTERNAL_STORAGE',
      ],
      granted: const [
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.MANAGE_EXTERNAL_STORAGE',
      ],
    )));

    expect(result.applications.single.caveats,
        contains(ApplicationPermissionCaveat.specialAccessStateUnavailable));
    for (final signal in result.applications.single.signals) {
      expect(signal.grantState, PermissionGrantState.unknown);
    }
  });

  test('retains collection truncation and visibility caveats', () {
    final result = analyzer.analyze(collection(
      app(requested: const ['android.permission.READ_CONTACTS'], installer: null),
      visibilityMayBeFiltered: true,
      truncated: true,
      permissionsTruncated: true,
    ));
    final review = result.applications.single;
    expect(review.caveats, containsAll([
      ApplicationPermissionCaveat.packageVisibilityMayBeFiltered,
      ApplicationPermissionCaveat.applicationListTruncated,
      ApplicationPermissionCaveat.permissionListTruncated,
    ]));
    expect(review.signals.any((signal) => signal.ruleId.contains('sideload')), isFalse);
  });

  test('uses review signal language without malicious or safe verdicts', () {
    final result = analyzer.analyze(collection(app(
      requested: const ['android.permission.RECEIVE_SMS'],
    )));
    final allCopy = result.applications.single.signals
        .map((signal) => '${signal.title} ${signal.explanation}')
        .join(' ')
        .toLowerCase();
    expect(allCopy, contains('review'));
    expect(allCopy, isNot(contains('malicious')));
    expect(allCopy, isNot(contains('safe')));
    expect(result.applications.single.verdict, isNull);
  });
}

