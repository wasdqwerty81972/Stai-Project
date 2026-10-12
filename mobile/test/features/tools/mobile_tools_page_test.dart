import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:svs_cyber_mobile/core/detection/local_detection_engine.dart';
import 'package:svs_cyber_mobile/core/platform/mobile_platform_client.dart';
import 'package:svs_cyber_mobile/core/platform/mobile_security_session.dart';
import 'package:svs_cyber_mobile/core/tools/mobile_tool_definition.dart';
import 'package:svs_cyber_mobile/core/tools/mobile_tool_registry.dart';
import 'package:svs_cyber_mobile/features/tools/mobile_tools_page.dart';

void main() {
  late MobileSecuritySession session;
  late List<String> platformCalls;
  late Map<String, Object?> response;
  Object? collectionError;

  setUp(() {
    platformCalls = [];
    response = _inventoryResponse();
    collectionError = null;
    session = MobileSecuritySession(
      platform: MethodChannelMobilePlatformClient.withTransports(
        invokeMethod: (method, arguments) async {
          platformCalls.add(method);
          if (collectionError != null) throw collectionError!;
          return response;
        },
        receiveEvents: () => const Stream<Object?>.empty(),
      ),
      detectionEngine: LocalDetectionEngine(rules: builtInPostureRules),
      clock: () => DateTime.utc(2026, 10, 12, 12),
    );
  });

  tearDown(() => session.dispose());

  testWidgets('shows every registered tool with its implementation status',
      (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(body: MobileToolsPage(session: session)),
    ));

    expect(find.text('Implementation status'), findsOneWidget);
    for (final tool in mobileToolRegistry) {
      expect(find.text(tool.name), findsOneWidget);
      expect(find.text(tool.summary), findsOneWidget);
      final card = find.ancestor(of: find.text(tool.name), matching: find.byType(Card));
      final status = tool.implementationStatus == MobileToolImplementationStatus.partial
          ? 'Partial implementation'
          : 'Planned';
      expect(find.descendant(of: card, matching: find.text(status)), findsOneWidget);
      expect(find.descendant(of: card, matching: find.byType(FilledButton)), findsNothing);
    }
    expect(find.byType(ElevatedButton), findsNothing);
    expect(find.byType(TextButton), findsNothing);
    expect(find.byType(IconButton), findsNothing);
    expect(platformCalls, isEmpty);
  });

  testWidgets('discloses phase and safety boundaries for each tool',
      (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(body: MobileToolsPage(session: session)),
    ));

    final baseline = find.ancestor(
      of: find.text('Device baseline'),
      matching: find.byType(Card),
    );
    expect(find.descendant(of: baseline, matching: find.text('Phase: Foundation')),
        findsOneWidget);
    expect(find.descendant(of: baseline, matching: find.text('Network: No network use')),
        findsOneWidget);
    expect(find.descendant(of: baseline, matching: find.text('State changes: None')),
        findsOneWidget);

    final urlCheck = find.ancestor(
      of: find.text('Local URL check'),
      matching: find.byType(Card),
    );
    expect(find.descendant(of: urlCheck, matching: find.text('Phase: Consumer MVP')),
        findsOneWidget);
    expect(find.descendant(of: urlCheck, matching: find.text('Network: Local processing only')),
        findsOneWidget);

    final export = find.ancestor(
      of: find.text('Diagnostic report export'),
      matching: find.byType(Card),
    );
    expect(find.descendant(of: export,
        matching: find.text('State changes: Creates a user-requested export')),
        findsOneWidget);
  });

  testWidgets('remains readable and scrollable on a narrow phone with large text',
      (tester) async {
    tester.view.physicalSize = const Size(320, 640);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await session.collectVisibleApplications();

    await tester.pumpWidget(MaterialApp(
      builder: (context, child) => MediaQuery(
        data: MediaQuery.of(context).copyWith(textScaler: const TextScaler.linear(1.8)),
        child: child!,
      ),
      home: Scaffold(body: MobileToolsPage(session: session)),
    ));

    await tester.ensureVisible(find.text('Diagnostic report export'));
    await tester.pumpAndSettle();

    expect(find.text('Diagnostic report export').hitTestable(), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('confirmation stays readable on a narrow phone with large text',
      (tester) async {
    tester.view.physicalSize = const Size(320, 640);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(MaterialApp(
      builder: (context, child) => MediaQuery(
        data: MediaQuery.of(context).copyWith(textScaler: const TextScaler.linear(1.8)),
        child: child!,
      ),
      home: Scaffold(body: MobileToolsPage(session: session)),
    ));

    await tester.ensureVisible(find.text('Review visible apps'));
    await tester.tap(find.text('Review visible apps'));
    await tester.pumpAndSettle();

    expect(find.text('Collect a visible app snapshot?'), findsOneWidget);
    expect(tester.takeException(), isNull);
    expect(platformCalls, isEmpty);
  });

  testWidgets('collects visible apps only after explicit confirmation',
      (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(body: MobileToolsPage(session: session)),
    ));
    expect(platformCalls, isEmpty);

    await tester.ensureVisible(find.text('Review visible apps'));
    await tester.tap(find.text('Review visible apps'));
    await tester.pumpAndSettle();
    expect(find.text('Collect a visible app snapshot?'), findsOneWidget);
    expect(find.textContaining('Results may be incomplete.'), findsWidgets);
    expect(platformCalls, isEmpty);

    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(platformCalls, isEmpty);

    await tester.tap(find.text('Review visible apps'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Collect visible apps'));
    await tester.pumpAndSettle();
    expect(platformCalls, ['collectVisibleApplications']);
    expect(find.text('Example calendar'), findsOneWidget);
    expect(find.textContaining('Snapshot observed:'), findsOneWidget);
    expect(session.findings, isEmpty);
  });

  testWidgets('shows app metadata and permission caveats without a safety verdict',
      (tester) async {
    await session.collectVisibleApplications();
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(body: MobileToolsPage(session: session)),
    ));

    await tester.ensureVisible(find.text('Example calendar'));
    await tester.tap(find.text('Example calendar'));
    await tester.pumpAndSettle();
    expect(find.text('org.example.calendar'), findsOneWidget);
    expect(find.text('Version: 2.1 (21)'), findsOneWidget);
    expect(find.text('Installer: Unknown or unavailable'), findsOneWidget);
    expect(find.text('System app: No'), findsOneWidget);
    expect(find.text('Declared permissions'), findsOneWidget);
    expect(find.text('Granted permissions'), findsOneWidget);
    expect(find.text('android.permission.READ_CONTACTS'), findsOneWidget);
    expect(find.textContaining('does not prove it was used'), findsOneWidget);
    expect(find.textContaining('malicious'), findsNothing);
    expect(find.text('Remediate'), findsNothing);
  });

  testWidgets('labels a truncated inventory and distinguishes an empty snapshot',
      (tester) async {
    response['truncated'] = true;
    await session.collectVisibleApplications();
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(body: MobileToolsPage(session: session)),
    ));
    expect(find.text('Collection limit reached; this snapshot is truncated.'),
        findsOneWidget);

    response = _inventoryResponse(applications: const []);
    await session.collectVisibleApplications();
    await tester.pumpAndSettle();
    expect(find.text('No launchable apps were returned in this visible scope.'),
        findsOneWidget);
    expect(find.text('Example calendar'), findsNothing);
  });

  testWidgets('shows a collection failure without inventing results',
      (tester) async {
    collectionError = const MobilePlatformException(
      'inventory_unavailable',
      'The visible app inventory is unavailable.',
    );
    await tester.pumpWidget(MaterialApp(
      home: Scaffold(body: MobileToolsPage(session: session)),
    ));
    await tester.ensureVisible(find.text('Review visible apps'));
    await tester.tap(find.text('Review visible apps'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Collect visible apps'));
    await tester.pumpAndSettle();

    expect(find.text('The visible app inventory is unavailable.'), findsOneWidget);
    expect(find.text('Example calendar'), findsNothing);
    expect(find.textContaining('Snapshot observed:'), findsNothing);
    expect(find.text('Review visible apps'), findsOneWidget);
  });
}

Map<String, Object?> _inventoryResponse({List<Map<String, Object?>>? applications}) {
  final observedAt = DateTime.utc(2026, 10, 12, 12).millisecondsSinceEpoch;
  return {
    'contractVersion': 1,
    'scope': 'launchable_packages_visible_to_this_app',
    'visibilityMayBeFiltered': true,
    'truncated': false,
    'observedAtEpochMs': observedAt,
    'applications': applications ?? [
      {
        'packageName': 'org.example.calendar',
        'label': 'Example calendar',
        'versionName': '2.1',
        'versionCode': 21,
        'installerPackageName': null,
        'isSystemApp': false,
        'requestedPermissions': [
          'android.permission.INTERNET',
          'android.permission.READ_CONTACTS',
        ],
        'grantedPermissions': ['android.permission.INTERNET'],
      },
    ],
    'events': [
      {
        'contractVersion': 1,
        'eventId': 'visible-app-test',
        'capabilityId': 'AND-012',
        'eventType': 'observation',
        'occurredAtEpochMs': observedAt,
        'observedAtEpochMs': observedAt,
        'availability': 'available',
        'operation': 'completed',
        'freshness': 'fresh',
        'continuous': false,
        'evidence': {'applicationCount': applications?.length ?? 1},
      },
    ],
  };
}
import 'dart:async';

