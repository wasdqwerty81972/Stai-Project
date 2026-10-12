import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:svs_cyber_mobile/app/app.dart';
import 'package:svs_cyber_mobile/app/privacy_onboarding.dart';
import 'package:svs_cyber_mobile/core/platform/mobile_platform_client.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const platformChannel = MethodChannel(mobilePlatformMethodChannelName);
  const privacyChannel = MethodChannel(privacySetupChannelName);
  var platformCalls = <String>[];
  var baselineEvents = <Object?>[];

  setUp(() {
    platformCalls = [];
    baselineEvents = [];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(platformChannel, (call) async {
      platformCalls.add(call.method);
      if (call.method == 'collectDeviceBaseline') {
        return {
          'contractVersion': 1,
          'collectedAtEpochMs': DateTime.utc(2026, 10, 12).millisecondsSinceEpoch,
          'continuousMonitoring': false,
          'events': baselineEvents,
        };
      }
      if (call.method == 'getJournalStatus') {
        return {
          'contractVersion': 1,
          'available': true,
          'eventCount': baselineEvents.length,
          'sizeBytes': 512,
          'encryptedAtRest': true,
          'retentionDays': 30,
          'maxBytes': 8388608,
          'warning': null,
        };
      }
      if (call.method == 'readEvents') {
        return {'contractVersion': 1, 'events': baselineEvents};
      }
      throw PlatformException(code: 'unexpected_method');
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(platformChannel, null);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(privacyChannel, null);
  });

  testWidgets('first-run flow persists local-only setup without collecting',
      (tester) async {
    var setupComplete = false;
    final setupCalls = <String>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(privacyChannel, (call) async {
      setupCalls.add(call.method);
      if (call.method == 'isPrivacySetupComplete') return setupComplete;
      if (call.method == 'completePrivacySetup') {
        setupComplete = true;
        return null;
      }
      throw PlatformException(code: 'unexpected_method');
    });

    await tester.pumpWidget(const SvsCyberMobileApp());
    await tester.pumpAndSettle();

    expect(find.text('Your data stays on this device'), findsOneWidget);
    expect(platformCalls, isEmpty);
    expect(setupCalls, ['isPrivacySetupComplete']);

    await tester.tap(find.text('Continue in local-only mode'));
    await tester.pumpAndSettle();

    expect(setupComplete, isTrue);
    expect(setupCalls, ['isPrivacySetupComplete', 'completePrivacySetup']);
    expect(platformCalls, isEmpty);
    expect(find.text('Protection is not enabled'), findsOneWidget);
  });

  testWidgets('opens without collecting and exposes the explicit baseline action',
      (tester) async {
    await tester.pumpWidget(SvsCyberMobileApp(firstRunStore: _CompletedOnboardingStore()));

    expect(platformCalls, isEmpty);
    expect(find.text('Protection is not enabled'), findsOneWidget);
    expect(find.text('Run device baseline'), findsOneWidget);
  });

  testWidgets('shows the mobile tool registry and full capability catalogue',
      (tester) async {
    await tester.pumpWidget(SvsCyberMobileApp(firstRunStore: _CompletedOnboardingStore()));

    await tester.tap(find.text('Tools'));
    await tester.pumpAndSettle();
    expect(find.text('Device baseline'), findsOneWidget);
    expect(find.text('Selected APK inspection'), findsOneWidget);

    await tester.tap(find.text('Capabilities'));
    await tester.pumpAndSettle();
    expect(find.textContaining('136 capability definitions'), findsOneWidget);
    expect(find.textContaining('AND-001'), findsOneWidget);
  });

  testWidgets('a baseline request uses the native point-in-time collector',
      (tester) async {
    baselineEvents = [_deviceVersionEvent()];
    await tester.pumpWidget(SvsCyberMobileApp(firstRunStore: _CompletedOnboardingStore()));

    await tester.tap(find.text('Run device baseline'));
    await tester.pumpAndSettle();

    expect(platformCalls, ['collectDeviceBaseline']);
    expect(find.text('Baseline checked'), findsOneWidget);
    expect(find.text('No finding was created from this baseline.'), findsOneWidget);
  });

  testWidgets('turns an Android baseline observation into an evidence-linked finding',
      (tester) async {
    final observedAt = DateTime.now().toUtc();
    baselineEvents = [
      {
        'contractVersion': 1,
        'eventId': 'native-lock-observation',
        'capabilityId': 'AND-008',
        'eventType': 'observation',
        'occurredAtEpochMs': observedAt.millisecondsSinceEpoch,
        'observedAtEpochMs': observedAt.millisecondsSinceEpoch,
        'availability': 'available',
        'operation': 'completed',
        'freshness': 'fresh',
        'continuous': false,
        'evidence': {'secureLockConfigured': false},
      },
    ];
    await tester.pumpWidget(SvsCyberMobileApp(firstRunStore: _CompletedOnboardingStore()));

    await tester.tap(find.text('Run device baseline'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Findings'));
    await tester.pumpAndSettle();

    expect(find.text('Secure screen lock is not configured'), findsOneWidget);
    expect(find.textContaining('AND-008'), findsOneWidget);
    expect(find.textContaining('1 evidence reference'), findsOneWidget);
  });

  testWidgets('restores encrypted journal observations only on the user request',
      (tester) async {
    final observedAt = DateTime.now().toUtc();
    baselineEvents = [
      {
        'contractVersion': 1,
        'eventId': 'restored-lock-observation',
        'capabilityId': 'AND-008',
        'eventType': 'observation',
        'occurredAtEpochMs': observedAt.millisecondsSinceEpoch,
        'observedAtEpochMs': observedAt.millisecondsSinceEpoch,
        'availability': 'available',
        'operation': 'completed',
        'freshness': 'fresh',
        'continuous': false,
        'evidence': {'secureLockConfigured': false},
      },
    ];
    await tester.pumpWidget(SvsCyberMobileApp(firstRunStore: _CompletedOnboardingStore()));

    expect(platformCalls, isEmpty);
    await tester.tap(find.text('Restore last 24 hours'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Findings'));
    await tester.pumpAndSettle();

    expect(platformCalls, ['getJournalStatus', 'readEvents']);
    expect(find.text('Secure screen lock is not configured'), findsOneWidget);
  });

  testWidgets('capability status reflects a completed Android baseline observation',
      (tester) async {
    baselineEvents = [_deviceVersionEvent()];
    await tester.pumpWidget(SvsCyberMobileApp(firstRunStore: _CompletedOnboardingStore()));

    await tester.tap(find.text('Run device baseline'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Capabilities'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Android Version'));
    await tester.pumpAndSettle();

    expect(find.textContaining('AVAILABLE'), findsOneWidget);
    expect(find.text('LATEST COLLECTION OPERATION'), findsOneWidget);
    expect(find.text('COMPLETED'), findsOneWidget);
    expect(find.text('LAST SUCCESSFUL OBSERVATION'), findsOneWidget);
  });
}

class _CompletedOnboardingStore implements PrivacyOnboardingStore {
  @override
  Future<bool> isComplete() async => true;

  @override
  Future<void> markComplete() async {}
}

Map<String, Object?> _deviceVersionEvent() {
  final observedAt = DateTime.now().toUtc();
  return {
    'contractVersion': 1,
    'eventId': 'native-device-version-observation',
    'capabilityId': 'AND-001',
    'eventType': 'observation',
    'occurredAtEpochMs': observedAt.millisecondsSinceEpoch,
    'observedAtEpochMs': observedAt.millisecondsSinceEpoch,
    'availability': 'available',
    'operation': 'completed',
    'freshness': 'fresh',
    'continuous': false,
    'evidence': {'release': 'Android test', 'sdkInt': 36},
  };
}
