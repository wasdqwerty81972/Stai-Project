import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:svs_cyber_mobile/app/privacy_onboarding.dart';

class MemoryOnboardingStore implements PrivacyOnboardingStore {
  MemoryOnboardingStore({this.completed = false});

  bool completed;
  bool failNextWrite = false;
  int readCount = 0;
  int writeCount = 0;

  @override
  Future<bool> isComplete() async {
    readCount++;
    return completed;
  }

  @override
  Future<void> markComplete() async {
    writeCount++;
    if (failNextWrite) {
      failNextWrite = false;
      throw StateError('write failed');
    }
    completed = true;
  }
}

void main() {
  testWidgets('first launch shows privacy choices without starting collection',
      (tester) async {
    final store = MemoryOnboardingStore();
    var appOpened = false;

    await tester.pumpWidget(MaterialApp(
      home: PrivacyOnboardingGate(
        store: store,
        appBuilder: (_) {
          appOpened = true;
          return const Text('Mobile home');
        },
      ),
    ));
    await tester.pumpAndSettle();

    expect(find.text('Your data stays on this device'), findsOneWidget);
    expect(find.text('No sensors run until you start a check.'), findsOneWidget);
    expect(find.text('AI is optional.'), findsOneWidget);
    expect(find.text('Continue in local-only mode'), findsOneWidget);
    expect(store.readCount, 1);
    expect(store.writeCount, 0);
    expect(appOpened, isFalse);
  });

  testWidgets('continuing persists setup before opening the app', (tester) async {
    final store = MemoryOnboardingStore();
    await tester.pumpWidget(MaterialApp(
      home: PrivacyOnboardingGate(
        store: store,
        appBuilder: (_) => const Text('Mobile home'),
      ),
    ));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Continue in local-only mode'));
    await tester.pumpAndSettle();

    expect(store.writeCount, 1);
    expect(find.text('Mobile home'), findsOneWidget);
  });

  testWidgets('completed setup opens the app without showing onboarding',
      (tester) async {
    final store = MemoryOnboardingStore(completed: true);
    await tester.pumpWidget(MaterialApp(
      home: PrivacyOnboardingGate(
        store: store,
        appBuilder: (_) => const Text('Mobile home'),
      ),
    ));
    await tester.pumpAndSettle();

    expect(find.text('Mobile home'), findsOneWidget);
    expect(find.text('Your data stays on this device'), findsNothing);
    expect(store.writeCount, 0);
  });

  testWidgets('failed save retry stays on onboarding until a save succeeds',
      (tester) async {
    final store = MemoryOnboardingStore()..failNextWrite = true;
    await tester.pumpWidget(MaterialApp(
      home: PrivacyOnboardingGate(
        store: store,
        appBuilder: (_) => const Text('Mobile home'),
      ),
    ));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Continue in local-only mode'));
    await tester.pumpAndSettle();
    expect(find.text('Mobile home'), findsNothing);

    await tester.tap(find.text('Retry'));
    await tester.pumpAndSettle();
    expect(find.text('Your data stays on this device'), findsOneWidget);
    expect(store.writeCount, 1);

    await tester.tap(find.text('Continue in local-only mode'));
    await tester.pumpAndSettle();
    expect(store.writeCount, 2);
    expect(find.text('Mobile home'), findsOneWidget);
  });
}
