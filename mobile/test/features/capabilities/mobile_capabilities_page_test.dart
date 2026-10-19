import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:svs_cyber_mobile/features/capabilities/mobile_capabilities_page.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('renders the bundled catalogue and exposes truthful status',
      (tester) async {
    await tester.pumpWidget(const MaterialApp(home: MobileCapabilitiesPage()));
    await tester.pumpAndSettle();

    expect(find.textContaining('136 capability definitions'), findsOneWidget);
    expect(find.textContaining('AND-001'), findsOneWidget);
    expect(find.textContaining('NOT CHECKED'), findsWidgets);
    expect(find.textContaining('DISABLED'), findsWidgets);
  });

  testWidgets('filters the capability list by identifier', (tester) async {
    await tester.pumpWidget(const MaterialApp(home: MobileCapabilitiesPage()));
    await tester.pumpAndSettle();

    await tester.enterText(find.byKey(const Key('capability-search')), 'AND-129');
    await tester.pumpAndSettle();

    expect(find.textContaining('AND-129'), findsOneWidget);
    expect(find.textContaining('AND-001'), findsNothing);
  });

  testWidgets('filters by a capability category', (tester) async {
    await tester.pumpWidget(const MaterialApp(home: MobileCapabilitiesPage()));
    await tester.pumpAndSettle();

    final categoryFilter = find.byKey(const Key(
        'category-filter-Managed-device and security-log sensors'));
    await tester.ensureVisible(categoryFilter);
    await tester.tap(categoryFilter);
    await tester.pumpAndSettle();

    expect(find.textContaining('AND-129'), findsOneWidget);
    expect(find.textContaining('AND-001'), findsNothing);
  });
}
