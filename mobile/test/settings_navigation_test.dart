import 'package:flutter_test/flutter_test.dart';
import 'package:svs_cyber_mobile/app/app.dart';

void main() {
  testWidgets('opens provider key settings from the existing Settings page', (
    tester,
  ) async {
    await tester.pumpWidget(const SvsCyberMobileApp());

    await tester.tap(find.byTooltip('Settings'));
    await tester.pumpAndSettle();

    expect(find.text('Settings'), findsOneWidget);
    await tester.tap(find.text('Manage AI provider keys'));
    await tester.pumpAndSettle();

    expect(find.text('AI provider keys'), findsOneWidget);
    expect(find.text('Internal testing only'), findsOneWidget);
  });
}
