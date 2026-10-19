import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:svs_cyber_mobile/core/ai/credential_vault.dart';
import 'package:svs_cyber_mobile/features/settings/provider_credential_settings_page.dart';

void main() {
  group('ProviderCredentialSettingsPage', () {
    testWidgets('requires a key before calling the vault', (tester) async {
      final vault = _FakeCredentialVault();
      await _pumpPage(tester, vault);

      await tester.tap(find.text('Save key'));
      await tester.pumpAndSettle();

      expect(find.text('Enter a provider key.'), findsOneWidget);
      expect(vault.storeCalls, 0);
      expect(vault.replaceCalls, 0);
    });

    testWidgets('obscures the key and clears its field after submit', (
      tester,
    ) async {
      final vault = _FakeCredentialVault();
      await _pumpPage(tester, vault);
      final formFieldFinder = find.byKey(const Key('credential-secret-field'));
      final textInputFinder = find.descendant(
        of: formFieldFinder,
        matching: find.byType(EditableText),
      );
      await tester.enterText(textInputFinder, 'internal-test-secret');

      final textField = tester.widget<TextField>(
        find.descendant(of: formFieldFinder, matching: find.byType(TextField)),
      );
      expect(textField.obscureText, isTrue);

      await tester.tap(find.text('Save key'));
      await tester.pumpAndSettle();

      expect(vault.submittedSecrets, ['internal-test-secret']);
      expect(tester.widget<TextField>(
        find.descendant(of: formFieldFinder, matching: find.byType(TextField)),
      ).controller?.text, isEmpty);
      expect(find.text('Credential saved on this device.'), findsOneWidget);
    });

    testWidgets('shows credential metadata without rendering stored values', (
      tester,
    ) async {
      final vault = _FakeCredentialVault(
        initialMetadata: [
          MobileCredentialMetadata(
            provider: MobileCredentialProvider.googleGemini,
            configured: true,
            updatedAtEpochMs: 1760000000000,
          ),
        ],
      );
      await _pumpPage(tester, vault);

      expect(find.text('Configured'), findsOneWidget);
      expect(find.textContaining('internal-test-secret'), findsNothing);
      expect(find.textContaining('AIza'), findsNothing);
    });

    testWidgets('does not offer replacement when a saved record is unreadable', (
      tester,
    ) async {
      final vault = _FakeCredentialVault(
        initialMetadata: [
          MobileCredentialMetadata(
            provider: MobileCredentialProvider.googleGemini,
            configured: false,
            updatedAtEpochMs: 0,
          ),
        ],
      );
      await _pumpPage(tester, vault);

      expect(find.text('Saved key unavailable'), findsOneWidget);
      expect(find.textContaining('cannot be replaced'), findsOneWidget);
      expect(find.text('Replace key'), findsNothing);
      expect(find.byKey(const Key('credential-secret-field')), findsNothing);
      final deleteButton = find.widgetWithText(OutlinedButton, 'Delete saved key');
      expect(deleteButton, findsOneWidget);
      expect(tester.widget<OutlinedButton>(deleteButton).onPressed, isNotNull);
    });

    testWidgets('keeps native write errors generic and clears the entered key', (
      tester,
    ) async {
      final vault = _FakeCredentialVault(
        writeError: const CredentialVaultException('credential_already_exists'),
      );
      await _pumpPage(tester, vault);
      final formFieldFinder = find.byKey(const Key('credential-secret-field'));
      final textInputFinder = find.descendant(
        of: formFieldFinder,
        matching: find.byType(EditableText),
      );
      await tester.enterText(textInputFinder, 'internal-test-secret');

      await tester.tap(find.text('Save key'));
      await tester.pumpAndSettle();

      expect(find.textContaining('Credential could not be saved.'), findsOneWidget);
      expect(find.textContaining('credential_already_exists'), findsNothing);
      expect(tester.widget<TextField>(
        find.descendant(of: formFieldFinder, matching: find.byType(TextField)),
      ).controller?.text, isEmpty);
    });

    testWidgets('explains when the native secure vault is unavailable', (
      tester,
    ) async {
      final vault = _FakeCredentialVault(
        listError: const CredentialVaultException('unavailable'),
      );
      await _pumpPage(tester, vault);

      expect(find.text('Secure credential storage unavailable'), findsOneWidget);
      expect(find.textContaining('This Android build does not provide'), findsOneWidget);
      expect(find.byKey(const Key('credential-secret-field')), findsNothing);
    });
  });
}

Future<void> _pumpPage(WidgetTester tester, MobileCredentialVault vault) async {
  await tester.pumpWidget(MaterialApp(
    home: ProviderCredentialSettingsPage(vault: vault),
  ));
  await tester.pumpAndSettle();
}

class _FakeCredentialVault implements MobileCredentialVault {
  _FakeCredentialVault({
    this.initialMetadata = const [],
    this.listError,
    this.writeError,
  });

  final List<MobileCredentialMetadata> initialMetadata;
  final CredentialVaultException? listError;
  final CredentialVaultException? writeError;
  final List<String> submittedSecrets = [];
  int storeCalls = 0;
  int replaceCalls = 0;

  @override
  Future<MobileCredentialMetadata> storeKey({
    required MobileCredentialProvider provider,
    required String secret,
  }) async {
    storeCalls++;
    submittedSecrets.add(secret);
    if (writeError != null) throw writeError!;
    return MobileCredentialMetadata(
      provider: provider,
      configured: true,
      updatedAtEpochMs: 1760000000000,
    );
  }

  @override
  Future<MobileCredentialMetadata> replaceKey({
    required MobileCredentialProvider provider,
    required String secret,
  }) async {
    replaceCalls++;
    submittedSecrets.add(secret);
    if (writeError != null) throw writeError!;
    return MobileCredentialMetadata(
      provider: provider,
      configured: true,
      updatedAtEpochMs: 1760000000000,
    );
  }

  @override
  Future<bool> deleteKey({required MobileCredentialProvider provider}) async => true;

  @override
  Future<List<MobileCredentialMetadata>> listKeyMetadata() async {
    if (listError != null) throw listError!;
    return initialMetadata;
  }
}
