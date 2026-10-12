import 'package:flutter/material.dart';

import '../../core/ai/credential_vault.dart';

/// Settings for storing provider credentials on this Android device.
///
/// The page only calls the vault's metadata/store/replace/delete surface. It
/// never reads or renders a saved credential value and does not invoke a
/// provider.
class ProviderCredentialSettingsPage extends StatefulWidget {
  const ProviderCredentialSettingsPage({
    required this.vault,
    super.key,
  });

  final MobileCredentialVault vault;

  @override
  State<ProviderCredentialSettingsPage> createState() =>
      _ProviderCredentialSettingsPageState();
}

class _ProviderCredentialSettingsPageState
    extends State<ProviderCredentialSettingsPage> {
  final _secretController = TextEditingController();
  final Map<MobileCredentialProvider, MobileCredentialMetadata> _metadata = {};

  MobileCredentialProvider _provider = MobileCredentialProvider.googleGemini;
  bool _loading = true;
  bool _saving = false;
  bool _unsupported = false;
  bool _metadataLoadFailed = false;
  String? _message;
  bool _messageIsError = false;

  @override
  void initState() {
    super.initState();
    _loadMetadata();
  }

  @override
  void dispose() {
    _secretController.dispose();
    super.dispose();
  }

  Future<void> _loadMetadata() async {
    setState(() {
      _loading = true;
      _unsupported = false;
      _metadataLoadFailed = false;
      _message = null;
    });
    try {
      final items = await widget.vault.listKeyMetadata();
      if (!mounted) return;
      setState(() {
        _metadata
          ..clear()
          ..addEntries(items.map((item) => MapEntry(item.provider, item)));
        _loading = false;
        _metadataLoadFailed = false;
      });
    } on CredentialVaultException catch (error) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _unsupported = error.code == 'unavailable';
        _metadataLoadFailed = error.code != 'unavailable';
        _message = error.code == 'unavailable'
            ? null
            : 'Saved credential status could not be loaded.';
        _messageIsError = true;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _metadataLoadFailed = true;
        _message = 'Saved credential status could not be loaded.';
        _messageIsError = true;
      });
    }
  }

  Future<void> _submit() async {
    if (_unsupported || _saving || _loading) return;
    if (_metadata[_provider]?.configured == false) return;
    final secret = _secretController.text;
    if (secret.trim().isEmpty) {
      setState(() {
        _message = 'Enter a provider key.';
        _messageIsError = true;
      });
      return;
    }

    final isReplace = _metadata.containsKey(_provider);
    // Clear the visible field before crossing the platform channel. Dart
    // strings cannot be reliably zeroized, so callers must not retain them.
    _secretController.clear();
    setState(() {
      _saving = true;
      _message = null;
    });

    try {
      final result = isReplace
          ? await widget.vault.replaceKey(provider: _provider, secret: secret)
          : await widget.vault.storeKey(provider: _provider, secret: secret);
      if (!mounted) return;
      setState(() {
        _metadata[_provider] = result;
        _saving = false;
        _message = isReplace
            ? 'Credential replaced on this device.'
            : 'Credential saved on this device.';
        _messageIsError = false;
      });
    } on CredentialVaultException catch (error) {
      if (!mounted) return;
      setState(() {
        _saving = false;
        _unsupported = error.code == 'unavailable';
        _message = error.code == 'unavailable'
            ? null
            : 'Credential could not be saved. Check the provider selection and try again.';
        _messageIsError = true;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _saving = false;
        _message = 'Credential could not be saved. Try again.';
        _messageIsError = true;
      });
    } finally {
      // Keep the controller empty for both success and failure paths.
      _secretController.clear();
    }
  }

  Future<void> _deleteCredential() async {
    if (_saving || _unsupported) return;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Delete saved key?'),
        content: const Text(
          'This removes the saved credential from this device. It does not revoke the key with its provider.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('Delete key'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    setState(() {
      _saving = true;
      _message = null;
    });
    try {
      await widget.vault.deleteKey(provider: _provider);
      if (!mounted) return;
      setState(() {
        _metadata.remove(_provider);
        _saving = false;
        _message = 'Saved credential deleted from this device.';
        _messageIsError = false;
      });
    } on CredentialVaultException catch (error) {
      if (!mounted) return;
      setState(() {
        _saving = false;
        _unsupported = error.code == 'unavailable';
        _message = error.code == 'unavailable'
            ? null
            : 'Credential could not be deleted. Try again.';
        _messageIsError = true;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _saving = false;
        _message = 'Credential could not be deleted. Try again.';
        _messageIsError = true;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final currentMetadata = _metadata[_provider];
    final hasStoredRecord = currentMetadata != null;
    final configured = currentMetadata?.configured ?? false;
    final colors = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(title: const Text('AI provider keys')),
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(18, 16, 18, 28),
          children: [
            Text(
              'Optional AI assistance',
              style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.w800,
                  ),
            ),
            const SizedBox(height: 8),
            const Text(
              'Local checks work without an AI provider. These settings only save or remove a key; they do not send findings or call a provider.',
              style: TextStyle(color: Colors.white70, height: 1.45),
            ),
            const SizedBox(height: 16),
            _SecurityNotice(colors: colors),
            const SizedBox(height: 18),
            if (_unsupported) ...[
              _UnsupportedNotice(colors: colors),
            ] else if (_loading) ...[
              const Center(
                child: Padding(
                  padding: EdgeInsets.all(28),
                  child: CircularProgressIndicator(),
                ),
              ),
            ] else if (_metadataLoadFailed) ...[
              _MetadataUnavailableNotice(colors: colors),
              const SizedBox(height: 12),
              OutlinedButton.icon(
                onPressed: _loadMetadata,
                icon: const Icon(Icons.refresh_rounded),
                label: const Text('Try again'),
              ),
            ] else ...[
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        DropdownButtonFormField<MobileCredentialProvider>(
                          value: _provider,
                          decoration: const InputDecoration(
                            labelText: 'Provider',
                            border: OutlineInputBorder(),
                          ),
                          items: [
                            for (final provider in MobileCredentialProvider.values)
                              DropdownMenuItem(
                                value: provider,
                                child: Text(_providerLabel(provider)),
                              ),
                          ],
                          onChanged: _saving
                              ? null
                              : (provider) {
                                  if (provider == null) return;
                                  setState(() {
                                    _provider = provider;
                                    _message = null;
                                    _secretController.clear();
                                  });
                                },
                        ),
                        const SizedBox(height: 14),
                        if (hasStoredRecord && !configured) ...[
                          const _UnreadableCredentialNotice(),
                        ] else ...[
                          TextFormField(
                            key: const Key('credential-secret-field'),
                            controller: _secretController,
                            obscureText: true,
                            enableSuggestions: false,
                            autocorrect: false,
                            keyboardType: TextInputType.visiblePassword,
                            textInputAction: TextInputAction.done,
                            autofillHints: const [],
                            decoration: InputDecoration(
                              labelText: hasStoredRecord ? 'Replacement key' : 'Provider key',
                              hintText: 'Key is never displayed after saving',
                              border: const OutlineInputBorder(),
                            ),
                            onFieldSubmitted: (_) => _submit(),
                          ),
                          const SizedBox(height: 10),
                        ],
                        _CredentialStatus(
                          metadata: currentMetadata,
                        ),
                        if (!(hasStoredRecord && !configured)) ...[
                          const SizedBox(height: 14),
                          FilledButton.icon(
                            onPressed: _saving ? null : _submit,
                            icon: _saving
                                ? const SizedBox.square(
                                    dimension: 18,
                                    child: CircularProgressIndicator(strokeWidth: 2),
                                  )
                                : Icon(hasStoredRecord ? Icons.sync_rounded : Icons.lock_rounded),
                            label: Text(
                              _saving
                                  ? 'Saving securely…'
                                  : hasStoredRecord
                                      ? 'Replace key'
                                      : 'Save key',
                            ),
                          ),
                        ],
                        if (hasStoredRecord) ...[
                          const SizedBox(height: 8),
                          OutlinedButton.icon(
                            onPressed: _saving ? null : _deleteCredential,
                            icon: const Icon(Icons.delete_outline_rounded),
                            label: const Text('Delete saved key'),
                          ),
                        ],
                      ],
                    ),
                  ),
                ),
              ),
            ],
            if (_message != null) ...[
              const SizedBox(height: 12),
              _FeedbackMessage(
                message: _message!,
                isError: _messageIsError,
              ),
            ],
            if (_unsupported) ...[
              const SizedBox(height: 12),
              OutlinedButton.icon(
                onPressed: _loadMetadata,
                icon: const Icon(Icons.refresh_rounded),
                label: const Text('Check again'),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

String _providerLabel(MobileCredentialProvider provider) => switch (provider) {
      MobileCredentialProvider.googleGemini => 'Google Gemini',
      MobileCredentialProvider.openAiCompatible => 'OpenAI-compatible API',
    };

class _SecurityNotice extends StatelessWidget {
  const _SecurityNotice({required this.colors});

  final ColorScheme colors;

  @override
  Widget build(BuildContext context) => Card(
        color: colors.tertiaryContainer.withValues(alpha: .22),
        child: Padding(
          padding: const EdgeInsets.all(14),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.warning_amber_rounded, color: colors.tertiary),
              const SizedBox(width: 12),
              const Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Internal testing only',
                      style: TextStyle(fontWeight: FontWeight.w800),
                    ),
                    SizedBox(height: 5),
                    Text(
                      'Android Keystore protects saved keys at rest, but a client-side key can still be extracted from a compromised or runtime-instrumented app. Do not use provider keys in a public build until a mobile-only proxy or on-device model is selected.',
                      style: TextStyle(color: Colors.white70, height: 1.4),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      );
}

class _UnsupportedNotice extends StatelessWidget {
  const _UnsupportedNotice({required this.colors});

  final ColorScheme colors;

  @override
  Widget build(BuildContext context) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.lock_outline_rounded, color: colors.tertiary),
              const SizedBox(height: 10),
              const Text(
                'Secure credential storage unavailable',
                style: TextStyle(fontWeight: FontWeight.w800),
              ),
              const SizedBox(height: 6),
              const Text(
                'This Android build does not provide the credential vault. No key was stored. You can still use local checks without AI.',
                style: TextStyle(color: Colors.white70, height: 1.4),
              ),
            ],
          ),
        ),
      );
}

class _CredentialStatus extends StatelessWidget {
  const _CredentialStatus({required this.metadata});

  final MobileCredentialMetadata? metadata;

  @override
  Widget build(BuildContext context) {
    final configured = metadata?.configured ?? false;
    final hasStoredRecord = metadata != null;
    return Row(
      children: [
        Icon(
          configured
              ? Icons.check_circle_outline
              : hasStoredRecord
                  ? Icons.warning_amber_rounded
                  : Icons.info_outline,
          size: 18,
          color: configured ? Colors.greenAccent : Colors.white54,
        ),
        const SizedBox(width: 8),
        Text(
          configured
              ? 'Configured'
              : hasStoredRecord
                  ? 'Saved key unavailable'
                  : 'Not configured',
          style: TextStyle(
            color: configured ? Colors.greenAccent : Colors.white70,
            fontWeight: FontWeight.w600,
          ),
        ),
      ],
    );
  }
}

class _UnreadableCredentialNotice extends StatelessWidget {
  const _UnreadableCredentialNotice();

  @override
  Widget build(BuildContext context) => const Padding(
        padding: EdgeInsets.symmetric(vertical: 8),
        child: Text(
          'This saved record cannot be replaced because Android Keystore cannot read it. Delete the record, then set up a new key.',
          style: TextStyle(color: Colors.orangeAccent, height: 1.4),
        ),
      );
}

class _MetadataUnavailableNotice extends StatelessWidget {
  const _MetadataUnavailableNotice({required this.colors});

  final ColorScheme colors;

  @override
  Widget build(BuildContext context) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.error_outline_rounded, color: colors.tertiary),
              const SizedBox(height: 10),
              const Text(
                'Saved credential status could not be read',
                style: TextStyle(fontWeight: FontWeight.w800),
              ),
              const SizedBox(height: 6),
              const Text(
                'The app will not offer to save or replace a key until the secure vault can report whether one is already stored.',
                style: TextStyle(color: Colors.white70, height: 1.4),
              ),
            ],
          ),
        ),
      );
}

class _FeedbackMessage extends StatelessWidget {
  const _FeedbackMessage({required this.message, required this.isError});

  final String message;
  final bool isError;

  @override
  Widget build(BuildContext context) => Semantics(
        liveRegion: true,
        child: Text(
          message,
          style: TextStyle(
            color: isError ? Colors.orangeAccent : Colors.greenAccent,
            fontWeight: FontWeight.w600,
          ),
        ),
      );
}
