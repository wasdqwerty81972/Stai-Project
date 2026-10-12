import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

const privacySetupChannelName = 'com.svscyber.mobile/privacy_setup.v1';

abstract interface class PrivacyOnboardingStore {
  Future<bool> isComplete();
  Future<void> markComplete();
}

class MethodChannelPrivacyOnboardingStore implements PrivacyOnboardingStore {
  MethodChannelPrivacyOnboardingStore({MethodChannel? channel})
      : _channel = channel ?? const MethodChannel(privacySetupChannelName);

  final MethodChannel _channel;

  @override
  Future<bool> isComplete() async =>
      await _channel.invokeMethod<bool>('isPrivacySetupComplete') ?? false;

  @override
  Future<void> markComplete() =>
      _channel.invokeMethod<void>('completePrivacySetup');
}

class PrivacyOnboardingGate extends StatefulWidget {
  const PrivacyOnboardingGate({
    super.key,
    required this.store,
    required this.appBuilder,
  });

  final PrivacyOnboardingStore store;
  final WidgetBuilder appBuilder;

  @override
  State<PrivacyOnboardingGate> createState() => _PrivacyOnboardingGateState();
}

class _PrivacyOnboardingGateState extends State<PrivacyOnboardingGate> {
  late Future<bool> _setup;
  bool _saving = false;
  bool _saveFailed = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _setup = widget.store.isComplete();
  }

  void _retryLoad() {
    if (_saveFailed) {
      setState(() => _error = null);
      return;
    }
    setState(() {
      _error = null;
      _setup = widget.store.isComplete();
    });
  }

  Future<void> _completeSetup() async {
    setState(() {
      _saving = true;
      _error = null;
    });
    try {
      await widget.store.markComplete();
      if (mounted) {
        setState(() {
          _saveFailed = false;
          _setup = Future.value(true);
        });
      }
    } on PlatformException {
      if (mounted) {
        setState(() {
          _saveFailed = true;
          _error = 'Privacy setup could not be saved on this device.';
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() {
          _saveFailed = true;
          _error = 'Privacy setup could not be saved on this device.';
        });
      }
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  @override
  Widget build(BuildContext context) => FutureBuilder<bool>(
        future: _setup,
        builder: (context, snapshot) {
          if (snapshot.connectionState != ConnectionState.done) {
            return const Scaffold(
              body: Center(child: CircularProgressIndicator()),
            );
          }
          if (snapshot.data == true) return widget.appBuilder(context);
          return _privacySetupPage(context, loadError: snapshot.hasError);
        },
      );

  Widget _privacySetupPage(BuildContext context, {required bool loadError}) =>
      Scaffold(
        body: SafeArea(
          child: ListView(
            padding: const EdgeInsets.fromLTRB(24, 36, 24, 28),
            children: [
              Icon(Icons.security_rounded,
                  size: 42, color: Theme.of(context).colorScheme.primary),
              const SizedBox(height: 24),
              Text('PRIVACY SETUP',
                  style: TextStyle(
                    color: Theme.of(context).colorScheme.primary,
                    fontSize: 11,
                    letterSpacing: 1.4,
                    fontWeight: FontWeight.w800,
                  )),
              const SizedBox(height: 10),
              Text('Your data stays on this device',
                  style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                        fontWeight: FontWeight.w800,
                        height: 1.1,
                      )),
              const SizedBox(height: 12),
              const Text(
                'SVS-Cyber Mobile starts in local-only mode. You choose when to run a check and what evidence to review.',
                style: TextStyle(color: Colors.white70, height: 1.5),
              ),
              const SizedBox(height: 22),
              const _PrivacyItem(
                icon: Icons.pause_circle_outline_rounded,
                title: 'No sensors run until you start a check.',
                detail: 'This build only performs a point-in-time device baseline when you request it.',
              ),
              const SizedBox(height: 12),
              const _PrivacyItem(
                icon: Icons.phone_android_rounded,
                title: 'Observations stay in app storage.',
                detail: 'The local event journal is encrypted. Nothing is uploaded automatically.',
              ),
              const SizedBox(height: 12),
              const _PrivacyItem(
                icon: Icons.cloud_off_outlined,
                title: 'AI is optional.',
                detail: 'No provider is contacted here. External evidence sharing will require a separate review and confirmation.',
              ),
              if (loadError || _error != null) ...[
                const SizedBox(height: 16),
                Text(
                  _error ?? 'Privacy setup status could not be read.',
                  style: TextStyle(color: Theme.of(context).colorScheme.error),
                ),
                TextButton(
                  onPressed: _saving ? null : _retryLoad,
                  child: const Text('Retry'),
                ),
              ],
              const SizedBox(height: 20),
              FilledButton(
                onPressed: _saving || loadError ? null : _completeSetup,
                child: _saving
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Text('Continue in local-only mode'),
              ),
              const SizedBox(height: 10),
              const Text(
                'You can review privacy and provider settings at any time.',
                textAlign: TextAlign.center,
                style: TextStyle(color: Colors.white54, fontSize: 12),
              ),
            ],
          ),
        ),
      );
}

class _PrivacyItem extends StatelessWidget {
  const _PrivacyItem({
    required this.icon,
    required this.title,
    required this.detail,
  });

  final IconData icon;
  final String title;
  final String detail;

  @override
  Widget build(BuildContext context) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(icon, color: Theme.of(context).colorScheme.primary),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(title,
                        style: const TextStyle(fontWeight: FontWeight.w700)),
                    const SizedBox(height: 5),
                    Text(detail,
                        style: const TextStyle(
                            color: Colors.white60, fontSize: 12, height: 1.4)),
                  ],
                ),
              ),
            ],
          ),
        ),
      );
}
