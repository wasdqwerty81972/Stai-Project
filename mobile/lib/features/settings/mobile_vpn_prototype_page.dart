import 'package:flutter/material.dart';

import '../../core/platform/mobile_vpn_consent_client.dart';

class MobileVpnPrototypePage extends StatefulWidget {
  const MobileVpnPrototypePage({super.key, required this.client});

  final MobileVpnConsentClient client;

  @override
  State<MobileVpnPrototypePage> createState() => _MobileVpnPrototypePageState();
}

class _MobileVpnPrototypePageState extends State<MobileVpnPrototypePage> {
  MobileVpnConsentStatus? _status;
  bool _loading = true;
  bool _requesting = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _refreshStatus();
  }

  Future<void> _refreshStatus() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final status = await widget.client.getVpnStatus();
      if (!mounted) return;
      setState(() {
        _status = status;
        _loading = false;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _status = null;
        _loading = false;
        _error = 'VPN status is unavailable on this device.';
      });
    }
  }

  Future<void> _requestConsent() async {
    final status = _status;
    if (_requesting || status == null || !status.enabledForBuild ||
        status.state != MobileVpnConsentState.consentRequired) {
      return;
    }
    setState(() {
      _requesting = true;
      _error = null;
    });
    try {
      final updated = await widget.client.requestVpnConsent();
      if (!mounted) return;
      setState(() {
        _status = updated;
        _requesting = false;
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _requesting = false;
        _error = 'Android could not complete the consent request.';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final status = _status;
    final requestEnabled = !_loading &&
        !_requesting &&
        status?.enabledForBuild == true &&
        status?.state == MobileVpnConsentState.consentRequired;
    return Scaffold(
      appBar: AppBar(title: const Text('Tor routing prototype')),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(18, 18, 18, 28),
        children: [
          Text('INTERNAL PROTOTYPE',
              style: TextStyle(
                color: Theme.of(context).colorScheme.primary,
                fontSize: 11,
                letterSpacing: 1.3,
                fontWeight: FontWeight.w800,
              )),
          const SizedBox(height: 10),
          Text('Tor network routing',
              style: Theme.of(context)
                  .textTheme
                  .headlineSmall
                  ?.copyWith(fontWeight: FontWeight.w800)),
          const SizedBox(height: 8),
          const Text(
            'This page only checks Android VPN consent availability. The Tor routing engine is not connected yet.',
            style: TextStyle(color: Colors.white60, height: 1.45),
          ),
          const SizedBox(height: 20),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _StatusRow(
                    label: 'Build availability',
                    value: _loading
                        ? 'Checking…'
                        : status?.enabledForBuild == true
                            ? 'Available for internal testing'
                            : 'Unavailable in this build',
                  ),
                  const SizedBox(height: 14),
                  _StatusRow(
                    label: 'System consent',
                    value: _loading
                        ? 'Checking…'
                        : _consentLabel(status),
                  ),
                  const SizedBox(height: 14),
                  const _StatusRow(
                    label: 'Tor backend',
                    value: 'Unavailable · not integrated',
                  ),
                  const SizedBox(height: 14),
                  const _StatusRow(label: 'Tunnel', value: 'Inactive'),
                  const SizedBox(height: 14),
                  const _StatusRow(label: 'Traffic monitoring', value: 'Inactive'),
                  if (_error != null) ...[
                    const SizedBox(height: 14),
                    Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
                  ],
                ],
              ),
            ),
          ),
          const SizedBox(height: 14),
          Card(
            color: Theme.of(context).colorScheme.errorContainer.withValues(alpha: .28),
            child: const Padding(
              padding: EdgeInsets.all(16),
              child: Text(
                'Prototype notice: Android consent may be granted, but the Tor backend, DNS relay, VPN tunnel, and traffic monitoring are unavailable and not integrated. No traffic is routed or protected. The selected design will carry supported TCP through Tor, resolve supported DNS through Tor, and block unsupported UDP/QUIC while the tunnel is active. This is not HTTPS inspection or active threat blocking.',
                style: TextStyle(height: 1.45),
              ),
            ),
          ),
          const SizedBox(height: 16),
          FilledButton.icon(
            onPressed: requestEnabled ? _requestConsent : null,
            icon: _requesting
                ? const SizedBox.square(
                    dimension: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.verified_user_outlined),
            label: Text(_requesting ? 'Waiting for Android…' : 'Request system consent'),
          ),
          const SizedBox(height: 8),
          OutlinedButton.icon(
            onPressed: _loading || _requesting ? null : _refreshStatus,
            icon: const Icon(Icons.refresh_rounded),
            label: const Text('Refresh status'),
          ),
        ],
      ),
    );
  }

  String _consentLabel(MobileVpnConsentStatus? status) {
    if (status == null) return 'Unavailable';
    return switch (status.state) {
      MobileVpnConsentState.unavailable => 'Unavailable',
      MobileVpnConsentState.consentRequired =>
        status.reasonCode == MobileVpnConsentReason.userDenied
            ? 'Not granted · request was denied'
            : 'Consent required',
      MobileVpnConsentState.backendUnavailable =>
        'Granted · Tor backend unavailable',
    };
  }
}

class _StatusRow extends StatelessWidget {
  const _StatusRow({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) => Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(child: Text(label, style: const TextStyle(color: Colors.white60))),
          const SizedBox(width: 12),
          Expanded(
            child: Text(value,
                textAlign: TextAlign.end,
                style: const TextStyle(fontWeight: FontWeight.w700)),
          ),
        ],
      );
}
