import 'package:flutter/material.dart';

import '../core/ai/credential_vault.dart';
import '../core/detection/detection_models.dart';
import '../core/detection/local_detection_engine.dart';
import '../core/platform/mobile_platform_client.dart';
import '../core/platform/mobile_security_session.dart';
import '../features/capabilities/mobile_capabilities_page.dart';
import '../features/home/mobile_home_page.dart';
import '../features/settings/provider_credential_settings_page.dart';
import '../features/tools/mobile_tools_page.dart';

class MobileShell extends StatefulWidget {
  const MobileShell({super.key});

  @override
  State<MobileShell> createState() => _MobileShellState();
}

class _MobileShellState extends State<MobileShell> {
  static const _destinations = <_Destination>[
    _Destination('Home', Icons.radar_rounded),
    _Destination('Findings', Icons.shield_outlined),
    _Destination('Investigate', Icons.manage_search_rounded),
    _Destination('Tools', Icons.handyman_outlined),
    _Destination('Capabilities', Icons.grid_view_rounded),
  ];

  late final MobileSecuritySession _session;
  int _selectedIndex = 0;

  @override
  void initState() {
    super.initState();
    // The session constructor is inert. The first platform request happens
    // only when the user taps one of the explicit baseline/journal actions.
    _session = MobileSecuritySession(
      platform: MethodChannelMobilePlatformClient(),
      detectionEngine: LocalDetectionEngine(rules: builtInPostureRules),
    );
  }

  @override
  void dispose() {
    _session.dispose();
    super.dispose();
  }

  Widget _selectedPage() => switch (_selectedIndex) {
        0 => MobileHomePage(session: _session),
        1 => FindingsPage(session: _session),
        2 => const InvestigatePage(),
        3 => const MobileToolsPage(),
        _ => MobileCapabilitiesPage(session: _session),
      };

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            Container(
              width: 30,
              height: 30,
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.primary.withValues(alpha: .14),
                borderRadius: BorderRadius.circular(9),
              ),
              child: Icon(Icons.security_rounded,
                  size: 18, color: Theme.of(context).colorScheme.primary),
            ),
            const SizedBox(width: 10),
            const Text('SVS-Cyber'),
          ],
        ),
        actions: [
          IconButton(
            tooltip: 'Settings',
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute<void>(builder: (_) => const SettingsPage()),
            ),
            icon: const Icon(Icons.settings_outlined),
          ),
        ],
      ),
      body: SafeArea(child: _selectedPage()),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _selectedIndex,
        onDestinationSelected: (index) => setState(() => _selectedIndex = index),
        destinations: [
          for (final item in _destinations)
            NavigationDestination(icon: Icon(item.icon), label: item.label),
        ],
      ),
    );
  }
}

class _Destination {
  const _Destination(this.label, this.icon);
  final String label;
  final IconData icon;
}

class FindingsPage extends StatelessWidget {
  const FindingsPage({super.key, required this.session});

  final MobileSecuritySession session;

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
        animation: session,
        builder: (context, _) {
          final findings = session.findings;
          return _PageFrame(
            eyebrow: 'LOCAL DETECTIONS',
            title: 'Findings to review',
            subtitle:
                'Findings come from deterministic local rules and retain links to their source evidence.',
            children: findings.isEmpty
                ? const [
                    _InfoCard(
                      icon: Icons.shield_outlined,
                      title: 'No findings to review',
                      detail: 'Run a device baseline from Home to evaluate the supported posture rule.',
                    ),
                  ]
                : [
                    for (final finding in findings)
                      _FindingCard(finding: finding),
                  ],
          );
        },
      );
}

class _FindingCard extends StatelessWidget {
  const _FindingCard({required this.finding});
  final Finding finding;

  @override
  Widget build(BuildContext context) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(children: [
                Icon(Icons.warning_amber_rounded,
                    color: _severityColor(context, finding.severity)),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(finding.title,
                      style: const TextStyle(fontWeight: FontWeight.w700)),
                ),
                Text(finding.severity.name.toUpperCase(),
                    style: TextStyle(
                      color: _severityColor(context, finding.severity),
                      fontSize: 10,
                      fontWeight: FontWeight.w800,
                    )),
              ]),
              const SizedBox(height: 10),
              Text(finding.explanation,
                  style: const TextStyle(color: Colors.white70, height: 1.4)),
              const SizedBox(height: 10),
              Text('Next step: ${finding.recommendedAction}',
                  style: const TextStyle(color: Colors.white60, fontSize: 12)),
              const SizedBox(height: 8),
              Text(
                '${finding.evidenceReferences.length} evidence reference(s) · ${finding.ruleId} v${finding.ruleVersion} · ${finding.status.name}',
                style: const TextStyle(color: Colors.white38, fontSize: 11),
              ),
            ],
          ),
        ),
      );
}

Color _severityColor(BuildContext context, FindingSeverity severity) => switch (severity) {
      FindingSeverity.critical || FindingSeverity.high => Theme.of(context).colorScheme.error,
      FindingSeverity.medium => Colors.amber,
      FindingSeverity.low => Theme.of(context).colorScheme.primary,
      FindingSeverity.informational => Colors.white54,
    };

class InvestigatePage extends StatelessWidget {
  const InvestigatePage({super.key});

  @override
  Widget build(BuildContext context) => const _PageFrame(
        eyebrow: 'INVESTIGATION',
        title: 'Start with local evidence',
        subtitle:
            'Investigations use selected findings. External AI is optional and must show a review before evidence is sent.',
        children: [
          _InfoCard(
            icon: Icons.manage_search_rounded,
            title: 'AI investigation is not connected',
            detail: 'Local findings and checks work without an AI provider. No evidence is sent from this screen.',
            badge: 'LOCAL FIRST',
          ),
        ],
      );
}

class SettingsPage extends StatelessWidget {
  const SettingsPage({super.key});

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text('Settings')),
        body: _PageFrame(
          eyebrow: 'PREFERENCES',
          title: 'Privacy stays in your hands.',
          subtitle:
              'Provider keys, collection access, retention, and exports will be managed here.',
          children: [
            const _InfoCard(
              icon: Icons.lock_outline_rounded,
              title: 'Local storage',
              detail: 'Sensitive Android events are stored in the encrypted local journal.',
            ),
            const SizedBox(height: 12),
            const _InfoCard(
              icon: Icons.cloud_off_outlined,
              title: 'No automatic uploads',
              detail: 'Findings and diagnostics are not uploaded automatically.',
            ),
            const SizedBox(height: 12),
            Card(
              child: ListTile(
                leading: const Icon(Icons.key_outlined),
                title: const Text('Manage AI provider keys'),
                subtitle: const Text(
                  'Optional keys for internal testing. Local checks work without AI.',
                ),
                trailing: const Icon(Icons.chevron_right_rounded),
                onTap: () => Navigator.of(context).push(
                  MaterialPageRoute<void>(
                    builder: (_) => ProviderCredentialSettingsPage(
                      vault: MethodChannelMobileCredentialVault(),
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      );
}

class _PageFrame extends StatelessWidget {
  const _PageFrame({
    required this.eyebrow,
    required this.title,
    required this.subtitle,
    required this.children,
  });
  final String eyebrow;
  final String title;
  final String subtitle;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) => ListView(
        padding: const EdgeInsets.fromLTRB(18, 18, 18, 28),
        children: [
          Text(eyebrow,
              style: TextStyle(
                color: Theme.of(context).colorScheme.primary,
                fontSize: 11,
                letterSpacing: 1.3,
                fontWeight: FontWeight.w800,
              )),
          const SizedBox(height: 10),
          Text(title,
              style: Theme.of(context)
                  .textTheme
                  .headlineSmall
                  ?.copyWith(fontWeight: FontWeight.w800, height: 1.12)),
          const SizedBox(height: 8),
          Text(subtitle,
              style: const TextStyle(color: Colors.white60, height: 1.45)),
          const SizedBox(height: 22),
          ...children,
        ],
      );
}

class _InfoCard extends StatelessWidget {
  const _InfoCard({
    required this.icon,
    required this.title,
    required this.detail,
    this.badge,
  });
  final IconData icon;
  final String title;
  final String detail;
  final String? badge;

  @override
  Widget build(BuildContext context) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(icon, color: Theme.of(context).colorScheme.primary, size: 22),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(children: [
                      Expanded(
                          child: Text(title,
                              style: const TextStyle(fontWeight: FontWeight.w700))),
                      if (badge != null) ...[
                        const SizedBox(width: 8),
                        Text(badge!,
                            style: TextStyle(
                              color: Theme.of(context).colorScheme.primary,
                              fontSize: 9,
                              letterSpacing: .7,
                              fontWeight: FontWeight.w800,
                            )),
                      ],
                    ]),
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
