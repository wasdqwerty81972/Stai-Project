import 'dart:convert';

import 'package:flutter/material.dart';

import '../core/ai/credential_vault.dart';
import '../core/detection/detection_models.dart';
import '../core/detection/local_detection_engine.dart';
import '../core/detection/local_finding_investigator.dart';
import '../core/platform/mobile_platform_client.dart';
import '../core/platform/mobile_vpn_consent_client.dart';
import '../core/platform/mobile_security_session.dart';
import '../features/capabilities/mobile_capabilities_page.dart';
import '../features/home/mobile_home_page.dart';
import '../features/settings/provider_credential_settings_page.dart';
import '../features/settings/mobile_vpn_prototype_page.dart';
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
        2 => InvestigatePage(session: _session),
        3 => MobileToolsPage(session: _session),
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
          final inventoryAt = session.visibleApplicationsObservedAt;
          final inventoryIsOld = inventoryAt != null &&
              DateTime.now().toUtc().difference(inventoryAt) >
                  MobileSecuritySession.evidenceWindow;
          return _PageFrame(
            eyebrow: 'LOCAL DETECTIONS',
            title: 'Findings to review',
            subtitle:
                'Findings come from deterministic local rules and retain links to their source evidence. Review status and history are kept only for this app session.',
            children: [
              if (inventoryAt != null)
                _InfoCard(
                  icon: inventoryIsOld
                      ? Icons.history_rounded
                      : Icons.inventory_2_outlined,
                  title: inventoryIsOld
                      ? 'Application inventory is old'
                      : 'Application inventory status',
                  detail:
                      'Last explicit collection: ${inventoryAt.toLocal()}. Scope covers launchable packages visible to Android, not every installed app.'
                      '${session.visibleApplicationsTruncated ? ' The package list was truncated.' : ''}'
                      '${session.visibleApplicationsPermissionsTruncated ? ' Permission metadata was truncated.' : ''}'
                      '${session.visibleApplicationsError == null ? '' : ' The latest collection failed; this is the previous snapshot. ${session.visibleApplicationsError}'}',
                ),
              if (findings.isEmpty) ...[
                const _InfoCard(
                      icon: Icons.shield_outlined,
                      title: 'No findings to review',
                      detail: 'Run a device baseline from Home or collect visible application inventory from Tools to evaluate supported local rules.',
                    ),
              ] else
                for (final finding in findings)
                  _FindingCard(
                    finding: finding,
                    onReview: (status) => session.reviewFinding(
                      finding.id,
                      status: status,
                    ),
                  ),
            ],
          );
        },
      );
}

class _FindingCard extends StatelessWidget {
  const _FindingCard({required this.finding, required this.onReview});
  final Finding finding;
  final ValueChanged<FindingStatus> onReview;

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
                PopupMenuButton<FindingStatus>(
                  tooltip: 'Review finding',
                  onSelected: onReview,
                  itemBuilder: (context) => [
                    for (final status in FindingStatus.values)
                      PopupMenuItem(
                        value: status,
                        child: Text(switch (status) {
                          FindingStatus.open => 'Reopen',
                          FindingStatus.acknowledged => 'Acknowledge',
                          FindingStatus.resolved => 'Mark resolved',
                          FindingStatus.suppressed => 'Suppress',
                        }),
                      ),
                  ],
                  icon: const Icon(Icons.more_vert_rounded, size: 18),
                ),
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
              if (finding.evidenceReferences.isNotEmpty &&
                  DateTime.now().toUtc().difference(finding.lastObservedAt) >
                      MobileSecuritySession.evidenceWindow) ...[
                const SizedBox(height: 6),
                const Text(
                  'Evidence is older than the current local review window.',
                  style: TextStyle(color: Colors.amber, fontSize: 11),
                ),
              ],
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

class InvestigatePage extends StatefulWidget {
  const InvestigatePage({super.key, required this.session});

  final MobileSecuritySession session;

  @override
  State<InvestigatePage> createState() => _InvestigatePageState();
}

class _InvestigatePageState extends State<InvestigatePage> {
  static const _investigator = LocalFindingInvestigator();
  final Set<String> _selectedFindingIds = {};
  InvestigationBundle? _bundle;

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
        animation: widget.session,
        builder: (context, _) {
          final findings = widget.session.findings;
          _selectedFindingIds.removeWhere(
            (id) => !findings.any((finding) => finding.id == id),
          );
          return _PageFrame(
            eyebrow: 'LOCAL INVESTIGATION',
            title: 'Review evidence',
            subtitle:
                'Choose findings to verify their source references and inspect nearby events that share a recorded subject. Correlations remain hypotheses.',
            children: [
              const _InfoCard(
                icon: Icons.cloud_off_outlined,
                title: 'Local only',
                detail:
                    'This review uses findings and events already on this device. It does not contact an AI provider or change device settings.',
                badge: 'NO NETWORK',
              ),
              const SizedBox(height: 12),
              if (findings.isEmpty)
                const _InfoCard(
                  icon: Icons.search_off_rounded,
                  title: 'No findings available',
                  detail:
                      'Run a device baseline or collect visible application inventory first.',
                )
              else ...[
                for (final finding in findings)
                  Card(
                    child: CheckboxListTile(
                      value: _selectedFindingIds.contains(finding.id),
                      onChanged: (selected) => setState(() {
                        if (selected ?? false) {
                          _selectedFindingIds.add(finding.id);
                        } else {
                          _selectedFindingIds.remove(finding.id);
                        }
                        _bundle = null;
                      }),
                      title: Text(finding.title),
                      subtitle: Text(
                        '${finding.ruleId} · ${finding.evidenceReferences.length} evidence reference(s)',
                      ),
                      controlAffinity: ListTileControlAffinity.leading,
                    ),
                  ),
                const SizedBox(height: 8),
                FilledButton.icon(
                  onPressed: _selectedFindingIds.isEmpty
                      ? null
                      : () => setState(() {
                            _bundle = _investigator.investigate(
                              selectedFindingIds:
                                  _selectedFindingIds.toList()..sort(),
                              findings: widget.session.findings,
                              events: widget.session.events,
                            );
                          }),
                  icon: const Icon(Icons.manage_search_rounded),
                  label: const Text('Review selected evidence'),
                ),
              ],
              if (_bundle case final bundle?) ...[
                const SizedBox(height: 12),
                if (bundle.latestEventObservedAt != null)
                  Text(
                    'Local event window through ${bundle.latestEventObservedAt!.toLocal()}',
                    style: const TextStyle(color: Colors.white54, fontSize: 12),
                  ),
                for (final missingId in bundle.missingFindingIds)
                  _InfoCard(
                    icon: Icons.info_outline_rounded,
                    title: 'Finding no longer available',
                    detail: missingId,
                  ),
                for (final ambiguousId in bundle.ambiguousFindingIds)
                  _InfoCard(
                    icon: Icons.content_copy_rounded,
                    title: 'Finding ID is ambiguous',
                    detail:
                        'More than one local finding has this ID, so no record was chosen: $ambiguousId',
                  ),
                for (final item in bundle.findings) ...[
                  _InvestigationResultCard(item: item),
                  const SizedBox(height: 10),
                ],
              ],
            ],
          );
        },
      );
}

class _InvestigationResultCard extends StatelessWidget {
  const _InvestigationResultCard({required this.item});

  final InvestigationFinding item;

  @override
  Widget build(BuildContext context) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(item.finding.title,
                  style: const TextStyle(fontWeight: FontWeight.w800)),
              const SizedBox(height: 10),
              Text(item.hypothesis.statement,
                  style: const TextStyle(color: Colors.white70, height: 1.4)),
              const SizedBox(height: 12),
              const Text('Evidence references',
                  style: TextStyle(fontWeight: FontWeight.w700)),
              const SizedBox(height: 6),
              if (item.evidence.isEmpty)
                const Text('This finding has no source references to verify.',
                    style: TextStyle(color: Colors.white54, fontSize: 12)),
              for (final evidence in item.evidence)
                Padding(
                  padding: const EdgeInsets.only(bottom: 8),
                  child: Text(
                    '${evidence.reference.capabilityId} · ${evidence.reference.path}\n'
                    'Status: ${evidence.referenceStatus.name}\n'
                    'Recorded: ${_displayEvidence(evidence.storedReferenceValue)}'
                    '${evidence.value == null ? '' : '\nCurrent event: ${_displayEvidence(evidence.value)}'}',
                    style: const TextStyle(
                        color: Colors.white60, fontSize: 12, height: 1.35),
                  ),
                ),
              for (final note in item.missingReferenceNotes)
                Padding(
                  padding: const EdgeInsets.only(top: 4),
                  child: Text(note,
                      style: TextStyle(
                          color: Theme.of(context).colorScheme.error,
                          fontSize: 12)),
                ),
              if (item.relatedEvents.isNotEmpty) ...[
                const SizedBox(height: 8),
                const Text('Related events · correlation only',
                    style: TextStyle(fontWeight: FontWeight.w700)),
                for (final related in item.relatedEvents)
                  Padding(
                    padding: const EdgeInsets.only(top: 8),
                    child: Text(
                      '${related.event.capabilityId} · ${related.event.observedAt.toLocal()}\n'
                      '${related.relationship}\n${related.hypothesis}',
                      style: const TextStyle(
                          color: Colors.white60, fontSize: 12, height: 1.35),
                    ),
                  ),
              ],
            ],
          ),
        ),
      );
}

String _displayEvidence(Object? value) {
  try {
    return const JsonEncoder.withIndent('  ').convert(value);
  } on JsonUnsupportedObjectError {
    return value.toString();
  }
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
                leading: const Icon(Icons.vpn_lock_outlined),
                title: const Text('Network protection prototype'),
                subtitle: const Text(
                  'View internal VPN consent status. No tunnel or traffic monitoring is active.',
                ),
                trailing: const Icon(Icons.chevron_right_rounded),
                onTap: () => Navigator.of(context).push(
                  MaterialPageRoute<void>(
                    builder: (_) => MobileVpnPrototypePage(
                      client: MobileVpnConsentClient(),
                    ),
                  ),
                ),
              ),
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
