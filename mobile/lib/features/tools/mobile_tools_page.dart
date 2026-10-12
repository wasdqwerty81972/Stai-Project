import 'package:flutter/material.dart';

import '../../core/platform/mobile_platform_client.dart';
import '../../core/platform/mobile_security_session.dart';
import '../../core/tools/mobile_tool_definition.dart';
import '../../core/tools/mobile_tool_registry.dart';

/// Shows tool metadata and explicitly requested visible-app snapshots.
class MobileToolsPage extends StatefulWidget {
  const MobileToolsPage({super.key, required this.session});

  final MobileSecuritySession session;

  @override
  State<MobileToolsPage> createState() => _MobileToolsPageState();
}

class _MobileToolsPageState extends State<MobileToolsPage> {
  static const _inventoryScope =
      'Only launchable apps visible to this app under Android package visibility are included. Results may be incomplete.';
  static const _permissionCaveat =
      'A requested permission is a declaration; a granted permission does not prove it was used. Android may omit permission details.';

  bool _reviewing = false;
  bool _collecting = false;
  String? _scanError;

  Future<void> _reviewInventory() async {
    if (_reviewing || _collecting) return;
    setState(() => _reviewing = true);
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Collect a visible app snapshot?'),
        content: const SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(_inventoryScope),
              SizedBox(height: 12),
              Text('The snapshot reads package names, versions, installer metadata and permission declarations/grants. Results stay on this device.'),
              SizedBox(height: 12),
              Text(_permissionCaveat),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Collect visible apps'),
          ),
        ],
      ),
    );
    if (!mounted) return;
    setState(() => _reviewing = false);
    if (confirmed != true) return;

    setState(() {
      _collecting = true;
      _scanError = null;
    });
    String? error;
    try {
      await widget.session.collectVisibleApplications();
      error = widget.session.lastError;
    } catch (_) {
      error = 'The visible app inventory could not be collected.';
    }
    if (!mounted) return;
    setState(() {
      _collecting = false;
      _scanError = error;
    });
  }

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
      animation: widget.session,
      builder: (context, _) => SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(18, 18, 18, 28),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'MOBILE TOOLKIT',
              style: TextStyle(
                color: Theme.of(context).colorScheme.primary,
                fontSize: 11,
                letterSpacing: 1.3,
                fontWeight: FontWeight.w800,
              ),
            ),
            const SizedBox(height: 10),
            Text(
              'Mobile tool catalogue',
              style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.w800,
                    height: 1.12,
                  ),
            ),
            const SizedBox(height: 8),
            Text(
              '${mobileToolRegistry.where((tool) => tool.implementationStatus == MobileToolImplementationStatus.partial).length} partially implemented · '
              '${mobileToolRegistry.where((tool) => tool.implementationStatus == MobileToolImplementationStatus.planned).length} planned',
              style: TextStyle(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
                height: 1.45,
              ),
            ),
            const SizedBox(height: 22),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Implementation status',
                        style: TextStyle(fontWeight: FontWeight.w700)),
                    const SizedBox(height: 5),
                    Text(
                      'The baseline and one local posture check are partially available from Home. Review visible apps below to collect a limited inventory. Other tools remain planned.',
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                        fontSize: 13,
                        height: 1.4,
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),
            _buildInventory(context),
            const SizedBox(height: 12),
            for (final tool in mobileToolRegistry) ...[
              _ToolCard(tool: tool),
              const SizedBox(height: 12),
            ],
          ],
        ),
      ),
    );

  Widget _buildInventory(BuildContext context) {
    final session = widget.session;
    final observedAt = session.visibleApplicationsObservedAt;
    final secondary = Theme.of(context).colorScheme.onSurfaceVariant;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Visible app snapshot',
                style: TextStyle(fontWeight: FontWeight.w700)),
            const SizedBox(height: 8),
            Text(_inventoryScope,
                style: TextStyle(color: secondary, fontSize: 13, height: 1.4)),
            const SizedBox(height: 8),
            Text(_permissionCaveat,
                style: TextStyle(color: secondary, fontSize: 13, height: 1.4)),
            const SizedBox(height: 12),
            SizedBox(
              width: double.infinity,
              child: FilledButton(
                onPressed: _collecting || _reviewing ? null : _reviewInventory,
                child: Text(_collecting ? 'Collecting visible apps…' : 'Review visible apps'),
              ),
            ),
            if (_scanError case final error?) ...[
              const SizedBox(height: 8),
              Text(error, style: TextStyle(color: Theme.of(context).colorScheme.error)),
              if (observedAt != null)
                const Text('The previous snapshot remains below; it was not refreshed.'),
            ],
            if (observedAt != null) ...[
              const SizedBox(height: 12),
              Text('Snapshot observed: ${observedAt.toLocal()}'),
              const SizedBox(height: 4),
              Text('${session.visibleApplications.length} apps returned in this visible scope.'),
              if (session.visibleApplicationsTruncated) ...[
                const SizedBox(height: 4),
                const Text('Collection limit reached; this snapshot is truncated.'),
              ],
              if (session.visibleApplications.isEmpty) ...[
                const SizedBox(height: 8),
                const Text('No launchable apps were returned in this visible scope.'),
              ],
              for (final application in session.visibleApplications)
                _VisibleApplicationTile(application: application),
            ],
          ],
        ),
      ),
    );
  }
}

class _VisibleApplicationTile extends StatelessWidget {
  const _VisibleApplicationTile({required this.application});

  final VisibleApplication application;

  @override
  Widget build(BuildContext context) => ExpansionTile(
        key: ValueKey(application.packageName),
        tilePadding: EdgeInsets.zero,
        title: Text(application.label),
        subtitle: Text(application.packageName),
        childrenPadding: const EdgeInsets.only(bottom: 12),
        expandedCrossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Version: ${application.versionName ?? 'Unknown'} (${application.versionCode})'),
          const SizedBox(height: 4),
          Text('Installer: ${application.installerPackageName ?? 'Unknown or unavailable'}'),
          const SizedBox(height: 4),
          Text('System app: ${application.isSystemApp ? 'Yes' : 'No'}'),
          const SizedBox(height: 12),
          const Text('Declared permissions', style: TextStyle(fontWeight: FontWeight.w700)),
          const SizedBox(height: 4),
          if (application.requestedPermissions.isEmpty)
            const Text('None returned; details may be unavailable.')
          else
            for (final permission in application.requestedPermissions) Text(permission),
          const SizedBox(height: 12),
          const Text('Granted permissions', style: TextStyle(fontWeight: FontWeight.w700)),
          const SizedBox(height: 4),
          if (application.grantedPermissions.isEmpty)
            const Text('None reported; this does not establish actual permission use.')
          else
            for (final permission in application.grantedPermissions) Text(permission),
        ],
      );
}

class _ToolCard extends StatelessWidget {
  const _ToolCard({required this.tool});

  final MobileToolDefinition tool;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(_categoryIcon(tool.category), color: colors.primary, size: 22),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(tool.name,
                      style: const TextStyle(fontWeight: FontWeight.w700)),
                ),
              ],
            ),
            const SizedBox(height: 10),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                _MetadataBadge(_statusLabel(tool.implementationStatus)),
                _MetadataBadge('Phase: ${_phaseLabel(tool.phase)}'),
              ],
            ),
            const SizedBox(height: 10),
            Text(tool.summary,
                style: TextStyle(color: colors.onSurfaceVariant, height: 1.4)),
            const SizedBox(height: 12),
            Text('Network: ${_networkLabel(tool.networkBehavior)}',
                style: const TextStyle(fontSize: 12, height: 1.4)),
            const SizedBox(height: 4),
            Text('State changes: ${_stateChangeLabel(tool.stateChangeRisk)}',
                style: const TextStyle(fontSize: 12, height: 1.4)),
          ],
        ),
      ),
    );
  }
}

class _MetadataBadge extends StatelessWidget {
  const _MetadataBadge(this.label);

  final String label;

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.primary.withValues(alpha: .12),
          borderRadius: BorderRadius.circular(9),
        ),
        child: Text(label,
            style: TextStyle(
              color: Theme.of(context).colorScheme.primary,
              fontSize: 11,
              fontWeight: FontWeight.w700,
            )),
      );
}

String _statusLabel(MobileToolImplementationStatus status) => switch (status) {
      MobileToolImplementationStatus.planned => 'Planned',
      MobileToolImplementationStatus.partial => 'Partial implementation',
      MobileToolImplementationStatus.implemented => 'Implemented',
    };

String _phaseLabel(MobileToolPhase phase) => switch (phase) {
      MobileToolPhase.foundation => 'Foundation',
      MobileToolPhase.consumerMvp => 'Consumer MVP',
      MobileToolPhase.networkProtection => 'Network protection',
      MobileToolPhase.enterprise => 'Enterprise',
    };

String _networkLabel(MobileNetworkBehavior behavior) => switch (behavior) {
      MobileNetworkBehavior.none => 'No network use',
      MobileNetworkBehavior.localOnly => 'Local processing only',
      MobileNetworkBehavior.externalWithPerRequestConsent =>
        'External requests require consent each time',
    };

String _stateChangeLabel(MobileStateChangeRisk risk) => switch (risk) {
      MobileStateChangeRisk.none => 'None',
      MobileStateChangeRisk.createsUserRequestedExport =>
        'Creates a user-requested export',
    };

IconData _categoryIcon(MobileToolCategory category) => switch (category) {
      MobileToolCategory.devicePosture => Icons.phone_android_rounded,
      MobileToolCategory.applicationReview => Icons.apps_rounded,
      MobileToolCategory.artifactInspection => Icons.file_open_outlined,
      MobileToolCategory.linkAnalysis => Icons.link_rounded,
      MobileToolCategory.investigation => Icons.manage_search_rounded,
      MobileToolCategory.diagnostics => Icons.description_outlined,
    };
