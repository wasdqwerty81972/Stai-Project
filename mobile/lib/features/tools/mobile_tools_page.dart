import 'package:flutter/material.dart';

import '../../core/apps/application_permission_analyzer.dart';
import '../../core/apps/visible_application.dart';
import '../../core/files/selected_file_inspection.dart';
import '../../core/links/mobile_url_local_check.dart';
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
  final _urlController = TextEditingController();
  MobileUrlCheckResult? _urlResult;
  ApplicationPermissionAnalysis? _permissionAnalysis;

  @override
  void dispose() {
    _urlController.dispose();
    super.dispose();
  }

  void _checkUrl() {
    final result = MobileUrlLocalCheck.analyze(_urlController.text);
    setState(() {
      _urlResult = result;
      // URL contents may contain private paths or tokens. Keep only the
      // structural result in memory and clear the submitted string promptly.
      _urlController.clear();
    });
  }

  void _reviewPermissionPosture() {
    final session = widget.session;
    final observedAt = session.visibleApplicationsObservedAt;
    if (observedAt == null) return;
    final snapshot = VisibleApplicationCollection(
      contractVersion: 1,
      observedAt: observedAt,
      scope: VisibleApplicationCollection.supportedScope,
      visibilityMayBeFiltered: session.visibleApplicationsVisibilityMayBeFiltered,
      truncated: session.visibleApplicationsTruncated,
      permissionsTruncated: session.visibleApplicationsPermissionsTruncated,
      applications: session.visibleApplications,
      events: const [],
    );
    setState(() {
      _permissionAnalysis = const ApplicationPermissionAnalyzer().analyze(snapshot);
    });
  }

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
      if (error == null) _permissionAnalysis = null;
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
                      'The device baseline and visible app inventory are partially available. The inventory also includes a limited permission snapshot for the launchable apps Android makes visible.',
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
            _buildSelectedFileInspection(context),
            const SizedBox(height: 12),
            _buildUrlCheck(context),
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
              if (session.visibleApplicationsPermissionsTruncated) ...[
                const SizedBox(height: 4),
                const Text('Some applications declared more permissions than the display limit.'),
              ],
              if (session.visibleApplications.isEmpty) ...[
                const SizedBox(height: 8),
                const Text('No launchable apps were returned in this visible scope.'),
              ],
              for (final application in session.visibleApplications)
                _VisibleApplicationTile(application: application),
              const SizedBox(height: 10),
              SizedBox(
                width: double.infinity,
                child: OutlinedButton.icon(
                  onPressed: _reviewPermissionPosture,
                  icon: const Icon(Icons.rule_outlined),
                  label: const Text('Review permission posture'),
                ),
              ),
              if (_permissionAnalysis?.observedAt == observedAt)
                _PermissionAnalysisView(analysis: _permissionAnalysis!),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildUrlCheck(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    final result = _urlResult;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Check a URL', style: TextStyle(fontWeight: FontWeight.w700)),
            const SizedBox(height: 6),
            Text(
              'Checks URL structure on this device. It does not open the link, resolve its host, or verify reputation. The submitted text is cleared after analysis.',
              style: TextStyle(color: colors.onSurfaceVariant, fontSize: 13, height: 1.4),
            ),
            const SizedBox(height: 12),
            TextField(
              key: const ValueKey('mobile-url-input'),
              controller: _urlController,
              keyboardType: TextInputType.url,
              autocorrect: false,
              enableSuggestions: false,
              decoration: const InputDecoration(
                labelText: 'URL to inspect',
                hintText: 'https://example.com',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 10),
            SizedBox(
              width: double.infinity,
              child: FilledButton.icon(
                onPressed: _checkUrl,
                icon: const Icon(Icons.manage_search),
                label: const Text('Check URL structure'),
              ),
            ),
            if (result != null) ...[
              const Divider(height: 24),
              Text(result.isValid ? 'Structure parsed' : 'Could not parse URL',
                  style: const TextStyle(fontWeight: FontWeight.w700)),
              if (result.host != null) Text('Host: ${result.host}'),
              if (result.scheme != null) Text('Scheme: ${result.scheme}'),
              const SizedBox(height: 4),
              Text(result.explanation, style: TextStyle(color: colors.onSurfaceVariant, height: 1.4)),
              for (final signal in result.signals) ...[
                const SizedBox(height: 8),
                Text(signal.code.replaceAll('_', ' '), style: const TextStyle(fontWeight: FontWeight.w600)),
                Text(signal.explanation, style: TextStyle(color: colors.onSurfaceVariant, height: 1.4)),
              ],
              const SizedBox(height: 6),
              const Text('No safe or malicious verdict is produced.',
                  style: TextStyle(fontSize: 12)),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildSelectedFileInspection(BuildContext context) {
    final session = widget.session;
    final result = session.selectedFileInspection;
    final colors = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Inspect a selected file',
                style: TextStyle(fontWeight: FontWeight.w700)),
            const SizedBox(height: 6),
            Text(
              'Choose one file in Android’s system picker. Analysis in SVS-Cyber is bounded to 64 MiB and stays on-device. A cloud-backed provider may download the selected document. APKs are parsed as data only; nothing is installed, executed, or uploaded by SVS-Cyber.',
              style: TextStyle(color: colors.onSurfaceVariant, fontSize: 13, height: 1.4),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                OutlinedButton.icon(
                  onPressed: session.inspectingSelectedFile
                      ? null
                      : () => session.selectAndInspectFile(apk: false),
                  icon: const Icon(Icons.insert_drive_file_outlined),
                  label: const Text('Choose file'),
                ),
                OutlinedButton.icon(
                  onPressed: session.inspectingSelectedFile
                      ? null
                      : () => session.selectAndInspectFile(apk: true),
                  icon: const Icon(Icons.android),
                  label: const Text('Choose APK'),
                ),
              ],
            ),
            if (session.inspectingSelectedFile) ...[
              const SizedBox(height: 8),
              const LinearProgressIndicator(),
              const SizedBox(height: 5),
              const Text('Waiting for selection or bounded local inspection…'),
            ],
            if (session.selectedFileInspectionError case final error?) ...[
              const SizedBox(height: 8),
              Text(error, style: TextStyle(color: colors.error)),
              if (result != null)
                const Text('The previous inspection result is still shown below.'),
            ],
            if (result != null) ...[
              const Divider(height: 24),
              Text(
                session.selectedFileInspectionWasApk == true
                    ? 'APK inspection result'
                    : 'File inspection result',
                style: const TextStyle(fontWeight: FontWeight.w700),
              ),
              const SizedBox(height: 5),
              Text('Status: ${_fileInspectionStatus(result.status)}'),
              if (result.contentType != null) Text('Content type: ${result.contentType}'),
              if (result.byteSize != null)
                Text('Bytes read: ${result.byteSize}')
              else
                Text('Bytes read before limit or timeout: ${result.bytesRead}'),
              if (result.sha256 != null) ...[
                const SizedBox(height: 8),
                const Text('SHA-256', style: TextStyle(fontWeight: FontWeight.w600)),
                SelectableText(result.sha256!, style: const TextStyle(fontSize: 12)),
              ],
              if (result.apkMetadata case final metadata?) ...[
                const SizedBox(height: 10),
                const Text('Package metadata', style: TextStyle(fontWeight: FontWeight.w600)),
                Text('Package: ${metadata.packageName}'),
                Text('Version: ${metadata.versionName ?? 'Unknown'} (${metadata.versionCode})'),
                Text('Signer information: ${metadata.signatureStatus}'),
                for (final digest in metadata.certificateSha256)
                  SelectableText('Certificate SHA-256: $digest', style: const TextStyle(fontSize: 12)),
                if (metadata.requestedPermissions.isNotEmpty) ...[
                  const SizedBox(height: 5),
                  const Text('Declared permissions'),
                  for (final permission in metadata.requestedPermissions)
                    Text(permission, style: const TextStyle(fontSize: 12)),
                ],
                if (result.metadataTruncated)
                  const Text('Some APK metadata was omitted at the display limit.'),
              ],
              const SizedBox(height: 8),
              Text(
                result.status == SelectedFileInspectionStatus.unsupported
                    ? 'The file was hashed, but Android could not parse supported APK metadata.'
                    : 'A digest or signer fingerprint is identifying data, not a safe or malicious verdict.',
                style: TextStyle(color: colors.onSurfaceVariant, fontSize: 12, height: 1.4),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

String _fileInspectionStatus(SelectedFileInspectionStatus status) => switch (status) {
      SelectedFileInspectionStatus.complete => 'Complete',
      SelectedFileInspectionStatus.unsupported => 'Metadata unsupported',
      SelectedFileInspectionStatus.overLimit => 'Stopped at the size limit',
      SelectedFileInspectionStatus.timedOut => 'Stopped at the time limit',
    };

class _PermissionAnalysisView extends StatelessWidget {
  const _PermissionAnalysisView({required this.analysis});

  final ApplicationPermissionAnalysis analysis;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.only(top: 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Permission review · ${analysis.applications.length} visible app${analysis.applications.length == 1 ? '' : 's'}',
                style: const TextStyle(fontWeight: FontWeight.w700)),
            Text('Based on snapshot at ${analysis.observedAt.toLocal()}'),
            const SizedBox(height: 5),
            const Text('Signals describe declared access for review; they do not show how an app used a permission or establish that it is unsafe.'),
            for (final caveat in analysis.caveats)
              Text('Scope note: ${_permissionCaveatLabel(caveat)}'),
            const SizedBox(height: 8),
            for (final review in analysis.applications)
              if (review.signals.isNotEmpty)
                Padding(
                  padding: const EdgeInsets.only(bottom: 10),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(review.label, style: const TextStyle(fontWeight: FontWeight.w600)),
                      for (final signal in review.signals)
                        Padding(
                          padding: const EdgeInsets.only(top: 4),
                          child: Text('${signal.title} · ${_grantStateLabel(signal.grantState)}. ${signal.explanation}'),
                        ),
                      for (final caveat in review.caveats)
                        Text('Scope note: ${_permissionCaveatLabel(caveat)}'),
                    ],
                  ),
                ),
            if (analysis.applications.every((review) => review.signals.isEmpty))
              const Text('No permissions in the reviewed groups were returned for these visible apps.'),
          ],
        ),
      );
}

String _grantStateLabel(PermissionGrantState state) => switch (state) {
      PermissionGrantState.granted => 'Listed permissions granted',
      PermissionGrantState.partiallyGranted => 'Partially granted',
      PermissionGrantState.notGranted => 'None of the listed permissions granted',
      PermissionGrantState.unknown => 'Grant state unknown',
    };

String _permissionCaveatLabel(ApplicationPermissionCaveat caveat) => switch (caveat) {
      ApplicationPermissionCaveat.grantStateUnavailable => 'some grant states are unavailable',
      ApplicationPermissionCaveat.packageVisibilityMayBeFiltered => 'Android may hide apps from this inventory',
      ApplicationPermissionCaveat.applicationListTruncated => 'the app list is truncated',
      ApplicationPermissionCaveat.permissionListTruncated => 'some permission lists are truncated',
      ApplicationPermissionCaveat.installerUnknown => 'installer metadata is unavailable for some apps',
      ApplicationPermissionCaveat.specialAccessStateUnavailable => 'special app access state is unknown',
    };

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
          const SizedBox(height: 4),
          Text('Grant state: ${application.permissionGrantStateAvailable ? 'Available' : 'Unknown'}'),
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
