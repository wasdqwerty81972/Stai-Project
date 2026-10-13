import 'mobile_tool_definition.dart';

const _safRead = MobilePermissionDependency(
  id: 'android.storage_access_framework.read',
  kind: MobilePermissionKind.userSelectedUri,
  description: 'The user selects the exact file through the system picker.',
);

const _userOnly = {MobileInvocationSource.user};
const _userOrLocalRule = {
  MobileInvocationSource.user,
  MobileInvocationSource.enabledLocalRule,
};

/// The mobile tool catalogue is separate from the AND-001..AND-136 capability
/// catalogue. Definitions do not themselves provide runtime operation handlers.
const mobileToolRegistryVersion = 1;

const mobileToolRegistry = <MobileToolDefinition>[
  MobileToolDefinition(
    id: 'mobile.device_baseline',
    name: 'Device baseline',
    summary: 'Read a bounded snapshot of supported device and Android facts.',
    phase: MobileToolPhase.foundation,
    category: MobileToolCategory.devicePosture,
    implementationStatus: MobileToolImplementationStatus.partial,
    inputFields: [
      MobileToolField(
        name: 'includeDeviceModel',
        type: 'boolean',
        description: 'Include manufacturer and model in this local result.',
      ),
      MobileToolField(
        name: 'fieldIds',
        type: 'string[]',
        description: 'Requested fields; unknown or unavailable fields are reported.',
      ),
    ],
    outputFields: [
      MobileToolField(name: 'androidApiLevel', type: 'integer', description: 'Android API level.'),
      MobileToolField(name: 'androidRelease', type: 'string?', description: 'Reported Android release.'),
      MobileToolField(name: 'securityPatchLevel', type: 'string?', description: 'Reported patch level.'),
      MobileToolField(name: 'manufacturerAndModel', type: 'string?', description: 'Optional device identity.'),
      MobileToolField(name: 'secureLockConfigured', type: 'boolean?', description: 'Supported keyguard posture result.'),
      MobileToolField(name: 'fieldAvailability', type: 'object', description: 'Per-field available or unsupported status.'),
      MobileToolField(name: 'observedAt', type: 'timestamp', description: 'Observation time.'),
    ],
    permissions: [],
    networkBehavior: MobileNetworkBehavior.none,
    dataSensitivity: MobileDataSensitivity.moderate,
    stateChangeRisk: MobileStateChangeRisk.none,
    limits: MobileToolLimits(maxItems: 16, maxDurationSeconds: 3, notes: 'No polling; report unsupported fields without inferring a pass.'),
    passiveCapabilityIds: ['AND-001', 'AND-002', 'AND-003', 'AND-004', 'AND-008'],
    allowedInvocationSources: _userOrLocalRule,
    userConsentRequired: false,
  ),
  MobileToolDefinition(
    id: 'mobile.posture_check',
    name: 'Security posture check',
    summary: 'Evaluate selected local posture checks using available evidence.',
    phase: MobileToolPhase.foundation,
    category: MobileToolCategory.devicePosture,
    implementationStatus: MobileToolImplementationStatus.partial,
    inputFields: [
      MobileToolField(name: 'checkIds', type: 'string[]', description: 'IDs from the bundled local posture rules.', required: true),
      MobileToolField(name: 'baselineSnapshotId', type: 'string?', description: 'Optional previously collected baseline.'),
    ],
    outputFields: [
      MobileToolField(name: 'results', type: 'PostureCheckResult[]', description: 'Each result includes status, explanation, evidence refs, confidence and limitation.'),
      MobileToolField(name: 'checkedAt', type: 'timestamp', description: 'Evaluation time.'),
    ],
    permissions: [],
    networkBehavior: MobileNetworkBehavior.localOnly,
    dataSensitivity: MobileDataSensitivity.moderate,
    stateChangeRisk: MobileStateChangeRisk.none,
    limits: MobileToolLimits(maxItems: 32, maxDurationSeconds: 5, notes: 'Only deterministic local rules; unavailable evidence maps to unknown.'),
    passiveCapabilityIds: ['AND-001', 'AND-002', 'AND-005', 'AND-008'],
    allowedInvocationSources: _userOrLocalRule,
    userConsentRequired: false,
  ),
  MobileToolDefinition(
    id: 'mobile.visible_app_inventory',
    name: 'Visible application inventory',
    summary: 'List only packages visible to this app under Android package visibility.',
    phase: MobileToolPhase.consumerMvp,
    category: MobileToolCategory.applicationReview,
    implementationStatus: MobileToolImplementationStatus.partial,
    inputFields: [
      MobileToolField(name: 'fields', type: 'string[]', description: 'Requested minimal metadata fields.'),
      MobileToolField(name: 'limit', type: 'integer', description: 'Maximum result count.'),
    ],
    outputFields: [
      MobileToolField(name: 'applications', type: 'VisibleApplication[]', description: 'Package id, label, version and available source/signing metadata.'),
      MobileToolField(name: 'inventoryScope', type: 'string', description: 'Must state that Android visibility may be filtered.'),
      MobileToolField(name: 'observedAt', type: 'timestamp', description: 'Observation time.'),
    ],
    permissions: [
      MobilePermissionDependency(
        id: 'android.package_visibility',
        kind: MobilePermissionKind.packageVisibility,
        description: 'A declared launcher intent query limits results to launchable packages visible to this app; other installed packages can remain hidden.',
        optional: true,
      ),
    ],
    staticConstraints: [
      MobileToolStaticConstraint(
        id: 'play.query_all_packages_declaration',
        kind: MobileToolConstraintKind.distributionPolicy,
        description: 'Broad app visibility through QUERY_ALL_PACKAGES is not declared; adding it would require separate policy review and justification.',
        minimumApiLevel: 30,
      ),
      MobileToolStaticConstraint(
        id: 'android.package_visibility_filtered',
        kind: MobileToolConstraintKind.publicApiLimitation,
        description: 'Android filters app queries by default when targeting API 30 or higher; results must be labeled as visible packages, not a complete inventory.',
        minimumApiLevel: 30,
      ),
    ],
    networkBehavior: MobileNetworkBehavior.none,
    dataSensitivity: MobileDataSensitivity.high,
    stateChangeRisk: MobileStateChangeRisk.none,
    limits: MobileToolLimits(maxItems: 200, maxDurationSeconds: 10, notes: 'Lists launchable packages visible through the declared intent query; result and per-package permissions are bounded.'),
    passiveCapabilityIds: ['AND-012', 'AND-013', 'AND-016'],
    allowedInvocationSources: _userOnly,
    userConsentRequired: true,
  ),
  MobileToolDefinition(
    id: 'mobile.visible_app_permission_audit',
    name: 'Visible app permission audit',
    summary: 'Assess declared and publicly observable permission posture for selected visible packages.',
    phase: MobileToolPhase.consumerMvp,
    category: MobileToolCategory.applicationReview,
    implementationStatus: MobileToolImplementationStatus.partial,
    inputFields: [
      MobileToolField(name: 'inventorySnapshot', type: 'VisibleApplication[]', description: 'Permission metadata returned in the user-confirmed visible app inventory.', required: true),
    ],
    outputFields: [
      MobileToolField(name: 'applicationResults', type: 'ApplicationPermissionResult[]', description: 'Declared and granted permission names for returned visible launcher apps; no permission-use history.'),
      MobileToolField(name: 'observedAt', type: 'timestamp', description: 'Observation time.'),
    ],
    permissions: [
      MobilePermissionDependency(id: 'android.package_visibility', kind: MobilePermissionKind.packageVisibility, description: 'The inventory and permission snapshot cover only launchable packages visible under the declared intent query.', optional: true),
    ],
    networkBehavior: MobileNetworkBehavior.localOnly,
    dataSensitivity: MobileDataSensitivity.high,
    stateChangeRisk: MobileStateChangeRisk.none,
    limits: MobileToolLimits(maxItems: 200, maxDurationSeconds: 10, notes: 'Read-only snapshot from the visible application inventory; permissions are not evidence of actual usage.'),
    passiveCapabilityIds: ['AND-025', 'AND-026'],
    allowedInvocationSources: _userOnly,
    userConsentRequired: true,
  ),
  MobileToolDefinition(
    id: 'mobile.selected_apk_inspection',
    name: 'Selected APK inspection',
    summary: 'Inspect a user-selected APK as inert data; never install or execute it.',
    phase: MobileToolPhase.consumerMvp,
    category: MobileToolCategory.artifactInspection,
    implementationStatus: MobileToolImplementationStatus.partial,
    inputFields: [
      MobileToolField(name: 'contentUri', type: 'uri', description: 'URI granted by the Android document picker.', required: true),
    ],
    outputFields: [
      MobileToolField(name: 'status', type: 'enum', description: 'Complete, unsupported, over limit, or timed out.'),
      MobileToolField(name: 'contentType', type: 'string?', description: 'Content type reported by Android for the selected URI.'),
      MobileToolField(name: 'byteSize', type: 'integer?', description: 'Exact size only after a complete bounded read.'),
      MobileToolField(name: 'apkMetadata', type: 'object?', description: 'Package name, version, requested permissions, and signer digests when parseable.'),
      MobileToolField(name: 'sha256', type: 'string?', description: 'Full-file digest only after a complete bounded read.'),
      MobileToolField(name: 'metadataTruncated', type: 'boolean', description: 'Whether APK metadata exceeded a display limit.'),
    ],
    permissions: [_safRead],
    staticConstraints: [
      MobileToolStaticConstraint(
        id: 'android.saf_scoped_access',
        kind: MobileToolConstraintKind.publicApiLimitation,
        description: 'The app receives access only to the user-selected URI; Android restricts some directories.',
        minimumApiLevel: 19,
      ),
    ],
    networkBehavior: MobileNetworkBehavior.localOnly,
    dataSensitivity: MobileDataSensitivity.high,
    stateChangeRisk: MobileStateChangeRisk.none,
    limits: MobileToolLimits(maxInputBytes: 67108864, maxItems: 1, maxDurationSeconds: 15, notes: '64 MiB cap; user-selected APK is parsed as inert data. A cloud-backed document provider may fetch the selected content; SVS-Cyber performs no upload, install, execution, or reputation lookup.'),
    passiveCapabilityIds: ['AND-017'],
    allowedInvocationSources: _userOnly,
    userConsentRequired: true,
  ),
  MobileToolDefinition(
    id: 'mobile.selected_file_inspection',
    name: 'Selected file inspection',
    summary: 'Compute a SHA-256 digest for one user-selected file within a strict size and time limit.',
    phase: MobileToolPhase.consumerMvp,
    category: MobileToolCategory.artifactInspection,
    implementationStatus: MobileToolImplementationStatus.partial,
    inputFields: [
      MobileToolField(name: 'contentUri', type: 'uri', description: 'URI granted by the Android document picker.', required: true),
    ],
    outputFields: [
      MobileToolField(name: 'status', type: 'enum', description: 'Complete, over limit, or timed out.'),
      MobileToolField(name: 'contentType', type: 'string?', description: 'Content type reported by Android for the selected URI.'),
      MobileToolField(name: 'byteSize', type: 'integer?', description: 'Exact size only after a complete read.'),
      MobileToolField(name: 'sha256', type: 'string?', description: 'Full-file digest only after a complete bounded read.'),
    ],
    permissions: [_safRead],
    staticConstraints: [
      MobileToolStaticConstraint(
        id: 'android.saf_scoped_access',
        kind: MobileToolConstraintKind.publicApiLimitation,
        description: 'The app receives access only to the user-selected URI; Android restricts some directories.',
        minimumApiLevel: 19,
      ),
    ],
    networkBehavior: MobileNetworkBehavior.localOnly,
    dataSensitivity: MobileDataSensitivity.high,
    stateChangeRisk: MobileStateChangeRisk.none,
    limits: MobileToolLimits(maxInputBytes: 67108864, maxItems: 1, maxDurationSeconds: 15, notes: '64 MiB cap; hashes only. A cloud-backed provider may fetch content; SVS-Cyber never deletes, modifies, or uploads the source.'),
    passiveCapabilityIds: [],
    allowedInvocationSources: _userOnly,
    userConsentRequired: true,
  ),
  MobileToolDefinition(
    id: 'mobile.url_local_check',
    name: 'Local URL check',
    summary: 'Inspect a submitted URL’s structure using local heuristics only; no safety verdict.',
    phase: MobileToolPhase.consumerMvp,
    category: MobileToolCategory.linkAnalysis,
    implementationStatus: MobileToolImplementationStatus.partial,
    inputFields: [
      MobileToolField(name: 'url', type: 'string', description: 'User-submitted URL; sensitive query tokens should be removed before persistence.', required: true),
    ],
    outputFields: [
      MobileToolField(name: 'normalizedHost', type: 'string?', description: 'Normalized hostname when parseable.'),
      MobileToolField(name: 'scheme', type: 'string?', description: 'URL scheme.'),
      MobileToolField(name: 'indicators', type: 'EvidenceIndicator[]', description: 'Local structure and IDN indicators.'),
      MobileToolField(name: 'limitations', type: 'string[]', description: 'No destination fetch or reputation claim.'),
    ],
    permissions: [],
    networkBehavior: MobileNetworkBehavior.localOnly,
    dataSensitivity: MobileDataSensitivity.high,
    stateChangeRisk: MobileStateChangeRisk.none,
    limits: MobileToolLimits(maxInputCharacters: 2048, maxItems: 1, maxDurationSeconds: 2, notes: 'Never open, resolve, or redirect-fetch the destination; display only structural fields and host.'),
    passiveCapabilityIds: ['AND-081'],
    allowedInvocationSources: _userOnly,
    userConsentRequired: true,
  ),
  MobileToolDefinition(
    id: 'mobile.finding_correlate_explain',
    name: 'Local finding correlation',
    summary: 'Correlate selected local findings and explain evidence provenance.',
    phase: MobileToolPhase.foundation,
    category: MobileToolCategory.investigation,
    inputFields: [
      MobileToolField(name: 'findingIds', type: 'string[]', description: 'Local finding identifiers.', required: true),
      MobileToolField(name: 'evidenceRefIds', type: 'string[]', description: 'Evidence references selected for local analysis.'),
    ],
    outputFields: [
      MobileToolField(name: 'summary', type: 'string', description: 'Evidence-grounded explanation.'),
      MobileToolField(name: 'relationships', type: 'FindingRelationship[]', description: 'Correlations with supporting references.'),
      MobileToolField(name: 'hypotheses', type: 'string[]', description: 'Clearly labeled hypotheses.'),
      MobileToolField(name: 'ruleVersions', type: 'string[]', description: 'Detection rule provenance.'),
    ],
    permissions: [],
    networkBehavior: MobileNetworkBehavior.localOnly,
    dataSensitivity: MobileDataSensitivity.high,
    stateChangeRisk: MobileStateChangeRisk.none,
    limits: MobileToolLimits(maxItems: 100, maxDurationSeconds: 5, notes: 'No provider calls; no action execution; preserve rule/evidence provenance.'),
    passiveCapabilityIds: ['AND-024', 'AND-036', 'AND-040', 'AND-055', 'AND-072'],
    allowedInvocationSources: _userOrLocalRule,
    userConsentRequired: false,
  ),
  MobileToolDefinition(
    id: 'mobile.protection_coverage_report',
    name: 'Protection coverage report',
    summary: 'Show catalogue implementation, access, operation, freshness, and health gaps.',
    phase: MobileToolPhase.foundation,
    category: MobileToolCategory.diagnostics,
    inputFields: [
      MobileToolField(name: 'categoryIds', type: 'string[]', description: 'Optional capability categories to include.'),
    ],
    outputFields: [
      MobileToolField(name: 'capabilityStates', type: 'CapabilityStatus[]', description: 'Implementation, availability, operation, last observation and health.'),
      MobileToolField(name: 'coverageSummary', type: 'object', description: 'Counts and explicit coverage gaps.'),
      MobileToolField(name: 'generatedAt', type: 'timestamp', description: 'Report time.'),
    ],
    permissions: [],
    networkBehavior: MobileNetworkBehavior.none,
    dataSensitivity: MobileDataSensitivity.low,
    stateChangeRisk: MobileStateChangeRisk.none,
    limits: MobileToolLimits(maxItems: 136, maxDurationSeconds: 3, notes: 'Capability metadata is not evidence that collection is supported or healthy.'),
    passiveCapabilityIds: ['AND-001', 'AND-002', 'AND-003', 'AND-004', 'AND-005', 'AND-006', 'AND-007', 'AND-008', 'AND-121', 'AND-122', 'AND-123', 'AND-124', 'AND-125', 'AND-126', 'AND-127', 'AND-128'],
    allowedInvocationSources: _userOrLocalRule,
    userConsentRequired: false,
  ),
  MobileToolDefinition(
    id: 'mobile.diagnostic_report_export',
    name: 'Diagnostic report export',
    summary: 'Create a redacted local diagnostic report at the user’s request.',
    phase: MobileToolPhase.foundation,
    category: MobileToolCategory.diagnostics,
    inputFields: [
      MobileToolField(name: 'from', type: 'timestamp?', description: 'Optional start of selected time range.'),
      MobileToolField(name: 'to', type: 'timestamp?', description: 'Optional end of selected time range.'),
      MobileToolField(name: 'sections', type: 'string[]', description: 'Explicitly included report sections.', required: true),
      MobileToolField(name: 'redactionMode', type: 'enum', description: 'Must default to redacted.'),
    ],
    outputFields: [
      MobileToolField(name: 'exportUri', type: 'uri', description: 'User-selected destination URI.'),
      MobileToolField(name: 'includedSections', type: 'string[]', description: 'Sections actually included.'),
      MobileToolField(name: 'redactions', type: 'string[]', description: 'Redactions applied.'),
      MobileToolField(name: 'generatedAt', type: 'timestamp', description: 'Generation time.'),
    ],
    permissions: [
      MobilePermissionDependency(id: 'android.storage_access_framework.create', kind: MobilePermissionKind.userSelectedUri, description: 'The user chooses the destination in the system save picker.'),
    ],
    networkBehavior: MobileNetworkBehavior.none,
    dataSensitivity: MobileDataSensitivity.high,
    stateChangeRisk: MobileStateChangeRisk.createsUserRequestedExport,
    limits: MobileToolLimits(maxInputBytes: 5242880, maxItems: 10000, maxDurationSeconds: 15, notes: 'Redact by default; require a user-initiated save/share; never auto-upload.'),
    passiveCapabilityIds: ['AND-121', 'AND-122', 'AND-123', 'AND-124', 'AND-125', 'AND-126', 'AND-127', 'AND-128'],
    allowedInvocationSources: _userOnly,
    userConsentRequired: true,
  ),
];

/// Cheap catalogue invariant check suitable for app startup diagnostics.
/// It validates metadata only and never calls Android APIs.
List<String> validateMobileToolRegistry() {
  final errors = <String>[];
  final ids = <String>{};
  for (final tool in mobileToolRegistry) {
    if (!ids.add(tool.id)) errors.add('Duplicate tool id: ${tool.id}');
    if (!tool.id.startsWith('mobile.')) errors.add('Non-mobile tool id: ${tool.id}');
    if (tool.limits.maxDurationSeconds < 1 || tool.limits.maxConcurrency < 1) {
      errors.add('Invalid limits for ${tool.id}');
    }
    if (tool.networkBehavior == MobileNetworkBehavior.externalWithPerRequestConsent &&
        !tool.userConsentRequired) {
      errors.add('External network tool lacks explicit consent: ${tool.id}');
    }
  }
  return errors;
}
