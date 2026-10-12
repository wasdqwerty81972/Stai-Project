/// Metadata-only contract for a mobile tool.
///
/// Tool definitions describe an operation and its safety boundary. They do not
/// provide an executor and must not be treated as Android capability sensors.
enum MobileToolPhase { foundation, consumerMvp, networkProtection, enterprise }

enum MobileToolImplementationStatus { planned, partial, implemented }

enum MobileToolCategory {
  devicePosture,
  applicationReview,
  artifactInspection,
  linkAnalysis,
  investigation,
  diagnostics,
}

enum MobileDataSensitivity { low, moderate, high, critical }

enum MobileNetworkBehavior {
  /// The tool uses no network connection.
  none,

  /// Processing is local. This does not authorize any network lookup.
  localOnly,

  /// Network use is permitted only through a separate, disclosed consent flow.
  externalWithPerRequestConsent,
}

enum MobileStateChangeRisk { none, createsUserRequestedExport }

enum MobileInvocationSource { user, enabledLocalRule }

enum MobilePermissionKind {
  androidRuntime,
  specialAccess,
  packageVisibility,
  userSelectedUri,
  userSelectedDirectory,
}

enum MobileToolConstraintKind {
  androidApi,
  distributionPolicy,
  publicApiLimitation,
  enterpriseProvisioning,
  notImplemented,
}

/// A static platform or distribution requirement, not a runtime permission
/// grant or availability result.
class MobileToolStaticConstraint {
  const MobileToolStaticConstraint({
    required this.id,
    required this.kind,
    required this.description,
    this.minimumApiLevel,
    this.maximumApiLevel,
  });

  final String id;
  final MobileToolConstraintKind kind;
  final String description;
  final int? minimumApiLevel;
  final int? maximumApiLevel;
}

class MobilePermissionDependency {
  const MobilePermissionDependency({
    required this.id,
    required this.kind,
    required this.description,
    this.androidPermission,
    this.optional = false,
  });

  final String id;
  final MobilePermissionKind kind;
  final String description;
  final String? androidPermission;
  final bool optional;
}

class MobileToolField {
  const MobileToolField({
    required this.name,
    required this.type,
    required this.description,
    this.required = false,
  });

  final String name;
  final String type;
  final String description;
  final bool required;
}

class MobileToolLimits {
  const MobileToolLimits({
    this.maxInputCharacters,
    this.maxInputBytes,
    this.maxItems,
    this.maxDurationSeconds = 10,
    this.maxConcurrency = 1,
    required this.notes,
  });

  final int? maxInputCharacters;
  final int? maxInputBytes;
  final int? maxItems;
  final int maxDurationSeconds;
  final int maxConcurrency;
  final String notes;
}

class MobileToolDefinition {
  const MobileToolDefinition({
    required this.id,
    required this.name,
    required this.summary,
    required this.phase,
    required this.category,
    required this.inputFields,
    required this.outputFields,
    required this.permissions,
    required this.networkBehavior,
    required this.dataSensitivity,
    required this.stateChangeRisk,
    required this.limits,
    required this.passiveCapabilityIds,
    required this.allowedInvocationSources,
    required this.userConsentRequired,
    this.implementationStatus = MobileToolImplementationStatus.planned,
    this.staticConstraints = const [],
  });

  final String id;
  final String name;
  final String summary;
  final MobileToolPhase phase;
  final MobileToolCategory category;
  final List<MobileToolField> inputFields;
  final List<MobileToolField> outputFields;
  final List<MobilePermissionDependency> permissions;
  final MobileNetworkBehavior networkBehavior;
  final MobileDataSensitivity dataSensitivity;
  final MobileStateChangeRisk stateChangeRisk;
  final MobileToolLimits limits;

  /// References in the independent capability catalogue; this does not
  /// register, activate, or implement any capability.
  final List<String> passiveCapabilityIds;

  /// Local-rule invocation is only eligible after a feature-level opt-in.
  final Set<MobileInvocationSource> allowedInvocationSources;
  final bool userConsentRequired;

  /// Static implementation maturity. Runtime state is tracked separately.
  final MobileToolImplementationStatus implementationStatus;

  /// Static platform and distribution requirements. These are not live status.
  final List<MobileToolStaticConstraint> staticConstraints;
}
