/// Static feasibility for the proposed Android capability.
///
/// This is independent from runtime [availability], which must be determined
/// by a real Android access check rather than inferred from this metadata.
enum CapabilityAccessClass {
  standard,
  packageVisibility,
  runtimePermission,
  onlineService,
  specialUserAccess,
  userConsent,
  derived,
  enterprise,
  unavailable,
}

enum CapabilityTier { consumer, enterprise }

enum CapabilityImplementationStatus { planned, partial, implemented }

enum CapabilityCollectionHealth { notEvaluated, healthy, degraded, failed }

/// Runtime access status. `notChecked` is the honest default before a native
/// collector has probed Android and its relevant permissions.
enum CapabilityAvailability {
  notChecked,
  available,
  consentRequired,
  permissionMissing,
  permissionRevoked,
  unsupported,
  enterpriseRequired,
  policyRestricted,
  temporarilyUnavailable,
}

enum CapabilityOperationStatus {
  disabled,
  active,
  scheduled,
  paused,
  degraded,
  failed,
}

enum CapabilityFreshness { neverObserved, fresh, stale, unknown }

class CapabilityDefinition {
  const CapabilityDefinition({
    required this.id,
    required this.name,
    required this.category,
    required this.description,
    required this.tier,
    required this.accessClass,
    required this.accessRequirements,
    required this.evidenceSource,
    required this.minAndroidApi,
    required this.maxAndroidApi,
    required this.apiConditions,
    required this.collectorDependency,
    required this.implementation,
    required this.collectionHealth,
    required this.lastSuccessfulObservation,
    required this.availability,
    required this.operation,
    required this.freshness,
    required this.privacyTags,
    required this.derived,
    required this.backgroundExecution,
    required this.batteryImpact,
    required this.distributionRestrictions,
    required this.limitations,
  });

  final String id;
  final String name;
  final String category;
  final String description;
  final CapabilityTier tier;

  /// Feasibility and authorization class from platform review, not live state.
  final CapabilityAccessClass accessClass;
  final List<String> accessRequirements;
  final String evidenceSource;
  final int minAndroidApi;
  final int? maxAndroidApi;
  final List<String> apiConditions;
  final String collectorDependency;

  /// Product implementation maturity; this does not imply live collection.
  final CapabilityImplementationStatus implementation;
  final CapabilityCollectionHealth collectionHealth;
  final DateTime? lastSuccessfulObservation;

  /// Runtime dimensions are populated only by actual platform probes/results.
  final CapabilityAvailability availability;
  final CapabilityOperationStatus operation;
  final CapabilityFreshness freshness;

  final List<String> privacyTags;
  final bool derived;
  final String backgroundExecution;
  final String batteryImpact;
  final List<String> distributionRestrictions;
  final List<String> limitations;

  factory CapabilityDefinition.fromJson(Map<String, Object?> json) {
    return CapabilityDefinition(
      id: _requiredString(json, 'id'),
      name: _requiredString(json, 'name'),
      category: _requiredString(json, 'category'),
      description: _requiredString(json, 'description'),
      tier: _enumValue(CapabilityTier.values, json, 'tier'),
      accessClass: _enumValue(
        CapabilityAccessClass.values,
        json,
        'access_class',
        jsonName: true,
      ),
      accessRequirements: _stringList(json, 'access_requirements'),
      evidenceSource: _requiredString(json, 'evidence_source'),
      minAndroidApi: _requiredInt(json, 'android_api_min'),
      maxAndroidApi: _nullableInt(json, 'android_api_max'),
      apiConditions: _stringList(json, 'android_api_conditions'),
      collectorDependency: _requiredString(json, 'collector_dependency'),
      implementation: _enumValue(
        CapabilityImplementationStatus.values,
        json,
        'implementation',
      ),
      collectionHealth: _enumValue(
        CapabilityCollectionHealth.values,
        json,
        'collection_health',
        jsonName: true,
      ),
      lastSuccessfulObservation: _nullableDateTime(
        json,
        'last_successful_observation',
      ),
      availability: _enumValue(
        CapabilityAvailability.values,
        json,
        'availability',
        jsonName: true,
      ),
      operation: _enumValue(
        CapabilityOperationStatus.values,
        json,
        'operation',
      ),
      freshness: _enumValue(
        CapabilityFreshness.values,
        json,
        'freshness',
        jsonName: true,
      ),
      privacyTags: _stringList(json, 'privacy_tags'),
      derived: _requiredBool(json, 'derived'),
      backgroundExecution: _requiredString(json, 'background_execution'),
      batteryImpact: _requiredString(json, 'battery_impact'),
      distributionRestrictions: _stringList(json, 'distribution_restrictions'),
      limitations: _stringList(json, 'limitations'),
    );
  }
}

String _requiredString(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is String && value.isNotEmpty) return value;
  throw FormatException('Capability field "$key" must be a non-empty string.');
}

bool _requiredBool(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is bool) return value;
  throw FormatException('Capability field "$key" must be a boolean.');
}

int _requiredInt(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is int) return value;
  throw FormatException('Capability field "$key" must be an integer.');
}

int? _nullableInt(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value == null || value is int) return value as int?;
  throw FormatException('Capability field "$key" must be an integer or null.');
}

DateTime? _nullableDateTime(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value == null) return null;
  if (value is String) {
    final parsed = DateTime.tryParse(value);
    if (parsed != null) return parsed.toUtc();
  }
  throw FormatException('Capability field "$key" must be an ISO timestamp or null.');
}

List<String> _stringList(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is List<Object?> && value.every((item) => item is String)) {
    return List<String>.unmodifiable(value.cast<String>());
  }
  throw FormatException('Capability field "$key" must be a list of strings.');
}

T _enumValue<T extends Enum>(
  List<T> values,
  Map<String, Object?> json,
  String key, {
  bool jsonName = false,
}) {
  final raw = _requiredString(json, key);
  final normalized = jsonName ? raw.replaceAll('_', '') : raw;
  for (final value in values) {
    if (value.name.toLowerCase() == normalized.toLowerCase()) return value;
  }
  throw FormatException('Capability field "$key" has unknown value "$raw".');
}
