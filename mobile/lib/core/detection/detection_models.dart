import 'dart:convert';

enum FindingSeverity { informational, low, medium, high, critical }

enum FindingStatus { open, acknowledged, resolved, suppressed }

enum EvidenceComparison { equals }

class MobileEvent {
  const MobileEvent({
    required this.contractVersion,
    required this.eventId,
    required this.capabilityId,
    required this.eventType,
    required this.occurredAt,
    required this.observedAt,
    required this.availability,
    required this.operation,
    required this.freshness,
    required this.continuous,
    required this.evidence,
  });

  final int contractVersion;
  final String eventId;
  final String capabilityId;
  final String eventType;
  final DateTime occurredAt;
  final DateTime observedAt;
  final String availability;
  final String operation;
  final String freshness;
  final bool continuous;
  final Map<String, Object?> evidence;

  factory MobileEvent.fromJson(Map<String, Object?> json) {
    final event = MobileEvent(
      contractVersion: _int(json, 'contractVersion'),
      eventId: _string(json, 'eventId'),
      capabilityId: _string(json, 'capabilityId'),
      eventType: _string(json, 'eventType'),
      occurredAt: _epochDate(json, 'occurredAtEpochMs'),
      observedAt: _epochDate(json, 'observedAtEpochMs'),
      availability: _string(json, 'availability'),
      operation: _string(json, 'operation'),
      freshness: _string(json, 'freshness'),
      continuous: _bool(json, 'continuous'),
      evidence: _objectMap(json, 'evidence'),
    );
    if (event.contractVersion != 1) {
      throw FormatException('Unsupported native event contract ${event.contractVersion}.');
    }
    if (!RegExp(r'^AND-\d{3}$').hasMatch(event.capabilityId)) {
      throw FormatException('Invalid capability id ${event.capabilityId}.');
    }
    return event;
  }

  factory MobileEvent.fromJsonString(String source) {
    final value = jsonDecode(source);
    if (value is! Map<String, Object?>) {
      throw const FormatException('Mobile event must be a JSON object.');
    }
    return MobileEvent.fromJson(value);
  }

  Map<String, Object?> toJson() => {
        'contractVersion': contractVersion,
        'eventId': eventId,
        'capabilityId': capabilityId,
        'eventType': eventType,
        'occurredAtEpochMs': occurredAt.millisecondsSinceEpoch,
        'observedAtEpochMs': observedAt.millisecondsSinceEpoch,
        'availability': availability,
        'operation': operation,
        'freshness': freshness,
        'continuous': continuous,
        'evidence': evidence,
      };
}

class EvidenceReference {
  const EvidenceReference({
    required this.eventId,
    required this.capabilityId,
    required this.path,
    required this.observedAt,
    required this.value,
  });

  final String eventId;
  final String capabilityId;

  /// Dot-separated path relative to the event's evidence object.
  final String path;
  final DateTime observedAt;
  final Object? value;

  String get id => '$eventId#$path';

  factory EvidenceReference.fromJson(Map<String, Object?> json) =>
      EvidenceReference(
        eventId: _string(json, 'eventId'),
        capabilityId: _string(json, 'capabilityId'),
        path: _string(json, 'path'),
        observedAt: DateTime.parse(_string(json, 'observedAt')),
        value: json['value'],
      );

  Map<String, Object?> toJson() => {
        'eventId': eventId,
        'capabilityId': capabilityId,
        'path': path,
        'observedAt': observedAt.toUtc().toIso8601String(),
        'value': value,
      };
}

class FindingReviewEntry {
  const FindingReviewEntry({
    required this.action,
    required this.at,
    this.note,
  });

  final String action;
  final DateTime at;
  final String? note;

  factory FindingReviewEntry.fromJson(Map<String, Object?> json) =>
      FindingReviewEntry(
        action: _string(json, 'action'),
        at: DateTime.parse(_string(json, 'at')),
        note: json['note'] as String?,
      );

  Map<String, Object?> toJson() => {
        'action': action,
        'at': at.toUtc().toIso8601String(),
        if (note != null) 'note': note,
      };
}

class Finding {
  const Finding({
    required this.id,
    required this.deduplicationKey,
    required this.ruleId,
    required this.ruleVersion,
    required this.capabilityIds,
    required this.title,
    required this.createdAt,
    required this.firstObservedAt,
    required this.lastObservedAt,
    this.resolvedAt,
    required this.severity,
    required this.confidence,
    required this.evidenceReferences,
    required this.explanation,
    required this.affectedComponent,
    required this.limitations,
    required this.recommendedAction,
    required this.status,
    required this.reviewHistory,
  });

  final String id;
  final String deduplicationKey;
  final String ruleId;
  final String ruleVersion;
  final List<String> capabilityIds;
  final String title;
  final DateTime createdAt;
  final DateTime firstObservedAt;
  final DateTime lastObservedAt;
  final DateTime? resolvedAt;
  final FindingSeverity severity;
  final double confidence;
  final List<EvidenceReference> evidenceReferences;
  final String explanation;
  final String affectedComponent;
  final List<String> limitations;
  final String recommendedAction;
  final FindingStatus status;
  final List<FindingReviewEntry> reviewHistory;

  factory Finding.fromJson(Map<String, Object?> json) {
    final confidence = json['confidence'];
    if (confidence is! num || confidence < 0 || confidence > 1) {
      throw const FormatException('Finding confidence must be in the range 0..1.');
    }
    return Finding(
      id: _string(json, 'id'),
      deduplicationKey: _string(json, 'deduplicationKey'),
      ruleId: _string(json, 'ruleId'),
      ruleVersion: _string(json, 'ruleVersion'),
      capabilityIds: _strings(json, 'capabilityIds'),
      title: _string(json, 'title'),
      createdAt: DateTime.parse(_string(json, 'createdAt')),
      firstObservedAt: DateTime.parse(_string(json, 'firstObservedAt')),
      lastObservedAt: DateTime.parse(_string(json, 'lastObservedAt')),
      resolvedAt: json['resolvedAt'] == null
          ? null
          : DateTime.parse(_string(json, 'resolvedAt')),
      severity: _enumByName(FindingSeverity.values, json, 'severity'),
      confidence: confidence.toDouble(),
      evidenceReferences: _objects(json, 'evidenceReferences')
          .map(EvidenceReference.fromJson)
          .toList(growable: false),
      explanation: _string(json, 'explanation'),
      affectedComponent: _string(json, 'affectedComponent'),
      limitations: _strings(json, 'limitations'),
      recommendedAction: _string(json, 'recommendedAction'),
      status: _enumByName(FindingStatus.values, json, 'status'),
      reviewHistory: _objects(json, 'reviewHistory')
          .map(FindingReviewEntry.fromJson)
          .toList(growable: false),
    );
  }

  Map<String, Object?> toJson() => {
        'id': id,
        'deduplicationKey': deduplicationKey,
        'ruleId': ruleId,
        'ruleVersion': ruleVersion,
        'capabilityIds': capabilityIds,
        'title': title,
        'createdAt': createdAt.toUtc().toIso8601String(),
        'firstObservedAt': firstObservedAt.toUtc().toIso8601String(),
        'lastObservedAt': lastObservedAt.toUtc().toIso8601String(),
        if (resolvedAt != null)
          'resolvedAt': resolvedAt!.toUtc().toIso8601String(),
        'severity': severity.name,
        'confidence': confidence,
        'evidenceReferences': evidenceReferences.map((item) => item.toJson()).toList(),
        'explanation': explanation,
        'affectedComponent': affectedComponent,
        'limitations': limitations,
        'recommendedAction': recommendedAction,
        'status': status.name,
        'reviewHistory': reviewHistory.map((item) => item.toJson()).toList(),
      };
}

class DetectionRule {
  const DetectionRule({
    required this.id,
    required this.version,
    required this.capabilityId,
    required this.evidencePath,
    required this.comparison,
    required this.expectedValue,
    this.resolutionExpectedValue,
    required this.deduplicationKey,
    required this.title,
    required this.explanation,
    required this.affectedComponent,
    required this.severity,
    required this.confidence,
    required this.limitations,
    required this.recommendedAction,
  });

  final String id;
  final String version;
  final String capabilityId;
  final String evidencePath;
  final EvidenceComparison comparison;
  final Object? expectedValue;
  final Object? resolutionExpectedValue;
  final String deduplicationKey;
  final String title;
  final String explanation;
  final String affectedComponent;
  final FindingSeverity severity;
  final double confidence;
  final List<String> limitations;
  final String recommendedAction;

  factory DetectionRule.fromJson(Map<String, Object?> json) {
    final confidence = json['confidence'];
    if (confidence is! num || confidence < 0 || confidence > 1) {
      throw const FormatException('Rule confidence must be in the range 0..1.');
    }
    final expectedValue = json['expectedValue'];
    if (expectedValue is Map || expectedValue is List) {
      throw const FormatException('Rule expectedValue must be a JSON scalar.');
    }
    final resolutionExpectedValue = json['resolutionExpectedValue'];
    if (resolutionExpectedValue is Map || resolutionExpectedValue is List) {
      throw const FormatException('Rule resolutionExpectedValue must be a JSON scalar.');
    }
    return DetectionRule(
      id: _string(json, 'id'),
      version: _string(json, 'version'),
      capabilityId: _string(json, 'capabilityId'),
      evidencePath: _string(json, 'evidencePath'),
      comparison: _enumByName(EvidenceComparison.values, json, 'comparison'),
      expectedValue: expectedValue,
      resolutionExpectedValue: resolutionExpectedValue,
      deduplicationKey: _string(json, 'deduplicationKey'),
      title: _string(json, 'title'),
      explanation: _string(json, 'explanation'),
      affectedComponent: _string(json, 'affectedComponent'),
      severity: _enumByName(FindingSeverity.values, json, 'severity'),
      confidence: confidence.toDouble(),
      limitations: _strings(json, 'limitations'),
      recommendedAction: _string(json, 'recommendedAction'),
    );
  }

  Map<String, Object?> toJson() => {
        'id': id,
        'version': version,
        'capabilityId': capabilityId,
        'evidencePath': evidencePath,
        'comparison': comparison.name,
        'expectedValue': expectedValue,
        'resolutionExpectedValue': resolutionExpectedValue,
        'deduplicationKey': deduplicationKey,
        'title': title,
        'explanation': explanation,
        'affectedComponent': affectedComponent,
        'severity': severity.name,
        'confidence': confidence,
        'limitations': limitations,
        'recommendedAction': recommendedAction,
      };

  bool isUsableAt(
    MobileEvent event, {
    required DateTime asOf,
    required Duration maxAge,
  }) {
    if (event.eventType != 'observation' ||
        event.capabilityId != capabilityId ||
        event.availability != 'available' ||
        event.operation != 'completed' ||
        event.freshness != 'fresh' ||
        event.observedAt.isAfter(asOf) ||
        asOf.difference(event.observedAt) > maxAge) {
      return false;
    }
    return true;
  }

  bool matchesTrigger(MobileEvent event) =>
      _matchesValue(event, expectedValue);

  bool matchesResolution(MobileEvent event) =>
      resolutionExpectedValue != null &&
      _matchesValue(event, resolutionExpectedValue);

  bool _matchesValue(MobileEvent event, Object? expected) {
    final value = _readEvidencePath(event.evidence, evidencePath);
    return value != _missing && _jsonValueEquals(value, expected);
  }
}

const Object _missing = Object();

Object? _readEvidencePath(Map<String, Object?> evidence, String path) {
  Object? value = evidence;
  for (final segment in path.split('.')) {
    if (value is! Map<String, Object?> || !value.containsKey(segment)) {
      return _missing;
    }
    value = value[segment];
  }
  return value;
}

bool _jsonValueEquals(Object? left, Object? right) {
  if (left is num && right is num) return left == right;
  return left == right;
}

bool _bool(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is bool) return value;
  throw FormatException('Field "$key" must be a boolean.');
}

String _string(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is String && value.isNotEmpty) return value;
  throw FormatException('Field "$key" must be a non-empty string.');
}

int _int(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is int) return value;
  throw FormatException('Field "$key" must be an integer.');
}

DateTime _epochDate(Map<String, Object?> json, String key) =>
    DateTime.fromMillisecondsSinceEpoch(_int(json, key), isUtc: true);

Map<String, Object?> _objectMap(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is Map<String, Object?>) return Map.unmodifiable(value);
  throw FormatException('Field "$key" must be an object.');
}

List<String> _strings(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is List<Object?> && value.every((item) => item is String)) {
    return List<String>.unmodifiable(value.cast<String>());
  }
  throw FormatException('Field "$key" must be a list of strings.');
}

List<Map<String, Object?>> _objects(Map<String, Object?> json, String key) {
  final value = json[key];
  if (value is List<Object?> && value.every((item) => item is Map<String, Object?>)) {
    return value.cast<Map<String, Object?>>();
  }
  throw FormatException('Field "$key" must be a list of objects.');
}

T _enumByName<T extends Enum>(List<T> values, Map<String, Object?> json, String key) {
  final raw = _string(json, key);
  for (final value in values) {
    if (value.name == raw) return value;
  }
  throw FormatException('Field "$key" has unknown value "$raw".');
}
