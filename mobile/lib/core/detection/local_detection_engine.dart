import 'dart:convert';

import 'detection_models.dart';

/// Deterministic metadata-driven rule set for local posture observations.
/// Findings from these rules describe configuration posture, never compromise.
const builtInPostureRules = <DetectionRule>[
  DetectionRule(
    id: 'mobile.posture.secure_lock_required',
    version: '1.0.0',
    capabilityId: 'AND-008',
    evidencePath: 'secureLockConfigured',
    comparison: EvidenceComparison.equals,
    expectedValue: false,
    resolutionExpectedValue: true,
    deduplicationKey: 'device:secure-lock-unconfigured',
    title: 'Secure screen lock is not configured',
    explanation:
        'Android reported that a secure device lock is not configured at the time of this observation.',
    affectedComponent: 'Android device lock configuration',
    severity: FindingSeverity.medium,
    confidence: 1.0,
    limitations: [
      'This is a device-posture observation, not evidence that the device is compromised.',
      'The value reflects the last successful observation and may have changed since then.',
    ],
    recommendedAction: 'Review the screen-lock settings in Android Settings.',
  ),
];

class LocalDetectionEngine {
  LocalDetectionEngine({
    required List<DetectionRule> rules,
    this.maxEventAge = defaultDetectionEvidenceMaxAge,
  }) : rules = List<DetectionRule>.unmodifiable(rules);

  final List<DetectionRule> rules;
  final Duration maxEventAge;

  /// Evaluates only completed, fresh, available observations.
  ///
  /// Existing findings are merged by deterministic rule/deduplication key.
  /// Repeated event IDs and repeated evidence references are ignored. This
  /// engine emits findings only; it has no interface for executing actions.
  List<Finding> evaluate({
    required Iterable<MobileEvent> events,
    required DateTime asOf,
    Iterable<Finding> existingFindings = const [],
  }) {
    final byDedupeKey = <String, Finding>{
      for (final finding in existingFindings)
        finding.deduplicationKey: finding,
    };
    final seenEventIds = <String>{};
    final orderedEvents = events.toList()
      ..sort((left, right) {
        final timeOrder = left.observedAt.compareTo(right.observedAt);
        if (timeOrder != 0) return timeOrder;
        final idOrder = left.eventId.compareTo(right.eventId);
        if (idOrder != 0) return idOrder;
        return jsonEncode(left.toJson()).compareTo(jsonEncode(right.toJson()));
      });

    for (final event in orderedEvents) {
      if (!seenEventIds.add(event.eventId)) continue;
      for (final rule in rules) {
        if (!rule.isUsableAt(event, asOf: asOf, maxAge: maxEventAge)) continue;

        final deduplicationKey = '${rule.id}::${rule.deduplicationKey}';
        final previous = byDedupeKey[deduplicationKey];
        if (rule.matchesResolution(event)) {
          if (previous != null) {
            final shouldResolve = previous.status != FindingStatus.resolved &&
                previous.status != FindingStatus.suppressed;
            byDedupeKey[deduplicationKey] = _withEvidence(
              previous,
              event,
              rule,
              status: previous.status == FindingStatus.suppressed
                  ? FindingStatus.suppressed
                  : FindingStatus.resolved,
              resolvedAt: previous.status == FindingStatus.suppressed
                  ? previous.resolvedAt
                  : _later(previous.resolvedAt, event.observedAt),
              machineAction: shouldResolve
                  ? 'resolved_by_posture_observation'
                  : null,
            );
          }
          continue;
        }
        if (!rule.matchesTrigger(event)) continue;

        final reference = EvidenceReference(
          eventId: event.eventId,
          capabilityId: event.capabilityId,
          path: rule.evidencePath,
          observedAt: event.observedAt,
          value: _evidenceValue(event, rule.evidencePath),
        );
        if (previous == null) {
          final finding = Finding(
            id: 'finding/${Uri.encodeComponent(rule.id)}/${Uri.encodeComponent(rule.deduplicationKey)}',
            deduplicationKey: deduplicationKey,
            ruleId: rule.id,
            ruleVersion: rule.version,
            capabilityIds: [rule.capabilityId],
            title: rule.title,
            createdAt: event.observedAt,
            firstObservedAt: event.observedAt,
            lastObservedAt: event.observedAt,
            resolvedAt: null,
            severity: rule.severity,
            confidence: rule.confidence,
            evidenceReferences: [reference],
            explanation: rule.explanation,
            affectedComponent: rule.affectedComponent,
            limitations: rule.limitations,
            recommendedAction: rule.recommendedAction,
            status: FindingStatus.open,
            reviewHistory: const [],
          );
          byDedupeKey[deduplicationKey] = finding;
        } else {
          final shouldReopen = previous.status == FindingStatus.resolved;
          byDedupeKey[deduplicationKey] = _withEvidence(
            previous,
            event,
            rule,
            status: shouldReopen
                ? FindingStatus.open
                : previous.status,
            resolvedAt: null,
            machineAction: shouldReopen
                ? 'reopened_by_posture_observation'
                : null,
          );
        }
      }
    }

    final result = byDedupeKey.values.toList()
      ..sort((left, right) {
        final timeOrder = left.createdAt.compareTo(right.createdAt);
        return timeOrder != 0 ? timeOrder : left.id.compareTo(right.id);
      });
    return List<Finding>.unmodifiable(result);
  }
}

const defaultDetectionEvidenceMaxAge = Duration(hours: 24);
const maxEvidenceReferencesPerFinding = 64;

Finding _withEvidence(
  Finding previous,
  MobileEvent event,
  DetectionRule rule, {
  required FindingStatus status,
  required DateTime? resolvedAt,
  String? machineAction,
}) {
  final reference = EvidenceReference(
    eventId: event.eventId,
    capabilityId: event.capabilityId,
    path: rule.evidencePath,
    observedAt: event.observedAt,
    value: _evidenceValue(event, rule.evidencePath),
  );
  final references = [...previous.evidenceReferences];
  if (references.every((item) => item.id != reference.id)) {
    references.add(reference);
  }
  final cappedReferences = references.length <= maxEvidenceReferencesPerFinding
      ? references
      : references.sublist(references.length - maxEvidenceReferencesPerFinding);
  final reviewHistory = [...previous.reviewHistory];
  if (machineAction != null) {
    reviewHistory.add(
      FindingReviewEntry(
        action: machineAction,
        at: event.observedAt,
        note: 'Automatic rule state transition based on event ${event.eventId} (${event.capabilityId}).',
      ),
    );
  }
  return Finding(
    id: previous.id,
    deduplicationKey: previous.deduplicationKey,
    ruleId: previous.ruleId,
    ruleVersion: previous.ruleVersion,
    capabilityIds: previous.capabilityIds,
    title: previous.title,
    createdAt: previous.createdAt,
    firstObservedAt: previous.firstObservedAt,
    lastObservedAt: _later(previous.lastObservedAt, event.observedAt)!,
    resolvedAt: resolvedAt,
    severity: previous.severity,
    confidence: previous.confidence,
    evidenceReferences: List.unmodifiable(cappedReferences),
    explanation: previous.explanation,
    affectedComponent: previous.affectedComponent,
    limitations: previous.limitations,
    recommendedAction: previous.recommendedAction,
    status: status,
    reviewHistory: List.unmodifiable(reviewHistory),
  );
}

DateTime? _later(DateTime? left, DateTime? right) {
  if (left == null) return right;
  if (right == null) return left;
  return left.isAfter(right) ? left : right;
}

Object? _evidenceValue(MobileEvent event, String path) {
  Object? value = event.evidence;
  for (final segment in path.split('.')) {
    if (value is! Map<String, Object?>) return null;
    value = value[segment];
  }
  return value;
}
