import 'detection_models.dart';

/// Builds a provenance-first, deterministic bundle from caller-supplied local
/// findings and events. This class has no platform, network, or provider access.
class LocalFindingInvestigator {
  const LocalFindingInvestigator({
    this.relatedEventWindow = const Duration(minutes: 15),
  });

  final Duration relatedEventWindow;

  InvestigationBundle investigate({
    required List<String> selectedFindingIds,
    required Iterable<Finding> findings,
    required Iterable<MobileEvent> events,
  }) {
    final findingsById = <String, List<Finding>>{};
    for (final finding in findings) {
      findingsById.putIfAbsent(finding.id, () => []).add(finding);
    }

    final eventsById = <String, List<MobileEvent>>{};
    for (final event in events) {
      eventsById.putIfAbsent(event.eventId, () => []).add(event);
    }

    final selected = <InvestigationFinding>[];
    final missingFindingIds = <String>[];
    final ambiguousFindingIds = <String>[];
    final seenFindingIds = <String>{};
    for (final id in selectedFindingIds) {
      if (!seenFindingIds.add(id)) continue;
      final matches = findingsById[id] ?? const <Finding>[];
      if (matches.isEmpty) {
        missingFindingIds.add(id);
        continue;
      }
      if (matches.length > 1) {
        ambiguousFindingIds.add(id);
        continue;
      }
      selected.add(_investigateFinding(matches.single, eventsById));
    }

    return InvestigationBundle(
      findings: List.unmodifiable(selected),
      missingFindingIds: List.unmodifiable(missingFindingIds),
      ambiguousFindingIds: List.unmodifiable(ambiguousFindingIds),
      latestEventObservedAt: _latestObservedAt(eventsById),
    );
  }

  InvestigationFinding _investigateFinding(
    Finding finding,
    Map<String, List<MobileEvent>> eventsById,
  ) {
    final resolved = <ResolvedEvidenceReference>[];
    final missingNotes = <String>[];
    final anchorEvents = <MobileEvent>[];

    for (final reference in finding.evidenceReferences) {
      final matches = eventsById[reference.eventId] ?? const <MobileEvent>[];
      if (matches.isEmpty) {
        final item = ResolvedEvidenceReference(
          reference: reference,
          referenceStatus: EvidenceReferenceStatus.eventMissing,
          storedReferenceValue: reference.value,
          value: null,
        );
        resolved.add(item);
        missingNotes.add('Missing event "${reference.eventId}" for evidence path "${reference.path}".');
        continue;
      }
      if (matches.length > 1) {
        resolved.add(ResolvedEvidenceReference(
          reference: reference,
          referenceStatus: EvidenceReferenceStatus.eventAmbiguous,
          storedReferenceValue: reference.value,
          value: null,
        ));
        missingNotes.add('Event id "${reference.eventId}" is ambiguous because multiple local events share it.');
        continue;
      }

      final event = matches.single;
      if (event.capabilityId != reference.capabilityId) {
        resolved.add(ResolvedEvidenceReference(
          reference: reference,
          referenceStatus: EvidenceReferenceStatus.capabilityMismatch,
          storedReferenceValue: reference.value,
          value: null,
        ));
        missingNotes.add(
          'Event "${reference.eventId}" capability does not match referenced capability "${reference.capabilityId}".',
        );
        continue;
      }
      if (event.observedAt != reference.observedAt) {
        resolved.add(ResolvedEvidenceReference(
          reference: reference,
          referenceStatus: EvidenceReferenceStatus.timestampMismatch,
          storedReferenceValue: reference.value,
          value: null,
        ));
        missingNotes.add(
          'Event "${reference.eventId}" timestamp does not match the referenced observation time.',
        );
        continue;
      }
      anchorEvents.add(event);
      final actual = _readPath(event.evidence, reference.path);
      if (identical(actual, _missing)) {
        resolved.add(ResolvedEvidenceReference(
          reference: reference,
          referenceStatus: EvidenceReferenceStatus.pathMissing,
          storedReferenceValue: reference.value,
          value: null,
        ));
        missingNotes.add('Event "${reference.eventId}" has no evidence value at "${reference.path}".');
      } else {
        final status = _sameJsonValue(actual, reference.value)
            ? EvidenceReferenceStatus.matched
            : EvidenceReferenceStatus.valueChanged;
        resolved.add(ResolvedEvidenceReference(
          reference: reference,
          referenceStatus: status,
          storedReferenceValue: reference.value,
          value: actual,
        ));
        if (status == EvidenceReferenceStatus.valueChanged) {
          missingNotes.add('Stored value for "${reference.eventId}#${reference.path}" differs from the supplied event value.');
        }
      }
    }

    if (finding.evidenceReferences.isEmpty) {
      missingNotes.add(
        'Finding has no evidence references to verify against local events.',
      );
    }

    final related = _relatedEvents(finding, anchorEvents, eventsById);
    final hypothesis = InvestigationHypothesis(
      label: 'Hypothesis',
      statement:
          'The finding describes a locally observed condition that may be relevant to review; it does not establish compromise or causation.',
      isConclusion: false,
      limitations: List.unmodifiable(finding.limitations),
    );
    return InvestigationFinding(
      finding: finding,
      evidence: List.unmodifiable(resolved),
      missingReferenceNotes: List.unmodifiable(missingNotes),
      relatedEvents: List.unmodifiable(related),
      hypothesis: hypothesis,
    );
  }

  List<RelatedMobileEvent> _relatedEvents(
    Finding finding,
    List<MobileEvent> anchorEvents,
    Map<String, List<MobileEvent>> eventsById,
  ) {
    final anchorSubjects = <String>{};
    for (final event in anchorEvents) {
      anchorSubjects.addAll(_subjects(event.evidence));
    }
    if (anchorSubjects.isEmpty) return const [];

    final start = finding.firstObservedAt.subtract(relatedEventWindow);
    final end = finding.lastObservedAt.add(relatedEventWindow);
    final candidates = <RelatedMobileEvent>[];
    for (final entry in eventsById.entries) {
      if (entry.value.length != 1) continue;
      final event = entry.value.single;
      if (anchorEvents.any((anchor) => anchor.eventId == event.eventId)) continue;
      if (event.observedAt.isBefore(start) || event.observedAt.isAfter(end)) continue;
      final shared = _subjects(event.evidence).intersection(anchorSubjects).toList()
        ..sort();
      if (shared.isEmpty) continue;
      final relation = shared.first;
      candidates.add(RelatedMobileEvent(
        event: event,
        relationship:
            'Shares local subject "$relation" with referenced evidence and was observed within ${relatedEventWindow.inMinutes} minutes of the finding time range.',
        hypothesis:
            'Possible correlation only: temporal proximity and a matching subject do not establish a causal link.',
      ));
    }
    candidates.sort((left, right) {
      final time = left.event.observedAt.compareTo(right.event.observedAt);
      return time != 0 ? time : left.event.eventId.compareTo(right.event.eventId);
    });
    return List.unmodifiable(candidates);
  }
}

class InvestigationBundle {
  const InvestigationBundle({
    required this.findings,
    required this.missingFindingIds,
    required this.ambiguousFindingIds,
    required this.latestEventObservedAt,
  });

  final List<InvestigationFinding> findings;
  final List<String> missingFindingIds;
  final List<String> ambiguousFindingIds;

  /// Latest observed timestamp in the supplied local event set, or null if empty.
  final DateTime? latestEventObservedAt;
}

class InvestigationFinding {
  const InvestigationFinding({
    required this.finding,
    required this.evidence,
    required this.missingReferenceNotes,
    required this.relatedEvents,
    required this.hypothesis,
  });

  final Finding finding;
  final List<ResolvedEvidenceReference> evidence;
  final List<String> missingReferenceNotes;
  final List<RelatedMobileEvent> relatedEvents;
  final InvestigationHypothesis hypothesis;
}

enum EvidenceReferenceStatus {
  matched,
  valueChanged,
  capabilityMismatch,
  eventMissing,
  eventAmbiguous,
  timestampMismatch,
  pathMissing,
}

class ResolvedEvidenceReference {
  const ResolvedEvidenceReference({
    required this.reference,
    required this.referenceStatus,
    required this.storedReferenceValue,
    required this.value,
  });

  final EvidenceReference reference;
  final EvidenceReferenceStatus referenceStatus;

  /// Exact value recorded on the finding's evidence reference.
  final Object? storedReferenceValue;

  /// Exact value read from the supplied event, when the event and path exist.
  final Object? value;
}

class RelatedMobileEvent {
  const RelatedMobileEvent({
    required this.event,
    required this.relationship,
    required this.hypothesis,
  });

  final MobileEvent event;

  /// Deterministic same-subject and time-window relationship explanation.
  final String relationship;
  final String hypothesis;
}

class InvestigationHypothesis {
  const InvestigationHypothesis({
    required this.label,
    required this.statement,
    required this.isConclusion,
    required this.limitations,
  });

  final String label;
  final String statement;
  final bool isConclusion;
  final List<String> limitations;
}

const _subjectKeys = <String>{
  'packageName',
  'packageId',
  'appPackage',
  'component',
  'componentName',
  'uid',
  'domain',
  'host',
  'subjectId',
};

Set<String> _subjects(Object? value, [String path = r'$']) {
  final result = <String>{};
  if (value is Map) {
    for (final entry in value.entries) {
      if (entry.key is! String) continue;
      final key = entry.key as String;
      final childPath = '$path.$key';
      final child = entry.value;
      if (_subjectKeys.contains(key) && child is String && child.trim().isNotEmpty) {
        result.add('$key=${child.trim()}');
      } else if (_subjectKeys.contains(key) && child is num) {
        result.add('$key=$child');
      }
      result.addAll(_subjects(child, childPath));
    }
  } else if (value is List) {
    for (var index = 0; index < value.length; index++) {
      result.addAll(_subjects(value[index], '$path[$index]'));
    }
  }
  return result;
}

const Object _missing = Object();

Object? _readPath(Map<String, Object?> evidence, String path) {
  Object? value = evidence;
  for (final segment in path.split('.')) {
    if (value is Map) {
      if (!value.containsKey(segment)) return _missing;
      value = value[segment];
      continue;
    }
    if (value is List) {
      final index = int.tryParse(segment);
      if (index == null || index < 0 || index >= value.length) return _missing;
      value = value[index];
      continue;
    }
    return _missing;
  }
  return value;
}

bool _sameJsonValue(Object? left, Object? right) {
  if (identical(left, right)) return true;
  if (left is num && right is num) return left == right;
  if (left is List && right is List) {
    if (left.length != right.length) return false;
    for (var index = 0; index < left.length; index++) {
      if (!_sameJsonValue(left[index], right[index])) return false;
    }
    return true;
  }
  if (left is Map && right is Map) {
    if (left.length != right.length) return false;
    for (final key in left.keys) {
      if (!right.containsKey(key) ||
          !_sameJsonValue(left[key], right[key])) {
        return false;
      }
    }
    return true;
  }
  return left == right;
}

DateTime? _latestObservedAt(Map<String, List<MobileEvent>> eventsById) {
  DateTime? latest;
  for (final events in eventsById.values) {
    for (final event in events) {
      if (latest == null || event.observedAt.isAfter(latest)) {
        latest = event.observedAt;
      }
    }
  }
  return latest;
}
