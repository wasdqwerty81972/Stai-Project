import 'package:flutter_test/flutter_test.dart';
import 'package:svs_cyber_mobile/core/detection/detection_models.dart';
import 'package:svs_cyber_mobile/core/detection/local_finding_investigator.dart';

void main() {
  group('LocalFindingInvestigator', () {
    test('preserves exact referenced values and notes missing references', () {
      final finding = _finding(
        evidenceReferences: [
          _reference(eventId: 'event-1', path: 'app.packageName', value: 'com.example.app'),
          _reference(eventId: 'gone-event', path: 'flag', value: true),
          _reference(eventId: 'event-1', path: 'notPresent', value: null),
        ],
      );
      final bundle = const LocalFindingInvestigator().investigate(
        selectedFindingIds: const ['finding-1'],
        findings: [finding],
        events: [_event('event-1', {'app': {'packageName': 'com.example.app'}})],
      );

      final result = bundle.findings.single;
      expect(result.evidence.first.value, 'com.example.app');
      expect(result.evidence.first.referenceStatus, EvidenceReferenceStatus.matched);
      expect(result.evidence[1].referenceStatus, EvidenceReferenceStatus.eventMissing);
      expect(result.evidence[1].storedReferenceValue, isTrue);
      expect(result.evidence.last.referenceStatus, EvidenceReferenceStatus.pathMissing);
      expect(result.missingReferenceNotes, hasLength(2));
    });

    test('compares structured JSON values by content', () {
      final finding = _finding(
        evidenceReferences: [
          _reference(
            eventId: 'event-1',
            path: 'snapshot',
            value: {'items': [1, 'two']},
          ),
        ],
      );
      final bundle = const LocalFindingInvestigator().investigate(
        selectedFindingIds: const ['finding-1'],
        findings: [finding],
        events: [_event('event-1', {'snapshot': {'items': [1, 'two']}})],
      );

      expect(bundle.findings.single.evidence.single.referenceStatus,
          EvidenceReferenceStatus.matched);
    });

    test('resolves list-index evidence paths from an application snapshot', () {
      final permissions = [
        'android.permission.READ_SMS',
        'android.permission.SEND_SMS',
      ];
      final finding = _finding(
        evidenceReferences: [
          _reference(
            eventId: 'event-1',
            path: 'applications.0.requestedPermissions',
            value: permissions,
          ),
        ],
      );
      final bundle = const LocalFindingInvestigator().investigate(
        selectedFindingIds: const ['finding-1'],
        findings: [finding],
        events: [
          _event('event-1', {
            'applications': [
              {'requestedPermissions': permissions},
            ],
          }),
        ],
      );

      expect(bundle.findings.single.evidence.single.referenceStatus,
          EvidenceReferenceStatus.matched);
    });

    test('flags an event timestamp that differs from its evidence reference', () {
      final finding = _finding(
        evidenceReferences: [
          _reference(eventId: 'event-1', path: 'flag', value: true),
        ],
      );
      final bundle = const LocalFindingInvestigator().investigate(
        selectedFindingIds: const ['finding-1'],
        findings: [finding],
        events: [
          _event('event-1', {'flag': true}, at: DateTime.utc(2026, 10, 13, 12, 1)),
        ],
      );

      expect(bundle.findings.single.evidence.single.referenceStatus,
          EvidenceReferenceStatus.timestampMismatch);
    });

    test('includes related events only when same subject and within the time window', () {
      final finding = _finding(
        evidenceReferences: [
          _reference(eventId: 'source', path: 'packageName', value: 'com.example.app'),
        ],
      );
      final bundle = const LocalFindingInvestigator().investigate(
        selectedFindingIds: const ['finding-1'],
        findings: [finding],
        events: [
          _event('source', {'packageName': 'com.example.app'}),
          _event('same-near', {'packageName': 'com.example.app'}, at: DateTime.utc(2026, 10, 13, 12, 10)),
          _event('different-subject', {'packageName': 'com.other.app'}, at: DateTime.utc(2026, 10, 13, 12, 10)),
          _event('same-too-old', {'packageName': 'com.example.app'}, at: DateTime.utc(2026, 10, 13, 13)),
        ],
      );

      expect(bundle.findings.single.relatedEvents.map((item) => item.event.eventId), ['same-near']);
      expect(bundle.findings.single.relatedEvents.single.relationship, contains('packageName'));
    });

    test('labels hypotheses and unknown selected IDs without a verdict', () {
      final bundle = const LocalFindingInvestigator().investigate(
        selectedFindingIds: const ['finding-1', 'missing-finding'],
        findings: [_finding()],
        events: const [],
      );

      expect(bundle.findings.single.hypothesis.label, 'Hypothesis');
      expect(bundle.findings.single.hypothesis.isConclusion, isFalse);
      expect(bundle.missingFindingIds, ['missing-finding']);
      expect(bundle.findings.single.missingReferenceNotes, isNotEmpty);
    });
  });
}

MobileEvent _event(String id, Map<String, Object?> evidence, {DateTime? at}) {
  final time = at ?? DateTime.utc(2026, 10, 13, 12);
  return MobileEvent(
    contractVersion: 1,
    eventId: id,
    capabilityId: 'AND-017',
    eventType: 'observation',
    occurredAt: time,
    observedAt: time,
    availability: 'available',
    operation: 'completed',
    freshness: 'fresh',
    continuous: false,
    evidence: evidence,
  );
}

EvidenceReference _reference({
  required String eventId,
  required String path,
  required Object? value,
}) => EvidenceReference(
  eventId: eventId,
  capabilityId: 'AND-017',
  path: path,
  observedAt: DateTime.utc(2026, 10, 13, 12),
  value: value,
);

Finding _finding({List<EvidenceReference> evidenceReferences = const []}) => Finding(
  id: 'finding-1',
  deduplicationKey: 'app:com.example.app',
  ruleId: 'mobile.test.rule',
  ruleVersion: '1.0.0',
  capabilityIds: const ['AND-017'],
  title: 'APK metadata needs review',
  createdAt: DateTime.utc(2026, 10, 13, 12),
  firstObservedAt: DateTime.utc(2026, 10, 13, 12),
  lastObservedAt: DateTime.utc(2026, 10, 13, 12),
  severity: FindingSeverity.medium,
  confidence: 0.8,
  evidenceReferences: evidenceReferences,
  explanation: 'A local rule matched package metadata.',
  affectedComponent: 'com.example.app',
  limitations: const ['Static metadata does not establish behavior.'],
  recommendedAction: 'Review the selected artifact.',
  status: FindingStatus.open,
  reviewHistory: const [],
);
