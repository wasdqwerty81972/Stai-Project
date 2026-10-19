import 'package:flutter_test/flutter_test.dart';
import 'package:svs_cyber_mobile/core/detection/detection_models.dart';
import 'package:svs_cyber_mobile/core/detection/local_detection_engine.dart';

void main() {
  group('MobileEvent persistence contract', () {
    test('round-trips the native v1 event channel map', () {
      final event = MobileEvent.fromJson(_event().toJson());

      expect(event.contractVersion, 1);
      expect(event.capabilityId, 'AND-008');
      expect(event.evidence['secureLockConfigured'], isFalse);
      expect(event.observedAt, DateTime.utc(2026, 10, 12));
    });

    test('parses the literal native Kotlin v1 channel payload', () {
      const nativePayload = '''
      {"contractVersion":1,"eventId":"native-event-008","capabilityId":"AND-008","eventType":"observation","occurredAtEpochMs":1791763200000,"observedAtEpochMs":1791763200000,"availability":"available","operation":"completed","freshness":"fresh","continuous":false,"evidence":{"secureLockConfigured":false}}
      ''';

      final event = MobileEvent.fromJsonString(nativePayload);

      expect(event.eventId, 'native-event-008');
      expect(event.continuous, isFalse);
      expect(event.evidence, {'secureLockConfigured': false});
      expect(event.toJson().keys, containsAll([
        'contractVersion',
        'occurredAtEpochMs',
        'observedAtEpochMs',
        'continuous',
        'evidence',
      ]));
    });

    test('rejects a missing or malformed continuous flag', () {
      final missing = Map<String, Object?>.from(_event().toJson())
        ..remove('continuous');
      final malformed = Map<String, Object?>.from(_event().toJson())
        ..['continuous'] = 'false';

      expect(() => MobileEvent.fromJson(missing), throwsFormatException);
      expect(() => MobileEvent.fromJson(malformed), throwsFormatException);
    });
  });

  group('LocalDetectionEngine', () {
    final engine = LocalDetectionEngine(rules: builtInPostureRules);

    test('persists the versioned rule contract', () {
      final rule = DetectionRule.fromJson(builtInPostureRules.single.toJson());

      expect(rule.id, 'mobile.posture.secure_lock_required');
      expect(rule.version, '1.0.0');
      expect(rule.expectedValue, isFalse);
      expect(rule.confidence, 1.0);
    });

    test('creates an evidence-backed posture finding from a supported observation', () {
      final findings = engine.evaluate(
        events: [_event()],
        asOf: DateTime.utc(2026, 10, 12),
      );

      expect(findings, hasLength(1));
      expect(findings.single.ruleId, 'mobile.posture.secure_lock_required');
      expect(findings.single.ruleVersion, '1.0.0');
      expect(findings.single.severity, FindingSeverity.medium);
      expect(findings.single.confidence, 1.0);
      expect(findings.single.evidenceReferences.single.path, 'secureLockConfigured');
      expect(findings.single.limitations, isNotEmpty);
      expect(findings.single.title, contains('screen lock'));
    });

    test('does not infer a finding from unavailable or failed evidence', () {
      final events = [
        _event(availability: 'unsupported'),
        _event(eventId: 'failed', operation: 'failed'),
        _event(eventId: 'stale', freshness: 'stale'),
        _event(eventId: 'missing_value', evidence: const {}),
      ];

      expect(
        engine.evaluate(events: events, asOf: DateTime.utc(2026, 10, 12)),
        isEmpty,
      );
    });

    test('leaves posture unchanged when secure lock is configured', () {
      expect(
        engine.evaluate(
          events: [_event(evidence: const {'secureLockConfigured': true})],
          asOf: DateTime.utc(2026, 10, 12),
        ),
        isEmpty,
      );
    });

    test('coalesces repeated evidence and suppresses duplicate event IDs', () {
      final first = _event();
      final later = _event(
        eventId: 'later',
        occurredAt: DateTime.utc(2026, 10, 13),
        observedAt: DateTime.utc(2026, 10, 13),
      );

      final findings = engine.evaluate(
        events: [first, first, later],
        asOf: DateTime.utc(2026, 10, 13),
      );

      expect(findings, hasLength(1));
      expect(findings.single.firstObservedAt, first.observedAt);
      expect(findings.single.lastObservedAt, later.observedAt);
      expect(findings.single.evidenceReferences, hasLength(2));
    });

    test('updates an existing persisted finding instead of creating a duplicate', () {
      final initial = engine
          .evaluate(events: [_event()], asOf: DateTime.utc(2026, 10, 12))
          .single;
      final next = _event(
        eventId: 'next',
        occurredAt: DateTime.utc(2026, 10, 13),
        observedAt: DateTime.utc(2026, 10, 13),
      );

      final findings = engine.evaluate(
        events: [next],
        existingFindings: [initial],
        asOf: DateTime.utc(2026, 10, 13),
      );

      expect(findings, hasLength(1));
      expect(findings.single.id, initial.id);
      expect(findings.single.lastObservedAt, next.observedAt);
      expect(findings.single.evidenceReferences, hasLength(2));
      expect(Finding.fromJson(findings.single.toJson()).id, initial.id);
    });

    test('resolves on a later secure-lock observation and reopens on regression', () {
      final initial = engine
          .evaluate(events: [_event()], asOf: DateTime.utc(2026, 10, 12))
          .single;
      final previouslyReviewed = Finding.fromJson({
        ...initial.toJson(),
        'status': FindingStatus.acknowledged.name,
        'reviewHistory': [
          {
            'action': 'acknowledged',
            'at': DateTime.utc(2026, 10, 12, 1).toIso8601String(),
            'note': 'Reviewed by user',
          },
        ],
      });
      final secured = _event(
        eventId: 'secured',
        occurredAt: DateTime.utc(2026, 10, 13),
        observedAt: DateTime.utc(2026, 10, 13),
        evidence: const {'secureLockConfigured': true},
      );

      final resolved = engine.evaluate(
        events: [secured],
        existingFindings: [previouslyReviewed],
        asOf: secured.observedAt,
      ).single;

      expect(resolved.id, initial.id);
      expect(resolved.status, FindingStatus.resolved);
      expect(resolved.resolvedAt, secured.observedAt);
      expect(resolved.evidenceReferences, hasLength(2));
      expect(resolved.reviewHistory, hasLength(2));
      expect(resolved.reviewHistory.first.action, 'acknowledged');
      expect(resolved.reviewHistory.last.action, 'resolved_by_posture_observation');
      expect(resolved.reviewHistory.last.at, secured.observedAt);
      expect(resolved.reviewHistory.last.note, contains(secured.eventId));

      final regressed = _event(
        eventId: 'regressed',
        occurredAt: DateTime.utc(2026, 10, 14),
        observedAt: DateTime.utc(2026, 10, 14),
      );
      final reopened = engine.evaluate(
        events: [regressed],
        existingFindings: [resolved],
        asOf: regressed.observedAt,
      ).single;

      expect(reopened.id, initial.id);
      expect(reopened.status, FindingStatus.open);
      expect(reopened.resolvedAt, isNull);
      expect(reopened.lastObservedAt, regressed.observedAt);
      expect(reopened.evidenceReferences, hasLength(3));
      expect(reopened.reviewHistory, hasLength(3));
      expect(reopened.reviewHistory.last.action, 'reopened_by_posture_observation');
      expect(reopened.reviewHistory.last.at, regressed.observedAt);
      expect(reopened.reviewHistory.last.note, contains(regressed.eventId));
    });

    test('does not change a suppressed finding status on posture observations', () {
      final initial = engine
          .evaluate(events: [_event()], asOf: DateTime.utc(2026, 10, 12))
          .single;
      final suppressed = Finding.fromJson({
        ...initial.toJson(),
        'status': FindingStatus.suppressed.name,
      });
      final secured = _event(
        eventId: 'secured-while-suppressed',
        occurredAt: DateTime.utc(2026, 10, 13),
        observedAt: DateTime.utc(2026, 10, 13),
        evidence: const {'secureLockConfigured': true},
      );

      final afterResolution = engine.evaluate(
        events: [secured],
        existingFindings: [suppressed],
        asOf: secured.observedAt,
      ).single;
      final regressed = _event(
        eventId: 'regressed-while-suppressed',
        occurredAt: DateTime.utc(2026, 10, 14),
        observedAt: DateTime.utc(2026, 10, 14),
      );
      final afterRegression = engine.evaluate(
        events: [regressed],
        existingFindings: [afterResolution],
        asOf: regressed.observedAt,
      ).single;

      expect(afterResolution.status, FindingStatus.suppressed);
      expect(afterRegression.status, FindingStatus.suppressed);
      expect(afterResolution.reviewHistory, isEmpty);
      expect(afterRegression.reviewHistory, isEmpty);
    });

    test('does not evaluate an observation after its freshness window expires', () {
      final oldEvent = _event(
        occurredAt: DateTime.utc(2026, 10, 12),
        observedAt: DateTime.utc(2026, 10, 12),
      );

      expect(
        engine.evaluate(
          events: [oldEvent],
          asOf: DateTime.utc(2026, 10, 14),
        ),
        isEmpty,
      );
    });
  });
}

MobileEvent _event({
  String eventId = 'baseline-lock',
  String availability = 'available',
  String operation = 'completed',
  String freshness = 'fresh',
  DateTime? occurredAt,
  DateTime? observedAt,
  Map<String, Object?> evidence = const {'secureLockConfigured': false},
}) => MobileEvent(
      contractVersion: 1,
      eventId: eventId,
      capabilityId: 'AND-008',
      eventType: 'observation',
      occurredAt: occurredAt ?? DateTime.utc(2026, 10, 12),
      observedAt: observedAt ?? DateTime.utc(2026, 10, 12),
      availability: availability,
      operation: operation,
      freshness: freshness,
      continuous: false,
      evidence: evidence,
    );
