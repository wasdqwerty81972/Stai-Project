import 'dart:convert';

import 'package:flutter/foundation.dart';

import '../apps/application_permission_detection.dart';
import '../apps/visible_application.dart';
import '../detection/detection_models.dart';
import '../detection/local_detection_engine.dart';
import '../files/selected_file_inspection.dart';
import 'mobile_platform_client.dart';

/// Coordinates explicitly requested, point-in-time platform observations.
///
/// Construction is inert: it never starts an event subscription or invokes a
/// platform method. Findings stay in memory for this session; native journal
/// events can be restored on demand.
class MobileSecuritySession extends ChangeNotifier {
  MobileSecuritySession({
    required MobilePlatformClient platform,
    required LocalDetectionEngine detectionEngine,
    DateTime Function()? clock,
  })  : _platform = platform,
        _detectionEngine = detectionEngine,
        _clock = clock ?? DateTime.now;

  final MobilePlatformClient _platform;
  final LocalDetectionEngine _detectionEngine;
  final DateTime Function() _clock;
  static const _permissionCombinationDetector =
      ApplicationPermissionCombinationDetector();

  static const evidenceWindow = Duration(hours: 24);

  List<MobileEvent> _events = const [];
  List<Finding> _findings = const [];
  List<VisibleApplication> _visibleApplications = const [];
  List<MobileEvent> _visibleApplicationSourceEvents = const [];
  DateTime? _visibleApplicationsObservedAt;
  bool _visibleApplicationsTruncated = false;
  bool _visibleApplicationsPermissionsTruncated = false;
  bool _visibleApplicationsVisibilityMayBeFiltered = true;
  MobileJournalStatus? _journalStatus;
  String? _lastError;
  String? _visibleApplicationsError;
  SelectedFileInspection? _selectedFileInspection;
  bool? _selectedFileInspectionWasApk;
  bool _inspectingSelectedFile = false;
  String? _selectedFileInspectionError;

  List<MobileEvent> get events => _events;
  List<Finding> get findings => _findings;
  List<VisibleApplication> get visibleApplications => _visibleApplications;
  DateTime? get visibleApplicationsObservedAt => _visibleApplicationsObservedAt;
  bool get visibleApplicationsTruncated => _visibleApplicationsTruncated;
  bool get visibleApplicationsPermissionsTruncated =>
      _visibleApplicationsPermissionsTruncated;
  bool get visibleApplicationsVisibilityMayBeFiltered =>
      _visibleApplicationsVisibilityMayBeFiltered;
  MobileJournalStatus? get journalStatus => _journalStatus;
  String? get lastError => _lastError;
  String? get visibleApplicationsError => _visibleApplicationsError;
  SelectedFileInspection? get selectedFileInspection => _selectedFileInspection;
  bool? get selectedFileInspectionWasApk => _selectedFileInspectionWasApk;
  bool get inspectingSelectedFile => _inspectingSelectedFile;
  String? get selectedFileInspectionError => _selectedFileInspectionError;

  /// Opens Android's system document picker only after an explicit user action.
  /// Cancellation preserves the previous in-memory result.
  Future<void> selectAndInspectFile({required bool apk}) async {
    if (_inspectingSelectedFile) return;
    _inspectingSelectedFile = true;
    _selectedFileInspectionError = null;
    notifyListeners();
    try {
      final result = await _platform.selectAndInspectFile(apk: apk);
      if (result != null) {
        _selectedFileInspection = result;
        _selectedFileInspectionWasApk = apk;
      }
    } catch (error) {
      _selectedFileInspectionError = _safeError(error);
    } finally {
      _inspectingSelectedFile = false;
      notifyListeners();
    }
  }

  /// Collects one baseline after an explicit caller request.
  Future<void> collectBaseline() async {
    _lastError = null;
    notifyListeners();
    try {
      final baseline = await _platform.collectDeviceBaseline();
      if (baseline.contractVersion != mobilePlatformContractVersion ||
          baseline.continuousMonitoring) {
        throw const FormatException('Baseline is not a supported point-in-time v1 observation.');
      }
      final now = _clock().toUtc();
      final accepted = _withinWindow(baseline.events, now);
      _commitEvents(accepted, now);
    } catch (error) {
      _lastError = _safeError(error);
    }
    notifyListeners();
  }

  /// Collects launchable application metadata only after an explicit request.
  Future<void> collectVisibleApplications({int limit = 100}) async {
    _lastError = null;
    _visibleApplicationsError = null;
    notifyListeners();
    try {
      final inventory = await _platform.collectVisibleApplicationInventory(limit: limit);
      final now = _clock().toUtc();
      if (inventory.contractVersion != mobilePlatformContractVersion ||
          inventory.scope != VisibleApplicationCollection.supportedScope ||
          inventory.observedAt.isAfter(now) ||
          inventory.observedAt.isBefore(now.subtract(evidenceWindow))) {
        throw const FormatException('Visible application inventory is outside the supported v1 scope.');
      }
      final accepted = _withinWindow(inventory.events, now);
      if (accepted.length != inventory.events.length ||
          !accepted.any((event) => event.capabilityId == 'AND-012')) {
        throw const FormatException('Visible application inventory is missing recent package evidence.');
      }
      _visibleApplications = inventory.applications;
      _visibleApplicationSourceEvents =
          List<MobileEvent>.unmodifiable(inventory.events);
      _visibleApplicationsObservedAt = inventory.observedAt;
      _visibleApplicationsTruncated = inventory.truncated;
      _visibleApplicationsPermissionsTruncated = inventory.permissionsTruncated;
      _visibleApplicationsVisibilityMayBeFiltered = inventory.visibilityMayBeFiltered;
      _commitEvents(accepted, now, reconcileApplicationSnapshot: true);
    } catch (error) {
      _lastError = _safeError(error);
      _visibleApplicationsError = _lastError;
    }
    notifyListeners();
  }

  /// Restores recent events from the native journal after an explicit request.
  Future<void> restoreJournal() async {
    _lastError = null;
    notifyListeners();
    try {
      final status = await _platform.getJournalStatus();
      _journalStatus = status;
      if (status.contractVersion != mobilePlatformContractVersion) {
        throw const FormatException('Journal status uses an unsupported contract version.');
      }
      if (!status.available) {
        throw const MobilePlatformException(
          'journal_unavailable',
          'The local event journal is unavailable.',
        );
      }

      final now = _clock().toUtc();
      final read = await _platform.readEvents(
        after: now.subtract(evidenceWindow),
        limit: 500,
      );
      final accepted = _withinWindow(read, now);
      _commitEvents(accepted, now);
      _restoreVisibleApplications(accepted);
      _refreshApplicationPermissionFindings(now, reconcileSnapshot: true);
    } catch (error) {
      _lastError = _safeError(error);
    }
    notifyListeners();
  }

  void _restoreVisibleApplications(List<MobileEvent> recentEvents) {
    final candidates = recentEvents
        .where((event) => event.capabilityId == 'AND-012')
        .toList()
      ..sort((left, right) => right.observedAt.compareTo(left.observedAt));
    if (candidates.isEmpty) return;
    final latest = candidates.first;
    final evidence = latest.evidence;
    if (evidence['scope'] != VisibleApplicationCollection.supportedScope ||
        evidence['inventorySchemaVersion'] != 1 ||
        evidence['applications'] is! List<Object?>) {
      return;
    }
    try {
      final rawApps = evidence['applications']! as List<Object?>;
      if (rawApps.length > VisibleApplicationCollection.maxApplications ||
          evidence['truncated'] is! bool ||
          evidence['permissionsTruncated'] is! bool ||
          evidence['visibilityMayBeFiltered'] is! bool) {
        throw const FormatException('Invalid application snapshot metadata.');
      }
      final apps = rawApps.map((value) {
        if (value is! Map<Object?, Object?>) {
          throw const FormatException('Invalid application snapshot event.');
        }
        return VisibleApplication.fromMap(_stringMap(value));
      }).toList(growable: false);
      if (apps.map((app) => app.packageName).toSet().length != apps.length) {
        throw const FormatException('Application snapshot contains duplicate packages.');
      }
      _visibleApplications = List<VisibleApplication>.unmodifiable(apps);
      _visibleApplicationSourceEvents = List<MobileEvent>.unmodifiable([latest]);
      _visibleApplicationsObservedAt = latest.observedAt;
      _visibleApplicationsTruncated = evidence['truncated']! as bool;
      _visibleApplicationsPermissionsTruncated =
          evidence['permissionsTruncated']! as bool;
      _visibleApplicationsVisibilityMayBeFiltered =
          evidence['visibilityMayBeFiltered']! as bool;
    } on FormatException {
      // Keep the prior in-memory snapshot if an older or malformed journal entry
      // does not contain a recoverable application list.
    }
  }

  List<MobileEvent> _withinWindow(Iterable<MobileEvent> candidates, DateTime now) {
    final cutoff = now.subtract(evidenceWindow);
    final byId = <String, MobileEvent>{};
    for (final event in candidates) {
      if (event.contractVersion != mobilePlatformContractVersion || event.continuous) {
        throw const FormatException('Native event is not a supported point-in-time v1 observation.');
      }
      if (event.observedAt.isBefore(cutoff) || event.observedAt.isAfter(now)) continue;
      final previous = byId[event.eventId];
      if (previous != null &&
          jsonEncode(previous.toJson()) != jsonEncode(event.toJson())) {
        throw const FormatException('Native events contain a conflicting duplicate ID.');
      }
      byId[event.eventId] = event;
    }
    final result = byId.values.toList()
      ..sort((left, right) {
        final timeOrder = left.observedAt.compareTo(right.observedAt);
        return timeOrder != 0 ? timeOrder : left.eventId.compareTo(right.eventId);
      });
    return List<MobileEvent>.unmodifiable(result);
  }

  void _commitEvents(
    List<MobileEvent> accepted,
    DateTime now, {
    bool reconcileApplicationSnapshot = false,
  }) {
    final merged = <String, MobileEvent>{
      for (final event in _events) event.eventId: event,
      for (final event in accepted) event.eventId: event,
    };
    final recent = _withinWindow(merged.values, now);
    final updatedFindings = _detectionEngine.evaluate(
      events: recent,
      existingFindings: _findings,
      asOf: now,
    );
    _events = recent;
    _findings = List<Finding>.unmodifiable(updatedFindings);
    _refreshApplicationPermissionFindings(
      now,
      reconcileSnapshot: reconcileApplicationSnapshot,
    );
  }

  void _refreshApplicationPermissionFindings(
    DateTime now, {
    bool reconcileSnapshot = false,
  }) {
    final snapshotObservedAt = _visibleApplicationsObservedAt;
    if (snapshotObservedAt == null ||
        snapshotObservedAt.isAfter(now) ||
        snapshotObservedAt.isBefore(now.subtract(evidenceWindow))) {
      return;
    }
    final collection = VisibleApplicationCollection(
      contractVersion: mobilePlatformContractVersion,
      observedAt: _visibleApplicationsObservedAt!,
      scope: VisibleApplicationCollection.supportedScope,
      visibilityMayBeFiltered: _visibleApplicationsVisibilityMayBeFiltered,
      truncated: _visibleApplicationsTruncated,
      permissionsTruncated: _visibleApplicationsPermissionsTruncated,
      applications: _visibleApplications,
      events: _visibleApplicationSourceEvents,
    );
    final detections = _permissionCombinationDetector.detect(collection);
    final detectionKeys = <String>{
      for (final detection in detections)
        'mobile.application_permission.${detection.ruleId}::${detection.packageName}',
    };
    final byKey = <String, Finding>{
      for (final finding in _findings) finding.deduplicationKey: finding,
    };
    final packageEventIsComplete = _visibleApplicationSourceEvents.any((event) =>
        event.capabilityId == 'AND-012' &&
        event.observedAt == _visibleApplicationsObservedAt &&
        event.operation == 'completed');
    if (reconcileSnapshot &&
        packageEventIsComplete &&
        !_visibleApplicationsPermissionsTruncated) {
      final visiblePackages =
          _visibleApplications.map((application) => application.packageName).toSet();
      for (final entry in byKey.entries.toList()) {
        final previous = entry.value;
        if (!previous.ruleId.startsWith('APP-PERM-') ||
            detectionKeys.contains(entry.key) ||
            !visiblePackages.contains(previous.affectedComponent) ||
            !_visibleApplicationsObservedAt!.isAfter(previous.lastObservedAt) ||
            previous.status == FindingStatus.suppressed ||
            previous.status == FindingStatus.resolved) {
          continue;
        }
        byKey[entry.key] = Finding(
          id: previous.id,
          deduplicationKey: previous.deduplicationKey,
          ruleId: previous.ruleId,
          ruleVersion: previous.ruleVersion,
          capabilityIds: previous.capabilityIds,
          title: previous.title,
          createdAt: previous.createdAt,
          firstObservedAt: previous.firstObservedAt,
          lastObservedAt: previous.lastObservedAt,
          resolvedAt: _visibleApplicationsObservedAt,
          severity: previous.severity,
          confidence: previous.confidence,
          evidenceReferences: previous.evidenceReferences,
          explanation: previous.explanation,
          affectedComponent: previous.affectedComponent,
          limitations: previous.limitations,
          recommendedAction: previous.recommendedAction,
          status: FindingStatus.resolved,
          reviewHistory: [
            ...previous.reviewHistory,
            FindingReviewEntry(
              action: 'resolved_by_permission_snapshot',
              at: _visibleApplicationsObservedAt!,
              note: 'A complete visible-app snapshot no longer matched this permission rule.',
            ),
          ],
        );
      }
    }
    for (final detection in detections) {
      final deduplicationKey =
          'mobile.application_permission.${detection.ruleId}::${detection.packageName}';
      final previous = byKey[deduplicationKey];
      final reference = detection.evidenceReferences.single;
      final limitations = <String>[
        'This rule describes declared permissions only; it does not prove that permissions are granted or used.',
        'Android package visibility can filter the inventory, so this is not a complete device-wide application list.',
        if (detection.caveats.contains(
          ApplicationPermissionDetectionCaveat.applicationListTruncated,
        ))
          'The application inventory was truncated.',
        if (detection.caveats.contains(
          ApplicationPermissionDetectionCaveat.permissionListTruncated,
        ))
          'One or more permission lists were truncated.',
        if (detection.caveats.contains(
          ApplicationPermissionDetectionCaveat.inventoryCollectionDegraded,
        ))
          'The Android inventory operation was degraded; some visible package details could not be collected.',
      ];
      final shouldReopen = previous?.status == FindingStatus.resolved &&
          reference.observedAt.isAfter(previous!.lastObservedAt);
      final nextStatus = switch (previous?.status) {
        FindingStatus.suppressed => FindingStatus.suppressed,
        FindingStatus.acknowledged => FindingStatus.acknowledged,
        FindingStatus.resolved when !shouldReopen => FindingStatus.resolved,
        _ => FindingStatus.open,
      };
      byKey[deduplicationKey] = Finding(
        id: 'finding/${Uri.encodeComponent(detection.ruleId)}/${Uri.encodeComponent(detection.packageName)}',
        deduplicationKey: deduplicationKey,
        ruleId: detection.ruleId,
        ruleVersion: detection.ruleVersion,
        capabilityIds: const ['AND-012'],
        title: '${detection.title}: ${detection.label}',
        createdAt: previous?.createdAt ?? reference.observedAt,
        firstObservedAt: previous?.firstObservedAt ?? reference.observedAt,
        lastObservedAt: reference.observedAt,
        resolvedAt: nextStatus == FindingStatus.resolved
            ? previous?.resolvedAt
            : null,
        severity: FindingSeverity.low,
        confidence: 0.5,
        evidenceReferences: [reference],
        explanation: detection.explanation,
        affectedComponent: detection.packageName,
        limitations: List.unmodifiable(limitations),
        recommendedAction: 'Review the app’s expected use and declared permission needs.',
        status: nextStatus,
        reviewHistory: [
          if (previous != null) ...previous.reviewHistory,
          if (shouldReopen)
            FindingReviewEntry(
              action: 'reopened_by_permission_observation',
              at: reference.observedAt,
              note: 'The permission combination appeared again in a later package snapshot.',
            ),
        ],
      );
    }
    _findings = List<Finding>.unmodifiable(byKey.values);
  }

  /// Records an explicit local review action for a finding.
  bool reviewFinding(
    String findingId, {
    required FindingStatus status,
    String? note,
  }) {
    final index = _findings.indexWhere((finding) => finding.id == findingId);
    if (index < 0) return false;
    final previous = _findings[index];
    if (previous.status == status) return true;
    final now = _clock().toUtc();
    final updated = Finding(
      id: previous.id,
      deduplicationKey: previous.deduplicationKey,
      ruleId: previous.ruleId,
      ruleVersion: previous.ruleVersion,
      capabilityIds: previous.capabilityIds,
      title: previous.title,
      createdAt: previous.createdAt,
      firstObservedAt: previous.firstObservedAt,
      lastObservedAt: previous.lastObservedAt,
      resolvedAt: status == FindingStatus.resolved ? now : null,
      severity: previous.severity,
      confidence: previous.confidence,
      evidenceReferences: previous.evidenceReferences,
      explanation: previous.explanation,
      affectedComponent: previous.affectedComponent,
      limitations: previous.limitations,
      recommendedAction: previous.recommendedAction,
      status: status,
      reviewHistory: [
        ...previous.reviewHistory,
        FindingReviewEntry(action: status.name, at: now, note: note),
      ],
    );
    final findings = [..._findings]..[index] = updated;
    _findings = List<Finding>.unmodifiable(findings);
    notifyListeners();
    return true;
  }

  String _safeError(Object error) {
    if (error is MobilePlatformException) return error.message;
    if (error is FormatException) return 'The Android platform returned invalid data.';
    return 'The requested security operation could not be completed.';
  }
}

Map<String, Object?> _stringMap(Map<Object?, Object?> map) {
  final result = <String, Object?>{};
  for (final entry in map.entries) {
    if (entry.key is! String) {
      throw const FormatException('Application snapshot has a non-string key.');
    }
    result[entry.key! as String] = entry.value;
  }
  return result;
}
