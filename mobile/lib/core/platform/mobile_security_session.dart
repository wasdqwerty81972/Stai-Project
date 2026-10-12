import 'package:flutter/foundation.dart';

import '../apps/visible_application.dart';
import '../detection/detection_models.dart';
import '../detection/local_detection_engine.dart';
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

  static const evidenceWindow = Duration(hours: 24);

  List<MobileEvent> _events = const [];
  List<Finding> _findings = const [];
  List<VisibleApplication> _visibleApplications = const [];
  DateTime? _visibleApplicationsObservedAt;
  bool _visibleApplicationsTruncated = false;
  bool _visibleApplicationsVisibilityMayBeFiltered = true;
  MobileJournalStatus? _journalStatus;
  String? _lastError;

  List<MobileEvent> get events => _events;
  List<Finding> get findings => _findings;
  List<VisibleApplication> get visibleApplications => _visibleApplications;
  DateTime? get visibleApplicationsObservedAt => _visibleApplicationsObservedAt;
  bool get visibleApplicationsTruncated => _visibleApplicationsTruncated;
  bool get visibleApplicationsVisibilityMayBeFiltered =>
      _visibleApplicationsVisibilityMayBeFiltered;
  MobileJournalStatus? get journalStatus => _journalStatus;
  String? get lastError => _lastError;

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
      _commitEvents(accepted, now);
      _visibleApplications = inventory.applications;
      _visibleApplicationsObservedAt = inventory.observedAt;
      _visibleApplicationsTruncated = inventory.truncated;
      _visibleApplicationsVisibilityMayBeFiltered = inventory.visibilityMayBeFiltered;
    } catch (error) {
      _lastError = _safeError(error);
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
      final apps = rawApps.map((value) {
        if (value is! Map<Object?, Object?>) {
          throw const FormatException('Invalid application snapshot event.');
        }
        return VisibleApplication.fromMap(_stringMap(value));
      }).toList(growable: false);
      _visibleApplications = List<VisibleApplication>.unmodifiable(apps);
      _visibleApplicationsObservedAt = latest.observedAt;
      _visibleApplicationsTruncated = evidence['truncated'] == true;
      _visibleApplicationsVisibilityMayBeFiltered =
          evidence['visibilityMayBeFiltered'] != false;
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
      byId[event.eventId] = event;
    }
    final result = byId.values.toList()
      ..sort((left, right) {
        final timeOrder = left.observedAt.compareTo(right.observedAt);
        return timeOrder != 0 ? timeOrder : left.eventId.compareTo(right.eventId);
      });
    return List<MobileEvent>.unmodifiable(result);
  }

  void _commitEvents(List<MobileEvent> accepted, DateTime now) {
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
