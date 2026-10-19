import 'package:flutter/foundation.dart';

import '../detection/detection_models.dart';
import 'visible_application.dart';

enum ApplicationPermissionDetectionCaveat {
  packageVisibilityMayBeFiltered,
  applicationListTruncated,
  permissionListTruncated,
  inventoryCollectionDegraded,
}

/// A local review prompt derived from a specific permission combination.
/// It is evidence of declared permissions, not a maliciousness verdict.
@immutable
class ApplicationPermissionCombinationDetection {
  const ApplicationPermissionCombinationDetection({
    required this.ruleId,
    required this.ruleVersion,
    required this.packageName,
    required this.label,
    required this.title,
    required this.explanation,
    required this.requestedPermissions,
    required this.evidenceReferences,
    required this.caveats,
  });

  final String ruleId;
  final String ruleVersion;
  final String packageName;
  final String label;
  final String title;
  final String explanation;
  final List<String> requestedPermissions;
  final List<EvidenceReference> evidenceReferences;
  final List<ApplicationPermissionDetectionCaveat> caveats;

  /// Permission-combination rules do not classify applications as safe or
  /// malicious.
  String? get verdict => null;
}

/// Deterministic rules over user-collected, visible application inventory.
/// The detector requires a matching AND-012 source event for every result.
class ApplicationPermissionCombinationDetector {
  const ApplicationPermissionCombinationDetector();

  static const ruleVersion = '1';

  static const _rules = <_PermissionCombinationRule>[
    _PermissionCombinationRule(
      id: 'APP-PERM-SMS-READ-SEND',
      title: 'Review combined SMS access',
      explanation:
          'This app declares permissions to read and send SMS messages. Review whether both capabilities are needed for its expected use.',
      permissions: {
        'android.permission.READ_SMS',
        'android.permission.SEND_SMS',
      },
    ),
    _PermissionCombinationRule(
      id: 'APP-PERM-CONTACTS-LOCATION',
      title: 'Review contacts and location access',
      explanation:
          'This app declares access to contacts and location. Review whether collecting both types of information is expected.',
      permissions: {
        'android.permission.READ_CONTACTS',
        'android.permission.WRITE_CONTACTS',
        'android.permission.ACCESS_COARSE_LOCATION',
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.ACCESS_BACKGROUND_LOCATION',
      },
      minimumGroups: 2,
      groups: [
        {'android.permission.READ_CONTACTS', 'android.permission.WRITE_CONTACTS'},
        {
          'android.permission.ACCESS_COARSE_LOCATION',
          'android.permission.ACCESS_FINE_LOCATION',
          'android.permission.ACCESS_BACKGROUND_LOCATION',
        },
      ],
    ),
    _PermissionCombinationRule(
      id: 'APP-PERM-CAMERA-MIC-BACKGROUND-LOCATION',
      title: 'Review camera, microphone, and background location access',
      explanation:
          'This app declares camera, microphone, and background location permissions. Review whether these capabilities are needed together.',
      permissions: {
        'android.permission.CAMERA',
        'android.permission.RECORD_AUDIO',
        'android.permission.ACCESS_BACKGROUND_LOCATION',
      },
    ),
  ];

  List<ApplicationPermissionCombinationDetection> detect(
    VisibleApplicationCollection collection,
  ) {
    final caveats = _caveatsFor(collection);
    final results = <ApplicationPermissionCombinationDetection>[];

    for (var appIndex = 0;
        appIndex < collection.applications.length;
        appIndex++) {
      final application = collection.applications[appIndex];
      final declared = application.requestedPermissions.toSet();
      for (final rule in _rules) {
        final matched = _matchedPermissions(rule, declared);
        if (!_matches(rule, declared)) continue;

        final evidence = _sourceReference(
          collection.events,
          appIndex: appIndex,
          application: application,
          matchedPermissions: matched,
          observedAt: collection.observedAt,
          packageCount: collection.applications.length,
        );
        if (evidence == null) continue;

        results.add(ApplicationPermissionCombinationDetection(
          ruleId: rule.id,
          ruleVersion: ruleVersion,
          packageName: application.packageName,
          label: application.label,
          title: rule.title,
          explanation:
              '${rule.explanation} The review covers only packages visible to this app; Android may filter the list.',
          requestedPermissions: List<String>.unmodifiable(matched),
          evidenceReferences: List<EvidenceReference>.unmodifiable([evidence]),
          caveats: List<ApplicationPermissionDetectionCaveat>.unmodifiable(caveats),
        ));
      }
    }
    return List<ApplicationPermissionCombinationDetection>.unmodifiable(results);
  }

  static bool _matches(_PermissionCombinationRule rule, Set<String> declared) {
    if (rule.groups.isEmpty) {
      return rule.permissions.every(declared.contains);
    }
    return rule.groups.where((group) => group.any(declared.contains)).length >=
        rule.minimumGroups;
  }

  static List<String> _matchedPermissions(
    _PermissionCombinationRule rule,
    Set<String> declared,
  ) => (rule.permissions.where(declared.contains).toList()..sort());

  static EvidenceReference? _sourceReference(
    List<MobileEvent> events, {
    required int appIndex,
    required VisibleApplication application,
    required List<String> matchedPermissions,
    required DateTime observedAt,
    required int packageCount,
  }) {
    final orderedEvents = events.where((event) =>
        event.contractVersion == 1 &&
        event.capabilityId == 'AND-012' &&
        event.eventType == 'observation' &&
        event.availability == 'available' &&
        (event.operation == 'completed' || event.operation == 'degraded') &&
        event.freshness == 'fresh' &&
        !event.continuous).toList()
      ..sort((left, right) => left.eventId.compareTo(right.eventId));

    for (final event in orderedEvents) {
      if (event.evidence['scope'] != VisibleApplicationCollection.supportedScope) {
        continue;
      }
      if (event.observedAt != observedAt ||
          event.evidence['packageCount'] != packageCount) {
        continue;
      }
      final rawApplications = event.evidence['applications'];
      if (rawApplications is! List<Object?> || appIndex >= rawApplications.length) {
        continue;
      }
      final rawApplication = rawApplications[appIndex];
      if (rawApplication is! Map<Object?, Object?> ||
          rawApplication['packageName'] != application.packageName) {
        continue;
      }
      final requested = rawApplication['requestedPermissions'];
      if (requested is! List<Object?> ||
          requested.any((permission) => permission is! String) ||
          !listEquals(requested.cast<String>(), application.requestedPermissions) ||
          !matchedPermissions.every(requested.cast<String>().contains)) {
        continue;
      }
      return EvidenceReference(
        eventId: event.eventId,
        capabilityId: event.capabilityId,
        path: 'applications.$appIndex.requestedPermissions',
        observedAt: event.observedAt,
        value: List<String>.unmodifiable(requested.cast<String>()),
      );
    }
    return null;
  }

  static List<ApplicationPermissionDetectionCaveat> _caveatsFor(
    VisibleApplicationCollection collection,
  ) {
    final caveats = <ApplicationPermissionDetectionCaveat>[];
    if (collection.visibilityMayBeFiltered) {
      caveats.add(
        ApplicationPermissionDetectionCaveat.packageVisibilityMayBeFiltered,
      );
    }
    if (collection.truncated) {
      caveats.add(ApplicationPermissionDetectionCaveat.applicationListTruncated);
    }
    if (collection.permissionsTruncated) {
      caveats.add(ApplicationPermissionDetectionCaveat.permissionListTruncated);
    }
    if (collection.events.any((event) =>
        event.capabilityId == 'AND-012' &&
        event.observedAt == collection.observedAt &&
        event.operation == 'degraded')) {
      caveats.add(ApplicationPermissionDetectionCaveat.inventoryCollectionDegraded);
    }
    return caveats;
  }
}

class _PermissionCombinationRule {
  const _PermissionCombinationRule({
    required this.id,
    required this.title,
    required this.explanation,
    required this.permissions,
    this.minimumGroups = 0,
    this.groups = const [],
  });

  final String id;
  final String title;
  final String explanation;
  final Set<String> permissions;
  final int minimumGroups;
  final List<Set<String>> groups;
}
