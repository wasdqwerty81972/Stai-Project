import 'package:flutter/foundation.dart';

import '../detection/detection_models.dart';

@immutable
class VisibleApplication {
  const VisibleApplication({
    required this.packageName,
    required this.label,
    required this.versionName,
    required this.versionCode,
    required this.installerPackageName,
    required this.isSystemApp,
    required this.requestedPermissions,
    required this.grantedPermissions,
    required this.permissionGrantStateAvailable,
  });

  final String packageName;
  final String label;
  final String? versionName;
  final int versionCode;
  final String? installerPackageName;
  final bool isSystemApp;
  final List<String> requestedPermissions;
  final List<String> grantedPermissions;
  final bool permissionGrantStateAvailable;

  factory VisibleApplication.fromMap(Map<String, Object?> map) {
    final requested = _stringList(map, 'requestedPermissions');
    final granted = _stringList(map, 'grantedPermissions');
    final grantStateAvailable = _requiredBool(map, 'permissionGrantStateAvailable');
    final packageName = _requiredString(map, 'packageName');
    final label = _requiredString(map, 'label');
    final versionName = _nullableString(map, 'versionName');
    final installerPackageName = _nullableString(map, 'installerPackageName');
    if (!_packagePattern.hasMatch(packageName) ||
        packageName.contains('..') ||
        packageName.length > maxPackageNameLength) {
      throw const FormatException('Application has an invalid package name.');
    }
    if (label.length > maxLabelLength ||
        (versionName?.length ?? 0) > maxVersionNameLength ||
        (installerPackageName?.length ?? 0) > maxPackageNameLength) {
      throw const FormatException('Application metadata exceeds its size limits.');
    }
    if (granted.any((permission) => !requested.contains(permission))) {
      throw const FormatException(
        'Granted permissions must also appear in the requested permission list.',
      );
    }
    if (requested.any((permission) => permission.length > maxPermissionNameLength)) {
      throw const FormatException('Application permission metadata exceeds its limits.');
    }
    if (!grantStateAvailable && granted.isNotEmpty) {
      throw const FormatException('Unknown grant state cannot include granted permissions.');
    }
    return VisibleApplication(
      packageName: packageName,
      label: label,
      versionName: versionName,
      versionCode: _requiredInt(map, 'versionCode'),
      installerPackageName: installerPackageName,
      isSystemApp: _requiredBool(map, 'isSystemApp'),
      requestedPermissions: List<String>.unmodifiable(requested),
      grantedPermissions: List<String>.unmodifiable(granted),
      permissionGrantStateAvailable: grantStateAvailable,
    );
  }
}

@immutable
class VisibleApplicationCollection {
  const VisibleApplicationCollection({
    required this.contractVersion,
    required this.observedAt,
    required this.scope,
    required this.visibilityMayBeFiltered,
    required this.truncated,
    required this.permissionsTruncated,
    required this.applications,
    required this.events,
  });

  static const supportedScope = 'launchable_packages_visible_to_this_app';
  static const maxApplications = 200;
  static const maxPermissionsPerApplication = 32;
  static const maxPermissionNameLength = 255;
  static const maxLabelLength = 120;
  static const maxVersionNameLength = 100;
  static const maxPackageNameLength = 255;

  final int contractVersion;
  final DateTime observedAt;
  final String scope;
  final bool visibilityMayBeFiltered;
  final bool truncated;
  final bool permissionsTruncated;
  final List<VisibleApplication> applications;
  final List<MobileEvent> events;

  factory VisibleApplicationCollection.fromMap(Map<String, Object?> map) {
    final contractVersion = _requiredInt(map, 'contractVersion');
    final scope = _requiredString(map, 'scope');
    final observedAtEpochMs = _requiredInt(map, 'observedAtEpochMs');
    final applicationsRaw = map['applications'];
    final eventsRaw = map['events'];
    if (contractVersion != 1) {
      throw FormatException('Unsupported inventory contract version $contractVersion.');
    }
    if (scope != supportedScope) {
      throw const FormatException('Application inventory has an unsupported visibility scope.');
    }
    if (applicationsRaw is! List<Object?> || eventsRaw is! List<Object?>) {
      throw const FormatException('Application inventory arrays are malformed.');
    }
    if (applicationsRaw.length > maxApplications) {
      throw const FormatException('Application inventory exceeds its item limit.');
    }
    if (eventsRaw.length != 5) {
      throw const FormatException('Application inventory must contain exactly five events.');
    }

    final applications = applicationsRaw.map((value) {
      if (value is! Map<Object?, Object?>) {
        throw const FormatException('Application inventory item must be an object.');
      }
      return VisibleApplication.fromMap(_stringMap(value));
    }).toList(growable: false);
    final packageNames = applications.map((app) => app.packageName).toSet();
    if (packageNames.length != applications.length) {
      throw const FormatException('Application inventory contains duplicate packages.');
    }

    final events = eventsRaw.map((value) {
      if (value is! Map<Object?, Object?>) {
        throw const FormatException('Application inventory event must be an object.');
      }
      final event = MobileEvent.fromJson(_stringMap(value));
      if (event.contractVersion != 1 || event.continuous) {
        throw const FormatException('Application inventory event contract is unsupported.');
      }
      if (event.observedAt.millisecondsSinceEpoch != observedAtEpochMs) {
        throw const FormatException('Application inventory event timestamps do not match the snapshot.');
      }
      return event;
    }).toList(growable: false);
    if (events.map((event) => event.eventId).toSet().length != events.length) {
      throw const FormatException('Application inventory contains duplicate event IDs.');
    }
    const expectedCapabilities = {'AND-012', 'AND-013', 'AND-016', 'AND-025', 'AND-026'};
    final eventCapabilities = events.map((event) => event.capabilityId).toSet();
    if (events.length != expectedCapabilities.length ||
        eventCapabilities.length != events.length ||
        !eventCapabilities.containsAll(expectedCapabilities)) {
      throw const FormatException('Application inventory is missing capability evidence.');
    }
    for (final event in events) {
      if (event.evidence['scope'] != scope ||
          event.evidence['packageCount'] != applications.length) {
        throw const FormatException('Application inventory event summary contradicts the snapshot.');
      }
    }
    final packageEvent = events.singleWhere((event) => event.capabilityId == 'AND-012');
    if (packageEvent.evidence['inventorySchemaVersion'] != 1 ||
        packageEvent.evidence['visibilityMayBeFiltered'] !=
            _requiredBool(map, 'visibilityMayBeFiltered') ||
        packageEvent.evidence['truncated'] != _requiredBool(map, 'truncated') ||
        packageEvent.evidence['permissionsTruncated'] !=
            _requiredBool(map, 'permissionsTruncated')) {
      throw const FormatException('Package inventory event metadata contradicts the snapshot.');
    }
    final eventApplications = packageEvent.evidence['applications'];
    if (eventApplications is! List<Object?> ||
        eventApplications.length != applications.length) {
      throw const FormatException('Package inventory event is missing its application snapshot.');
    }
    for (var index = 0; index < applications.length; index++) {
      final value = eventApplications[index];
      if (value is! Map<Object?, Object?> ||
          !_sameApplication(
            applications[index],
            VisibleApplication.fromMap(_stringMap(value)),
          )) {
        throw const FormatException('Package inventory event contradicts its application snapshot.');
      }
    }

    return VisibleApplicationCollection(
      contractVersion: contractVersion,
      observedAt: DateTime.fromMillisecondsSinceEpoch(observedAtEpochMs, isUtc: true),
      scope: scope,
      visibilityMayBeFiltered: _requiredBool(map, 'visibilityMayBeFiltered'),
      truncated: _requiredBool(map, 'truncated'),
      permissionsTruncated: _requiredBool(map, 'permissionsTruncated'),
      applications: List<VisibleApplication>.unmodifiable(applications),
      events: List<MobileEvent>.unmodifiable(events),
    );
  }
}

bool _sameApplication(VisibleApplication left, VisibleApplication right) =>
    left.packageName == right.packageName &&
    left.label == right.label &&
    left.versionName == right.versionName &&
    left.versionCode == right.versionCode &&
    left.installerPackageName == right.installerPackageName &&
    left.isSystemApp == right.isSystemApp &&
    listEquals(left.requestedPermissions, right.requestedPermissions) &&
    listEquals(left.grantedPermissions, right.grantedPermissions) &&
    left.permissionGrantStateAvailable == right.permissionGrantStateAvailable;

final _packagePattern = RegExp(r'^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$');

Map<String, Object?> _stringMap(Map<Object?, Object?> map) {
  final result = <String, Object?>{};
  for (final entry in map.entries) {
    if (entry.key is! String) {
      throw const FormatException('Application inventory object has a non-string key.');
    }
    result[entry.key! as String] = entry.value;
  }
  return result;
}

String _requiredString(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is String && value.trim().isNotEmpty) return value;
  throw FormatException('Application inventory field "$key" is invalid.');
}

String? _nullableString(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value == null || value is String) return value as String?;
  throw FormatException('Application inventory field "$key" is invalid.');
}

int _requiredInt(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is int && value >= 0) return value;
  throw FormatException('Application inventory field "$key" is invalid.');
}

bool _requiredBool(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is bool) return value;
  throw FormatException('Application inventory field "$key" is invalid.');
}

List<String> _stringList(Map<String, Object?> map, String key) {
  final value = map[key];
  if (value is! List<Object?> ||
      value.length > VisibleApplicationCollection.maxPermissionsPerApplication ||
      value.any((item) => item is! String || item.isEmpty)) {
    throw FormatException('Application inventory field "$key" is invalid.');
  }
  final list = value.cast<String>();
  if (list.toSet().length != list.length) {
    throw FormatException('Application inventory field "$key" has duplicates.');
  }
  return list;
}
