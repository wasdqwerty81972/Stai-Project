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
  });

  final String packageName;
  final String label;
  final String? versionName;
  final int versionCode;
  final String? installerPackageName;
  final bool isSystemApp;
  final List<String> requestedPermissions;
  final List<String> grantedPermissions;

  factory VisibleApplication.fromMap(Map<String, Object?> map) {
    final requested = _stringList(map, 'requestedPermissions');
    final granted = _stringList(map, 'grantedPermissions');
    final packageName = _requiredString(map, 'packageName');
    if (!_packagePattern.hasMatch(packageName) || packageName.contains('..')) {
      throw const FormatException('Application has an invalid package name.');
    }
    if (granted.any((permission) => !requested.contains(permission))) {
      throw const FormatException(
        'Granted permissions must also appear in the requested permission list.',
      );
    }
    return VisibleApplication(
      packageName: packageName,
      label: _requiredString(map, 'label'),
      versionName: _nullableString(map, 'versionName'),
      versionCode: _requiredInt(map, 'versionCode'),
      installerPackageName: _nullableString(map, 'installerPackageName'),
      isSystemApp: _requiredBool(map, 'isSystemApp'),
      requestedPermissions: List<String>.unmodifiable(requested),
      grantedPermissions: List<String>.unmodifiable(granted),
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
    required this.applications,
    required this.events,
  });

  static const supportedScope = 'launchable_packages_visible_to_this_app';
  static const maxApplications = 200;

  final int contractVersion;
  final DateTime observedAt;
  final String scope;
  final bool visibilityMayBeFiltered;
  final bool truncated;
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
      return event;
    }).toList(growable: false);
    if (!events.any((event) => event.capabilityId == 'AND-012')) {
      throw const FormatException('Application inventory is missing package identifier provenance.');
    }

    return VisibleApplicationCollection(
      contractVersion: contractVersion,
      observedAt: DateTime.fromMillisecondsSinceEpoch(observedAtEpochMs, isUtc: true),
      scope: scope,
      visibilityMayBeFiltered: _requiredBool(map, 'visibilityMayBeFiltered'),
      truncated: _requiredBool(map, 'truncated'),
      applications: List<VisibleApplication>.unmodifiable(applications),
      events: List<MobileEvent>.unmodifiable(events),
    );
  }
}

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
  if (value is! List<Object?> || value.any((item) => item is! String || item.isEmpty)) {
    throw FormatException('Application inventory field "$key" is invalid.');
  }
  final list = value.cast<String>();
  if (list.toSet().length != list.length) {
    throw FormatException('Application inventory field "$key" has duplicates.');
  }
  return list;
}
